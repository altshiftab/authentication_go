package dbsc_refresh_endpoint

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	accountPkg "github.com/altshiftab/authentication_go/pkg/database/types/account"
	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	"github.com/altshiftab/authentication_go/pkg/database/types/dbsc_challenge"
	"github.com/altshiftab/authentication_go/pkg/session"
	loginTesting "github.com/altshiftab/authentication_go/pkg/session/testing"
	"github.com/altshiftab/authentication_go/pkg/session/types/dbsc_session_response_processor"
	"github.com/altshiftab/authentication_go/pkg/session/types/dbsc_session_response_processor/dbsc_session_response_processor_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/endpoint/dbsc_refresh_endpoint/dbsc_refresh_endpoint_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/endpoint/dbsc_register_endpoint/dbsc_register_endpoint_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_manager"
	altshiftCryptoInterfaces "github.com/altshiftab/utils_go/pkg/crypto/interfaces"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
	muxTesting "github.com/altshiftab/utils_go/pkg/http/mux/testing"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	altshiftTestingCmp "github.com/altshiftab/utils_go/pkg/testing/cmp"
)

// Errors the tests' stand-ins fail with.
var (
	errTestAuthenticationIdMismatch = errors.New("authentication id mismatch")
)

// testAuthenticationId is the session the browser names: the authentication id registration handed
// out, which is a uuid.
const testAuthenticationId = "6f1c2b9e-3d4a-4f5b-8c7d-9e0a1b2c3d4e"

var defaultTestEndpoint = New()
var defaultHttpServer *httptest.Server
var defaultProcessor *dbsc_session_response_processor.Processor

var db *sql.DB
var method altshiftCryptoInterfaces.Method
var sessionManager *session_manager.Manager

func TestMain(m *testing.M) {
	var err error

	_, method, db = loginTesting.SetUp()
	sessionManager, err = session_manager.New(method, db, loginTesting.Issuer, loginTesting.RegisteredDomain)
	if err != nil {
		panic(fmt.Errorf("session manager new: %w", err))
	}

	defaultProcessor, err = dbsc_session_response_processor.New("https://example.com"+dbsc_register_endpoint_config.DefaultPath, db)
	if err != nil {
		panic(fmt.Errorf("dbsc session response processor new: %w", err))
	}

	if err := defaultTestEndpoint.Initialize(defaultProcessor, sessionManager); err != nil {
		panic(fmt.Errorf("test endpoint initialize: %w", err))
	}

	mux := &muxPkg.Mux{}
	mux.Add(defaultTestEndpoint.Endpoint.Endpoint)
	defaultHttpServer = httptest.NewServer(mux)
	defer defaultHttpServer.Close()

	code := m.Run()
	if db != nil {
		_ = db.Close()
	}
	os.Exit(code)
}

func TestEndpoint(t *testing.T) {
	t.Parallel()

	const testChallenge = "test-challenge"

	// Minted the way a browser sends it: the public key in the JWT header, the challenge as jti.
	validToken, validTokenPublicKey := loginTesting.MakeDbscProof(testChallenge)

	// A different, valid key: the proof then fails verification rather than parsing.
	_, otherPublicKey := loginTesting.MakeDbscProof(testChallenge)

	testCases := []struct {
		name                  string
		args                  *muxTesting.Args
		noDbAuthentication    bool
		emptyPublicKey        bool
		publicKeyMismatch     bool
		endedAuthentication   bool
		expiredAuthentication bool
		spentChallenge        bool
		expiredChallenge      bool
		// wantNoChallenge is a request that must be answered without a challenge being stored.
		wantNoChallenge bool
	}{
		{
			// The challenge on the success is what makes the next refresh a single request: the
			// browser caches it and signs it then, instead of having to be challenged first.
			name: "valid session response token happy path",
			args: &muxTesting.Args{
				Headers:            [][2]string{{session.DbscSessionIdHeaderName, testAuthenticationId}, {session.DbscSessionResponseHeaderName, validToken}},
				ExpectedStatusCode: http.StatusNoContent,
				ExpectedHeaders: [][2]string{
					{session.DbscSessionChallengeHeaderName, fmt.Sprintf("\"%s\";id=\"%s\"", testChallenge, testAuthenticationId)},
				},
			},
		},
		{
			// A browser signing the challenge it cached, which single use has already spent. The
			// session is sound, so it is challenged afresh rather than given an error: the
			// specification's rejection is a 403 carrying a new challenge, which it signs and
			// retries. An error instead leaves it nothing to do but repeat the spent proof.
			name: "spent challenge is answered with a fresh challenge",
			args: &muxTesting.Args{
				Headers:            [][2]string{{session.DbscSessionIdHeaderName, testAuthenticationId}, {session.DbscSessionResponseHeaderName, validToken}},
				ExpectedStatusCode: http.StatusForbidden,
				ExpectedHeaders: [][2]string{
					{session.DbscSessionChallengeHeaderName, fmt.Sprintf("\"%s\";id=\"%s\"", testChallenge, testAuthenticationId)},
				},
			},
			spentChallenge: true,
		},
		{
			// The other way a cached challenge stops being redeemable. The browser holds one from
			// the previous refresh and cannot know how long that has been, so an expired challenge
			// has to be answered exactly as a spent one is; a plain error leaves it repeating a
			// proof that can never be accepted.
			name: "expired challenge is answered with a fresh challenge",
			args: &muxTesting.Args{
				Headers:            [][2]string{{session.DbscSessionIdHeaderName, testAuthenticationId}, {session.DbscSessionResponseHeaderName, validToken}},
				ExpectedStatusCode: http.StatusForbidden,
				ExpectedHeaders: [][2]string{
					{session.DbscSessionChallengeHeaderName, fmt.Sprintf("\"%s\";id=\"%s\"", testChallenge, testAuthenticationId)},
				},
			},
			expiredChallenge: true,
		},
		{
			// A session that cannot be refreshed again is ended, so the browser stops applying it.
			name: "no db authentication ends the session",
			args: &muxTesting.Args{
				Headers:            [][2]string{{session.DbscSessionIdHeaderName, testAuthenticationId}, {session.DbscSessionResponseHeaderName, validToken}},
				ExpectedStatusCode: http.StatusOK,
				ExpectedBody:       []byte(`{"continue":false}`),
			},
			noDbAuthentication: true,
		},
		{
			name: "ended authentication ends the session",
			args: &muxTesting.Args{
				Headers:            [][2]string{{session.DbscSessionIdHeaderName, testAuthenticationId}, {session.DbscSessionResponseHeaderName, validToken}},
				ExpectedStatusCode: http.StatusOK,
				ExpectedBody:       []byte(`{"continue":false}`),
			},
			endedAuthentication: true,
		},
		{
			name: "expired authentication ends the session",
			args: &muxTesting.Args{
				Headers:            [][2]string{{session.DbscSessionIdHeaderName, testAuthenticationId}, {session.DbscSessionResponseHeaderName, validToken}},
				ExpectedStatusCode: http.StatusOK,
				ExpectedBody:       []byte(`{"continue":false}`),
			},
			expiredAuthentication: true,
		},
		{
			name: "valid session response token, empty public key",
			args: &muxTesting.Args{
				Headers:            [][2]string{{session.DbscSessionIdHeaderName, testAuthenticationId}, {session.DbscSessionResponseHeaderName, validToken}},
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "No public key for authentication.",
				},
			},
			emptyPublicKey: true,
		},
		{
			name: "valid session response token, public key mismatch",
			args: &muxTesting.Args{
				Headers:            [][2]string{{session.DbscSessionIdHeaderName, testAuthenticationId}, {session.DbscSessionResponseHeaderName, validToken}},
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "Invalid token.",
				},
			},
			publicKeyMismatch: true,
		},
		{
			name: "invalid session response token",
			args: &muxTesting.Args{
				Headers:               [][2]string{{session.DbscSessionIdHeaderName, testAuthenticationId}, {session.DbscSessionResponseHeaderName, "invalid"}},
				ExpectedStatusCode:    http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{Detail: "Invalid token."},
			},
		},
		{
			name: "multiple session response headers",
			args: &muxTesting.Args{
				Headers: [][2]string{
					{session.DbscSessionIdHeaderName, testAuthenticationId},
					{"Secure-Session-Response", "val1"},
					{"Secure-Session-Response", "val2"},
				},
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail:    "Multiple header values.",
					Extension: map[string]any{"header": session.DbscSessionResponseHeaderName},
				},
			},
		},
		{
			// The session cannot be identified without it, and there is no cookie to fall back on.
			name: "missing session id header",
			args: &muxTesting.Args{
				Headers:            [][2]string{{session.DbscSessionResponseHeaderName, validToken}},
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail:    "A single session id is required.",
					Extension: map[string]any{"header": session.DbscSessionIdHeaderName},
				},
			},
		},
		{
			// Nothing names a session but a uuid, so anything else is turned away before the store
			// is asked about it or anything is stored for it.
			name: "a session id that is no uuid is refused",
			args: &muxTesting.Args{
				Headers:               [][2]string{{session.DbscSessionIdHeaderName, "test-authentication-id"}},
				ExpectedStatusCode:    http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{Detail: "The session id is malformed."},
			},
			wantNoChallenge: true,
		},
		{
			// A challenge is a row stored for the session, so none is stored for one that is not
			// there; the browser is told to stop applying it instead.
			name: "no proof and no db authentication ends the session without a challenge",
			args: &muxTesting.Args{
				Headers:            [][2]string{{session.DbscSessionIdHeaderName, testAuthenticationId}},
				ExpectedStatusCode: http.StatusOK,
				ExpectedBody:       []byte(`{"continue":false}`),
			},
			noDbAuthentication: true,
			wantNoChallenge:    true,
		},
		{
			name: "no proof and an ended authentication ends the session without a challenge",
			args: &muxTesting.Args{
				Headers:            [][2]string{{session.DbscSessionIdHeaderName, testAuthenticationId}},
				ExpectedStatusCode: http.StatusOK,
				ExpectedBody:       []byte(`{"continue":false}`),
			},
			endedAuthentication: true,
			wantNoChallenge:     true,
		},
		{
			// A session with no key has nothing to refresh with. A challenge handed to it is one
			// that registration would accept, from whoever holds the session's cookie.
			name: "no proof and no registered key is refused without a challenge",
			args: &muxTesting.Args{
				Headers:            [][2]string{{session.DbscSessionIdHeaderName, testAuthenticationId}},
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "No public key for authentication.",
				},
			},
			emptyPublicKey:  true,
			wantNoChallenge: true,
		},
		{
			name: "no session response header happy path",
			args: &muxTesting.Args{
				Headers:            [][2]string{{session.DbscSessionIdHeaderName, testAuthenticationId}},
				ExpectedStatusCode: http.StatusForbidden,
				ExpectedHeaders: [][2]string{
					{session.DbscSessionChallengeHeaderName, fmt.Sprintf("\"%s\";id=\"%s\"", testChallenge, testAuthenticationId)},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint := New()
			testEndpointProcessor, err := dbsc_session_response_processor.New(
				"https://example.com"+dbsc_register_endpoint_config.DefaultPath,
				db,
				dbsc_session_response_processor_config.WithPopDbscChallenge(
					func(ctx context.Context, challenge string, authenticationId string, db *sql.DB) (*dbsc_challenge.Challenge, error) {
						if authenticationId != testAuthenticationId {
							return nil, fmt.Errorf("%w: got %s, want %s", errTestAuthenticationIdMismatch, authenticationId, testAuthenticationId)
						}

						// How the store reports a challenge that has been redeemed already.
						if tc.spentChallenge {
							return nil, sql.ErrNoRows
						}

						expiresAt := time.Now().Add(time.Hour)
						if tc.expiredChallenge {
							expiresAt = time.Now().Add(-time.Hour)
						}
						return &dbsc_challenge.Challenge{
							Authentication: &authenticationPkg.Authentication{Id: authenticationId},
							Challenge:      []byte(challenge),
							ExpiresAt:      &expiresAt,
						}, nil
					},
				),
			)
			if err != nil {
				t.Fatalf("dbsc session response processor new: %v", err)
			}

			if err := testEndpoint.Initialize(testEndpointProcessor, sessionManager); err != nil {
				t.Fatalf("test endpoint initialize: %v", err)
			}

			testEndpoint.selectRefreshAuthentication = func(ctx context.Context, id string, database *sql.DB) (*authenticationPkg.Authentication, error) {
				if id != testAuthenticationId {
					t.Fatalf("expected id and authentication id to match: got %s, want %s", id, testAuthenticationId)
				}

				if tc.noDbAuthentication {
					return nil, sql.ErrNoRows
				}

				publicKey := validTokenPublicKey
				if tc.emptyPublicKey {
					publicKey = nil
				}

				if tc.publicKeyMismatch {
					publicKey = otherPublicKey
				}

				expiresAt := time.Now().Add(time.Hour)
				if tc.expiredAuthentication {
					expiresAt = time.Now().Add(-time.Hour)
				}
				createdAt := time.Now().Add(-time.Hour)
				return &authenticationPkg.Authentication{
					Id: id,
					Account: &accountPkg.Account{
						Id:           "test-account-id",
						EmailAddress: "test@example.com",
						Roles:        []string{"test-role"},
					},
					Ended:         tc.endedAuthentication,
					DbscPublicKey: publicKey,
					CreatedAt:     &createdAt,
					ExpiresAt:     &expiresAt,
				}, nil
			}

			testEndpoint.generateDbscChallenge = func() (string, error) {
				return testChallenge, nil
			}

			var challengesInserted atomic.Int32
			testEndpoint.insertDbscChallenge = func(ctx context.Context, challenge string, authenticationId string, challengeDuration time.Duration, db *sql.DB) error {
				challengesInserted.Add(1)

				if challenge != testChallenge {
					t.Fatalf("expected challenge to match: got %s, want %s", challenge, testChallenge)
				}

				if authenticationId != testAuthenticationId {
					t.Fatalf("expected authentication id to match: got %s, want %s", authenticationId, testAuthenticationId)
				}

				if challengeDuration != testEndpoint.ChallengeDuration {
					t.Fatalf("expected challenge duration to match: got %s, want %s", challengeDuration, testEndpoint.ChallengeDuration)
				}

				return nil
			}

			mux := &muxPkg.Mux{}
			mux.Add(testEndpoint.Endpoint.Endpoint)
			httpServer := httptest.NewServer(mux)
			defer httpServer.Close()

			tc.args.Path = testEndpoint.Path
			tc.args.Method = testEndpoint.Method

			muxTesting.TestArgs(t, tc.args, httpServer.URL)

			if inserted := challengesInserted.Load(); tc.wantNoChallenge && inserted != 0 {
				t.Errorf("%s: %d challenges stored, want none", tc.name, inserted)
			}
		})
	}
}

func TestEndpoint_Initialize(t *testing.T) {
	t.Parallel()

	type args struct {
		pr *dbsc_session_response_processor.Processor
		sm *session_manager.Manager
	}

	sm, err := session_manager.New(method, db, loginTesting.Issuer, "example.com")
	if err != nil {
		t.Fatalf("session manager new: %v", err)
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "nil processor", args: args{pr: nil, sm: sm}, wantErr: true},
		{name: "nil session manager", args: args{pr: defaultProcessor, sm: nil}, wantErr: true},
		{name: "nil db in processor", args: args{pr: &dbsc_session_response_processor.Processor{}, sm: sm}, wantErr: true},
		{name: "success", args: args{pr: defaultProcessor, sm: sm}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := New().Initialize(tt.args.pr, tt.args.sm); (err != nil) != tt.wantErr {
				t.Errorf("Initialize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	opts := []altshiftTestingCmp.Option{
		altshiftTestingCmp.IgnoreFields(
			Endpoint{},
			"insertDbscChallenge",
			"generateDbscChallenge",
			"selectRefreshAuthentication",
		),
		altshiftTestingCmp.EquateComparable(adapter.Adapter[struct{}]{}),
	}

	type args struct {
		options []dbsc_refresh_endpoint_config.Option
	}
	tests := []struct {
		name string
		args args
		want *Endpoint
	}{
		{
			name: "success, default args",
			want: &Endpoint{
				Endpoint: &initialization_endpoint.Endpoint{
					Endpoint: &endpoint.Endpoint{
						Path:      dbsc_refresh_endpoint_config.DefaultPath,
						Method:    http.MethodPost,
						Public:    true,
						UrlParser: adapter.New(query_extractor.Empty),
					},
				},
				SessionDuration:   dbsc_refresh_endpoint_config.DefaultSessionDuration,
				ChallengeDuration: dbsc_refresh_endpoint_config.DefaultChallengeDuration,
			},
		},
		{
			name: "success, custom path",
			args: args{options: []dbsc_refresh_endpoint_config.Option{dbsc_refresh_endpoint_config.WithPath("/test")}},
			want: &Endpoint{
				Endpoint: &initialization_endpoint.Endpoint{
					Endpoint: &endpoint.Endpoint{
						Path:      "/test",
						Method:    http.MethodPost,
						Public:    true,
						UrlParser: adapter.New(query_extractor.Empty),
					},
				},
				SessionDuration:   dbsc_refresh_endpoint_config.DefaultSessionDuration,
				ChallengeDuration: dbsc_refresh_endpoint_config.DefaultChallengeDuration,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := New(tt.args.options...)
			if diff := altshiftTestingCmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("endpoint mismatch (-expected +got):\n%s", diff)
			}
		})
	}
}
