package dbsc_refresh_endpoint

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	motmedelCryptoInterfaces "github.com/Motmedel/utils_go/pkg/crypto/interfaces"
	muxPkg "github.com/Motmedel/utils_go/pkg/http/mux"
	muxTesting "github.com/Motmedel/utils_go/pkg/http/mux/testing"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	motmedelTestingCmp "github.com/Motmedel/utils_go/pkg/testing/cmp"
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
)

var defaultTestEndpoint = New()
var defaultHttpServer *httptest.Server
var defaultProcessor *dbsc_session_response_processor.Processor

var db *sql.DB
var method motmedelCryptoInterfaces.Method
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
	}{
		{
			name: "valid session response token happy path",
			args: &muxTesting.Args{
				Headers:            [][2]string{{session.DbscSessionIdHeaderName, loginTesting.AuthenticationId}, {session.DbscSessionResponseHeaderName, validToken}},
				ExpectedStatusCode: http.StatusNoContent,
			},
		},
		{
			// A session that cannot be refreshed again is ended, so the browser stops applying it.
			name: "no db authentication ends the session",
			args: &muxTesting.Args{
				Headers:            [][2]string{{session.DbscSessionIdHeaderName, loginTesting.AuthenticationId}, {session.DbscSessionResponseHeaderName, validToken}},
				ExpectedStatusCode: http.StatusOK,
				ExpectedBody:       []byte(`{"continue":false}`),
			},
			noDbAuthentication: true,
		},
		{
			name: "ended authentication ends the session",
			args: &muxTesting.Args{
				Headers:            [][2]string{{session.DbscSessionIdHeaderName, loginTesting.AuthenticationId}, {session.DbscSessionResponseHeaderName, validToken}},
				ExpectedStatusCode: http.StatusOK,
				ExpectedBody:       []byte(`{"continue":false}`),
			},
			endedAuthentication: true,
		},
		{
			name: "expired authentication ends the session",
			args: &muxTesting.Args{
				Headers:            [][2]string{{session.DbscSessionIdHeaderName, loginTesting.AuthenticationId}, {session.DbscSessionResponseHeaderName, validToken}},
				ExpectedStatusCode: http.StatusOK,
				ExpectedBody:       []byte(`{"continue":false}`),
			},
			expiredAuthentication: true,
		},
		{
			name: "valid session response token, empty public key",
			args: &muxTesting.Args{
				Headers:            [][2]string{{session.DbscSessionIdHeaderName, loginTesting.AuthenticationId}, {session.DbscSessionResponseHeaderName, validToken}},
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
				Headers:            [][2]string{{session.DbscSessionIdHeaderName, loginTesting.AuthenticationId}, {session.DbscSessionResponseHeaderName, validToken}},
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
				Headers:               [][2]string{{session.DbscSessionIdHeaderName, loginTesting.AuthenticationId}, {session.DbscSessionResponseHeaderName, "invalid"}},
				ExpectedStatusCode:    http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{Detail: "Invalid token."},
			},
		},
		{
			name: "multiple session response headers",
			args: &muxTesting.Args{
				Headers: [][2]string{
					{session.DbscSessionIdHeaderName, loginTesting.AuthenticationId},
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
			name: "no session response header happy path",
			args: &muxTesting.Args{
				Headers:            [][2]string{{session.DbscSessionIdHeaderName, loginTesting.AuthenticationId}},
				ExpectedStatusCode: http.StatusForbidden,
				ExpectedHeaders: [][2]string{
					{session.DbscSessionChallengeHeaderName, fmt.Sprintf("\"%s\";id=\"%s\"", testChallenge, loginTesting.AuthenticationId)},
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
						if authenticationId != loginTesting.AuthenticationId {
							return nil, fmt.Errorf("authentication id mismatch: got %s, want %s", authenticationId, loginTesting.AuthenticationId)
						}

						expiresAt := time.Now().Add(time.Hour)
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
				if id != loginTesting.AuthenticationId {
					t.Fatalf("expected id and authentication id to match: got %s, want %s", id, loginTesting.AuthenticationId)
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

			testEndpoint.insertDbscChallenge = func(ctx context.Context, challenge string, authenticationId string, challengeDuration time.Duration, db *sql.DB) error {
				if challenge != testChallenge {
					t.Fatalf("expected challenge to match: got %s, want %s", challenge, testChallenge)
				}

				if authenticationId != loginTesting.AuthenticationId {
					t.Fatalf("expected authentication id to match: got %s, want %s", authenticationId, loginTesting.AuthenticationId)
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
			if err := New().Initialize(tt.args.pr, tt.args.sm); (err != nil) != tt.wantErr {
				t.Errorf("Initialize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	opts := []motmedelTestingCmp.Option{
		motmedelTestingCmp.IgnoreFields(
			Endpoint{},
			"insertDbscChallenge",
			"generateDbscChallenge",
			"selectRefreshAuthentication",
		),
		motmedelTestingCmp.EquateComparable(adapter.Adapter[struct{}]{}),
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
			if diff := motmedelTestingCmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("endpoint mismatch (-expected +got):\n%s", diff)
			}
		})
	}
}
