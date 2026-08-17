package refresh_endpoint

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	accountPkg "github.com/altshiftab/authentication_go/pkg/database/types/account"
	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	loginTesting "github.com/altshiftab/authentication_go/pkg/session/testing"
	"github.com/altshiftab/authentication_go/pkg/session/types/authentication_method"
	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser"
	"github.com/altshiftab/authentication_go/pkg/session/types/endpoint/refresh_endpoint/refresh_endpoint_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_manager"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
	altshiftCryptoInterfaces "github.com/altshiftab/utils_go/pkg/crypto/interfaces"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
	muxTesting "github.com/altshiftab/utils_go/pkg/http/mux/testing"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/body_loader"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/body_loader/body_setting"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/cors_configurator"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claims/registered_claims"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claims/session_claims"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/numeric_date"
	altshiftTestingCmp "github.com/altshiftab/utils_go/pkg/testing/cmp"
)

var defaultAuthenticationParser request_parser.RequestParser[any]

var db *sql.DB
var method altshiftCryptoInterfaces.Method
var sessionManager *session_manager.Manager

func TestMain(m *testing.M) {
	var authorizationRequestParser *authorizer_request_parser.Parser
	authorizationRequestParser, method, db = loginTesting.SetUp()
	defaultAuthenticationParser = adapter.New(authorizationRequestParser)

	var err error
	sessionManager, err = session_manager.New(method, db, loginTesting.Issuer, loginTesting.RegisteredDomain)
	if err != nil {
		panic(fmt.Errorf("session manager new: %w", err))
	}

	code := m.Run()
	if db != nil {
		_ = db.Close()
	}

	os.Exit(code)
}

func TestEndpoint(t *testing.T) {
	t.Parallel()

	// A session token with most of its lifetime left is not refreshed and never reaches the
	// authentication, so cases that exercise the lookup carry one that is due for refresh.
	dueForRefreshCookie := loginTesting.MakeCookieExplicit(
		loginTesting.AuthenticationId,
		method,
		[]string{"ext"},
		time.Now().Add(time.Minute),
		time.Now().Add(-59*time.Minute),
	)

	testCases := []struct {
		name                      string
		args                      *muxTesting.Args
		noDbAuthentication        bool
		hasPublicKey              bool
		dbErr                     error
		nilDbAuthentication       bool
		nilSessionToken           bool
		invalidSessionTokenClaims bool
		invalidSessionTokenExp    bool
		invalidSessionTokenNbf    bool
		negativeDuration          bool
	}{
		{
			name: "ext session happy path refresh",
			args: &muxTesting.Args{
				Headers: [][2]string{
					{
						"Cookie",
						loginTesting.MakeCookieExplicit(
							loginTesting.AuthenticationId,
							method,
							[]string{authentication_method.Sso},
							time.Now().Add(1*time.Hour),
							time.Now().Add(-1*99*time.Hour),
						),
					},
				},
				ExpectedStatusCode:     http.StatusNoContent,
				ExpectedHeadersPresent: []string{"Set-Cookie"},
			},
		},
		{
			name: "ext session happy path no refresh",
			args: &muxTesting.Args{
				Headers: [][2]string{
					{
						"Cookie",
						loginTesting.MakeCookieExplicit(
							loginTesting.AuthenticationId,
							method,
							[]string{authentication_method.Sso},
							time.Now().Add(99*time.Hour),
							time.Now(),
						),
					},
				},
				ExpectedStatusCode:        http.StatusNoContent,
				ExpectedHeadersNotPresent: []string{"Set-Cookie"},
			},
		},
		{
			name: "ext session public key",
			args: &muxTesting.Args{
				Headers: [][2]string{
					{
						"Cookie",
						loginTesting.MakeStandardCookie(loginTesting.AuthenticationId, method),
					},
				},
				ExpectedStatusCode:        http.StatusNoContent,
				ExpectedHeadersNotPresent: []string{"Set-Cookie"},
			},
			hasPublicKey: true,
		},
		{
			name: "hwk session happy path",
			args: &muxTesting.Args{
				Headers: [][2]string{
					{
						"Cookie",
						loginTesting.MakeCookieExplicit(
							loginTesting.AuthenticationId,
							method,
							[]string{authentication_method.Dbsc},
							time.Now().Add(1*time.Hour),
							time.Now().Add(-1*99*time.Hour),
						),
					},
				},
				ExpectedStatusCode:        http.StatusNoContent,
				ExpectedHeadersNotPresent: []string{"Set-Cookie"},
			},
		},
		{
			name: "db error",
			args: &muxTesting.Args{
				Headers: [][2]string{
					{
						"Cookie",
						dueForRefreshCookie,
					},
				},
				ExpectedStatusCode:        http.StatusInternalServerError,
				ExpectedProblemDetail:     &problem_detail.Detail{},
				ExpectedHeadersNotPresent: []string{"Set-Cookie"},
			},
			dbErr: errors.New("db error"),
		},
		{
			// Clients poll this endpoint far more often than a refresh is due, so a call that
			// needs no refresh must not read the authentication. The database would error here.
			name: "not due for refresh does not read the authentication",
			args: &muxTesting.Args{
				Headers: [][2]string{
					{
						"Cookie",
						loginTesting.MakeStandardCookie(loginTesting.AuthenticationId, method),
					},
				},
				ExpectedStatusCode:        http.StatusNoContent,
				ExpectedHeadersNotPresent: []string{"Set-Cookie"},
			},
			dbErr: errors.New("db error"),
		},
		{
			name: "nil db authentication",
			args: &muxTesting.Args{
				Headers: [][2]string{
					{
						"Cookie",
						dueForRefreshCookie,
					},
				},
				ExpectedStatusCode:    http.StatusInternalServerError,
				ExpectedProblemDetail: &problem_detail.Detail{},
			},
			nilDbAuthentication: true,
		},
		{
			name: "empty authentication id",
			args: &muxTesting.Args{
				Headers: [][2]string{
					{
						"Cookie",
						loginTesting.MakeCookieExplicit(
							"",
							method,
							[]string{authentication_method.Sso},
							time.Now().Add(1*time.Hour),
							time.Now().Add(-1*99*time.Hour),
						),
					},
				},
				ExpectedStatusCode:        http.StatusBadRequest,
				ExpectedProblemDetail:     &problem_detail.Detail{Detail: "The session token authentication id is empty."},
				ExpectedHeadersNotPresent: []string{"Set-Cookie"},
			},
		},
		{
			name: "nil session token",
			args: &muxTesting.Args{
				ExpectedStatusCode:        http.StatusInternalServerError,
				ExpectedProblemDetail:     &problem_detail.Detail{},
				ExpectedHeadersNotPresent: []string{"Set-Cookie"},
			},
			nilSessionToken: true,
		},
		{
			name: "invalid session token claims",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The session token claims are empty.",
				},
				ExpectedHeadersNotPresent: []string{"Set-Cookie"},
			},
			invalidSessionTokenClaims: true,
		},
		{
			name: "invalid session token exp",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The session token expires at is empty.",
				},
				ExpectedHeadersNotPresent: []string{"Set-Cookie"},
			},
			invalidSessionTokenExp: true,
		},
		{
			name: "invalid session token exp",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The session token not before is empty.",
				},
				ExpectedHeadersNotPresent: []string{"Set-Cookie"},
			},
			invalidSessionTokenNbf: true,
		},
		{
			// The session token is short-lived and the cookie carrying it outlives it, so an
			// expired token is the normal case for a refresh; the authentication is what decides.
			name: "expired session token",
			args: &muxTesting.Args{
				ExpectedStatusCode:     http.StatusNoContent,
				ExpectedHeadersPresent: []string{"Set-Cookie"},
			},
			negativeDuration: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint := New()
			if err := testEndpoint.Initialize(defaultAuthenticationParser, &cors_configurator.Configurator{}, sessionManager); err != nil {
				t.Fatalf("test endpoint initialize: %v", err)
			}

			testEndpoint.selectRefreshAuthentication = func(ctx context.Context, id string, db *sql.DB) (*authenticationPkg.Authentication, error) {
				if id != loginTesting.AuthenticationId {
					t.Fatalf("expected id and authentication id to match: got %s, want %s", id, loginTesting.AuthenticationId)
				}

				if testCase.dbErr != nil {
					return nil, testCase.dbErr
				}

				if testCase.noDbAuthentication {
					return nil, sql.ErrNoRows
				}

				if testCase.nilDbAuthentication {
					return nil, nil
				}

				authentication := &authenticationPkg.Authentication{
					Id:        id,
					Account:   &accountPkg.Account{Roles: []string{"test-role"}},
					Ended:     false,
					ExpiresAt: new(time.Now().Add(time.Hour)),
				}

				if testCase.hasPublicKey {
					authentication.DbscPublicKey = []byte{1, 2, 3}
				}

				return authentication, nil
			}

			if testCase.nilSessionToken || testCase.invalidSessionTokenClaims || testCase.invalidSessionTokenExp || testCase.invalidSessionTokenNbf || testCase.negativeDuration {
				if testCase.nilSessionToken {
					testEndpoint.AuthenticationParser = request_parser.New(
						func(r *http.Request) (any, *response_error.ResponseError) {
							return nil, nil
						},
					)
				} else if testCase.invalidSessionTokenClaims {
					testEndpoint.AuthenticationParser = request_parser.New(
						func(r *http.Request) (any, *response_error.ResponseError) {
							return &session_token.Token{
								AuthenticationId: loginTesting.AuthenticationId,
								Claims:           nil,
							}, nil
						},
					)
				} else if testCase.invalidSessionTokenExp {
					testEndpoint.AuthenticationParser = request_parser.New(
						func(r *http.Request) (any, *response_error.ResponseError) {
							return &session_token.Token{
								AuthenticationId: loginTesting.AuthenticationId,
								Claims: &session_claims.Claims{
									Claims: registered_claims.Claims{
										ExpiresAt: nil,
									},
								},
							}, nil
						},
					)
				} else if testCase.invalidSessionTokenNbf {
					testEndpoint.AuthenticationParser = request_parser.New(
						func(r *http.Request) (any, *response_error.ResponseError) {
							return &session_token.Token{
								AuthenticationId: loginTesting.AuthenticationId,
								Claims: &session_claims.Claims{
									Claims: registered_claims.Claims{
										ExpiresAt: numeric_date.New(time.Now().Add(time.Hour)),
										NotBefore: nil,
									},
								},
							}, nil
						},
					)
				} else if testCase.negativeDuration {
					testEndpoint.AuthenticationParser = request_parser.New(
						func(r *http.Request) (any, *response_error.ResponseError) {
							return &session_token.Token{
								AuthenticationId: loginTesting.AuthenticationId,
								Claims: &session_claims.Claims{
									Claims: registered_claims.Claims{
										ExpiresAt: numeric_date.New(time.Now().Add(-1 * time.Hour)),
										NotBefore: numeric_date.New(time.Now()),
									},
									AuthenticationMethods: []string{authentication_method.Sso},
								},
							}, nil
						},
					)
				} else {
					t.Fatalf("unexpected authentication parser replace case")
				}
			}

			mux := &muxPkg.Mux{}
			mux.Add(testEndpoint.Endpoint.Endpoint)
			httpServer := httptest.NewServer(mux)
			defer httpServer.Close()

			testCase.args.Path = testEndpoint.Path
			testCase.args.Method = testEndpoint.Method

			muxTesting.TestArgs(t, testCase.args, httpServer.URL)
		})
	}

}

func TestInitialize(t *testing.T) {
	t.Parallel()

	corsConfigurator := &cors_configurator.Configurator{}

	testCases := []struct {
		name                 string
		authenticationParser request_parser.RequestParser[any]
		corsConfigurator     *cors_configurator.Configurator
		sessionManager       *session_manager.Manager
		wantErr              error
	}{
		{
			name:                 "valid arguments",
			authenticationParser: defaultAuthenticationParser,
			corsConfigurator:     corsConfigurator,
			sessionManager:       sessionManager,
		},
		{
			name:                 "nil authorizer request parser",
			authenticationParser: nil,
			corsConfigurator:     corsConfigurator,
			sessionManager:       sessionManager,
			wantErr:              nil_error.New("authorizer request parser"),
		},
		{
			name:                 "nil cors configurator",
			authenticationParser: defaultAuthenticationParser,
			corsConfigurator:     nil,
			sessionManager:       sessionManager,
			wantErr:              nil_error.New("cors configurator"),
		},
		{
			name:                 "nil session manager",
			authenticationParser: defaultAuthenticationParser,
			corsConfigurator:     corsConfigurator,
			sessionManager:       nil,
			wantErr:              nil_error.New("session manager"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint := New()
			err := testEndpoint.Initialize(testCase.authenticationParser, testCase.corsConfigurator, testCase.sessionManager)
			altshiftTestingCmp.CompareErr(t, err, testCase.wantErr)
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	opts := []altshiftTestingCmp.Option{
		altshiftTestingCmp.IgnoreFields(
			Endpoint{},
			"selectRefreshAuthentication",
		),
		altshiftTestingCmp.EquateComparable(adapter.Adapter[struct{}]{}),
	}

	type args struct {
		options []refresh_endpoint_config.Option
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
						Path:       refresh_endpoint_config.DefaultPath,
						Method:     http.MethodPost,
						UrlParser:  adapter.New(query_extractor.Empty),
						BodyLoader: &body_loader.Loader{Setting: body_setting.Forbidden},
					},
				},
				SessionDuration: refresh_endpoint_config.DefaultSessionDuration,
			},
		},
		{
			name: "success, custom path",
			args: args{options: []refresh_endpoint_config.Option{refresh_endpoint_config.WithPath("/test")}},
			want: &Endpoint{
				Endpoint: &initialization_endpoint.Endpoint{
					Endpoint: &endpoint.Endpoint{
						Path:       "/test",
						Method:     http.MethodPost,
						UrlParser:  adapter.New(query_extractor.Empty),
						BodyLoader: &body_loader.Loader{Setting: body_setting.Forbidden},
					},
				},
				SessionDuration: refresh_endpoint_config.DefaultSessionDuration,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := New(tt.args.options...)
			if diff := altshiftTestingCmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("endpoint mismatch (-expected +got):\n%s", diff)
			}
		})
	}
}
