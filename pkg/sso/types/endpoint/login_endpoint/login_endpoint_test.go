package login_endpoint

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	motmedelSqlTesting "github.com/Motmedel/utils_go/pkg/database/sql/testing"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	muxPkg "github.com/Motmedel/utils_go/pkg/http/mux"
	muxTesting "github.com/Motmedel/utils_go/pkg/http/mux/testing"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	motmedelOauth2Config "github.com/Motmedel/utils_go/pkg/oauth2/types/config"
	motmedelTestingCmp "github.com/Motmedel/utils_go/pkg/testing/cmp"
	"github.com/altshiftab/authentication_go/pkg/database/types/oauth_flow"
	testing2 "github.com/altshiftab/authentication_go/pkg/sso/testing"
)

const (
	defaultPath         = "/login"
	defaultCallbackPath = "/callback"
	defaultCodeVerifier = "test-code-verifier"
	defaultState        = "test-state"
)

var (
	oauthConfig *motmedelOauth2Config.Config
	db          *sql.DB
)

func TestMain(m *testing.M) {
	_, _, oauthConfig, _ = testing2.SetUp()

	db = motmedelSqlTesting.NewDb()

	code := m.Run()
	_ = db.Close()

	os.Exit(code)
}

func TestEndpoint(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                    string
		args                    *muxTesting.Args
		dbErr                   error
		nilDbOauthFlow          bool
		emptyDbOauthFlowId      bool
		nilDbOauthFlowExpiresAt bool
		codeVerifierErr         error
		stateErr                error
		emptyCodeVerifier       bool
		emptyState              bool
	}{
		{
			name: "success",
			args: &muxTesting.Args{
				ExpectedStatusCode:     http.StatusFound,
				ExpectedHeadersPresent: []string{"Set-Cookie", "Location"},
			},
		},
		{
			name: "db error",
			args: &muxTesting.Args{
				ExpectedStatusCode:    http.StatusInternalServerError,
				ExpectedProblemDetail: &problem_detail.Detail{},
			},
			dbErr: sql.ErrConnDone,
		},
		{
			name: "nil db oauth flow",
			args: &muxTesting.Args{
				ExpectedStatusCode:    http.StatusInternalServerError,
				ExpectedProblemDetail: &problem_detail.Detail{},
			},
			nilDbOauthFlow: true,
		},
		{
			name: "empty db oauth flow id",
			args: &muxTesting.Args{
				ExpectedStatusCode:    http.StatusInternalServerError,
				ExpectedProblemDetail: &problem_detail.Detail{},
			},
			emptyDbOauthFlowId: true,
		},
		{
			name: "nil db oauth flow expires at",
			args: &muxTesting.Args{
				ExpectedStatusCode:    http.StatusInternalServerError,
				ExpectedProblemDetail: &problem_detail.Detail{},
			},
			nilDbOauthFlowExpiresAt: true,
		},
		{
			name: "make code verifier error",
			args: &muxTesting.Args{
				ExpectedStatusCode:    http.StatusInternalServerError,
				ExpectedProblemDetail: &problem_detail.Detail{},
			},
			codeVerifierErr: errors.New("code verifier error"),
		},
		{
			name: "empty code verifier",
			args: &muxTesting.Args{
				ExpectedStatusCode:    http.StatusInternalServerError,
				ExpectedProblemDetail: &problem_detail.Detail{},
			},
			emptyCodeVerifier: true,
		},
		{
			name: "make state error",
			args: &muxTesting.Args{
				ExpectedStatusCode:    http.StatusInternalServerError,
				ExpectedProblemDetail: &problem_detail.Detail{},
			},
			stateErr: errors.New("state error"),
		},
		{
			name: "empty state",
			args: &muxTesting.Args{
				ExpectedStatusCode:    http.StatusInternalServerError,
				ExpectedProblemDetail: &problem_detail.Detail{},
			},
			emptyState: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint, err := New(defaultPath, defaultCallbackPath)
			if err != nil {
				t.Fatalf("new endpoint: %v", err)
			}

			if err := testEndpoint.Initialize(testing2.Domain, oauthConfig, db); err != nil {
				t.Fatalf("initialize endpoint: %v", err)
			}

			testEndpoint.insertOauthFlow = func(ctx context.Context, state string, codeVerifier string, redirectUrl string, expirationDuration time.Duration, database *sql.DB) (*oauth_flow.Flow, error) {
				if testCase.dbErr != nil {
					return nil, testCase.dbErr
				}

				if testCase.nilDbOauthFlow {
					return nil, nil
				}

				var flow oauth_flow.Flow

				if !testCase.emptyDbOauthFlowId {
					flow.Id = testing2.OauthFlowId
				}

				if !testCase.nilDbOauthFlowExpiresAt {
					expiresAt := time.Now().Add(expirationDuration)
					flow.ExpiresAt = &expiresAt
				}

				return &flow, nil
			}

			testEndpoint.makeCodeVerifier = func() (string, error) {
				var codeVerifier string
				if !testCase.emptyCodeVerifier {
					codeVerifier = defaultCodeVerifier
				}
				return codeVerifier, testCase.codeVerifierErr
			}

			testEndpoint.makeState = func() (string, error) {
				var state string
				if !testCase.emptyState {
					state = defaultState
				}
				return state, testCase.stateErr
			}

			mux := &muxPkg.Mux{}
			mux.Add(testEndpoint.Endpoint.Endpoint)
			httpServer := httptest.NewServer(mux)
			defer httpServer.Close()

			requestUrl, err := url.Parse(httpServer.URL + defaultPath)
			if err != nil {
				t.Fatalf("url parse: %v", err)
			}

			requestUrl.RawQuery = url.Values{"redirect": {"https://" + testing2.Domain}}.Encode()

			muxTesting.TestArgs(t, testCase.args, requestUrl.String())

		})
	}
}

func TestInitialize(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		domain      string
		oauthConfig *motmedelOauth2Config.Config
		db          *sql.DB
		wantErr     error
	}{
		{
			name:        "valid arguments",
			domain:      testing2.Domain,
			oauthConfig: oauthConfig,
			db:          db,
		},
		{
			name:        "empty domain",
			domain:      "",
			oauthConfig: oauthConfig,
			db:          db,
			wantErr:     empty_error.New("domain"),
		},
		{
			name:        "nil oauth config",
			domain:      testing2.Domain,
			oauthConfig: nil,
			db:          db,
			wantErr:     nil_error.New("oauth config"),
		},
		{
			name:        "nil db",
			domain:      testing2.Domain,
			oauthConfig: oauthConfig,
			db:          nil,

			wantErr: nil_error.New("sql db"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint, err := New(defaultPath, defaultCallbackPath)
			if err != nil {
				t.Fatalf("new endpoint: %v", err)
			}

			err = testEndpoint.Initialize(testCase.domain, testCase.oauthConfig, testCase.db)
			motmedelTestingCmp.CompareErr(t, err, testCase.wantErr)
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		path         string
		callbackPath string
		wantErr      bool
	}{
		{name: "success", path: defaultPath, callbackPath: defaultCallbackPath},
		{name: "empty path", path: "", callbackPath: defaultCallbackPath, wantErr: true},
		{name: "empty callback path", path: defaultPath, callbackPath: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := New(tt.path, tt.callbackPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestRealRandomHelpers(t *testing.T) {
	t.Parallel()

	cv, err := makeCodeVerifier()
	if err != nil {
		t.Fatalf("makeCodeVerifier: %v", err)
	}
	if cv == "" {
		t.Errorf("makeCodeVerifier returned empty string")
	}

	state, err := makeState()
	if err != nil {
		t.Fatalf("makeState: %v", err)
	}
	if state == "" {
		t.Errorf("makeState returned empty string")
	}
}

// TODO: Implement tests
//	- New()
