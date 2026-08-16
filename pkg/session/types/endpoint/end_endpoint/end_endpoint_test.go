package end_endpoint

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	motmedelCryptoInterfaces "github.com/Motmedel/utils_go/pkg/crypto/interfaces"
	muxPkg "github.com/Motmedel/utils_go/pkg/http/mux"
	muxTesting "github.com/Motmedel/utils_go/pkg/http/mux/testing"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/body_loader"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/body_loader/body_setting"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/cors_configurator"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	motmedelTestingCmp "github.com/Motmedel/utils_go/pkg/testing/cmp"
	loginTesting "github.com/altshiftab/authentication_go/pkg/session/testing"
	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser"
	"github.com/altshiftab/authentication_go/pkg/session/types/endpoint/end_endpoint/end_endpoint_config"
)

var defaultSessionCookieString string
var defaultAuthorizationRequestParser *authorizer_request_parser.Parser

var db *sql.DB
var method motmedelCryptoInterfaces.Method

func TestMain(m *testing.M) {

	defaultAuthorizationRequestParser, method, db = loginTesting.SetUp()
	defaultSessionCookieString = loginTesting.MakeStandardCookie(loginTesting.AuthenticationId, method)

	code := m.Run()
	if db != nil {
		_ = db.Close()
	}

	os.Exit(code)
}

func TestEndpoint(t *testing.T) {
	t.Parallel()

	emptyAuthenticationIdToken := loginTesting.MakeStandardCookie("", method)
	corsConfigurator := &cors_configurator.Configurator{}

	testCases := []struct {
		name  string
		args  *muxTesting.Args
		dbErr error
	}{
		{
			name: "authenticated happy path",
			args: &muxTesting.Args{
				Headers: [][2]string{
					{"Cookie", defaultSessionCookieString},
				},
				ExpectedStatusCode: http.StatusNoContent,
				ExpectedHeaders: [][2]string{
					{"Clear-Site-Data", "\"cookies\""},
				},
			},
		},
		{
			name: "authenticated with db error",
			args: &muxTesting.Args{
				Headers: [][2]string{
					{"Cookie", defaultSessionCookieString},
				},
				ExpectedStatusCode:    http.StatusInternalServerError,
				ExpectedProblemDetail: &problem_detail.Detail{},
			},
			dbErr: errors.New("db error"),
		},
		{
			name: "authenticated with empty authentication id",
			args: &muxTesting.Args{
				Headers: [][2]string{
					{"Cookie", emptyAuthenticationIdToken},
				},
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "Missing authentication id in the session token.",
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint := New()
			if err := testEndpoint.Initialize(defaultAuthorizationRequestParser, corsConfigurator, db); err != nil {
				t.Fatalf("test endpoint initialize: %v", err)
			}

			testEndpoint.updateAuthenticationWithEnded = func(ctx context.Context, authenticationId string, db *sql.DB) error {
				return testCase.dbErr
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

func TestEndpoint_Initialize(t *testing.T) {
	t.Parallel()

	corsConfigurator := &cors_configurator.Configurator{}

	type args struct {
		authorizerRequestParser *authorizer_request_parser.Parser
		db                      *sql.DB
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "empty authorizer request parser",
			args: args{
				authorizerRequestParser: nil,
				db:                      db,
			},
			wantErr: true,
		},
		{
			name: "empty db",
			args: args{
				authorizerRequestParser: &authorizer_request_parser.Parser{},
				db:                      nil,
			},
			wantErr: true,
		},
		{
			name: "success",
			args: args{
				authorizerRequestParser: &authorizer_request_parser.Parser{},
				db:                      db,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := New().Initialize(tt.args.authorizerRequestParser, corsConfigurator, tt.args.db); (err != nil) != tt.wantErr {
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
			"updateAuthenticationWithEnded",
		),
		motmedelTestingCmp.EquateComparable(adapter.Adapter[struct{}]{}),
	}

	type args struct {
		options []end_endpoint_config.Option
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
						Path:       end_endpoint_config.DefaultPath,
						Method:     http.MethodPost,
						UrlParser:  adapter.New(query_extractor.Empty),
						BodyLoader: &body_loader.Loader{Setting: body_setting.Forbidden},
					},
				},
			},
		},
		{
			name: "success, args",
			args: args{
				[]end_endpoint_config.Option{end_endpoint_config.WithPath("/test")},
			},
			want: &Endpoint{
				Endpoint: &initialization_endpoint.Endpoint{
					Endpoint: &endpoint.Endpoint{
						Path:       "/test",
						Method:     http.MethodPost,
						UrlParser:  adapter.New(query_extractor.Empty),
						BodyLoader: &body_loader.Loader{Setting: body_setting.Forbidden},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := New(tt.args.options...)
			if diff := motmedelTestingCmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("endpoint mismatch (-expected +got):\n%s", diff)
			}
		})
	}
}
