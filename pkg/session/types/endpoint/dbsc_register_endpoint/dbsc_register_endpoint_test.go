package dbsc_register_endpoint

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	databaseErrors "github.com/altshiftab/authentication_go/pkg/database/errors"
	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	"github.com/altshiftab/authentication_go/pkg/database/types/dbsc_challenge"
	"github.com/altshiftab/authentication_go/pkg/session"
	loginTesting "github.com/altshiftab/authentication_go/pkg/session/testing"
	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser"
	"github.com/altshiftab/authentication_go/pkg/session/types/dbsc_session_response_processor"
	"github.com/altshiftab/authentication_go/pkg/session/types/dbsc_session_response_processor/dbsc_session_response_processor_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/endpoint/dbsc_refresh_endpoint/dbsc_refresh_endpoint_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/endpoint/dbsc_register_endpoint/dbsc_register_endpoint_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_cookie"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_cookie/session_cookie_config"
	altshiftCryptoInterfaces "github.com/altshiftab/utils_go/pkg/crypto/interfaces"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
	muxTesting "github.com/altshiftab/utils_go/pkg/http/mux/testing"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/token_cookie_extractor/token_cookie_extractor_config"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	altshiftTestingCmp "github.com/altshiftab/utils_go/pkg/testing/cmp"
)

// Errors the tests' stand-ins fail with.
var (
	errTestAuthenticationIdMismatch = errors.New("authentication id mismatch")
)

var defaultSessionCookieString string
var defaultAuthorizationRequestParser *authorizer_request_parser.Parser
var defaultProcessor *dbsc_session_response_processor.Processor

var db *sql.DB
var method altshiftCryptoInterfaces.Method

func TestMain(m *testing.M) {
	var err error

	defaultAuthorizationRequestParser, method, db = loginTesting.SetUp()
	defaultProcessor, err = dbsc_session_response_processor.New("https://example.com"+dbsc_register_endpoint_config.DefaultPath, db)
	if err != nil {
		panic(fmt.Errorf("dbsc session response processor new: %w", err))
	}

	defaultSessionCookieString = loginTesting.MakeStandardCookie(loginTesting.AuthenticationId, method)

	code := m.Run()
	if db != nil {
		_ = db.Close()
	}
	os.Exit(code)
}

const originPlaceholder = ""

var errAuthenticationIdMismatch = errors.New("authentication id mismatch")

// expectedSiteOrigin is the scope origin a session that includes the site has to carry: the
// registrable domain instead of the host actually serving registration, on the same port.
func expectedSiteOrigin(t *testing.T, serverUrl string) string {
	t.Helper()

	parsedServerUrl, err := url.Parse(serverUrl)
	if err != nil {
		t.Fatalf("url parse (server url): %v", err)
	}

	return "http://" + net.JoinHostPort(loginTesting.RegisteredDomain, parsedServerUrl.Port())
}

func TestEndpoint(t *testing.T) {
	t.Parallel()

	validToken, _ := loginTesting.MakeDbscProof("cv")

	response := Response{
		SessionIdentifier: loginTesting.AuthenticationId,
		RefreshURL:        dbsc_register_endpoint_config.DefaultRefreshPath,
		Scope: &Scope{
			Origin:      originPlaceholder,
			IncludeSite: true,
		},
		Credentials: []*Credential{
			{
				Type:       "cookie",
				Name:       token_cookie_extractor_config.DefaultName,
				Attributes: session_cookie.Attributes(loginTesting.RegisteredDomain),
			},
		},
	}

	testCases := []struct {
		name           string
		args           *muxTesting.Args
		emptyPublicKey bool
	}{
		{
			name: "valid session response token happy path",
			args: &muxTesting.Args{
				Headers:            [][2]string{{"Cookie", defaultSessionCookieString}, {session.DbscSessionResponseHeaderName, validToken}},
				ExpectedStatusCode: http.StatusOK,
				ExpectedBody:       []byte("placeholder"),
			},
		},
		{
			name: "invalid session response token",
			args: &muxTesting.Args{
				Headers:               [][2]string{{"Cookie", defaultSessionCookieString}, {session.DbscSessionResponseHeaderName, "invalid"}},
				ExpectedStatusCode:    http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{Detail: "Invalid token."},
			},
		},
		{
			name: "missing session response token",
			args: &muxTesting.Args{
				Headers:            [][2]string{{"Cookie", defaultSessionCookieString}},
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "Missing header.",
					Extension: map[string]any{
						"header": session.DbscSessionResponseHeaderName,
					},
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
							return nil, fmt.Errorf("%w: got %s, want %s", errTestAuthenticationIdMismatch, authenticationId, loginTesting.AuthenticationId)
						}

						return &dbsc_challenge.Challenge{
							Authentication: &authenticationPkg.Authentication{Id: authenticationId},
							Challenge:      []byte(challenge),
							ExpiresAt:      new(time.Now().Add(time.Hour)),
						}, nil
					},
				),
			)
			if err != nil {
				t.Fatalf("dbsc session response processor new: %v", err)
			}

			if err := testEndpoint.Initialize(defaultAuthorizationRequestParser, testEndpointProcessor, loginTesting.RegisteredDomain); err != nil {
				t.Fatalf("test endpoint initialize: %v", err)
			}

			mux := &muxPkg.Mux{}
			mux.Add(testEndpoint.Endpoint.Endpoint)
			httpServer := httptest.NewServer(mux)
			defer httpServer.Close()

			if len(tc.args.ExpectedBody) != 0 {
				// Scope is a pointer, so it is replaced rather than assigned through: the
				// subtests run in parallel and each has its own port.
				scopedResponse := response
				scopedResponse.Scope = &Scope{
					Origin:      expectedSiteOrigin(t, httpServer.URL),
					IncludeSite: true,
				}
				responseData, err := json.Marshal(scopedResponse)
				if err != nil {
					t.Fatalf("json marshal (response): %v", err)
				}
				tc.args.ExpectedBody = responseData
			}

			tc.args.Path = testEndpoint.Path
			tc.args.Method = testEndpoint.Method

			muxTesting.TestArgs(t, tc.args, httpServer.URL)
		})
	}
}

func TestEndpoint_SessionCookieOptions(t *testing.T) {
	t.Parallel()

	validToken, _ := loginTesting.MakeDbscProof("cv")

	sessionCookieOption := session_cookie_config.WithSameSite(http.SameSiteStrictMode)

	expectedResponse := Response{
		SessionIdentifier: loginTesting.AuthenticationId,
		RefreshURL:        dbsc_register_endpoint_config.DefaultRefreshPath,
		Scope: &Scope{
			Origin:      originPlaceholder,
			IncludeSite: true,
		},
		Credentials: []*Credential{
			{
				Type:       "cookie",
				Name:       token_cookie_extractor_config.DefaultName,
				Attributes: session_cookie.Attributes(loginTesting.RegisteredDomain, sessionCookieOption),
			},
		},
	}

	if !strings.Contains(expectedResponse.Credentials[0].Attributes, "SameSite=Strict") {
		t.Fatalf("precondition: expected attributes to contain SameSite=Strict, got %q", expectedResponse.Credentials[0].Attributes)
	}

	testEndpoint := New()
	testEndpointProcessor, err := dbsc_session_response_processor.New(
		"https://example.com"+dbsc_register_endpoint_config.DefaultPath,
		db,
		dbsc_session_response_processor_config.WithPopDbscChallenge(
			func(ctx context.Context, challenge string, authenticationId string, db *sql.DB) (*dbsc_challenge.Challenge, error) {
				if authenticationId != loginTesting.AuthenticationId {
					return nil, fmt.Errorf("%w: got %s, want %s", errTestAuthenticationIdMismatch, authenticationId, loginTesting.AuthenticationId)
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

	if err := testEndpoint.Initialize(defaultAuthorizationRequestParser, testEndpointProcessor, loginTesting.RegisteredDomain, sessionCookieOption); err != nil {
		t.Fatalf("test endpoint initialize: %v", err)
	}

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint.Endpoint.Endpoint)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	expectedResponse.Scope.Origin = expectedSiteOrigin(t, httpServer.URL)
	expectedBody, err := json.Marshal(expectedResponse)
	if err != nil {
		t.Fatalf("json marshal (expected response): %v", err)
	}

	muxTesting.TestArgs(
		t,
		&muxTesting.Args{
			Path:               testEndpoint.Path,
			Method:             testEndpoint.Method,
			Headers:            [][2]string{{"Cookie", defaultSessionCookieString}, {session.DbscSessionResponseHeaderName, validToken}},
			ExpectedStatusCode: http.StatusOK,
			ExpectedBody:       expectedBody,
		},
		httpServer.URL,
	)
}

// TestEndpoint_OriginScoped covers a session that does not include the site. Its scope stays the
// origin actually being served, since naming the registrable domain is required only of a session
// that claims the whole site.
func TestEndpoint_OriginScoped(t *testing.T) {
	t.Parallel()

	validToken, _ := loginTesting.MakeDbscProof("cv")

	testEndpoint := New(dbsc_register_endpoint_config.WithIncludeSite(false))
	testEndpointProcessor, err := dbsc_session_response_processor.New(
		"https://example.com"+dbsc_register_endpoint_config.DefaultPath,
		db,
		dbsc_session_response_processor_config.WithPopDbscChallenge(
			func(ctx context.Context, challenge string, authenticationId string, db *sql.DB) (*dbsc_challenge.Challenge, error) {
				if authenticationId != loginTesting.AuthenticationId {
					return nil, fmt.Errorf(
						"%w: got %s, want %s",
						errAuthenticationIdMismatch, authenticationId, loginTesting.AuthenticationId,
					)
				}

				return &dbsc_challenge.Challenge{
					Authentication: &authenticationPkg.Authentication{Id: authenticationId},
					Challenge:      []byte(challenge),
					ExpiresAt:      new(time.Now().Add(time.Hour)),
				}, nil
			},
		),
	)
	if err != nil {
		t.Fatalf("dbsc session response processor new: %v", err)
	}

	if err := testEndpoint.Initialize(defaultAuthorizationRequestParser, testEndpointProcessor, loginTesting.RegisteredDomain); err != nil {
		t.Fatalf("test endpoint initialize: %v", err)
	}

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint.Endpoint.Endpoint)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	expectedBody, err := json.Marshal(
		Response{
			SessionIdentifier: loginTesting.AuthenticationId,
			RefreshURL:        dbsc_register_endpoint_config.DefaultRefreshPath,
			Scope:             &Scope{Origin: httpServer.URL, IncludeSite: false},
			Credentials: []*Credential{
				{
					Type:       "cookie",
					Name:       token_cookie_extractor_config.DefaultName,
					Attributes: session_cookie.Attributes(loginTesting.RegisteredDomain),
				},
			},
		},
	)
	if err != nil {
		t.Fatalf("json marshal (expected response): %v", err)
	}

	muxTesting.TestArgs(
		t,
		&muxTesting.Args{
			Path:               testEndpoint.Path,
			Method:             testEndpoint.Method,
			Headers:            [][2]string{{"Cookie", defaultSessionCookieString}, {session.DbscSessionResponseHeaderName, validToken}},
			ExpectedStatusCode: http.StatusOK,
			ExpectedBody:       expectedBody,
		},
		httpServer.URL,
	)
}

func TestSiteOrigin(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		origin           string
		registeredDomain string
		expected         string
		expectError      bool
	}{
		{
			name:             "subdomain gives way to the registrable domain",
			origin:           "https://login.example.com",
			registeredDomain: "example.com",
			expected:         "https://example.com",
		},
		{
			name:             "port is kept",
			origin:           "https://login.example.com:8443",
			registeredDomain: "example.com",
			expected:         "https://example.com:8443",
		},
		{
			name:             "scheme is kept",
			origin:           "http://login.example.com:8080",
			registeredDomain: "example.com",
			expected:         "http://example.com:8080",
		},
		{
			name:             "deeper subdomain gives way as well",
			origin:           "https://dev.login.example.com",
			registeredDomain: "example.com",
			expected:         "https://example.com",
		},
		{
			name:             "an origin already naming the site is unchanged",
			origin:           "https://example.com",
			registeredDomain: "example.com",
			expected:         "https://example.com",
		},
		{
			name:             "empty origin",
			origin:           "",
			registeredDomain: "example.com",
			expectError:      true,
		},
		{
			name:             "empty registered domain",
			origin:           "https://login.example.com",
			registeredDomain: "",
			expectError:      true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			origin, err := siteOrigin(testCase.origin, testCase.registeredDomain)
			if testCase.expectError {
				if err == nil {
					t.Fatalf("expected an error, got origin %q", origin)
				}
				return
			}
			if err != nil {
				t.Fatalf("site origin: %v", err)
			}

			if origin != testCase.expected {
				t.Errorf("got %q, expected %q", origin, testCase.expected)
			}
		})
	}
}

func TestEndpoint_Initialize(t *testing.T) {
	t.Parallel()

	type args struct {
		arp *authorizer_request_parser.Parser
		pr  *dbsc_session_response_processor.Processor
		dom string
	}

	arp, _, _ := loginTesting.SetUp()

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "nil authorizer parser", args: args{arp: nil, pr: defaultProcessor, dom: "example.com"}, wantErr: true},
		{name: "empty cookie name in parser", args: args{arp: &authorizer_request_parser.Parser{}, pr: defaultProcessor, dom: "example.com"}, wantErr: true},
		{name: "nil processor", args: args{arp: arp, pr: nil, dom: "example.com"}, wantErr: true},
		{name: "nil db in processor", args: args{arp: arp, pr: &dbsc_session_response_processor.Processor{}, dom: "example.com"}, wantErr: true},
		{name: "empty cookie domain", args: args{arp: arp, pr: defaultProcessor, dom: ""}, wantErr: true},
		{name: "cookie domain that is a public suffix", args: args{arp: arp, pr: defaultProcessor, dom: "co.uk"}, wantErr: true},
		{name: "success", args: args{arp: arp, pr: defaultProcessor, dom: "example.com"}},
		{name: "success, cookie domain narrower than the site", args: args{arp: arp, pr: defaultProcessor, dom: "dev.example.com"}},
		{name: "success, localhost", args: args{arp: arp, pr: defaultProcessor, dom: "localhost"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := New().Initialize(tt.args.arp, tt.args.pr, tt.args.dom); (err != nil) != tt.wantErr {
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
			"updateAuthenticationWithDbscPublicKey",
			"updateAuthenticationWithSessionExpiresAt",
		),
		altshiftTestingCmp.EquateComparable(adapter.Adapter[struct{}]{}),
	}

	type args struct {
		options []dbsc_register_endpoint_config.Option
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
						Path:      dbsc_register_endpoint_config.DefaultPath,
						Method:    http.MethodPost,
						UrlParser: adapter.New(query_extractor.Empty),
					},
				},
				RefreshPath: dbsc_refresh_endpoint_config.DefaultPath,
				IncludeSite: dbsc_register_endpoint_config.DefaultIncludeSite,
			},
		},
		{
			name: "success, custom path",
			args: args{options: []dbsc_register_endpoint_config.Option{dbsc_register_endpoint_config.WithPath("/test")}},
			want: &Endpoint{
				Endpoint: &initialization_endpoint.Endpoint{
					Endpoint: &endpoint.Endpoint{
						Path:      "/test",
						Method:    http.MethodPost,
						UrlParser: adapter.New(query_extractor.Empty),
					},
				},
				RefreshPath: dbsc_refresh_endpoint_config.DefaultPath,
				IncludeSite: dbsc_register_endpoint_config.DefaultIncludeSite,
			},
		},
		{
			name: "success, custom refresh path",
			args: args{options: []dbsc_register_endpoint_config.Option{dbsc_register_endpoint_config.WithRefreshPath("/refresh-test")}},
			want: &Endpoint{
				Endpoint: &initialization_endpoint.Endpoint{
					Endpoint: &endpoint.Endpoint{
						Path:      dbsc_register_endpoint_config.DefaultPath,
						Method:    http.MethodPost,
						UrlParser: adapter.New(query_extractor.Empty),
					},
				},
				RefreshPath: "/refresh-test",
				IncludeSite: dbsc_register_endpoint_config.DefaultIncludeSite,
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

// TestEndpoint_ReissuesSessionCookieWithTokenExpiry asserts that registering a DBSC session
// reissues the session cookie so that it expires with the session token it carries. The browser
// refreshes a bound session when its cookie expires, and from registration onwards it is the only
// thing refreshing the session, so a cookie outliving the token would leave it unarmed.
func TestEndpoint_ReissuesSessionCookieWithTokenExpiry(t *testing.T) {
	t.Parallel()

	validToken, _ := loginTesting.MakeDbscProof("cv")

	// Shorter than the cookie a created session carries, which expires with the authentication.
	sessionTokenExpiresAt := time.Now().Add(15 * time.Minute)
	sessionCookieString := loginTesting.MakeCookieExplicit(
		loginTesting.AuthenticationId,
		method,
		[]string{"ext"},
		sessionTokenExpiresAt,
		time.Now(),
	)

	testEndpoint := New()
	testEndpointProcessor, err := dbsc_session_response_processor.New(
		"https://example.com"+dbsc_register_endpoint_config.DefaultPath,
		db,
		dbsc_session_response_processor_config.WithPopDbscChallenge(
			func(_ context.Context, challenge string, authenticationId string, _ *sql.DB) (*dbsc_challenge.Challenge, error) {
				return &dbsc_challenge.Challenge{
					Authentication: &authenticationPkg.Authentication{Id: authenticationId},
					Challenge:      []byte(challenge),
					ExpiresAt:      new(time.Now().Add(time.Hour)),
				}, nil
			},
		),
	)
	if err != nil {
		t.Fatalf("dbsc session response processor new: %v", err)
	}

	if err := testEndpoint.Initialize(
		defaultAuthorizationRequestParser,
		testEndpointProcessor,
		loginTesting.RegisteredDomain,
	); err != nil {
		t.Fatalf("test endpoint initialize: %v", err)
	}

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint.Endpoint.Endpoint)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	request, err := http.NewRequestWithContext(t.Context(), testEndpoint.Method, httpServer.URL+testEndpoint.Path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Cookie", sessionCookieString)
	request.Header.Set(session.DbscSessionResponseHeaderName, validToken)

	response, err := httpServer.Client().Do(request)
	if err != nil {
		t.Fatalf("client do: %v", err)
	}
	if response == nil {
		t.Fatal("nil response")
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("got status code %d, expected %d", response.StatusCode, http.StatusOK)
	}

	setCookie := response.Header.Get("Set-Cookie")
	if setCookie == "" {
		t.Fatalf("missing Set-Cookie header")
	}

	sessionCookie, err := http.ParseSetCookie(setCookie)
	if err != nil {
		t.Fatalf("parse set cookie: %v", err)
	}

	if sessionCookie.Expires.Sub(sessionTokenExpiresAt).Abs() > time.Minute {
		t.Errorf(
			"cookie expiry %s, expected the session token expiry %s",
			sessionCookie.Expires, sessionTokenExpiresAt,
		)
	}

	// The session token itself is untouched; only the cookie's expiry changes.
	requestCookie, err := http.ParseSetCookie(sessionCookieString)
	if err != nil {
		t.Fatalf("parse set cookie (request): %v", err)
	}
	if sessionCookie.Value != requestCookie.Value {
		t.Errorf("got cookie value %q, expected %q", sessionCookie.Value, requestCookie.Value)
	}
}

// TestEndpoint_CookieDomainNarrowerThanSite covers a cookie scoped below the site, as an
// environment of its own is: the credential and the reissued cookie keep that domain, while the
// scope still names the site, which is what the protocol requires of a session including it.
func TestEndpoint_CookieDomainNarrowerThanSite(t *testing.T) {
	t.Parallel()

	const cookieDomain = "dev." + loginTesting.RegisteredDomain

	validToken, _ := loginTesting.MakeDbscProof("cv")

	testEndpoint := New()
	testEndpointProcessor, err := dbsc_session_response_processor.New(
		"https://example.com"+dbsc_register_endpoint_config.DefaultPath,
		db,
		dbsc_session_response_processor_config.WithPopDbscChallenge(
			func(_ context.Context, challenge string, authenticationId string, _ *sql.DB) (*dbsc_challenge.Challenge, error) {
				return &dbsc_challenge.Challenge{
					Authentication: &authenticationPkg.Authentication{Id: authenticationId},
					Challenge:      []byte(challenge),
					ExpiresAt:      new(time.Now().Add(time.Hour)),
				}, nil
			},
		),
	)
	if err != nil {
		t.Fatalf("dbsc session response processor new: %v", err)
	}

	if err := testEndpoint.Initialize(defaultAuthorizationRequestParser, testEndpointProcessor, cookieDomain); err != nil {
		t.Fatalf("test endpoint initialize: %v", err)
	}

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint.Endpoint.Endpoint)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	request, err := http.NewRequestWithContext(t.Context(), testEndpoint.Method, httpServer.URL+testEndpoint.Path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Cookie", defaultSessionCookieString)
	request.Header.Set(session.DbscSessionResponseHeaderName, validToken)

	httpResponse, err := httpServer.Client().Do(request)
	if err != nil {
		t.Fatalf("client do: %v", err)
	}
	if httpResponse == nil {
		t.Fatal("nil response")
	}
	defer httpResponse.Body.Close()

	if httpResponse.StatusCode != http.StatusOK {
		t.Fatalf("got status code %d, expected %d", httpResponse.StatusCode, http.StatusOK)
	}

	var instructions Response
	if err := json.UnmarshalRead(httpResponse.Body, &instructions); err != nil {
		t.Fatalf("json unmarshal read: %v", err)
	}

	if instructions.Scope == nil {
		t.Fatalf("nil scope")
	}
	if expected := expectedSiteOrigin(t, httpServer.URL); instructions.Scope.Origin != expected {
		t.Errorf("scope origin %q, expected %q", instructions.Scope.Origin, expected)
	}

	if len(instructions.Credentials) != 1 || instructions.Credentials[0] == nil {
		t.Fatalf("expected one credential, got %v", instructions.Credentials)
	}
	if expected := session_cookie.Attributes(cookieDomain); instructions.Credentials[0].Attributes != expected {
		t.Errorf("credential attributes %q, expected %q", instructions.Credentials[0].Attributes, expected)
	}

	sessionCookie, err := http.ParseSetCookie(httpResponse.Header.Get("Set-Cookie"))
	if err != nil {
		t.Fatalf("parse set cookie: %v", err)
	}
	if sessionCookie.Domain != cookieDomain {
		t.Errorf("reissued cookie domain %q, expected %q", sessionCookie.Domain, cookieDomain)
	}
}

// TestEndpoint_KeyRegisteredOnce covers what the endpoint makes of the store's answer to a key. The
// cookie is all registration asks for, so a session that has a key already keeps it: a second one is
// refused as a conflict rather than taking the session from the device it is bound to.
func TestEndpoint_KeyRegisteredOnce(t *testing.T) {
	t.Parallel()

	validToken, _ := loginTesting.MakeDbscProof("cv")

	testCases := []struct {
		name               string
		updateErr          error
		expectedStatusCode int
		expectedDetail     string
	}{
		{name: "the first key is registered", expectedStatusCode: http.StatusOK},
		{
			name:               "a session with a key already is refused another",
			updateErr:          fmt.Errorf("update: %w", databaseErrors.ErrDbscPublicKeyRegistered),
			expectedStatusCode: http.StatusConflict,
			expectedDetail:     "A device key is already registered for the session.",
		},
		{
			name:               "an authentication that is gone is the store's failure",
			updateErr:          fmt.Errorf("update: %w", sql.ErrNoRows),
			expectedStatusCode: http.StatusInternalServerError,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint := New(
				dbsc_register_endpoint_config.WithUpdateAuthenticationWithDbscPublicKey(
					func(ctx context.Context, id string, key []byte, database *sql.DB) error {
						if id != loginTesting.AuthenticationId {
							return fmt.Errorf("%w: got %s, want %s", errTestAuthenticationIdMismatch, id, loginTesting.AuthenticationId)
						}
						return testCase.updateErr
					},
				),
			)
			testEndpointProcessor, err := dbsc_session_response_processor.New(
				"https://example.com"+dbsc_register_endpoint_config.DefaultPath,
				db,
				dbsc_session_response_processor_config.WithPopDbscChallenge(
					func(ctx context.Context, challenge string, authenticationId string, db *sql.DB) (*dbsc_challenge.Challenge, error) {
						return &dbsc_challenge.Challenge{
							Authentication: &authenticationPkg.Authentication{Id: authenticationId},
							Challenge:      []byte(challenge),
							ExpiresAt:      new(time.Now().Add(time.Hour)),
						}, nil
					},
				),
			)
			if err != nil {
				t.Fatalf("%s: dbsc session response processor new: %v", testCase.name, err)
			}

			if err := testEndpoint.Initialize(defaultAuthorizationRequestParser, testEndpointProcessor, loginTesting.RegisteredDomain); err != nil {
				t.Fatalf("%s: test endpoint initialize: %v", testCase.name, err)
			}

			mux := &muxPkg.Mux{}
			mux.Add(testEndpoint.Endpoint.Endpoint)
			httpServer := httptest.NewServer(mux)
			defer httpServer.Close()

			request, err := http.NewRequestWithContext(t.Context(), testEndpoint.Method, httpServer.URL+testEndpoint.Path, nil)
			if err != nil {
				t.Fatalf("%s: new request: %v", testCase.name, err)
			}
			request.Header.Set("Cookie", defaultSessionCookieString)
			request.Header.Set(session.DbscSessionResponseHeaderName, validToken)

			response, err := httpServer.Client().Do(request)
			if err != nil {
				t.Fatalf("%s: do: %v", testCase.name, err)
			}
			defer func() { _ = response.Body.Close() }()

			if response.StatusCode != testCase.expectedStatusCode {
				t.Fatalf("%s: status code %d, expected %d", testCase.name, response.StatusCode, testCase.expectedStatusCode)
			}

			if testCase.expectedDetail != "" {
				var detail problem_detail.Detail
				if err := json.UnmarshalRead(response.Body, &detail); err != nil {
					t.Fatalf("%s: json unmarshal read (problem detail): %v", testCase.name, err)
				}
				if detail.Detail != testCase.expectedDetail {
					t.Errorf("%s: detail %q, expected %q", testCase.name, detail.Detail, testCase.expectedDetail)
				}
			}
		})
	}
}

// TestEndpoint_RecordsSessionExpiresAt covers what binding a session records for its first refresh:
// when the token the reissued cookie carries expires, which is when the session begins to sit idle.
// Failing to record it costs that refresh its idle bound and nothing more, so the binding stands;
// a key that is refused binds nothing and records nothing.
func TestEndpoint_RecordsSessionExpiresAt(t *testing.T) {
	t.Parallel()

	validToken, _ := loginTesting.MakeDbscProof("cv")

	testCases := []struct {
		name               string
		updateKeyErr       error
		recordErr          error
		expectedStatusCode int
		wantRecorded       bool
	}{
		{name: "the token's expiry is recorded", expectedStatusCode: http.StatusOK, wantRecorded: true},
		{
			name:               "a failure to record it keeps the binding",
			recordErr:          sql.ErrConnDone,
			expectedStatusCode: http.StatusOK,
			wantRecorded:       true,
		},
		{
			name:               "a refused key records nothing",
			updateKeyErr:       databaseErrors.ErrDbscPublicKeyRegistered,
			expectedStatusCode: http.StatusConflict,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var recorded []time.Time
			var recordedMutex sync.Mutex

			testEndpoint := New(
				dbsc_register_endpoint_config.WithUpdateAuthenticationWithDbscPublicKey(
					func(context.Context, string, []byte, *sql.DB) error { return testCase.updateKeyErr },
				),
				dbsc_register_endpoint_config.WithUpdateAuthenticationWithSessionExpiresAt(
					func(ctx context.Context, id string, sessionExpiresAt time.Time, database *sql.DB) error {
						if id != loginTesting.AuthenticationId {
							return fmt.Errorf("%w: got %s, want %s", errTestAuthenticationIdMismatch, id, loginTesting.AuthenticationId)
						}
						recordedMutex.Lock()
						defer recordedMutex.Unlock()
						recorded = append(recorded, sessionExpiresAt)
						return testCase.recordErr
					},
				),
			)
			testEndpointProcessor, err := dbsc_session_response_processor.New(
				"https://example.com"+dbsc_register_endpoint_config.DefaultPath,
				db,
				dbsc_session_response_processor_config.WithPopDbscChallenge(
					func(ctx context.Context, challenge string, authenticationId string, db *sql.DB) (*dbsc_challenge.Challenge, error) {
						return &dbsc_challenge.Challenge{
							Authentication: &authenticationPkg.Authentication{Id: authenticationId},
							Challenge:      []byte(challenge),
							ExpiresAt:      new(time.Now().Add(time.Hour)),
						}, nil
					},
				),
			)
			if err != nil {
				t.Fatalf("%s: dbsc session response processor new: %v", testCase.name, err)
			}

			if err := testEndpoint.Initialize(defaultAuthorizationRequestParser, testEndpointProcessor, loginTesting.RegisteredDomain); err != nil {
				t.Fatalf("%s: test endpoint initialize: %v", testCase.name, err)
			}

			mux := &muxPkg.Mux{}
			mux.Add(testEndpoint.Endpoint.Endpoint)
			httpServer := httptest.NewServer(mux)
			defer httpServer.Close()

			request, err := http.NewRequestWithContext(t.Context(), testEndpoint.Method, httpServer.URL+testEndpoint.Path, nil)
			if err != nil {
				t.Fatalf("%s: new request: %v", testCase.name, err)
			}
			request.Header.Set("Cookie", defaultSessionCookieString)
			request.Header.Set(session.DbscSessionResponseHeaderName, validToken)

			response, err := httpServer.Client().Do(request)
			if err != nil {
				t.Fatalf("%s: do: %v", testCase.name, err)
			}
			defer func() { _ = response.Body.Close() }()

			if response.StatusCode != testCase.expectedStatusCode {
				t.Fatalf("%s: status code %d, expected %d", testCase.name, response.StatusCode, testCase.expectedStatusCode)
			}

			recordedMutex.Lock()
			defer recordedMutex.Unlock()
			if !testCase.wantRecorded {
				if len(recorded) != 0 {
					t.Errorf("%s: recorded %v, want nothing", testCase.name, recorded)
				}
				return
			}
			if len(recorded) != 1 {
				t.Fatalf("%s: recorded %v, want one expiry", testCase.name, recorded)
			}

			// The reissued cookie expires with the token, so its expiry is what was recorded.
			cookies := response.Cookies()
			if len(cookies) != 1 {
				t.Fatalf("%s: %d cookies set, want one", testCase.name, len(cookies))
			}
			if cookieExpiresAt := cookies[0].Expires; !cookieExpiresAt.Equal(recorded[0].Truncate(time.Second)) {
				t.Errorf("%s: recorded %s, the cookie expires %s", testCase.name, recorded[0], cookieExpiresAt)
			}
		})
	}
}
