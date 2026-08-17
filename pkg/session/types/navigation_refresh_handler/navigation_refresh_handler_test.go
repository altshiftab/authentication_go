package navigation_refresh_handler

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	accountPkg "github.com/altshiftab/authentication_go/pkg/database/types/account"
	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	loginTesting "github.com/altshiftab/authentication_go/pkg/session/testing"
	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser"
	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser/authorizer_request_parser_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/navigation_refresh_handler/navigation_refresh_handler_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_manager"
	altshiftCryptoEddsa "github.com/altshiftab/utils_go/pkg/crypto/eddsa"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
)

const (
	staticContentBody = "sign-in page"
	staticContentPath = "/index.html"
	// NewFromDataPath serves an index.html at the root, which is where a sign-in page lives.
	requestPath    = "/"
	redirectTarget = "https://app.example.com/orders"
)

var errSelectFailed = errors.New("select failed")

var method *altshiftCryptoEddsa.Method
var db *sql.DB

func TestMain(m *testing.M) {
	_, method, db = loginTesting.SetUp()

	code := m.Run()
	if db != nil {
		_ = db.Close()
	}
	os.Exit(code)
}

// signer returns the test signing method, checked once so that the rest of the file can use it
// without each call site having to account for a nil.
func signer(t *testing.T) *altshiftCryptoEddsa.Method {
	t.Helper()

	if method == nil {
		t.Fatalf("nil method")
	}

	return method
}

func expiredCookie(t *testing.T, authenticationMethods ...string) string {
	t.Helper()

	if len(authenticationMethods) == 0 {
		authenticationMethods = []string{"ext"}
	}

	now := time.Now()
	return loginTesting.MakeCookieExplicit(
		loginTesting.AuthenticationId,
		signer(t),
		authenticationMethods,
		now.Add(-time.Minute),
		now.Add(-time.Hour),
	)
}

func liveAuthentication() *authenticationPkg.Authentication {
	expiresAt := time.Now().Add(12 * time.Hour)
	return &authenticationPkg.Authentication{
		Id:        loginTesting.AuthenticationId,
		Account:   &accountPkg.Account{Id: "test-account-id", EmailAddress: "test@example.com", Roles: []string{"test-role"}},
		ExpiresAt: &expiresAt,
	}
}

// newServer serves the sign-in page with the handler attached, exactly as a service would: the
// static content stays in place, so the dispatch between page and redirect is what is exercised.
func newServer(
	t *testing.T,
	authentication *authenticationPkg.Authentication,
	selectError error,
) *httptest.Server {
	t.Helper()

	authorizer, err := authorizer_request_parser.New(
		signer(t),
		loginTesting.Issuer,
		loginTesting.Audience,
		authorizer_request_parser_config.WithSkipExp(true),
	)
	if err != nil {
		t.Fatalf("authorizer request parser new: %v", err)
	}

	sessionManager, err := session_manager.New(signer(t), db, loginTesting.Issuer, loginTesting.RegisteredDomain)
	if err != nil {
		t.Fatalf("session manager new: %v", err)
	}

	handler, err := New(
		authorizer,
		sessionManager,
		navigation_refresh_handler_config.WithSelectRefreshAuthentication(
			func(context.Context, string, *sql.DB) (*authenticationPkg.Authentication, error) {
				return authentication, selectError
			},
		),
	)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	testEndpoint, err := endpoint.NewFromDataPath(
		staticContentPath,
		[]byte(staticContentBody),
		time.Now().UTC().Format(http.TimeFormat),
		false,
		false,
	)
	if err != nil {
		t.Fatalf("endpoint new from data path: %v", err)
	}
	if testEndpoint == nil {
		t.Fatalf("nil test endpoint")
	}
	testEndpoint.Handler = handler

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint)

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	return server
}

func TestHandler(t *testing.T) {
	t.Parallel()

	endedAuthentication := liveAuthentication()
	endedAuthentication.Ended = true

	expiredAuthentication := liveAuthentication()
	expiredAuthentication.ExpiresAt = new(time.Now().Add(-time.Hour))

	dbscAuthentication := liveAuthentication()
	dbscAuthentication.DbscPublicKey = []byte("public-key")

	testCases := []struct {
		name string
		// fetchMode defaults to "navigate".
		fetchMode      string
		omitRedirect   bool
		redirect       string
		cookie         func(*testing.T) string
		authentication *authenticationPkg.Authentication
		selectError    error
		// expectedStatusCode defaults to 303, i.e. the session was renewed.
		expectedStatusCode int
	}{
		{
			name:               "expired token and live authentication is refreshed",
			cookie:             func(t *testing.T) string { return expiredCookie(t) },
			authentication:     liveAuthentication(),
			expectedStatusCode: http.StatusSeeOther,
		},
		{
			name:               "the site itself is an acceptable target",
			redirect:           "https://example.com/",
			cookie:             func(t *testing.T) string { return expiredCookie(t) },
			authentication:     liveAuthentication(),
			expectedStatusCode: http.StatusSeeOther,
		},
		{
			name:               "a target is matched without regard to case",
			redirect:           "https://APP.EXAMPLE.COM/orders",
			cookie:             func(t *testing.T) string { return expiredCookie(t) },
			authentication:     liveAuthentication(),
			expectedStatusCode: http.StatusSeeOther,
		},
		{
			name:               "a fetch is served the page",
			fetchMode:          "cors",
			cookie:             func(t *testing.T) string { return expiredCookie(t) },
			authentication:     liveAuthentication(),
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "no redirect parameter serves the page",
			omitRedirect:       true,
			cookie:             func(t *testing.T) string { return expiredCookie(t) },
			authentication:     liveAuthentication(),
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "a target off the site is refused",
			redirect:           "https://evil.example.net/",
			cookie:             func(t *testing.T) string { return expiredCookie(t) },
			authentication:     liveAuthentication(),
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "a target whose host merely ends in the site is refused",
			redirect:           "https://notexample.com/",
			cookie:             func(t *testing.T) string { return expiredCookie(t) },
			authentication:     liveAuthentication(),
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "a target with a scheme that is not http is refused",
			redirect:           "javascript:alert(1)",
			cookie:             func(t *testing.T) string { return expiredCookie(t) },
			authentication:     liveAuthentication(),
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "no session cookie serves the page",
			authentication:     liveAuthentication(),
			expectedStatusCode: http.StatusOK,
		},
		{
			// The guard against looping: a valid token means the rejection was over something a
			// refresh cannot fix.
			name: "an unexpired token is left alone",
			cookie: func(t *testing.T) string {
				return loginTesting.MakeStandardCookie(loginTesting.AuthenticationId, signer(t))
			},
			authentication:     liveAuthentication(),
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "a device bound token is left to the browser",
			cookie:             func(t *testing.T) string { return expiredCookie(t, "hwk") },
			authentication:     liveAuthentication(),
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "a device bound authentication is left to the browser",
			cookie:             func(t *testing.T) string { return expiredCookie(t) },
			authentication:     dbscAuthentication,
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "an ended authentication serves the page",
			cookie:             func(t *testing.T) string { return expiredCookie(t) },
			authentication:     endedAuthentication,
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "an expired authentication serves the page",
			cookie:             func(t *testing.T) string { return expiredCookie(t) },
			authentication:     expiredAuthentication,
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "a missing authentication serves the page",
			cookie:             func(t *testing.T) string { return expiredCookie(t) },
			selectError:        sql.ErrNoRows,
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "a failing lookup is a server error",
			cookie:             func(t *testing.T) string { return expiredCookie(t) },
			selectError:        errSelectFailed,
			expectedStatusCode: http.StatusInternalServerError,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			server := newServer(t, testCase.authentication, testCase.selectError)

			requestUrl := server.URL + requestPath
			if !testCase.omitRedirect {
				target := testCase.redirect
				if target == "" {
					target = redirectTarget
				}
				requestUrl += "?redirect=" + url.QueryEscape(target)
			}

			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, requestUrl, nil)
			if err != nil {
				t.Fatalf("http new request: %v", err)
			}

			fetchMode := testCase.fetchMode
			if fetchMode == "" {
				fetchMode = "navigate"
			}
			request.Header.Set("Sec-Fetch-Mode", fetchMode)
			request.Header.Set("Sec-Fetch-Site", "none")
			request.Header.Set("Sec-Fetch-Dest", "document")

			if testCase.cookie != nil {
				request.Header.Set("Cookie", testCase.cookie(t))
			}

			client := &http.Client{
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatalf("client do: %v", err)
			}
			defer func() { _ = response.Body.Close() }()

			if response.StatusCode != testCase.expectedStatusCode {
				t.Fatalf("got status %d, expected %d", response.StatusCode, testCase.expectedStatusCode)
			}

			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("io read all: %v", err)
			}

			if testCase.expectedStatusCode != http.StatusSeeOther {
				// Falling through has to leave the page intact, not merely the status.
				if testCase.expectedStatusCode == http.StatusOK && string(body) != staticContentBody {
					t.Errorf("got body %q, expected the page", body)
				}
				return
			}

			// A redirect carrying the page would mean the static content had answered after all.
			if len(body) != 0 {
				t.Errorf("got body %q, expected none", body)
			}

			expectedLocation := testCase.redirect
			if expectedLocation == "" {
				expectedLocation = redirectTarget
			}
			if location := response.Header.Get("Location"); location != expectedLocation {
				t.Errorf("got location %q, expected %q", location, expectedLocation)
			}

			// The point of the exercise: the browser leaves with a session it did not arrive with.
			setCookie := response.Header.Get("Set-Cookie")
			if setCookie == "" {
				t.Fatalf("no session cookie was set")
			}
			if !strings.Contains(setCookie, "Domain="+loginTesting.RegisteredDomain) {
				t.Errorf("got cookie %q, expected it scoped to %s", setCookie, loginTesting.RegisteredDomain)
			}
		})
	}
}
