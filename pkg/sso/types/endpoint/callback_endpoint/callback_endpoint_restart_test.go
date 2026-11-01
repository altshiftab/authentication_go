package callback_endpoint

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/altshiftab/authentication_go/pkg/database/types/oauth_flow"
	testing2 "github.com/altshiftab/authentication_go/pkg/sso/testing"
	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/callback_endpoint/callback_endpoint_config"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
)

const testLoginPath = "/login"

const restartDetail = "The OAuth flow has expired; the sign-in is restarted."

// A browser that comes back from the provider after its flow expired is sent to sign in again,
// bound where it was going; anything else that finds no flow is refused as before.
func TestEndpointRestart(t *testing.T) {
	t.Parallel()

	const otherFlowId = "6c2e9a41-0d3b-4f8a-b7e5-91a4c2d8f306"
	const sessionCookieValue = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl"
	// Where the flow the cookie names was bound, apart from where the state's flow was.
	const cookieFlowRedirectUrl = "https://example.com/elsewhere"

	expired := func() *time.Time { expiresAt := time.Now().Add(-time.Minute); return &expiresAt }
	live := func() *time.Time { expiresAt := time.Now().Add(time.Hour); return &expiresAt }

	restartLocation := func(origin string, redirectUrl string) string {
		return origin + testLoginPath + "?redirect=" + url.QueryEscape(redirectUrl)
	}

	testCases := []struct {
		name         string
		emptyOrigin  bool
		noLoginPath  bool
		rawQuery     string
		cookieValues []string
		// The flow the cookie's id pops; nil pops nothing.
		cookieFlow *oauth_flow.Flow
		// What popping the state's expired flow returns.
		expiredFlow *oauth_flow.Flow
		expiredErr  error

		expectedStatusCode  int
		expectedLocation    string
		expectedDetail      string
		expectedPops        int
		expectedStatePops   int
		expectCookieCleared bool
	}{
		{
			name:                "no cookie, state names an expired flow",
			expiredFlow:         &oauth_flow.Flow{RedirectUrl: testing2.RedirectUrl, ExpiresAt: expired()},
			expectedStatusCode:  http.StatusSeeOther,
			expectedLocation:    restartLocation(testOrigin, testing2.RedirectUrl),
			expectedDetail:      restartDetail,
			expectedStatePops:   1,
			expectCookieCleared: true,
		},
		{
			// A live flow, or none: a browser that cannot keep the cookie must not go round again.
			name:               "no cookie, state names no expired flow",
			expiredErr:         sql.ErrNoRows,
			expectedStatusCode: http.StatusBadRequest,
			expectedDetail:     "No callback cookie.",
			expectedStatePops:  1,
		},
		{
			name:                "empty cookie, state names an expired flow",
			cookieValues:        []string{""},
			expiredFlow:         &oauth_flow.Flow{RedirectUrl: testing2.RedirectUrl, ExpiresAt: expired()},
			expectedStatusCode:  http.StatusSeeOther,
			expectedLocation:    restartLocation(testOrigin, testing2.RedirectUrl),
			expectedDetail:      restartDetail,
			expectedStatePops:   1,
			expectCookieCleared: true,
		},
		{
			// Signed in already, and the flow cookie gone.
			name:                "session cookie alone, state names an expired flow",
			cookieValues:        []string{sessionCookieValue},
			expiredFlow:         &oauth_flow.Flow{RedirectUrl: testing2.RedirectUrl, ExpiresAt: expired()},
			expectedStatusCode:  http.StatusSeeOther,
			expectedLocation:    restartLocation(testOrigin, testing2.RedirectUrl),
			expectedDetail:      restartDetail,
			expectedStatePops:   1,
			expectCookieCleared: true,
		},
		{
			name:                "cookie names another flow, state names an expired flow",
			cookieValues:        []string{otherFlowId},
			expiredFlow:         &oauth_flow.Flow{RedirectUrl: testing2.RedirectUrl, ExpiresAt: expired()},
			expectedStatusCode:  http.StatusSeeOther,
			expectedLocation:    restartLocation(testOrigin, testing2.RedirectUrl),
			expectedDetail:      restartDetail,
			expectedPops:        1,
			expectedStatePops:   1,
			expectCookieCleared: true,
		},
		{
			// The cookie's flow is the browser's own, so it says where to go; the state is not asked.
			name:                "cookie names an expired flow",
			cookieValues:        []string{testing2.OauthFlowId},
			cookieFlow:          &oauth_flow.Flow{RedirectUrl: cookieFlowRedirectUrl, State: testing2.State, ExpiresAt: expired()},
			expectedStatusCode:  http.StatusSeeOther,
			expectedLocation:    restartLocation(testOrigin, cookieFlowRedirectUrl),
			expectedDetail:      restartDetail,
			expectedPops:        1,
			expectCookieCleared: true,
		},
		{
			// Not widened: a live flow whose state differs is refused as before.
			name:               "cookie names a live flow of another state",
			cookieValues:       []string{testing2.OauthFlowId},
			cookieFlow:         &oauth_flow.Flow{RedirectUrl: cookieFlowRedirectUrl, State: "other-state", ExpiresAt: live()},
			expiredFlow:        &oauth_flow.Flow{RedirectUrl: testing2.RedirectUrl, ExpiresAt: expired()},
			expectedStatusCode: http.StatusBadRequest,
			expectedDetail:     "The OAuth flow state and url state do not match.",
			expectedPops:       1,
		},
		{
			name:               "state lookup fails",
			expiredErr:         errStoreFailure,
			expectedStatusCode: http.StatusInternalServerError,
			expectedStatePops:  1,
		},
		{
			name:               "state lookup returns no flow and no error",
			expectedStatusCode: http.StatusInternalServerError,
			expectedStatePops:  1,
		},
		{
			// A store is configurable, so the handler does not take its word that a flow expired.
			name:               "state lookup returns a live flow",
			expiredFlow:        &oauth_flow.Flow{RedirectUrl: testing2.RedirectUrl, ExpiresAt: live()},
			expectedStatusCode: http.StatusInternalServerError,
			expectedStatePops:  1,
		},
		{
			name:               "state lookup returns a flow without an expiry",
			expiredFlow:        &oauth_flow.Flow{RedirectUrl: testing2.RedirectUrl},
			expectedStatusCode: http.StatusInternalServerError,
			expectedStatePops:  1,
		},
		{
			// A decline after the flow expired is not sent back to the provider to be asked again.
			name:               "provider error, no cookie, state names an expired flow",
			rawQuery:           "state=" + testing2.State + "&error=access_denied",
			expiredFlow:        &oauth_flow.Flow{RedirectUrl: testing2.RedirectUrl, ExpiresAt: expired()},
			expectedStatusCode: http.StatusBadRequest,
			expectedDetail:     "No callback cookie.",
		},
		{
			name:               "provider error, cookie names an expired flow",
			rawQuery:           "state=" + testing2.State + "&error=access_denied",
			cookieValues:       []string{testing2.OauthFlowId},
			cookieFlow:         &oauth_flow.Flow{RedirectUrl: cookieFlowRedirectUrl, State: testing2.State, ExpiresAt: expired()},
			expectedStatusCode: http.StatusBadRequest,
			expectedDetail:     "The OAuth flow has expired.",
			expectedPops:       1,
		},
		{
			// Without a login path the callback does not know where to restart.
			name:               "no login path",
			noLoginPath:        true,
			expiredFlow:        &oauth_flow.Flow{RedirectUrl: testing2.RedirectUrl, ExpiresAt: expired()},
			expectedStatusCode: http.StatusBadRequest,
			expectedDetail:     "No callback cookie.",
		},
		{
			name:               "no login path, cookie names an expired flow",
			noLoginPath:        true,
			cookieValues:       []string{testing2.OauthFlowId},
			cookieFlow:         &oauth_flow.Flow{RedirectUrl: cookieFlowRedirectUrl, State: testing2.State, ExpiresAt: expired()},
			expectedStatusCode: http.StatusBadRequest,
			expectedDetail:     "The OAuth flow has expired.",
			expectedPops:       1,
		},
		{
			// An empty state is never looked up.
			name:               "empty state in the url",
			rawQuery:           "state=&code=" + testing2.OauthCode,
			expiredFlow:        &oauth_flow.Flow{RedirectUrl: testing2.RedirectUrl, ExpiresAt: expired()},
			expectedStatusCode: http.StatusBadRequest,
			expectedDetail:     "No callback cookie.",
		},
		{
			name:                "empty origin",
			emptyOrigin:         true,
			expiredFlow:         &oauth_flow.Flow{RedirectUrl: testing2.RedirectUrl, ExpiresAt: expired()},
			expectedStatusCode:  http.StatusSeeOther,
			expectedLocation:    restartLocation("", testing2.RedirectUrl),
			expectedDetail:      restartDetail,
			expectedStatePops:   1,
			expectCookieCleared: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var options []callback_endpoint_config.Option
			if !testCase.noLoginPath {
				options = append(options, callback_endpoint_config.WithLoginPath(testLoginPath))
			}
			testEndpoint, err := New[*testing2.ProviderClaims](defaultPath, options...)
			if err != nil {
				t.Fatalf("new endpoint: %v", err)
			}

			origin := testOrigin
			if testCase.emptyOrigin {
				origin = ""
			}
			if err := testEndpoint.Initialize(origin, oauthConfig, idTokenAuthenticator, sessionManager); err != nil {
				t.Fatalf("test endpoint initialize: %v", err)
			}

			var pops int
			testEndpoint.popOauthFlow = func(_ context.Context, id string, _ *sql.DB) (*oauth_flow.Flow, error) {
				pops++
				if id != testing2.OauthFlowId || testCase.cookieFlow == nil {
					return nil, sql.ErrNoRows
				}
				return testCase.cookieFlow, nil
			}

			var statePops int
			testEndpoint.popExpiredOauthFlowByState = func(_ context.Context, state string, now time.Time, _ *sql.DB) (*oauth_flow.Flow, error) {
				statePops++
				if state != testing2.State {
					t.Errorf("%s: state: got %q, want %q", testCase.name, state, testing2.State)
				}
				if since := time.Since(now); since < 0 || since > time.Minute {
					t.Errorf("%s: now is not the present: %v", testCase.name, now)
				}
				if testCase.expiredErr != nil {
					return nil, testCase.expiredErr
				}
				return testCase.expiredFlow, nil
			}

			mux := &muxPkg.Mux{}
			mux.Add(testEndpoint.Endpoint.Endpoint)
			server := httptest.NewServer(mux)
			t.Cleanup(server.Close)

			rawQuery := testCase.rawQuery
			if rawQuery == "" {
				rawQuery = "state=" + testing2.State + "&code=" + testing2.OauthCode
			}

			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+defaultPath+"?"+rawQuery, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			request.Header.Set("Accept", "application/problem+json")
			if len(testCase.cookieValues) != 0 {
				var cookieParts []string
				for _, cookieValue := range testCase.cookieValues {
					cookieParts = append(cookieParts, testEndpoint.CallbackCookieName+"="+cookieValue)
				}
				request.Header.Set("Cookie", strings.Join(cookieParts, "; "))
			}

			client := &http.Client{
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			defer func() { _ = response.Body.Close() }()

			if response.StatusCode != testCase.expectedStatusCode {
				t.Errorf("%s: status code: got %d, want %d", testCase.name, response.StatusCode, testCase.expectedStatusCode)
			}

			if location := response.Header.Get("Location"); location != testCase.expectedLocation {
				t.Errorf("%s: location: got %q, want %q", testCase.name, location, testCase.expectedLocation)
			}

			if testCase.expectedDetail != "" {
				if contentType := response.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/problem+json") {
					t.Errorf("%s: content type: got %q", testCase.name, contentType)
				}
				body, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatalf("read body: %v", err)
				}
				var problemDetail struct {
					Detail string `json:"detail"`
				}
				if err := json.Unmarshal(body, &problemDetail); err != nil {
					t.Fatalf("%s: unmarshal body %q: %v", testCase.name, body, err)
				}
				if problemDetail.Detail != testCase.expectedDetail {
					t.Errorf("%s: detail: got %q, want %q", testCase.name, problemDetail.Detail, testCase.expectedDetail)
				}
			}

			var cookieCleared bool
			for _, cookie := range response.Cookies() {
				if cookie.Name == testEndpoint.CallbackCookieName && cookie.MaxAge < 0 && cookie.Path == defaultPath {
					cookieCleared = true
				}
			}
			if cookieCleared != testCase.expectCookieCleared {
				t.Errorf("%s: callback cookie cleared: got %v, want %v", testCase.name, cookieCleared, testCase.expectCookieCleared)
			}

			if pops != testCase.expectedPops {
				t.Errorf("%s: pops by id: got %d, want %d", testCase.name, pops, testCase.expectedPops)
			}
			if statePops != testCase.expectedStatePops {
				t.Errorf("%s: pops by state: got %d, want %d", testCase.name, statePops, testCase.expectedStatePops)
			}
		})
	}
}

func TestEndpointInitializeLoginPath(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		loginPath        string
		expectedLoginUrl string
		expectErr        bool
	}{
		{name: "none", loginPath: ""},
		{name: "absolute", loginPath: testLoginPath, expectedLoginUrl: testOrigin + testLoginPath},
		{name: "relative", loginPath: "login", expectErr: true},
		// Each of these would take the restart to another origin or mangle its query.
		{name: "scheme relative", loginPath: "//evil.example/login", expectErr: true},
		{name: "backslash", loginPath: `/\evil.example/login`, expectErr: true},
		{name: "absolute url", loginPath: "https://evil.example/login", expectErr: true},
		{name: "query", loginPath: "/login?x=1", expectErr: true},
		{name: "fragment", loginPath: "/login#x", expectErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint, err := New[*testing2.ProviderClaims](defaultPath, callback_endpoint_config.WithLoginPath(testCase.loginPath))
			if err != nil {
				t.Fatalf("new endpoint: %v", err)
			}

			err = testEndpoint.Initialize(testOrigin, oauthConfig, idTokenAuthenticator, sessionManager)
			if testCase.expectErr {
				if !errors.Is(err, errInvalidLoginPath) {
					t.Errorf("%s: error: got %v, want %v", testCase.name, err, errInvalidLoginPath)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: initialize: %v", testCase.name, err)
			}

			var loginUrl string
			if testEndpoint.loginUrl != nil {
				loginUrl = testEndpoint.loginUrl.String()
			}
			if loginUrl != testCase.expectedLoginUrl {
				t.Errorf("%s: login url: got %q, want %q", testCase.name, loginUrl, testCase.expectedLoginUrl)
			}
		})
	}
}
