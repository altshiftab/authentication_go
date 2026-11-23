package callback_endpoint

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/altshiftab/authentication_go/pkg/database/types/oauth_flow"
	"github.com/altshiftab/authentication_go/pkg/sso/errors/oauth_error"
	testing2 "github.com/altshiftab/authentication_go/pkg/sso/testing"
	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/callback_endpoint/callback_endpoint_config"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
)

func newRedirectTestServer(t *testing.T, origin string, options ...callback_endpoint_config.Option) (*httptest.Server, *Endpoint[*testing2.ProviderClaims]) {
	t.Helper()

	testEndpoint, err := New[*testing2.ProviderClaims](defaultPath, options...)
	if err != nil {
		t.Fatalf("new endpoint: %v", err)
	}
	if err := testEndpoint.Initialize(origin, oauthConfig, idTokenAuthenticator, sessionManager); err != nil {
		t.Fatalf("test endpoint initialize: %v", err)
	}
	testEndpoint.popOauthFlow = func(ctx context.Context, id string, database *sql.DB) (*oauth_flow.Flow, error) {
		expiresAt := time.Now().Add(time.Hour)
		return &oauth_flow.Flow{
			Id:          testing2.OauthFlowId,
			RedirectUrl: testing2.RedirectUrl,
			State:       testing2.State,
			ExpiresAt:   &expiresAt,
		}, nil
	}

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint.Endpoint.Endpoint)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, testEndpoint
}

func doCallback(t *testing.T, server *httptest.Server, endpoint *Endpoint[*testing2.ProviderClaims], rawQuery string) *http.Response {
	t.Helper()

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+defaultPath+"?"+rawQuery, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.AddCookie(&http.Cookie{Name: endpoint.CallbackCookieName, Value: testing2.OauthFlowId}) //nolint:gosec // G124: a request cookie; its attributes are never sent.

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("client do: %v", err)
	}
	if response == nil {
		t.Fatal("nil response")
	}
	return response
}

func TestProviderErrorRedirectByCategory(t *testing.T) {
	t.Parallel()

	server, endpoint := newRedirectTestServer(t, testOrigin)

	testCases := []struct {
		name         string
		query        string
		wantCategory oauth_error.Category
	}{
		{
			name:         "cancelled (microsoft subcode)",
			query:        "error=access_denied&error_subcode=cancel",
			wantCategory: oauth_error.CategoryCancelled,
		},
		{
			name:         "cancelled (bare access_denied)",
			query:        "error=access_denied",
			wantCategory: oauth_error.CategoryCancelled,
		},
		{
			name:         "access denied (policy)",
			query:        "error=access_denied&error_description=" + url.QueryEscape("AADSTS50105: not assigned"),
			wantCategory: oauth_error.CategoryAccessDenied,
		},
		{
			name:         "unavailable",
			query:        "error=temporarily_unavailable",
			wantCategory: oauth_error.CategoryUnavailable,
		},
		{
			name:         "failed (misconfiguration)",
			query:        "error=invalid_scope",
			wantCategory: oauth_error.CategoryFailed,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			response := doCallback(t, server, endpoint, "state="+testing2.State+"&"+testCase.query)
			defer func() { _ = response.Body.Close() }()

			wantLocation := testOrigin + categoryProblemPaths[testCase.wantCategory]
			if response.StatusCode != http.StatusSeeOther {
				t.Errorf("status = %d, want %d", response.StatusCode, http.StatusSeeOther)
			}
			if got := response.Header.Get("Location"); got != wantLocation {
				t.Errorf("Location = %q, want %q", got, wantLocation)
			}
			// The callback cookie must always be cleared.
			if response.Header.Get("Set-Cookie") == "" {
				t.Error("expected a Set-Cookie header clearing the callback cookie")
			}
		})
	}
}

func TestProviderErrorRedirectRelativeOrigin(t *testing.T) {
	t.Parallel()

	// An empty origin yields a same-origin relative redirect (just the path).
	server, endpoint := newRedirectTestServer(t, "")

	response := doCallback(t, server, endpoint, "state="+testing2.State+"&error=access_denied&error_subcode=cancel")
	defer func() { _ = response.Body.Close() }()

	wantLocation := categoryProblemPaths[oauth_error.CategoryCancelled]
	if got := response.Header.Get("Location"); got != wantLocation {
		t.Errorf("Location = %q, want %q (relative)", got, wantLocation)
	}
}

func TestProviderErrorRedirectCustomClassifier(t *testing.T) {
	t.Parallel()

	// A custom classifier forces every error to CategoryFailed.
	classifier := func(*oauth_error.Error) oauth_error.Category { return oauth_error.CategoryFailed }
	server, endpoint := newRedirectTestServer(t, testOrigin, callback_endpoint_config.WithOauthErrorClassifier(classifier))

	response := doCallback(t, server, endpoint, "state="+testing2.State+"&error=access_denied&error_subcode=cancel")
	defer func() { _ = response.Body.Close() }()

	wantLocation := testOrigin + categoryProblemPaths[oauth_error.CategoryFailed]
	if got := response.Header.Get("Location"); got != wantLocation {
		t.Errorf("Location = %q, want %q (custom classifier)", got, wantLocation)
	}
}

// TestFlowRedirectScheme covers the scheme of where a flow sends the browser once it is signed in. The
// login endpoint takes only https, but the flow is the store's, so one that names anything else --
// begun before the endpoint checked, or by another -- is refused here rather than followed. Plain http
// is followed only to this machine, when the origin is on it. The gate stands before the provider's
// answer is read, so a declined sign-in shows it as well as a completed one would.
func TestFlowRedirectScheme(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		origin      string
		redirectUrl string
		wantRefuse  bool
	}{
		{name: "https", origin: testOrigin, redirectUrl: testing2.RedirectUrl},
		{name: "plain http", origin: testOrigin, redirectUrl: "http://example.com/redirect", wantRefuse: true},
		{name: "a script", origin: testOrigin, redirectUrl: "javascript://example.com/%0aalert(1)", wantRefuse: true},
		{name: "an android intent", origin: testOrigin, redirectUrl: "intent://example.com/#Intent;scheme=https;end", wantRefuse: true},
		{name: "plain http to localhost, from an origin elsewhere", origin: testOrigin, redirectUrl: "http://localhost:3000/", wantRefuse: true},
		{name: "plain http to localhost, from an origin on it", origin: "http://localhost:8080", redirectUrl: "http://localhost:3000/"},
		{name: "a flow redirect that does not parse", origin: testOrigin, redirectUrl: "https://example.com/%zz", wantRefuse: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			server, endpoint := newRedirectTestServer(t, testCase.origin)
			endpoint.popOauthFlow = func(ctx context.Context, id string, database *sql.DB) (*oauth_flow.Flow, error) {
				return &oauth_flow.Flow{
					Id:          testing2.OauthFlowId,
					RedirectUrl: testCase.redirectUrl,
					State:       testing2.State,
					ExpiresAt:   new(time.Now().Add(time.Hour)),
				}, nil
			}

			response := doCallback(t, server, endpoint, "state="+testing2.State+"&error=access_denied")
			defer func() { _ = response.Body.Close() }()

			wantStatusCode := http.StatusSeeOther
			if testCase.wantRefuse {
				wantStatusCode = http.StatusBadRequest
			}
			if response.StatusCode != wantStatusCode {
				t.Errorf("%s: status %d, want %d", testCase.name, response.StatusCode, wantStatusCode)
			}
			if location := response.Header.Get("Location"); testCase.wantRefuse && location != "" {
				t.Errorf("%s: the browser is sent to %q", testCase.name, location)
			}
		})
	}
}
