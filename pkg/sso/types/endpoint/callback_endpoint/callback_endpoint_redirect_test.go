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

	request, err := http.NewRequest(http.MethodGet, server.URL+defaultPath+"?"+rawQuery, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.AddCookie(&http.Cookie{Name: endpoint.CallbackCookieName, Value: testing2.OauthFlowId})

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("client do: %v", err)
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
