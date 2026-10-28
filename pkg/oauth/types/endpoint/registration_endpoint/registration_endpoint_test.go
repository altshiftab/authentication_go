package registration_endpoint

import (
	"bytes"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/altshiftab/authentication_go/pkg/oauth/types/client_registrar"
)

func TestEndpoint(t *testing.T) {
	t.Parallel()

	registrar, err := client_registrar.New(bytes.Repeat([]byte{7}, 32), true, client_registrar.GeminiRedirectRules()...)
	if err != nil {
		t.Fatalf("client registrar new: %v", err)
	}
	endpoint := New()
	if err := endpoint.Initialize(registrar); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	testCases := []struct {
		name       string
		body       string
		wantStatus int
		wantError  string
	}{
		{
			name: "Gemini CLI",
			body: `{"client_name":"Gemini CLI MCP Client","redirect_uris":["http://localhost:41234/oauth/callback"],` +
				`"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none","scope":"vocab"}`,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "the Gemini app",
			body:       `{"redirect_uris":["https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-42-vocab"],"application_type":"web"}`,
			wantStatus: http.StatusCreated,
		},
		{name: "a site", body: `{"redirect_uris":["https://evil.example/cb"]}`, wantStatus: http.StatusBadRequest, wantError: "invalid_redirect_uri"},
		{name: "no redirect uris", body: `{"client_name":"x"}`, wantStatus: http.StatusBadRequest, wantError: "invalid_redirect_uri"},
		{
			name:       "a confidential client",
			body:       `{"redirect_uris":["http://localhost/cb"],"token_endpoint_auth_method":"client_secret_post"}`,
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_client_metadata",
		},
		{name: "not json", body: `redirect_uris=x`, wantStatus: http.StatusBadRequest, wantError: "invalid_client_metadata"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			response, responseError := endpoint.Handler(
				httptest.NewRequestWithContext(t.Context(), http.MethodPost, DefaultPath, nil), []byte(testCase.body),
			)
			if responseError != nil || response == nil {
				t.Fatalf("%s: handler: %+v", testCase.name, responseError)
			}
			if response.StatusCode != testCase.wantStatus {
				t.Fatalf("%s: status %d, want %d: %s", testCase.name, response.StatusCode, testCase.wantStatus, response.Body)
			}

			if testCase.wantError != "" {
				var refused ErrorResponse
				if err := json.Unmarshal(response.Body, &refused); err != nil || refused.Error != testCase.wantError || refused.ErrorDescription == "" {
					t.Errorf("%s: %s, want %s", testCase.name, response.Body, testCase.wantError)
				}
				return
			}

			var registered Response
			if err := json.Unmarshal(response.Body, &registered); err != nil {
				t.Fatalf("%s: unmarshal: %v", testCase.name, err)
			}
			if !strings.HasPrefix(registered.ClientId, client_registrar.IdPrefix) || registered.TokenEndpointAuthMethod != "none" ||
				registered.ClientIdIssuedAt == 0 || len(registered.RedirectUris) != 1 {
				t.Errorf("%s: %+v", testCase.name, registered)
			}
			// What it was given is an id the server knows it by.
			if resolved, err := registrar.Resolve(registered.ClientId); err != nil || resolved.Name != registered.ClientName {
				t.Errorf("%s: resolved %+v, %v", testCase.name, resolved, err)
			}
		})
	}

	if err := New().Initialize(nil); err == nil {
		t.Error("initialized without a registrar")
	}
}
