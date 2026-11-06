package registration_endpoint

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/altshiftab/authentication_go/pkg/log_options"
	"github.com/altshiftab/authentication_go/pkg/log_options/log_options_testing"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/client_registrar"
)

//nolint:paralleltest // Swaps the global slog default; running it in parallel would race.
func TestAuditEvents(t *testing.T) {
	registrar, err := client_registrar.New(bytes.Repeat([]byte{7}, 32), true, client_registrar.GeminiRedirectRules()...)
	if err != nil {
		t.Fatalf("client registrar new: %v", err)
	}
	endpoint := New(log_options.WithEventAttrs(slog.String("dataset", "service.audit")))
	if err := endpoint.Initialize(registrar); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	testCases := []struct {
		name    string
		body    string
		outcome string
	}{
		{
			name:    "a client registered",
			body:    `{"client_name":"Gemini CLI MCP Client","redirect_uris":["http://localhost:41234/oauth/callback"],"token_endpoint_auth_method":"none"}`,
			outcome: "success",
		},
		{name: "a registration refused", body: `{"redirect_uris":["https://evil.example/cb"]}`, outcome: "failure"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			lines, err := log_options_testing.Capture(func() {
				if _, responseError := endpoint.Handler(httptest.NewRequestWithContext(t.Context(), http.MethodPost, DefaultPath, nil), []byte(testCase.body)); responseError != nil {
					t.Errorf("handler: %+v", responseError)
				}
			})
			if err != nil {
				t.Fatalf("capture: %v", err)
			}

			want := map[string]any{"category": []any{"iam"}, "type": []any{"creation"}, "action": "oauth_client_registration", "outcome": testCase.outcome, "dataset": "service.audit"}
			if events := log_options_testing.Events(lines, "oauth_client_registration"); len(events) != 1 || !reflect.DeepEqual(events[0], want) {
				t.Errorf("got events %v, want one %v", events, want)
			}
		})
	}
}
