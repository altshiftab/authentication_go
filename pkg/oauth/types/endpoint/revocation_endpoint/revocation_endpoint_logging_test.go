package revocation_endpoint

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/altshiftab/authentication_go/pkg/log_options"
	"github.com/altshiftab/authentication_go/pkg/log_options/log_options_testing"
	"github.com/altshiftab/authentication_go/pkg/oauth"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/memory_store"
)

//nolint:paralleltest // Swaps the global slog default; running it in parallel would race.
func TestAuditEvents(t *testing.T) {
	store := memory_store.New("an-account")
	if _, err := store.InsertGrant(t.Context(), &oauth.Grant{AccountId: "an-account", ClientId: "a-client", Resource: "r", Scope: "vocab", CreatedAt: time.Now()},
		oauth.HashSecret("a-refresh-token"), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("insert grant: %v", err)
	}

	endpoint := New(log_options.WithEventAttrs(slog.String("dataset", "service.audit")), log_options.WithLogAttrs(slog.String("environment", "test")))
	if err := endpoint.Initialize(store); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	testCases := []struct {
		name string
		body string
		want map[string]any
	}{
		{
			name: "a revocation, whose outcome the store cannot tell",
			body: url.Values{"token": {"a-refresh-token"}}.Encode(),
			want: map[string]any{"category": []any{"authentication"}, "type": []any{"end"}, "action": "oauth_token_revocation", "outcome": "unknown", "dataset": "service.audit"},
		},
		{
			name: "a refused revocation",
			body: url.Values{"client_id": {"a-client"}}.Encode(),
			want: map[string]any{"category": []any{"authentication"}, "type": []any{"end"}, "action": "oauth_token_revocation", "outcome": "failure", "dataset": "service.audit"},
		},
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

			events := log_options_testing.Events(lines, "oauth_token_revocation")
			if len(events) != 1 || !reflect.DeepEqual(events[0], testCase.want) {
				t.Errorf("got events %v, want one %v", events, testCase.want)
			}
			if len(lines) == 0 || lines[0]["environment"] != "test" {
				t.Errorf("the service's line attribute is missing: %v", lines)
			}
		})
	}
}
