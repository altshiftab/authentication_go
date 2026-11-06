package token_endpoint

import (
	"context"
	"log/slog"
	"net/http"
	"reflect"
	"testing"

	"github.com/altshiftab/authentication_go/pkg/log_options"
	"github.com/altshiftab/authentication_go/pkg/log_options/log_options_testing"
	"github.com/altshiftab/authentication_go/pkg/oauth"
)

//nolint:paralleltest // Swaps the global slog default; running it in parallel would race.
func TestAuditEvents(t *testing.T) {
	endpoint := New(log_options.WithEventAttrs(slog.String("dataset", "service.audit")))
	ctx := context.Background()

	testCases := []struct {
		name    string
		log     func()
		outcome string
	}{
		{
			name: "a token issued",
			log: func() {
				endpoint.logIssued(ctx, &oauth.Grant{AccountId: "an-account", ClientId: "a-client", Resource: "r"}, []string{"vocab"}, "authorization_code")
			},
			outcome: "success",
		},
		{
			name:    "a token request refused",
			log:     func() { _, _ = endpoint.refuse(ctx, http.StatusBadRequest, "invalid_grant", "The code is invalid.") },
			outcome: "failure",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			lines, err := log_options_testing.Capture(testCase.log)
			if err != nil {
				t.Fatalf("capture: %v", err)
			}

			want := map[string]any{"category": []any{"authentication"}, "type": []any{"start"}, "action": "oauth_token_issuance", "outcome": testCase.outcome, "dataset": "service.audit"}
			if events := log_options_testing.Events(lines, "oauth_token_issuance"); len(events) != 1 || !reflect.DeepEqual(events[0], want) {
				t.Errorf("got events %v, want one %v", events, want)
			}
		})
	}
}
