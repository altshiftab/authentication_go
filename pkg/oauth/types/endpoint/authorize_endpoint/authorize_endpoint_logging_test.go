package authorize_endpoint

import (
	"context"
	"log/slog"
	"reflect"
	"testing"

	"github.com/altshiftab/authentication_go/pkg/log_options"
	"github.com/altshiftab/authentication_go/pkg/log_options/log_options_testing"
)

//nolint:paralleltest // Swaps the global slog default; running it in parallel would race.
func TestAuditEvents(t *testing.T) {
	endpoint := New(log_options.WithEventAttrs(slog.String("dataset", "service.audit")))

	lines, err := log_options_testing.Capture(func() {
		_, _ = endpoint.refusedPage(context.Background(), "The application is not known.", "unknown_client")
	})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}

	want := map[string]any{"category": []any{"authentication"}, "type": []any{"start"}, "action": "oauth_authorization", "outcome": "failure", "dataset": "service.audit"}
	if events := log_options_testing.Events(lines, "oauth_authorization"); len(events) != 1 || !reflect.DeepEqual(events[0], want) {
		t.Errorf("got events %v, want one %v", events, want)
	}
}
