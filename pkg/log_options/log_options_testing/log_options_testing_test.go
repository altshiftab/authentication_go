package log_options_testing

import (
	"log"
	"log/slog"
	"testing"
)

//nolint:paralleltest // Swaps the global slog default; running it in parallel would race.
func TestCapture(t *testing.T) {
	testCases := []struct {
		name       string
		run        func()
		action     string
		wantEvents int
		// wantDataset is what the merged event group carries beside the action; empty for nothing.
		wantDataset string
	}{
		{
			name: "same-named groups are merged, as the services' logger merges them",
			run: func() {
				slog.Info("line", slog.Group("event", slog.String("action", "sign_in")), slog.Group("event", slog.String("dataset", "x")))
			},
			action:      "sign_in",
			wantEvents:  1,
			wantDataset: "x",
		},
		{
			name:       "a line with another action is left out",
			run:        func() { slog.Info("line", slog.Group("event", slog.String("action", "other"))) },
			action:     "sign_in",
			wantEvents: 0,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			beforeLogger := slog.Default()
			beforeWriter := log.Writer()

			lines, err := Capture(testCase.run)
			if err != nil {
				t.Fatalf("capture: %v", err)
			}
			if slog.Default() != beforeLogger || log.Writer() != beforeWriter {
				t.Error("the default logger or the log package's output was not restored")
			}

			events := Events(lines, testCase.action)
			if len(events) != testCase.wantEvents {
				t.Fatalf("got %d events, want %d", len(events), testCase.wantEvents)
			}
			if testCase.wantEvents > 0 && len(lines) != 1 {
				t.Errorf("got %d lines, want the one", len(lines))
			}
			if testCase.wantDataset != "" && events[0]["dataset"] != testCase.wantDataset {
				t.Errorf("the groups were not merged: %v", events[0])
			}
		})
	}
}
