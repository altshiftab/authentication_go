package end_endpoint_config

import (
	"context"
	"database/sql"
	"testing"
)

func TestNew(t *testing.T) {
	t.Parallel()

	config := New()
	if config == nil {
		t.Fatalf("nil config")
	}

	if config.Path != DefaultPath {
		t.Errorf("path: got %q", config.Path)
	}
	if config.UpdateAuthenticationWithEnded == nil {
		t.Errorf("nil update authentication with ended")
	}
}

func TestOptions(t *testing.T) {
	t.Parallel()

	t.Run("with path", func(t *testing.T) {
		t.Parallel()

		if config := New(WithPath("/custom")); config.Path != "/custom" {
			t.Errorf("path: got %q", config.Path)
		}
	})

	t.Run("with update authentication with ended", func(t *testing.T) {
		t.Parallel()

		invoked := false
		config := New(WithUpdateAuthenticationWithEnded(func(_ context.Context, _ string, _ *sql.DB) error {
			invoked = true
			return nil
		}))

		if err := config.UpdateAuthenticationWithEnded(t.Context(), "", nil); err != nil {
			t.Fatalf("update authentication with ended: %v", err)
		}
		if !invoked {
			t.Errorf("expected the configured function to be invoked")
		}
	})
}
