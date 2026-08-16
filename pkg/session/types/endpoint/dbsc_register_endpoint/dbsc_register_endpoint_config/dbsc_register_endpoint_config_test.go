package dbsc_register_endpoint_config

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
	if config.RefreshPath != DefaultRefreshPath {
		t.Errorf("refresh path: got %q", config.RefreshPath)
	}
	if config.UpdateAuthenticationWithDbscPublicKey == nil {
		t.Errorf("nil update authentication with dbsc public key")
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

	t.Run("with refresh path", func(t *testing.T) {
		t.Parallel()

		if config := New(WithRefreshPath("/custom-refresh")); config.RefreshPath != "/custom-refresh" {
			t.Errorf("refresh path: got %q", config.RefreshPath)
		}
	})

	t.Run("with update authentication with dbsc public key", func(t *testing.T) {
		t.Parallel()

		invoked := false
		config := New(WithUpdateAuthenticationWithDbscPublicKey(
			func(_ context.Context, _ string, _ []byte, _ *sql.DB) error {
				invoked = true
				return nil
			},
		))

		if err := config.UpdateAuthenticationWithDbscPublicKey(t.Context(), "", nil, nil); err != nil {
			t.Fatalf("update authentication with dbsc public key: %v", err)
		}
		if !invoked {
			t.Errorf("expected the configured function to be invoked")
		}
	})
}
