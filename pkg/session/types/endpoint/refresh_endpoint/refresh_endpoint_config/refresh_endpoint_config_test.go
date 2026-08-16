package refresh_endpoint_config

import (
	"context"
	"database/sql"
	"testing"
	"time"

	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
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
	if config.SessionDuration != DefaultSessionDuration {
		t.Errorf("session duration: got %v", config.SessionDuration)
	}
	if config.SelectRefreshAuthentication == nil {
		t.Errorf("nil select refresh authentication")
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

	t.Run("with session duration", func(t *testing.T) {
		t.Parallel()

		if config := New(WithSessionDuration(time.Hour)); config.SessionDuration != time.Hour {
			t.Errorf("session duration: got %v", config.SessionDuration)
		}
	})

	t.Run("with select refresh authentication", func(t *testing.T) {
		t.Parallel()

		invoked := false
		config := New(WithSelectRefreshAuthentication(
			func(_ context.Context, _ string, _ *sql.DB) (*authenticationPkg.Authentication, error) {
				invoked = true
				return nil, nil
			},
		))

		if _, err := config.SelectRefreshAuthentication(t.Context(), "", nil); err != nil {
			t.Fatalf("select refresh authentication: %v", err)
		}
		if !invoked {
			t.Errorf("expected the configured function to be invoked")
		}
	})
}
