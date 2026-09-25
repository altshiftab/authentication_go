package active_session_processor_config

import (
	"context"
	"database/sql"
	"testing"

	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
)

func TestNew(t *testing.T) {
	t.Parallel()

	config := New()
	if config == nil {
		t.Fatalf("nil config")
	}
	if config.SelectAuthentication == nil {
		t.Errorf("nil select authentication")
	}
}

func TestOptions(t *testing.T) {
	t.Parallel()

	t.Run("with select authentication", func(t *testing.T) {
		t.Parallel()

		invoked := false
		config := New(WithSelectAuthentication(
			func(_ context.Context, _ string, _ *sql.DB) (*authenticationPkg.Authentication, error) {
				invoked = true
				return nil, nil
			},
		))

		if _, err := config.SelectAuthentication(t.Context(), "", nil); err != nil {
			t.Fatalf("select authentication: %v", err)
		}
		if !invoked {
			t.Errorf("expected the configured function to be invoked")
		}
	})
}
