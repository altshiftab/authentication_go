package dbsc_session_response_processor_config

import (
	"context"
	"database/sql"
	"slices"
	"testing"

	"github.com/altshiftab/authentication_go/pkg/database/types/dbsc_challenge"
)

func TestNew(t *testing.T) {
	t.Parallel()

	config := New()
	if config == nil {
		t.Fatalf("nil config")
	}

	if !slices.Equal(config.Algs, DefaultAlgs) {
		t.Errorf("algs: got %v", config.Algs)
	}
	if config.PopDbscChallenge == nil {
		t.Errorf("nil pop dbsc challenge")
	}
}

func TestOptions(t *testing.T) {
	t.Parallel()

	t.Run("with algs", func(t *testing.T) {
		t.Parallel()

		config := New(WithAlgs([]string{"ES384"}))
		if !slices.Equal(config.Algs, []string{"ES384"}) {
			t.Errorf("algs: got %v", config.Algs)
		}
	})

	t.Run("with pop dbsc challenge", func(t *testing.T) {
		t.Parallel()

		invoked := false
		config := New(WithPopDbscChallenge(
			func(_ context.Context, _ string, _ string, _ *sql.DB) (*dbsc_challenge.Challenge, error) {
				invoked = true
				return nil, nil
			},
		))

		if _, err := config.PopDbscChallenge(t.Context(), "", "", nil); err != nil {
			t.Fatalf("pop dbsc challenge: %v", err)
		}
		if !invoked {
			t.Errorf("expected the configured function to be invoked")
		}
	})
}
