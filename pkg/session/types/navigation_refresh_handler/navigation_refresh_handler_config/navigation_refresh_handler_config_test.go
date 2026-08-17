package navigation_refresh_handler_config

import (
	"context"
	"database/sql"
	"testing"
	"time"

	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/redirector/redirector_config"
)

func TestNew(t *testing.T) {
	t.Parallel()

	config := New()
	if config == nil {
		t.Fatalf("nil config")
	}

	if config.SessionDuration != DefaultSessionDuration {
		t.Errorf("session duration: got %v", config.SessionDuration)
	}
	if config.RedirectParameterName != DefaultRedirectParameterName {
		t.Errorf("redirect parameter name: got %q", config.RedirectParameterName)
	}
	if config.SelectRefreshAuthentication == nil {
		t.Errorf("nil select refresh authentication")
	}
}

// TestDefaultRedirectParameterNameMatchesRedirector guards the pairing: the redirector on the
// service that rejected the navigation writes the parameter this reads, so a change to either name
// alone would leave every redirected visitor at a sign-in page with nowhere to be sent back to.
func TestDefaultRedirectParameterNameMatchesRedirector(t *testing.T) {
	t.Parallel()

	if DefaultRedirectParameterName != redirector_config.DefaultParameterName {
		t.Errorf(
			"got %q, expected the redirector's %q",
			DefaultRedirectParameterName,
			redirector_config.DefaultParameterName,
		)
	}
}

func TestOptions(t *testing.T) {
	t.Parallel()

	t.Run("with session duration", func(t *testing.T) {
		t.Parallel()

		if config := New(WithSessionDuration(time.Hour)); config.SessionDuration != time.Hour {
			t.Errorf("session duration: got %v", config.SessionDuration)
		}
	})

	t.Run("with redirect parameter name", func(t *testing.T) {
		t.Parallel()

		if config := New(WithRedirectParameterName("return_to")); config.RedirectParameterName != "return_to" {
			t.Errorf("redirect parameter name: got %q", config.RedirectParameterName)
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
