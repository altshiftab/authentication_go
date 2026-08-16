package session_manager_config

import (
	"context"
	"database/sql"
	"slices"
	"testing"
	"time"

	accountPkg "github.com/altshiftab/authentication_go/pkg/database/types/account"
	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_cookie/session_cookie_config"
)

func TestNew(t *testing.T) {
	t.Parallel()

	config := New()
	if config == nil {
		t.Fatalf("nil config")
	}

	if config.CookieName != DefaultCookieName {
		t.Errorf("cookie name: got %q", config.CookieName)
	}
	if config.InitialSessionDuration != DefaultInitialSessionDuration {
		t.Errorf("initial session duration: got %v", config.InitialSessionDuration)
	}
	if config.AuthenticationDuration != DefaultAuthenticationDuration {
		t.Errorf("authentication duration: got %v", config.AuthenticationDuration)
	}
	if config.DbscChallengeDuration != DefaultDbscChallengeDuration {
		t.Errorf("dbsc challenge duration: got %v", config.DbscChallengeDuration)
	}
	if config.DbscRegisterPath != DefaultDbscRegisterPath {
		t.Errorf("dbsc register path: got %q", config.DbscRegisterPath)
	}
	if !slices.Equal(config.DbscAlgs, DefaultDbscAlgs) {
		t.Errorf("dbsc algs: got %v", config.DbscAlgs)
	}
	if config.SelectEmailAddressAccount == nil || config.InsertAuthentication == nil || config.InsertDbscChallenge == nil {
		t.Errorf("expected non-nil database functions")
	}
	if config.SessionCookieOptions != nil {
		t.Errorf("session cookie options: got %v", config.SessionCookieOptions)
	}
}

func TestOptions(t *testing.T) {
	t.Parallel()

	t.Run("with cookie name", func(t *testing.T) {
		t.Parallel()

		if config := New(WithCookieName("custom")); config.CookieName != "custom" {
			t.Errorf("cookie name: got %q", config.CookieName)
		}
	})

	t.Run("with initial session duration", func(t *testing.T) {
		t.Parallel()

		if config := New(WithInitialSessionDuration(time.Hour)); config.InitialSessionDuration != time.Hour {
			t.Errorf("initial session duration: got %v", config.InitialSessionDuration)
		}
	})

	t.Run("with authentication duration", func(t *testing.T) {
		t.Parallel()

		if config := New(WithAuthenticationDuration(time.Hour)); config.AuthenticationDuration != time.Hour {
			t.Errorf("authentication duration: got %v", config.AuthenticationDuration)
		}
	})

	t.Run("with dbsc challenge duration", func(t *testing.T) {
		t.Parallel()

		if config := New(WithDbscChallengeDuration(time.Minute)); config.DbscChallengeDuration != time.Minute {
			t.Errorf("dbsc challenge duration: got %v", config.DbscChallengeDuration)
		}
	})

	t.Run("with dbsc register path", func(t *testing.T) {
		t.Parallel()

		if config := New(WithDbscRegisterPath("/custom")); config.DbscRegisterPath != "/custom" {
			t.Errorf("dbsc register path: got %q", config.DbscRegisterPath)
		}
	})

	t.Run("with dbsc algs", func(t *testing.T) {
		t.Parallel()

		if config := New(WithDbscAlgs([]string{"ES384"})); !slices.Equal(config.DbscAlgs, []string{"ES384"}) {
			t.Errorf("dbsc algs: got %v", config.DbscAlgs)
		}
	})

	t.Run("with select email address account", func(t *testing.T) {
		t.Parallel()

		invoked := false
		config := New(WithSelectEmailAddressAccount(
			func(_ context.Context, _ string, _ *sql.DB) (*accountPkg.Account, error) {
				invoked = true
				return nil, nil
			},
		))

		if _, err := config.SelectEmailAddressAccount(t.Context(), "", nil); err != nil {
			t.Fatalf("select email address account: %v", err)
		}
		if !invoked {
			t.Errorf("expected the configured function to be invoked")
		}
	})

	t.Run("with insert authentication", func(t *testing.T) {
		t.Parallel()

		invoked := false
		config := New(WithInsertAuthentication(
			func(_ context.Context, _ string, _ []byte, _ time.Duration, _ *authenticationPkg.ClientMetadata, _ *sql.DB) (*authenticationPkg.Authentication, error) {
				invoked = true
				return nil, nil
			},
		))

		if _, err := config.InsertAuthentication(t.Context(), "", nil, 0, nil, nil); err != nil {
			t.Fatalf("insert authentication: %v", err)
		}
		if !invoked {
			t.Errorf("expected the configured function to be invoked")
		}
	})

	t.Run("with insert dbsc challenge", func(t *testing.T) {
		t.Parallel()

		invoked := false
		config := New(WithInsertDbscChallenge(
			func(_ context.Context, _ string, _ string, _ time.Duration, _ *sql.DB) error {
				invoked = true
				return nil
			},
		))

		if err := config.InsertDbscChallenge(t.Context(), "", "", 0, nil); err != nil {
			t.Fatalf("insert dbsc challenge: %v", err)
		}
		if !invoked {
			t.Errorf("expected the configured function to be invoked")
		}
	})

	t.Run("with session cookie options", func(t *testing.T) {
		t.Parallel()

		config := New(WithSessionCookieOptions(session_cookie_config.WithSameSite(0)))
		if len(config.SessionCookieOptions) != 1 {
			t.Errorf("session cookie options: got %d", len(config.SessionCookieOptions))
		}
	})
}
