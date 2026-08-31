package dbsc_refresh_endpoint_config

import (
	"testing"
	"time"
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
	if config.ChallengeDuration != DefaultChallengeDuration {
		t.Errorf("challenge duration: got %v", config.ChallengeDuration)
	}
}

func TestOptions(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		option Option
		check  func(t *testing.T, config *Config)
	}{
		{
			name:   "with path",
			option: WithPath("/custom"),
			check: func(t *testing.T, config *Config) {
				if config.Path != "/custom" {
					t.Errorf("path: got %q", config.Path)
				}
			},
		},
		{
			name:   "with session duration",
			option: WithSessionDuration(time.Hour),
			check: func(t *testing.T, config *Config) {
				if config.SessionDuration != time.Hour {
					t.Errorf("session duration: got %v", config.SessionDuration)
				}
			},
		},
		{
			name:   "with challenge duration",
			option: WithChallengeDuration(time.Minute),
			check: func(t *testing.T, config *Config) {
				if config.ChallengeDuration != time.Minute {
					t.Errorf("challenge duration: got %v", config.ChallengeDuration)
				}
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testCase.check(t, New(testCase.option))
		})
	}
}

// TestDefaultChallengeOutlivesSession pins the ordering the two defaults have to keep. A challenge
// is handed out on one refresh and signed on the next, so one that expires within a session's
// lifetime is already dead when the browser comes to use it: every refresh then costs a rejection
// and a retry, and the challenge on the success buys nothing. Five minutes against a fifteen minute
// session did exactly that.
func TestDefaultChallengeOutlivesSession(t *testing.T) {
	t.Parallel()

	config := New()
	if config.ChallengeDuration <= config.SessionDuration {
		t.Errorf(
			"challenge duration %v must outlive the session duration %v, or a cached challenge expires before it is used",
			config.ChallengeDuration,
			config.SessionDuration,
		)
	}
}
