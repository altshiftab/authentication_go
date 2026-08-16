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
