package login_endpoint_config

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

	if config.CallbackCookieName != DefaultCallbackCookieName {
		t.Errorf("callback cookie name: got %q", config.CallbackCookieName)
	}
	if config.OauthFlowDuration != DefaultOauthFlowDuration {
		t.Errorf("oauth flow duration: got %v", config.OauthFlowDuration)
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
			name:   "with callback cookie name",
			option: WithCallbackCookieName("custom"),
			check: func(t *testing.T, config *Config) {
				if config.CallbackCookieName != "custom" {
					t.Errorf("callback cookie name: got %q", config.CallbackCookieName)
				}
			},
		},
		{
			name:   "with oauth flow duration",
			option: WithOauthFlowDuration(time.Minute),
			check: func(t *testing.T, config *Config) {
				if config.OauthFlowDuration != time.Minute {
					t.Errorf("oauth flow duration: got %v", config.OauthFlowDuration)
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
