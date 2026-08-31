package login_endpoint_config

import (
	"time"

	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/callback_endpoint/callback_endpoint_config"
)

var (
	DefaultCallbackCookieName = callback_endpoint_config.DefaultCallbackCookieName
	DefaultOauthFlowDuration  = 8 * time.Minute
)

type Config struct {
	CallbackCookieName string
	OauthFlowDuration  time.Duration
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		CallbackCookieName: DefaultCallbackCookieName,
		OauthFlowDuration:  DefaultOauthFlowDuration,
	}
	for _, option := range options {
		option(config)
	}

	return config
}

func WithCallbackCookieName(callbackCookieName string) Option {
	return func(config *Config) {
		config.CallbackCookieName = callbackCookieName
	}
}

func WithOauthFlowDuration(oauthFlowDuration time.Duration) Option {
	return func(config *Config) {
		config.OauthFlowDuration = oauthFlowDuration
	}
}
