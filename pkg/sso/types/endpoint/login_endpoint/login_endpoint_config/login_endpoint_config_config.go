package login_endpoint_config

import (
	"time"

	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/callback_endpoint/callback_endpoint_config"
)

var (
	DefaultCallbackCookieName = callback_endpoint_config.DefaultCallbackCookieName
	DefaultOauthFlowDuration  = 8 * time.Minute
	// Providers only state how they authenticated a user when asked. Requesting it by default means
	// the authentication method references are available for logging, and for a multi-factor
	// requirement, without further configuration.
	DefaultRequestAuthenticationMethodReferences = true
)

type Config struct {
	CallbackCookieName string
	OauthFlowDuration  time.Duration
	// RequestAuthenticationMethodReferences asks the provider for the "amr" claim in the id token.
	RequestAuthenticationMethodReferences bool
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		CallbackCookieName:                    DefaultCallbackCookieName,
		OauthFlowDuration:                     DefaultOauthFlowDuration,
		RequestAuthenticationMethodReferences: DefaultRequestAuthenticationMethodReferences,
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

func WithRequestAuthenticationMethodReferences(requestAuthenticationMethodReferences bool) Option {
	return func(config *Config) {
		config.RequestAuthenticationMethodReferences = requestAuthenticationMethodReferences
	}
}
