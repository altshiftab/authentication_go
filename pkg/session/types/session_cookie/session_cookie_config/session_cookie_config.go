package session_cookie_config

import "net/http"

var (
	DefaultSameSite = http.SameSiteLaxMode
)

type Config struct {
	SameSite http.SameSite
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		SameSite: DefaultSameSite,
	}
	for _, option := range options {
		if option != nil {
			option(config)
		}
	}

	return config
}

func WithSameSite(sameSite http.SameSite) Option {
	return func(config *Config) {
		config.SameSite = sameSite
	}
}
