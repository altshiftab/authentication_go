package mint_token_config

type Config struct {
	// KeyThumbprint binds the token to a key: the RFC 7638 thumbprint of the key that signed the
	// DPoP proof the token was asked for with, written into the token as "cnf.jkt". Empty mints a
	// bearer token, as before.
	KeyThumbprint string

	// Audience is who the token is for. Empty is the manager's cookie domain, which every service
	// sharing the session accepts; a token meant for one service names that service instead, so
	// that no other one takes it -- including one on an older library, which would not hold a bound
	// token to its proof.
	Audience string
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{}
	for _, option := range options {
		option(config)
	}

	return config
}

func WithKeyThumbprint(keyThumbprint string) Option {
	return func(config *Config) {
		config.KeyThumbprint = keyThumbprint
	}
}

func WithAudience(audience string) Option {
	return func(config *Config) {
		config.Audience = audience
	}
}
