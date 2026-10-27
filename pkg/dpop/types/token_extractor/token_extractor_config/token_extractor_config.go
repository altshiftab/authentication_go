package token_extractor_config

type Config struct {
	// AcceptBearer is whether a token presented as "Authorization: Bearer" is read as well as one
	// presented as "Authorization: DPoP". On by default, so that an endpoint can take the extractor
	// without turning away the clients that do not bind their tokens yet; off for an endpoint that
	// takes bound tokens and nothing else, whose refusals then name only the DPoP scheme.
	AcceptBearer bool
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{AcceptBearer: true}
	for _, option := range options {
		option(config)
	}

	return config
}

func WithAcceptBearer(acceptBearer bool) Option {
	return func(config *Config) {
		config.AcceptBearer = acceptBearer
	}
}
