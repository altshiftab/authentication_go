package access_token_parser_config

type Config struct {
	// AllowedSubjects are the accounts whose tokens are taken. Nil takes any account the issuer
	// signs for; a resource that reaches one person's data names that person, since an access
	// token carries no role, only the account it acts for, and any account the issuer knows could
	// otherwise consent to a client and use the resource. Set but empty is a fault the parser
	// refuses, so that a configuration that lost its value does not admit everyone.
	AllowedSubjects []string
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{}
	for _, option := range options {
		option(config)
	}

	return config
}

func WithAllowedSubjects(subjects ...string) Option {
	return func(config *Config) {
		config.AllowedSubjects = append([]string{}, subjects...)
	}
}
