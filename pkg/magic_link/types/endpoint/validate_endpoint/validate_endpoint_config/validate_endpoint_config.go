package validate_endpoint_config

var (
	DefaultPath = "/api/login/magic/validate"
)

type Config struct {
	Path string
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		Path: DefaultPath,
	}
	for _, option := range options {
		option(config)
	}

	return config
}

func WithPath(path string) Option {
	return func(config *Config) {
		config.Path = path
	}
}
