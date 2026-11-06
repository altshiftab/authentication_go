package validate_endpoint_config

import "github.com/altshiftab/authentication_go/pkg/log_options"

var (
	DefaultPath = "/api/login/magic/validate"
)

type Config struct {
	Path string

	// Log is what the endpoint's audit lines say about the person they concern, and what the
	// service adds to them; see log_options. Empty by default: an id, and no address at all.
	Log *log_options.Config
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		Log:  log_options.New(),
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

// WithLog sets what the endpoint's audit lines say about the person they concern, and what the
// service adds to them, from log_options' options.
func WithLog(options ...log_options.Option) Option {
	return func(config *Config) {
		config.Log = log_options.New(options...)
	}
}
