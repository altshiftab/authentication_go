package end_endpoint_config

import (
	"context"
	"database/sql"

	"github.com/altshiftab/authentication_go/pkg/database"
)

var (
	DefaultPath                          = "/api/session/end"
	DefaultUpdateAuthenticationWithEnded = database.UpdateAuthenticationWithEnded
)

type Config struct {
	Path                          string
	UpdateAuthenticationWithEnded func(ctx context.Context, id string, database *sql.DB) error
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		Path:                          DefaultPath,
		UpdateAuthenticationWithEnded: DefaultUpdateAuthenticationWithEnded,
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

func WithUpdateAuthenticationWithEnded(updateAuthenticationWithEnded func(ctx context.Context, id string, database *sql.DB) error) Option {
	return func(config *Config) {
		config.UpdateAuthenticationWithEnded = updateAuthenticationWithEnded
	}
}
