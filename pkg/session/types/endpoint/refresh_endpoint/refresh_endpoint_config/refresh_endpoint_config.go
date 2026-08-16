package refresh_endpoint_config

import (
	"context"
	"database/sql"
	"time"

	"github.com/altshiftab/authentication_go/pkg/database"
	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
)

var (
	DefaultPath                        = "/api/session/refresh"
	DefaultSessionDuration             = 15 * time.Minute
	DefaultSelectRefreshAuthentication = database.SelectRefreshAuthentication
)

type Config struct {
	Path                        string
	SessionDuration             time.Duration
	SelectRefreshAuthentication func(ctx context.Context, id string, database *sql.DB) (*authenticationPkg.Authentication, error)
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		Path:                        DefaultPath,
		SessionDuration:             DefaultSessionDuration,
		SelectRefreshAuthentication: DefaultSelectRefreshAuthentication,
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

func WithSessionDuration(sessionDuration time.Duration) Option {
	return func(config *Config) {
		config.SessionDuration = sessionDuration
	}
}

func WithSelectRefreshAuthentication(selectRefreshAuthentication func(ctx context.Context, id string, database *sql.DB) (*authenticationPkg.Authentication, error)) Option {
	return func(config *Config) {
		config.SelectRefreshAuthentication = selectRefreshAuthentication
	}
}
