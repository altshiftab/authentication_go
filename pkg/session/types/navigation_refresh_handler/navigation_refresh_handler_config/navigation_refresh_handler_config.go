package navigation_refresh_handler_config

import (
	"context"
	"database/sql"
	"time"

	"github.com/altshiftab/authentication_go/pkg/database"
	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/redirector/redirector_config"
)

var (
	DefaultSessionDuration = 15 * time.Minute
	// DefaultRedirectParameterName is taken from the redirector rather than written out again: it
	// is the redirector on the other service that puts the parameter there, so the two names have
	// to agree or nothing is ever sent back.
	DefaultRedirectParameterName       = redirector_config.DefaultParameterName
	DefaultSelectRefreshAuthentication = database.SelectRefreshAuthentication
)

type Config struct {
	SessionDuration             time.Duration
	RedirectParameterName       string
	SelectRefreshAuthentication func(ctx context.Context, id string, database *sql.DB) (*authenticationPkg.Authentication, error)
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		SessionDuration:             DefaultSessionDuration,
		RedirectParameterName:       DefaultRedirectParameterName,
		SelectRefreshAuthentication: DefaultSelectRefreshAuthentication,
	}
	for _, option := range options {
		option(config)
	}

	return config
}

func WithSessionDuration(sessionDuration time.Duration) Option {
	return func(config *Config) {
		config.SessionDuration = sessionDuration
	}
}

func WithRedirectParameterName(redirectParameterName string) Option {
	return func(config *Config) {
		config.RedirectParameterName = redirectParameterName
	}
}

func WithSelectRefreshAuthentication(selectRefreshAuthentication func(ctx context.Context, id string, database *sql.DB) (*authenticationPkg.Authentication, error)) Option {
	return func(config *Config) {
		config.SelectRefreshAuthentication = selectRefreshAuthentication
	}
}
