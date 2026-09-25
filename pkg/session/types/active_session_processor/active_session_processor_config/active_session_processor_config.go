package active_session_processor_config

import (
	"context"
	"database/sql"

	"github.com/altshiftab/authentication_go/pkg/database"
	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
)

// DefaultSelectAuthentication is the refresh's own read: the authentication joined to its account
// and customer, which is everything the check needs in one round trip.
var DefaultSelectAuthentication = database.SelectRefreshAuthentication

type Config struct {
	SelectAuthentication func(ctx context.Context, id string, database *sql.DB) (*authenticationPkg.Authentication, error)
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		SelectAuthentication: DefaultSelectAuthentication,
	}
	for _, option := range options {
		option(config)
	}

	return config
}

func WithSelectAuthentication(selectAuthentication func(ctx context.Context, id string, database *sql.DB) (*authenticationPkg.Authentication, error)) Option {
	return func(config *Config) {
		config.SelectAuthentication = selectAuthentication
	}
}
