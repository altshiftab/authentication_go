package dbsc_register_endpoint_config

import (
	"context"
	"database/sql"

	"github.com/altshiftab/authentication_go/pkg/database"
	"github.com/altshiftab/authentication_go/pkg/session/types/endpoint/dbsc_refresh_endpoint/dbsc_refresh_endpoint_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_instructions"
)

var (
	DefaultPath                                  = "/api/session/dbsc/register"
	DefaultRefreshPath                           = dbsc_refresh_endpoint_config.DefaultPath
	DefaultUpdateAuthenticationWithDbscPublicKey = database.UpdateAuthenticationWithDbscPublicKey
	// A session covers the whole site by default, so that it applies across subdomains.
	DefaultIncludeSite = true
)

type Config struct {
	Path                                  string
	RefreshPath                           string
	UpdateAuthenticationWithDbscPublicKey func(ctx context.Context, id string, key []byte, database *sql.DB) error
	IncludeSite                           bool
	// ScopeSpecification narrows or widens the session's scope with include and exclude rules.
	ScopeSpecification []*session_instructions.ScopeSpecification
	// AllowedRefreshInitiators names hosts outside the scope that may still trigger a refresh.
	AllowedRefreshInitiators []string
	// Origin overrides the session's scope origin. Empty derives it from the request, which is
	// what the browser compares its requests against.
	Origin string
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		Path:                                  DefaultPath,
		RefreshPath:                           DefaultRefreshPath,
		UpdateAuthenticationWithDbscPublicKey: DefaultUpdateAuthenticationWithDbscPublicKey,
		IncludeSite:                           DefaultIncludeSite,
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

func WithRefreshPath(refreshPath string) Option {
	return func(config *Config) {
		config.RefreshPath = refreshPath
	}
}

func WithUpdateAuthenticationWithDbscPublicKey(updateAuthenticationWithDbscPublicKey func(ctx context.Context, id string, key []byte, database *sql.DB) error) Option {
	return func(config *Config) {
		config.UpdateAuthenticationWithDbscPublicKey = updateAuthenticationWithDbscPublicKey
	}
}

func WithIncludeSite(includeSite bool) Option {
	return func(config *Config) {
		config.IncludeSite = includeSite
	}
}

func WithOrigin(origin string) Option {
	return func(config *Config) {
		config.Origin = origin
	}
}

func WithScopeSpecification(scopeSpecification []*session_instructions.ScopeSpecification) Option {
	return func(config *Config) {
		config.ScopeSpecification = scopeSpecification
	}
}

func WithAllowedRefreshInitiators(allowedRefreshInitiators []string) Option {
	return func(config *Config) {
		config.AllowedRefreshInitiators = allowedRefreshInitiators
	}
}
