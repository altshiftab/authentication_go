package authorizer_request_parser_config

import (
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/token_cookie_extractor"
)

var DefaultTokenExtractor = token_cookie_extractor.New()

type Config struct {
	SkipExp         bool
	TokenExtractor  request_parser.RequestParser[string]
	AllowedRoles    []string
	AllowedTenantId string
	SuperAdminRoles []string
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		TokenExtractor: DefaultTokenExtractor,
	}
	for _, option := range options {
		option(config)
	}

	return config
}

func WithSkipExp(skipExp bool) Option {
	return func(config *Config) {
		config.SkipExp = skipExp
	}
}

func WithTokenExtractor(tokenExtractor request_parser.RequestParser[string]) Option {
	return func(config *Config) {
		config.TokenExtractor = tokenExtractor
	}
}

func WithAllowedRoles(allowedRoles ...string) Option {
	return func(config *Config) {
		config.AllowedRoles = allowedRoles
	}
}

func WithAllowedTenantId(allowedTenantId string) Option {
	return func(config *Config) {
		config.AllowedTenantId = allowedTenantId
	}
}

func WithSuperAdminRoles(superAdminRoles ...string) Option {
	return func(config *Config) {
		config.SuperAdminRoles = superAdminRoles
	}
}
