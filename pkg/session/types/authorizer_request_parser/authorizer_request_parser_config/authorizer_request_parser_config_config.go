package authorizer_request_parser_config

import (
	"github.com/altshiftab/authentication_go/pkg/session/types/authentication_method"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/token_cookie_extractor"
)

var DefaultTokenExtractor = token_cookie_extractor.New()

// DefaultAuthenticationMethods are the ways a browser session is come by, which is what an
// authorizer is for unless it says otherwise.
//
// It is an allow-list with a default rather than a deny-list for one reason: a method added to the
// library later -- a key the account registered, and whatever follows it -- is refused by every
// authorizer that was written before it existed. Widening is then something a service asks for at
// the endpoint it means, and forgetting to ask cannot admit a credential of a kind nobody had in
// mind when the endpoint was written.
var DefaultAuthenticationMethods = []string{
	authentication_method.Refresh,
	authentication_method.Dbsc,
	authentication_method.Sso,
	authentication_method.MagicLink,
}

type Config struct {
	SkipExp               bool
	TokenExtractor        request_parser.RequestParser[string]
	AuthenticationMethods []string
	AllowedRoles          []string
	AllowedTenantId       string
	SuperAdminRoles       []string
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		TokenExtractor:        DefaultTokenExtractor,
		AuthenticationMethods: DefaultAuthenticationMethods,
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

// WithAuthenticationMethods names the "amr" values the authorizer accepts, replacing the default
// set rather than adding to it: an authorizer that takes an API key's token and nothing else is as
// much a thing to want as one that takes both.
func WithAuthenticationMethods(authenticationMethods ...string) Option {
	return func(config *Config) {
		config.AuthenticationMethods = authenticationMethods
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
