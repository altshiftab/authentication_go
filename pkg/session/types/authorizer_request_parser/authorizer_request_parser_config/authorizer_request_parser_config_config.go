package authorizer_request_parser_config

import (
	"github.com/altshiftab/authentication_go/pkg/dpop/types/proof_verifier"
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

	// ProofVerifier checks the DPoP proof a bound token is presented with. Without one the
	// authorizer refuses every bound token, which is right for one that was never meant to see one.
	ProofVerifier *proof_verifier.Verifier

	// RequireBoundToken refuses tokens bound to no key.
	RequireBoundToken bool
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

// WithProofVerifier is what checks the DPoP proof a bound token comes with. It is needed by an
// authorizer whose token extractor reads the DPoP scheme, and by one that requires bound tokens.
func WithProofVerifier(proofVerifier *proof_verifier.Verifier) Option {
	return func(config *Config) {
		config.ProofVerifier = proofVerifier
	}
}

// WithRequireBoundToken refuses a token bound to no key. A copy of such a token, taken in transit,
// from a log or by a service it was sent to, is as good as the original; an endpoint that wants that
// ruled out asks for it here.
//
// Off by default, for the reason the authentication methods are an allow-list: nothing an
// authorizer accepted before the library knew DPoP is refused by it now without having been asked.
// A bound token, though, is held to its binding by every authorizer whatever this says -- presented
// without its proof it is refused (RFC 9449 §7.2) -- so the choice here is only about the tokens
// that are bound to nothing.
func WithRequireBoundToken(requireBoundToken bool) Option {
	return func(config *Config) {
		config.RequireBoundToken = requireBoundToken
	}
}

func WithSuperAdminRoles(superAdminRoles ...string) Option {
	return func(config *Config) {
		config.SuperAdminRoles = superAdminRoles
	}
}
