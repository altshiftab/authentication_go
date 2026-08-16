package callback_endpoint_config

import (
	"context"
	"database/sql"
	"github.com/altshiftab/authentication_go/pkg/sso/types/provider_claims"

	"github.com/altshiftab/authentication_go/pkg/database"
	"github.com/altshiftab/authentication_go/pkg/database/types/oauth_flow"
	"github.com/altshiftab/authentication_go/pkg/sso/errors/oauth_error"
)

var (
	DefaultCallbackCookieName          = "callback_id"
	DefaultPopOauthFlow                = database.PopOauthFlow
	DefaultRequireStrongAuthentication = false
	DefaultRequireOrganization         = false
	// The methods accepted as satisfying a multi-factor requirement; see the provider claims.
	DefaultStrongAuthenticationMethodReferences = provider_claims.StrongAuthenticationMethodReferences
)

// DefaultClassifyOauthError is the default classifier; it defers to the error's
// own Category method.
func DefaultClassifyOauthError(err *oauth_error.Error) oauth_error.Category {
	return err.Category()
}

type Config struct {
	CallbackCookieName string
	PopOauthFlow       func(ctx context.Context, id string, database *sql.DB) (*oauth_flow.Flow, error)

	// ClassifyOauthError maps an OAuth error to a category. Override it for
	// provider-specific precision (e.g. a Google-only deployment). The problem
	// page each category redirects to is derived from the origin passed to the
	// endpoint's Initialize method.
	ClassifyOauthError func(*oauth_error.Error) oauth_error.Category
	// RequireStrongAuthentication rejects a sign-in unless the identity provider states it used one
	// of StrongAuthenticationMethodReferences. It is not a count of factors: a passkey is a single
	// step but two factors, possession of the device and the biometric or PIN unlocking it, and the
	// providers report it without saying "mfa".
	//
	// Providers state their methods only when asked, and may stay silent even then, so enabling
	// this turns an unproven method into a refusal.
	RequireStrongAuthentication bool
	// StrongAuthenticationMethodReferences are the "amr" values accepted as satisfying
	// RequireStrongAuthentication.
	StrongAuthenticationMethodReferences []string
	// RequireOrganization refuses accounts that belong to no organization: personal accounts, which
	// no organization administers and on which therefore no authentication policy can be required.
	// Google omits the hosted domain for them; Microsoft places them in a fixed consumer tenant,
	// which the claims report as no organization.
	RequireOrganization bool
	// AllowedOrganizations restricts sign-in to accounts belonging to one of these organizations:
	// hosted domains for Google, tenants for Microsoft. Empty places no restriction. A non-empty
	// list implies an organization is required, since an account without one cannot be on it.
	AllowedOrganizations []string
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		CallbackCookieName:                   DefaultCallbackCookieName,
		RequireStrongAuthentication:          DefaultRequireStrongAuthentication,
		StrongAuthenticationMethodReferences: DefaultStrongAuthenticationMethodReferences,
		RequireOrganization:                  DefaultRequireOrganization,
		PopOauthFlow:                         DefaultPopOauthFlow,
		ClassifyOauthError:                   DefaultClassifyOauthError,
	}
	for _, option := range options {
		option(config)
	}

	return config
}

func WithCallbackCookieName(callbackCookieName string) Option {
	return func(config *Config) {
		config.CallbackCookieName = callbackCookieName
	}
}

func WithPopOauthFlow(popOauthFlow func(ctx context.Context, id string, database *sql.DB) (*oauth_flow.Flow, error)) Option {
	return func(config *Config) {
		config.PopOauthFlow = popOauthFlow
	}
}

func WithOauthErrorClassifier(classify func(*oauth_error.Error) oauth_error.Category) Option {
	return func(config *Config) {
		config.ClassifyOauthError = classify
	}
}

func WithRequireStrongAuthentication(requireStrongAuthentication bool) Option {
	return func(config *Config) {
		config.RequireStrongAuthentication = requireStrongAuthentication
	}
}

func WithRequireOrganization(requireOrganization bool) Option {
	return func(config *Config) {
		config.RequireOrganization = requireOrganization
	}
}

func WithAllowedOrganizations(allowedOrganizations []string) Option {
	return func(config *Config) {
		config.AllowedOrganizations = allowedOrganizations
	}
}

func WithStrongAuthenticationMethodReferences(strongAuthenticationMethodReferences []string) Option {
	return func(config *Config) {
		config.StrongAuthenticationMethodReferences = strongAuthenticationMethodReferences
	}
}
