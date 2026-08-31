package id_token_endpoint_config

var (
	DefaultRequireOrganization = false
)

type Config struct {
	// RequireOrganization refuses accounts that belong to no organization: personal accounts, which
	// no organization administers and on which therefore no authentication policy can be required.
	// Google omits the hosted domain for them; Microsoft places them in a fixed consumer tenant,
	// which the claims report as no organization.
	//
	// It mirrors the option of the same name on the authorization code flow's callback. A
	// deployment that requires an organization there and not here would refuse a personal account
	// at one route and admit it at the other, which is the same sign-in either way.
	RequireOrganization bool
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		RequireOrganization: DefaultRequireOrganization,
	}
	for _, option := range options {
		option(config)
	}

	return config
}

func WithRequireOrganization(requireOrganization bool) Option {
	return func(config *Config) {
		config.RequireOrganization = requireOrganization
	}
}
