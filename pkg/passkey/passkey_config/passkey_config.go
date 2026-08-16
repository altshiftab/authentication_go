package passkey_config

import "github.com/Motmedel/utils_go/pkg/webauthn"

// The WebAuthn attestation conveyance preferences (WebAuthn §5.4.7). "none" is the default and
// the privacy-preserving choice for passwordless passkey relying parties; the others request an
// attestation statement that AttestationVerifier can apply a trust policy to.
const (
	AttestationConveyancePreferenceNone       = "none"
	AttestationConveyancePreferenceIndirect   = "indirect"
	AttestationConveyancePreferenceDirect     = "direct"
	AttestationConveyancePreferenceEnterprise = "enterprise"
)

const DefaultAttestationConveyancePreference = AttestationConveyancePreferenceNone

type Config struct {
	// AttestationConveyancePreference is the attestation conveyance preference sent in
	// registration options.
	AttestationConveyancePreference string

	// AttestationVerifier, when set, is called with the verified attestation result of a
	// registration ceremony, after the statement itself has been verified. It applies the
	// relying party's trust policy — evaluating the trust path against acceptable roots,
	// checking the AAGUID against an allowlist, or requiring a particular attestation type.
	// Returning an error rejects the registration. It is not called for the "none" preference's
	// default use, but is invoked whenever set, so it may also reject a bare "none" result when
	// attestation is required.
	AttestationVerifier func(result *webauthn.AttestationVerificationResult) error
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		AttestationConveyancePreference: DefaultAttestationConveyancePreference,
	}

	for _, option := range options {
		if option != nil {
			option(config)
		}
	}

	return config
}

// WithAttestationConveyancePreference sets the attestation conveyance preference requested in
// registration options.
func WithAttestationConveyancePreference(preference string) Option {
	return func(config *Config) {
		config.AttestationConveyancePreference = preference
	}
}

// WithAttestationVerifier sets a trust policy applied to the verified attestation result of each
// registration.
func WithAttestationVerifier(verifier func(result *webauthn.AttestationVerificationResult) error) Option {
	return func(config *Config) {
		config.AttestationVerifier = verifier
	}
}
