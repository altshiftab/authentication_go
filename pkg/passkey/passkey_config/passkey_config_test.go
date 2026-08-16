package passkey_config

import (
	"errors"
	"testing"

	"github.com/Motmedel/utils_go/pkg/webauthn"
)

func TestNew(t *testing.T) {
	t.Parallel()

	config := New(nil)
	if config == nil {
		t.Fatalf("nil config")
	}

	if config.AttestationConveyancePreference != DefaultAttestationConveyancePreference {
		t.Errorf("attestation conveyance preference: got %q", config.AttestationConveyancePreference)
	}
	if config.AttestationConveyancePreference != AttestationConveyancePreferenceNone {
		t.Errorf("default preference should be none, got %q", config.AttestationConveyancePreference)
	}
	if config.AttestationVerifier != nil {
		t.Errorf("expected nil attestation verifier")
	}
}

func TestOptions(t *testing.T) {
	t.Parallel()

	t.Run("with attestation conveyance preference", func(t *testing.T) {
		t.Parallel()

		config := New(WithAttestationConveyancePreference(AttestationConveyancePreferenceDirect))
		if config.AttestationConveyancePreference != AttestationConveyancePreferenceDirect {
			t.Errorf("attestation conveyance preference: got %q", config.AttestationConveyancePreference)
		}
	})

	t.Run("with attestation verifier", func(t *testing.T) {
		t.Parallel()

		invoked := false
		config := New(WithAttestationVerifier(func(_ *webauthn.AttestationVerificationResult) error {
			invoked = true
			return errors.ErrUnsupported
		}))

		if config.AttestationVerifier == nil {
			t.Fatalf("nil attestation verifier")
		}
		if err := config.AttestationVerifier(nil); !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("expected the configured verifier's error, got %v", err)
		}
		if !invoked {
			t.Errorf("expected the configured verifier to be invoked")
		}
	})
}
