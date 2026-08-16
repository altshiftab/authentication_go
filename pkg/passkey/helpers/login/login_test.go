package login

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"testing"
)

func TestMakeEcdsaPublicKey(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa generate key: %v", err)
	}

	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix public key: %v", err)
	}

	ed25519PublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}
	ed25519Der, err := x509.MarshalPKIXPublicKey(ed25519PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix public key (ed25519): %v", err)
	}

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		publicKey, err := MakeEcdsaPublicKey(der)
		if err != nil {
			t.Fatalf("make ecdsa public key: %v", err)
		}
		if !privateKey.PublicKey.Equal(publicKey) {
			t.Errorf("key mismatch")
		}
	})

	t.Run("malformed der", func(t *testing.T) {
		t.Parallel()

		if _, err := MakeEcdsaPublicKey([]byte("garbage")); err == nil {
			t.Errorf("expected error")
		}
	})

	t.Run("non-ecdsa key", func(t *testing.T) {
		t.Parallel()

		if _, err := MakeEcdsaPublicKey(ed25519Der); err == nil {
			t.Errorf("expected error")
		}
	})
}

func TestMakeOptionsBytes(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		challenge := []byte("test-challenge")
		optionsBytes, err := MakeOptionsBytes(challenge, "example.com")
		if err != nil {
			t.Fatalf("make options bytes: %v", err)
		}

		var options struct {
			Challenge string `json:"challenge"`
			RpId      string `json:"rpId"`
		}
		if err := json.Unmarshal(optionsBytes, &options); err != nil {
			t.Fatalf("json unmarshal: %v", err)
		}

		if options.Challenge != base64.RawURLEncoding.EncodeToString(challenge) {
			t.Errorf("challenge: got %q", options.Challenge)
		}
		if options.RpId != "example.com" {
			t.Errorf("rp id: got %q", options.RpId)
		}
	})

	t.Run("empty challenge", func(t *testing.T) {
		t.Parallel()

		if _, err := MakeOptionsBytes(nil, "example.com"); err == nil {
			t.Errorf("expected error")
		}
	})
}
