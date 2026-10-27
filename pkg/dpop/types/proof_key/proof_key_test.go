package proof_key

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"maps"
	"strings"
	"testing"

	dpopTesting "github.com/altshiftab/authentication_go/pkg/dpop/testing"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
)

const urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// withUrlOnlyCharacter makes keys until one's "x" uses a character the standard base64 alphabet
// does not, so that rewriting it in that alphabet is a decoding fault rather than another key.
func withUrlOnlyCharacter(t *testing.T) map[string]any {
	t.Helper()

	for range 64 {
		jwk := dpopTesting.Jwk(&dpopTesting.NewKey().PublicKey)
		if x, _ := jwk["x"].(string); strings.ContainsAny(x, "-_") {
			return jwk
		}
	}

	t.Fatal("no key in 64 had a url-only character in x")
	return nil
}

func TestParse(t *testing.T) {
	t.Parallel()

	privateKey := dpopTesting.NewKey()
	valid := dpopTesting.Jwk(&privateKey.PublicKey)

	with := func(changes map[string]any) map[string]any {
		jwk := maps.Clone(valid)
		for name, value := range changes {
			if value == nil {
				delete(jwk, name)
				continue
			}
			jwk[name] = value
		}
		return jwk
	}

	x, _ := valid["x"].(string)
	urlOnly := withUrlOnlyCharacter(t)
	urlOnlyX, _ := urlOnly["x"].(string)

	// The last of 43 characters carries 4 bits of the coordinate and 2 that must be zero.
	lastIndex := strings.IndexByte(urlAlphabet, x[len(x)-1])
	nonZeroTrailingBits := x[:len(x)-1] + string(urlAlphabet[lastIndex|1])

	// Two random coordinates of the right width name a point on the curve with negligible chance.
	randomCoordinate := func() string {
		return base64.RawURLEncoding.EncodeToString(sha256Sum(rand.Text()))
	}

	testCases := []struct {
		name string
		jwk  map[string]any
		// What the refusal must say, so that a case cannot pass on a fault other than its own.
		wantErrContains string
	}{
		{name: "a P-256 public key", jwk: valid},
		{name: "no jwk", jwk: nil, wantErrContains: "jwk"},
		{name: "an RSA key", jwk: with(map[string]any{"kty": "RSA"}), wantErrContains: "not EC"},
		{name: "an OKP key", jwk: with(map[string]any{"kty": "OKP", "crv": "Ed25519"}), wantErrContains: "not EC"},
		{name: "no key type", jwk: with(map[string]any{"kty": nil}), wantErrContains: "kty"},
		{name: "a P-384 key", jwk: with(map[string]any{"crv": "P-384"}), wantErrContains: "not P-256"},
		{name: "a private key", jwk: with(map[string]any{"d": x}), wantErrContains: "private key"},
		{name: "no x", jwk: with(map[string]any{"x": nil}), wantErrContains: "(x)"},
		{name: "x as a number", jwk: with(map[string]any{"x": 1.0}), wantErrContains: "(x)"},
		{
			name:            "x a byte short",
			jwk:             with(map[string]any{"x": base64.RawURLEncoding.EncodeToString(make([]byte, 31))}),
			wantErrContains: "31 bytes",
		},
		{
			name:            "x a byte long",
			jwk:             with(map[string]any{"x": base64.RawURLEncoding.EncodeToString(make([]byte, 33))}),
			wantErrContains: "33 bytes",
		},
		{name: "x padded", jwk: with(map[string]any{"x": x + "="}), wantErrContains: "base64"},
		{
			name: "x in the standard alphabet",
			jwk: func() map[string]any {
				jwk := maps.Clone(urlOnly)
				jwk["x"] = strings.NewReplacer("-", "+", "_", "/").Replace(urlOnlyX)
				return jwk
			}(),
			wantErrContains: "base64",
		},
		{name: "x with non-zero trailing bits", jwk: with(map[string]any{"x": nonZeroTrailingBits}), wantErrContains: "base64"},
		{
			name:            "a point not on the curve",
			jwk:             with(map[string]any{"x": randomCoordinate(), "y": randomCoordinate()}),
			wantErrContains: "parse uncompressed public key",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			key, err := Parse(testCase.jwk)

			if testCase.wantErrContains == "" {
				if err != nil {
					t.Fatalf("%s: unexpected error: %v", testCase.name, err)
				}
				if key == nil || key.PublicKey == nil {
					t.Fatalf("%s: no key", testCase.name)
				}
				if !key.PublicKey.Equal(&privateKey.PublicKey) {
					t.Errorf("%s: parsed another key", testCase.name)
				}
				if want := dpopTesting.KeyThumbprint(&privateKey.PublicKey); key.Thumbprint != want {
					t.Errorf("%s: thumbprint %q, want %q", testCase.name, key.Thumbprint, want)
				}
				return
			}

			if err == nil {
				t.Fatalf("%s: accepted", testCase.name)
			}
			if key != nil {
				t.Errorf("%s: a key came back with the refusal", testCase.name)
			}
			// Every refusal is the client's, so an endpoint answers it 4xx.
			if !errors.Is(err, altshiftErrors.ErrValidationError) {
				t.Errorf("%s: not a validation error: %v", testCase.name, err)
			}
			if !strings.Contains(err.Error(), testCase.wantErrContains) {
				t.Errorf("%s: error %q does not mention %q", testCase.name, err, testCase.wantErrContains)
			}
		})
	}
}

func sha256Sum(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

func TestKey_NamedVerifier(t *testing.T) {
	t.Parallel()

	privateKey := dpopTesting.NewKey()
	otherKey := dpopTesting.NewKey()

	key, err := Parse(dpopTesting.Jwk(&privateKey.PublicKey))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	verifier, err := key.NamedVerifier()
	if err != nil {
		t.Fatalf("named verifier: %v", err)
	}
	if name := verifier.GetName(); name != "ES256" {
		t.Errorf("verifier name %q, want ES256", name)
	}

	testCases := []struct {
		name         string
		signedBy     string
		wantVerifies bool
	}{
		{name: "signed by the key", signedBy: "key", wantVerifies: true},
		{name: "signed by another key", signedBy: "other", wantVerifies: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			signer := privateKey
			if testCase.signedBy == "other" {
				signer = otherKey
			}
			proof := dpopTesting.MakeProof(signer, "GET", "https://example.com/", "", nil)
			signingInput := proof[:strings.LastIndexByte(proof, '.')]
			signature, err := base64.RawURLEncoding.DecodeString(proof[strings.LastIndexByte(proof, '.')+1:])
			if err != nil {
				t.Fatalf("%s: decode signature: %v", testCase.name, err)
			}

			err = verifier.Verify([]byte(signingInput), signature)
			if gotVerifies := err == nil; gotVerifies != testCase.wantVerifies {
				t.Errorf("%s: verifies = %v, want %v (%v)", testCase.name, gotVerifies, testCase.wantVerifies, err)
			}
		})
	}
}

func TestThumbprint(t *testing.T) {
	t.Parallel()

	privateKey := dpopTesting.NewKey()

	testCases := []struct {
		name      string
		publicKey *ecdsa.PublicKey
		want      string
		wantErr   bool
	}{
		{
			name:      "a P-256 key, as utils_go computes it",
			publicKey: &privateKey.PublicKey,
			want:      dpopTesting.KeyThumbprint(&privateKey.PublicKey),
		},
		{name: "no key", wantErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := Thumbprint(testCase.publicKey)
			if testCase.wantErr {
				if err == nil {
					t.Errorf("%s: got thumbprint %q, want an error", testCase.name, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", testCase.name, err)
			}
			if got != testCase.want {
				t.Errorf("%s: got %q, want %q", testCase.name, got, testCase.want)
			}
		})
	}
}
