package testing

import (
	"strings"
	"testing"

	"github.com/altshiftab/authentication_go/pkg/dpop"
	altshiftCryptoEcdsa "github.com/altshiftab/utils_go/pkg/crypto/ecdsa"
	"github.com/altshiftab/utils_go/pkg/json/jose/jws"
	altshiftJwtToken "github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/token"
)

func TestMakeProof(t *testing.T) {
	t.Parallel()

	privateKey := NewKey()
	otherKey := NewKey()

	testCases := []struct {
		name        string
		accessToken string
		mutate      func(header map[string]any, payload map[string]any)
		wantClaims  map[string]any
		wantAbsent  []string
		// Whether the signature verifies under the key the "jwk" header names.
		wantVerifies bool
	}{
		{
			name:         "a proof for a token endpoint",
			wantClaims:   map[string]any{"htm": "POST", "htu": "https://example.com/token"},
			wantAbsent:   []string{"ath"},
			wantVerifies: true,
		},
		{
			name:         "a proof for a resource",
			accessToken:  "a.b.c",
			wantClaims:   map[string]any{"ath": dpop.AccessTokenHash("a.b.c")},
			wantVerifies: true,
		},
		{
			name: "the header names another key",
			mutate: func(header map[string]any, _ map[string]any) {
				header["jwk"] = Jwk(&otherKey.PublicKey)
			},
			wantVerifies: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			proof := MakeProof(privateKey, "POST", "https://example.com/token", testCase.accessToken, testCase.mutate)

			token, err := altshiftJwtToken.New(proof)
			if err != nil {
				t.Fatalf("%s: token new: %v", testCase.name, err)
			}
			if token == nil {
				t.Fatalf("%s: no token", testCase.name)
			}

			if typ := token.Header["typ"]; typ != dpop.Type {
				t.Errorf("%s: typ = %v, want %q", testCase.name, typ, dpop.Type)
			}
			if alg := token.Header["alg"]; alg != dpop.Algorithm {
				t.Errorf("%s: alg = %v, want %q", testCase.name, alg, dpop.Algorithm)
			}
			if jti, _ := token.Payload["jti"].(string); jti == "" {
				t.Errorf("%s: no jti", testCase.name)
			}
			if _, ok := token.Payload["iat"].(float64); !ok {
				t.Errorf("%s: iat = %v, want a number", testCase.name, token.Payload["iat"])
			}
			for name, want := range testCase.wantClaims {
				if got := token.Payload[name]; got != want {
					t.Errorf("%s: %s = %v, want %v", testCase.name, name, got, want)
				}
			}
			for _, name := range testCase.wantAbsent {
				if _, ok := token.Payload[name]; ok {
					t.Errorf("%s: %s is present", testCase.name, name)
				}
			}

			// Verified against the key the header names, as a server would, rather than the one the
			// test knows signed it.
			verifyingKey := &privateKey.PublicKey
			if jwk, _ := token.Header["jwk"].(map[string]any); jwk["x"] != Jwk(verifyingKey)["x"] {
				verifyingKey = &otherKey.PublicKey
			}
			verifier, err := altshiftCryptoEcdsa.FromPublicKey(verifyingKey)
			if err != nil {
				t.Fatalf("%s: ecdsa from public key: %v", testCase.name, err)
			}

			err = jws.VerifyCompactSerialization(proof, verifier)
			if gotVerifies := err == nil; gotVerifies != testCase.wantVerifies {
				t.Errorf("%s: verifies = %v, want %v (%v)", testCase.name, gotVerifies, testCase.wantVerifies, err)
			}
		})
	}
}

func TestKeyThumbprint(t *testing.T) {
	t.Parallel()

	privateKey := NewKey()
	otherKey := NewKey()

	thumbprint := KeyThumbprint(&privateKey.PublicKey)

	// Base64url of a SHA-256 hash, without padding.
	if len(thumbprint) != 43 || strings.ContainsAny(thumbprint, "+/=") {
		t.Errorf("thumbprint %q is not base64url of 32 bytes", thumbprint)
	}
	if again := KeyThumbprint(&privateKey.PublicKey); again != thumbprint {
		t.Errorf("thumbprint changed between calls: %q, %q", thumbprint, again)
	}
	if other := KeyThumbprint(&otherKey.PublicKey); other == thumbprint {
		t.Error("two keys share a thumbprint")
	}
}
