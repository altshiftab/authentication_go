package public_key

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
)

func encodePublicKey(t *testing.T, publicKey any) string {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal pkix public key: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func newEddsaKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}

	return publicKey, privateKey
}

func newEcdsaKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa generate key: %v", err)
	}

	return privateKey
}

// What is accepted is the whole of what an account may register, so what is refused is the more
// interesting half: everything here that fails must fail as the registrant's mistake rather than
// as a fault of ours, which is what ErrValidationError and ErrParseError say to the endpoint.
func TestParse(t *testing.T) {
	t.Parallel()

	eddsaPublicKey, eddsaPrivateKey := newEddsaKey(t)
	ecdsaPrivateKey := newEcdsaKey(t, elliptic.P256())
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa generate key: %v", err)
	}

	eddsaPrivateDer, err := x509.MarshalPKCS8PrivateKey(eddsaPrivateKey)
	if err != nil {
		t.Fatalf("marshal pkcs8 private key: %v", err)
	}
	eddsaPrivatePem := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: eddsaPrivateDer}))

	testCases := []struct {
		name          string
		pem           string
		wantAlgorithm string
		wantErr       bool
	}{
		{
			name:          "an Ed25519 key",
			pem:           encodePublicKey(t, eddsaPublicKey),
			wantAlgorithm: AlgorithmEddsa,
		},
		{
			name:          "a P-256 key",
			pem:           encodePublicKey(t, &ecdsaPrivateKey.PublicKey),
			wantAlgorithm: AlgorithmEs256,
		},
		// The curves and key types that are not refused by accident but on purpose: each of them
		// parses perfectly well, and each is turned away.
		{
			name:    "a P-384 key",
			pem:     encodePublicKey(t, &newEcdsaKey(t, elliptic.P384()).PublicKey),
			wantErr: true,
		},
		{
			name:    "a P-521 key",
			pem:     encodePublicKey(t, &newEcdsaKey(t, elliptic.P521()).PublicKey),
			wantErr: true,
		},
		{
			name:    "an RSA key",
			pem:     encodePublicKey(t, &rsaPrivateKey.PublicKey),
			wantErr: true,
		},
		// The one worth a message of its own: somebody pasted the half they must keep.
		{
			name:    "a private key",
			pem:     eddsaPrivatePem,
			wantErr: true,
		},
		{name: "nothing at all", pem: "", wantErr: true},
		{name: "text that is not PEM", pem: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 someone@example.com", wantErr: true},
		{
			name:    "PEM whose body is not a key",
			pem:     string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not a key")})),
			wantErr: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			key, err := Parse(testCase.pem)

			if testCase.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got a %s key", key.Algorithm)
				}
				// The registrant's mistake, not the service's: the endpoint answers 4xx from this.
				if !altshiftErrors.IsAny(err, altshiftErrors.ErrValidationError, altshiftErrors.ErrParseError) {
					t.Errorf("expected a validation or parse error, got %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if key == nil {
				t.Fatal("The key is nil.")
			}
			if key.Algorithm != testCase.wantAlgorithm {
				t.Errorf("algorithm: got %q, want %q", key.Algorithm, testCase.wantAlgorithm)
			}
			if key.Id == "" {
				t.Error("The key has no id.")
			}
			if len(key.Der) == 0 {
				t.Error("The key kept no DER.")
			}
		})
	}
}

/*
 * The id is the key, and the same key must always be the same id: a client library computes it from
 * the public key with no help from us, and the database refuses a second registration of one key by
 * that id colliding. An id that drifted -- by encoding the coordinates differently, or by ordering
 * the JSON differently -- would break both of those quietly.
 *
 * The vector is the key published in RFC 8037's appendix A.2, whose thumbprint is computed from the
 * key material as the RFC prints it rather than from anything this package produced. RFC 7638's own
 * worked example is an RSA key, which is not one that can be registered here.
 */
func TestThumbprintVectors(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		pem  string
		want string
	}{
		{
			// RFC 8037 A.2's public key: x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".
			name: "the Ed25519 key of RFC 8037",
			pem: "-----BEGIN PUBLIC KEY-----\n" +
				"MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n" +
				"-----END PUBLIC KEY-----\n",
			want: "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			key, err := Parse(testCase.pem)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			if key.Id != testCase.want {
				t.Errorf("thumbprint: got %q, want %q", key.Id, testCase.want)
			}
		})
	}
}

// The id follows the key material and nothing else: the same key read from PEM and from the DER the
// row kept is one key, and two keys are never one id.
func TestThumbprintIsTheKey(t *testing.T) {
	t.Parallel()

	eddsaPublicKey, _ := newEddsaKey(t)
	otherPublicKey, _ := newEddsaKey(t)
	ecdsaPrivateKey := newEcdsaKey(t, elliptic.P256())

	for _, publicKey := range []any{eddsaPublicKey, &ecdsaPrivateKey.PublicKey} {
		fromPem, err := Parse(encodePublicKey(t, publicKey))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}

		fromDer, err := FromDer(fromPem.Der)
		if err != nil {
			t.Fatalf("from der: %v", err)
		}

		if fromPem.Id != fromDer.Id {
			t.Errorf("the key read back has another id: %q against %q", fromDer.Id, fromPem.Id)
		}
		if fromPem.Algorithm != fromDer.Algorithm {
			t.Errorf("the key read back has another algorithm: %q", fromDer.Algorithm)
		}
	}

	first, err := Parse(encodePublicKey(t, eddsaPublicKey))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	second, err := Parse(encodePublicKey(t, otherPublicKey))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if first.Id == second.Id {
		t.Error("Two keys share one id.")
	}
}

// A key in hand is known by the id the same key registered as PEM is: a client and the service
// must agree on what to call it without either telling the other.
func TestFromPublicKey(t *testing.T) {
	t.Parallel()

	eddsaPublicKey, _ := newEddsaKey(t)
	ecdsaPrivateKey := newEcdsaKey(t, elliptic.P256())
	p384PrivateKey := newEcdsaKey(t, elliptic.P384())

	testCases := []struct {
		name      string
		publicKey any
		algorithm string
		valid     bool
	}{
		{name: "ed25519", publicKey: eddsaPublicKey, algorithm: AlgorithmEddsa, valid: true},
		{name: "p-256", publicKey: &ecdsaPrivateKey.PublicKey, algorithm: AlgorithmEs256, valid: true},
		{name: "p-384", publicKey: &p384PrivateKey.PublicKey},
		{name: "nil", publicKey: nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			key, err := FromPublicKey(testCase.publicKey)
			if !testCase.valid {
				if err == nil {
					t.Fatalf("expected an error, got %+v", key)
				}
				return
			}
			if err != nil {
				t.Fatalf("from public key: %v", err)
			}

			registered, err := Parse(encodePublicKey(t, testCase.publicKey))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if key.Id != registered.Id || key.Algorithm != testCase.algorithm || string(key.Der) != string(registered.Der) {
				t.Errorf("in hand %s %s, registered %s %s", key.Id, key.Algorithm, registered.Id, registered.Algorithm)
			}
		})
	}
}
