// Package public_key reads the public keys accounts register for API access.
//
// Public keys arrive as PEM, which is what openssl, ssh-keygen, WebCrypto and every key manager
// emit and what a person can paste: parsing them is this package's job, and everything downstream
// works on the parsed key rather than on text.
package public_key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	altshiftCryptoEcdsa "github.com/altshiftab/utils_go/pkg/crypto/ecdsa"
	altshiftCryptoEddsa "github.com/altshiftab/utils_go/pkg/crypto/eddsa"
	altshiftCryptoInterfaces "github.com/altshiftab/utils_go/pkg/crypto/interfaces"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
)

// The JOSE names of what a registered key signs with. Two, deliberately: Ed25519 is the one to
// reach for, and P-256 is the one a key manager can hold -- GCP, AWS, Azure and a YubiKey all do
// P-256 and none of them does Ed25519, so a build runner that keeps its key in a manager rather
// than in a file needs it. Everything else is refused: RSA keys are large and easy to misuse, and
// the larger curves buy nothing here.
const (
	AlgorithmEddsa = "EdDSA"
	AlgorithmEs256 = "ES256"
)

// Key is a registered public key: what it is, what it signs with, and the id it is known by.
type Key struct {
	// Id is the key's RFC 7638 thumbprint, base64url without padding. It is derived from the key
	// material alone, so a client computes the same id with any JOSE library and two registrations
	// of one key cannot disagree about what to call it.
	Id string

	// Algorithm is one of the two above, settled from the key rather than from anything the holder
	// says: what an assertion claims in its header is checked against this, never the reverse.
	Algorithm string

	// Der is the key as a PKIX SubjectPublicKeyInfo, which is what the PEM carried and what is
	// stored, so that a key read back from the database is the key that was registered.
	Der []byte

	publicKey crypto.PublicKey
}

// Parse reads a PEM public key, refusing anything that is not an Ed25519 or P-256 one.
//
// Everything it refuses is a client error: the text came from whoever is registering the key.
func Parse(pemText string) (*Key, error) {
	if pemText == "" {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, empty_error.New("pem text")),
		)
	}

	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the text is not PEM", altshiftErrors.ErrParseError),
		)
	}

	// A private key pasted by mistake decodes as PEM and would otherwise be stored and reported
	// back; saying so plainly is worth more than a parse error about the key type, because the
	// reader needs to know they pasted the half they must keep.
	if block.Type != "PUBLIC KEY" {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf(
				"%w: the PEM holds %q, not a public key",
				altshiftErrors.ErrValidationError,
				block.Type,
			),
		)
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: x509 parse pkix public key: %w", altshiftErrors.ErrParseError, err),
		)
	}

	return fromPublicKey(parsed, block.Bytes)
}

// FromDer reads a key back from what was stored, which has already been through Parse.
func FromDer(der []byte) (*Key, error) {
	if len(der) == 0 {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("der"))
	}

	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("x509 parse pkix public key: %w", err))
	}

	return fromPublicKey(parsed, der)
}

// FromPublicKey reads a key a holder has in hand, as a crypto.Signer's public half, refusing anything
// that is not an Ed25519 or P-256 one: what a client computes its key's id from.
func FromPublicKey(publicKey crypto.PublicKey) (*Key, error) {
	if publicKey == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("public key"))
	}

	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: x509 marshal pkix public key: %w", altshiftErrors.ErrValidationError, err),
		)
	}

	return fromPublicKey(publicKey, der)
}

func fromPublicKey(parsed crypto.PublicKey, der []byte) (*Key, error) {
	switch publicKey := parsed.(type) {
	case ed25519.PublicKey:
		return &Key{
			Id:        eddsaThumbprint(publicKey),
			Algorithm: AlgorithmEddsa,
			Der:       der,
			publicKey: publicKey,
		}, nil
	case *ecdsa.PublicKey:
		if publicKey.Curve != elliptic.P256() {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf(
					"%w: the curve is not P-256",
					altshiftErrors.ErrValidationError,
				),
			)
		}

		thumbprint, err := ecdsaThumbprint(publicKey)
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("ecdsa thumbprint: %w", err), publicKey)
		}

		return &Key{
			Id:        thumbprint,
			Algorithm: AlgorithmEs256,
			Der:       der,
			publicKey: publicKey,
		}, nil
	default:
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf(
				"%w: the key is neither Ed25519 nor P-256 (%T)",
				altshiftErrors.ErrValidationError,
				parsed,
			),
		)
	}
}

/*
 * The RFC 7638 thumbprint: SHA-256 over the key's required JWK members, written as compact JSON
 * with the member names in lexicographic order and nothing else in it, base64url without padding.
 *
 * Written out rather than marshalled from a struct because the rule is about the bytes: a JSON
 * encoder that reorders the members, adds a space or escapes a character produces a different id
 * for the same key, and the id would then not be the one a client library computes.
 */

func eddsaThumbprint(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(fmt.Appendf(
		nil,
		`{"crv":"Ed25519","kty":"OKP","x":"%s"}`,
		base64.RawURLEncoding.EncodeToString(publicKey),
	))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func ecdsaThumbprint(publicKey *ecdsa.PublicKey) (string, error) {
	// The uncompressed point, 0x04 followed by the two coordinates at the curve's width. Read this
	// way rather than from the coordinates directly: those are deprecated as of Go 1.26, and they
	// are big integers, which would have to be padded back to a fixed width by hand -- a coordinate
	// whose leading byte is zero is still 32 bytes, and trimming it would give the key an id that
	// nothing else computes.
	point, err := publicKey.Bytes()
	if err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("ecdsa public key bytes: %w", err))
	}

	const size = 32
	if len(point) != 1+2*size {
		return "", altshiftErrors.NewWithTrace(
			fmt.Errorf(
				"%w: unexpected public key point length %d",
				altshiftErrors.ErrUnexpectedType,
				len(point),
			),
		)
	}

	sum := sha256.Sum256(fmt.Appendf(
		nil,
		`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`,
		base64.RawURLEncoding.EncodeToString(point[1:1+size]),
		base64.RawURLEncoding.EncodeToString(point[1+size:]),
	))

	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// NamedVerifier is what verifies a JWS signed by this key. Its name is the key's algorithm, which
// is what refuses an assertion whose header claims to have been signed with another.
func (k *Key) NamedVerifier() (altshiftCryptoInterfaces.NamedVerifier, error) {
	if k == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("key"))
	}

	switch publicKey := k.publicKey.(type) {
	case ed25519.PublicKey:
		return &altshiftCryptoEddsa.Method{PublicKey: publicKey}, nil
	case *ecdsa.PublicKey:
		method, err := altshiftCryptoEcdsa.FromPublicKey(publicKey)
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("ecdsa from public key: %w", err), publicKey)
		}
		return method, nil
	default:
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %T", altshiftErrors.ErrUnexpectedType, k.publicKey),
		)
	}
}
