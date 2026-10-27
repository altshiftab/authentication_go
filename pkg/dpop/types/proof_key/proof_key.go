// Package proof_key reads the public key a DPoP proof carries in its "jwk" header.
//
// The key arrives from whoever sent the request, so it is read as untrusted input rather than the
// way a key fetched from an issuer's key set is. utils_go's EC key is not used for it: it builds a
// public key from the coordinates without checking their length or that the point is on the curve,
// and its thumbprint hashes the coordinates as they were written. Here the point is parsed by the
// standard library, which refuses one that is not on the curve, and the thumbprint is computed from
// the parsed key, so that it is the RFC 7638 one by construction rather than a hash of whatever
// strings arrived.
package proof_key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	altshiftCryptoEcdsa "github.com/altshiftab/utils_go/pkg/crypto/ecdsa"
	altshiftCryptoInterfaces "github.com/altshiftab/utils_go/pkg/crypto/interfaces"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/utils"
)

// coordinateSize is the width of a P-256 coordinate. RFC 7518 §6.2.1.2 requires "x" and "y" to be
// written at the full width even when the leading byte is zero, so anything else is refused rather
// than padded: a shorter coordinate is a key some other library would not have written.
const coordinateSize = 32

// Key is a proof's public key and the thumbprint a bound token names it by.
type Key struct {
	// Thumbprint is the key's RFC 7638 thumbprint, base64url without padding: what "cnf.jkt" holds
	// in a token bound to this key.
	Thumbprint string

	PublicKey *ecdsa.PublicKey
}

// Parse reads a proof's "jwk" header, refusing anything but a P-256 public key.
//
// Every refusal is a client error, wrapped in ErrValidationError: the key came from the request.
func Parse(jwk map[string]any) (*Key, error) {
	if jwk == nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, nil_error.New("jwk")),
		)
	}

	kty, err := utils.MapGetConvert[string](jwk, "kty")
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: map get convert (kty): %w", altshiftErrors.ErrValidationError, err),
		)
	}
	if kty != "EC" {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the key type is not EC", altshiftErrors.ErrValidationError),
			kty,
		)
	}

	crv, err := utils.MapGetConvert[string](jwk, "crv")
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: map get convert (crv): %w", altshiftErrors.ErrValidationError, err),
		)
	}
	if crv != "P-256" {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the curve is not P-256", altshiftErrors.ErrValidationError),
			crv,
		)
	}

	// RFC 9449 §4.3 refuses a header carrying a private key, whatever else it holds: a client that
	// sends one has already given it away, and accepting it would say that was fine.
	if _, ok := jwk["d"]; ok {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the jwk holds a private key", altshiftErrors.ErrValidationError),
		)
	}

	x, err := coordinate(jwk, "x")
	if err != nil {
		return nil, err
	}

	y, err := coordinate(jwk, "y")
	if err != nil {
		return nil, err
	}

	point := make([]byte, 0, 1+2*coordinateSize)
	point = append(point, 0x04)
	point = append(point, x...)
	point = append(point, y...)

	publicKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: ecdsa parse uncompressed public key: %w", altshiftErrors.ErrValidationError, err),
		)
	}
	if publicKey == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("ecdsa public key"))
	}

	thumbprint, err := Thumbprint(publicKey)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("thumbprint: %w", err), publicKey)
	}

	return &Key{Thumbprint: thumbprint, PublicKey: publicKey}, nil
}

// Thumbprint is the RFC 7638 thumbprint of a P-256 key: SHA-256 over the key's required JWK members,
// written as compact JSON with the names in lexicographic order, base64url without padding.
//
// Written out rather than marshalled, because the rule is about the bytes: an encoder that reorders
// the members or escapes a character gives the same key another thumbprint, which would then not be
// the one a client library computes.
func Thumbprint(publicKey *ecdsa.PublicKey) (string, error) {
	if publicKey == nil {
		return "", altshiftErrors.NewWithTrace(nil_error.New("public key"))
	}

	point, err := publicKey.Bytes()
	if err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("ecdsa public key bytes: %w", err))
	}
	if len(point) != 1+2*coordinateSize {
		return "", altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the key is not a P-256 one", altshiftErrors.ErrUnexpectedType),
			len(point),
		)
	}

	sum := sha256.Sum256(fmt.Appendf(
		nil,
		`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`,
		base64.RawURLEncoding.EncodeToString(point[1:1+coordinateSize]),
		base64.RawURLEncoding.EncodeToString(point[1+coordinateSize:]),
	))

	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// NamedVerifier verifies a JWS signed by this key. Its name is ES256, which is what refuses a proof
// whose header claims another algorithm.
func (k *Key) NamedVerifier() (altshiftCryptoInterfaces.NamedVerifier, error) {
	if k == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("key"))
	}

	method, err := altshiftCryptoEcdsa.FromPublicKey(k.PublicKey)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("ecdsa from public key: %w", err), k.PublicKey)
	}
	if method == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("ecdsa method"))
	}

	return method, nil
}

// coordinate reads one coordinate, which must be base64url without padding and exactly the curve's
// width. Strict, so that the bits left over at the end of the encoding must be zero.
func coordinate(jwk map[string]any, name string) ([]byte, error) {
	value, err := utils.MapGetConvert[string](jwk, name)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: map get convert (%s): %w", altshiftErrors.ErrValidationError, name, err),
		)
	}

	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: base64 raw url encoding decode string (%s): %w", altshiftErrors.ErrValidationError, name, err),
			value,
		)
	}

	if len(decoded) != coordinateSize {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf(
				"%w: the %s coordinate is %d bytes, not %d",
				altshiftErrors.ErrValidationError, name, len(decoded), coordinateSize,
			),
		)
	}

	return decoded, nil
}
