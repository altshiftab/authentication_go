// Package testing makes the keys and proofs that tests of DPoP need.
//
// A proof is assembled here by hand rather than through utils_go's token encoder, so that a test can
// write what no conforming client would: an "alg" of "none", a "jwk" naming a key other than the one
// that signed, an "iat" an hour old. The defaults are what a conforming client sends.
package testing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"strings"
	"time"

	"github.com/altshiftab/authentication_go/pkg/dpop"
	altshiftCryptoEcdsa "github.com/altshiftab/utils_go/pkg/crypto/ecdsa"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwk/types/key/ec"
)

// NewKey makes a P-256 key, the kind a client holds in Android Keystore or a key manager.
func NewKey() *ecdsa.PrivateKey {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(altshiftErrors.NewWithTrace(fmt.Errorf("ecdsa generate key: %w", err)))
	}

	return privateKey
}

// Jwk is the public key as a proof's "jwk" header carries it.
func Jwk(publicKey *ecdsa.PublicKey) map[string]any {
	jwkKey := ecKey(publicKey)

	data, err := json.Marshal(jwkKey)
	if err != nil {
		panic(altshiftErrors.NewWithTrace(fmt.Errorf("json marshal (jwk): %w", err)))
	}

	var jwk map[string]any
	if err := json.Unmarshal(data, &jwk); err != nil {
		panic(altshiftErrors.NewWithTrace(fmt.Errorf("json unmarshal (jwk): %w", err)))
	}
	if jwk == nil {
		panic(altshiftErrors.NewWithTrace(nil_error.New("jwk")))
	}
	// The key type belongs to the JWK itself; the EC value carries only the curve and coordinates.
	jwk["kty"] = "EC"

	return jwk
}

// KeyThumbprint is the key's RFC 7638 thumbprint as utils_go computes it, which is a second
// implementation to hold the one under test to rather than a copy of it.
func KeyThumbprint(publicKey *ecdsa.PublicKey) string {
	return ecKey(publicKey).Thumbprint()
}

// MakeProof makes a proof for a request: method and targetUri as "htm" and "htu", a fresh "jti",
// "iat" now, and "ath" when accessToken is not empty. mutate, when not nil, may change the header
// and payload before they are signed by privateKey.
func MakeProof(
	privateKey *ecdsa.PrivateKey,
	method string,
	targetUri string,
	accessToken string,
	mutate func(header map[string]any, payload map[string]any),
) string {
	if privateKey == nil {
		panic(altshiftErrors.NewWithTrace(nil_error.New("private key")))
	}

	header := map[string]any{
		"typ": dpop.Type,
		"alg": dpop.Algorithm,
		"jwk": Jwk(&privateKey.PublicKey),
	}
	payload := map[string]any{
		"jti": rand.Text(),
		"htm": method,
		"htu": targetUri,
		"iat": time.Now().Unix(),
	}
	if accessToken != "" {
		payload["ath"] = dpop.AccessTokenHash(accessToken)
	}

	if mutate != nil {
		mutate(header, payload)
	}

	headerData, err := json.Marshal(header)
	if err != nil {
		panic(altshiftErrors.NewWithTrace(fmt.Errorf("json marshal (header): %w", err)))
	}

	payloadData, err := json.Marshal(payload)
	if err != nil {
		panic(altshiftErrors.NewWithTrace(fmt.Errorf("json marshal (payload): %w", err)))
	}

	signingInput := strings.Join(
		[]string{
			base64.RawURLEncoding.EncodeToString(headerData),
			base64.RawURLEncoding.EncodeToString(payloadData),
		},
		".",
	)

	signer, err := altshiftCryptoEcdsa.FromPrivateKey(privateKey)
	if err != nil {
		panic(altshiftErrors.New(fmt.Errorf("ecdsa from private key: %w", err)))
	}
	if signer == nil {
		panic(altshiftErrors.NewWithTrace(nil_error.New("signer")))
	}

	signature, err := signer.Sign([]byte(signingInput))
	if err != nil {
		panic(altshiftErrors.New(fmt.Errorf("signer sign: %w", err)))
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func ecKey(publicKey *ecdsa.PublicKey) *ec.Key {
	if publicKey == nil {
		panic(altshiftErrors.NewWithTrace(nil_error.New("public key")))
	}

	jwkKey, err := ec.NewFromPublicKey(publicKey)
	if err != nil {
		panic(altshiftErrors.New(fmt.Errorf("ec new from public key: %w", err)))
	}
	if jwkKey == nil {
		panic(altshiftErrors.NewWithTrace(nil_error.New("ec key")))
	}

	return jwkKey
}
