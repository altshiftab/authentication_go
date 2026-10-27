// Package dpop holds what the parts of DPoP (RFC 9449) share: the names it puts on the wire, the
// challenges a refusal answers with, and the hash by which a proof names the token it is sent with.
//
// DPoP binds a token to a key the client holds. The issuer writes the key's thumbprint into the
// token as "cnf.jkt", and with every request the client sends a proof -- a short JWT signed by that
// key, naming the request's method and URL and the token's hash -- so that a copy of the token,
// taken from a log, a proxy or a service that received it, is worth nothing to whoever lacks the
// key. Nothing here is required of anyone: a token without the binding is a bearer token, as before.
package dpop

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

const (
	// HeaderName is the request header a proof travels in (RFC 9449 §4.1). Go canonicalises it to
	// "Dpop", which http.Header's methods account for and a lookup by map key does not.
	HeaderName = "DPoP"

	// Scheme is the authentication scheme a bound token is presented under (RFC 9449 §7.1).
	Scheme = "DPoP"

	// Type is what a proof must say it is, in its JWS header.
	Type = "dpop+jwt"

	// Algorithm is the one signature algorithm a proof may use. P-256 is what Android Keystore, the
	// cloud key managers and WebCrypto all hold; a second algorithm would be a second way of reading
	// a key from someone the service does not know yet, for no client that needs it.
	Algorithm = "ES256"

	WwwAuthenticateHeaderName = "WWW-Authenticate"
)

// The error codes a challenge carries: the first three are RFC 6750 §3.1's, which RFC 9449 §7.1
// reuses for the DPoP scheme, and the last is RFC 9449's own, for a proof that is missing or wrong.
const (
	ErrorInvalidRequest    = "invalid_request"
	ErrorInvalidToken      = "invalid_token"
	ErrorInsufficientScope = "insufficient_scope"
	ErrorInvalidDpopProof  = "invalid_dpop_proof"
)

// Challenge renders a DPoP challenge (RFC 9449 §7.1). An empty errorCode renders the scheme with the
// algorithms alone, which is the answer to a request that carried no credential; a description is
// included only with a code.
func Challenge(errorCode string, errorDescription string) string {
	var builder strings.Builder
	builder.WriteString(Scheme)
	builder.WriteString(" ")
	writeError(&builder, errorCode, errorDescription)
	if errorCode != "" {
		builder.WriteString(", ")
	}
	builder.WriteString(`algs="`)
	builder.WriteString(Algorithm)
	builder.WriteString(`"`)

	return builder.String()
}

// BearerChallenge renders a Bearer challenge (RFC 6750 §3), for an endpoint that takes either
// scheme and so names both in its refusals. It is here rather than taken from utils_go because the
// version this module builds against has no renderer of its own.
//
// Only RFC 6750's codes are carried: "invalid_dpop_proof" means nothing to a bearer client, which
// is answered with the bare scheme instead.
func BearerChallenge(errorCode string, errorDescription string) string {
	switch errorCode {
	case ErrorInvalidRequest, ErrorInvalidToken, ErrorInsufficientScope:
	default:
		return "Bearer"
	}

	var builder strings.Builder
	builder.WriteString("Bearer ")
	writeError(&builder, errorCode, errorDescription)

	return builder.String()
}

// AccessTokenHash is a proof's "ath": the base64url encoding, without padding, of the SHA-256 hash
// of the access token as it was sent (RFC 9449 §4.2).
func AccessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func writeError(builder *strings.Builder, errorCode string, errorDescription string) {
	if errorCode == "" {
		return
	}

	builder.WriteString(`error="`)
	builder.WriteString(restrict(errorCode))
	builder.WriteString(`"`)
	if description := restrict(errorDescription); description != "" {
		builder.WriteString(`, error_description="`)
		builder.WriteString(description)
		builder.WriteString(`"`)
	}
}

// restrict keeps the characters RFC 6750 allows in error and error_description, printable ASCII less
// the quote and the backslash, which cannot be escaped there.
func restrict(value string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return -1
		}
		return r
	}, value)
}
