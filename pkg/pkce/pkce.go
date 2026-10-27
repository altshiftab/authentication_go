// Package pkce checks a Proof Key for Code Exchange (RFC 7636), which ties a one-time code to the
// party that asked for it: the client sends a hash of a secret when it starts, and the secret itself
// when it redeems the code, so that a code intercepted on its way back -- by another app claiming
// the same URI scheme, say -- is worth nothing to whoever intercepted it.
//
// Only S256. The "plain" method sends the secret where the hash should be, which defeats the point
// for exactly the interception it exists to stop.
package pkce

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// MethodS256 is the one challenge method accepted.
const MethodS256 = "S256"

// The verifier's length bounds (RFC 7636 §4.1). The lower one is what makes it unguessable: 43
// characters of the unreserved set carry 256 bits.
const (
	minimumVerifierLength = 43
	maximumVerifierLength = 128
)

// challengeLength is the length of an S256 challenge: a SHA-256 hash in base64url without padding.
const challengeLength = 43

// ValidVerifier reports whether a verifier is 43 to 128 characters of the unreserved set.
func ValidVerifier(verifier string) bool {
	if len(verifier) < minimumVerifierLength || len(verifier) > maximumVerifierLength {
		return false
	}

	for i := range len(verifier) {
		if !isUnreserved(verifier[i]) {
			return false
		}
	}

	return true
}

// ValidChallenge reports whether a challenge has the shape an S256 one has, so that one which could
// never be matched is refused when the flow starts rather than when it is about to finish.
func ValidChallenge(challenge string) bool {
	if len(challenge) != challengeLength {
		return false
	}

	decoded, err := base64.RawURLEncoding.Strict().DecodeString(challenge)
	return err == nil && len(decoded) == sha256.Size
}

// ChallengeS256 is the S256 challenge for a verifier: base64url, without padding, of its SHA-256.
func ChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// MatchesS256 reports whether a verifier is the one a challenge was made from. A verifier of the
// wrong shape never matches, whatever it hashes to.
func MatchesS256(verifier string, challenge string) bool {
	if !ValidVerifier(verifier) {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(ChallengeS256(verifier)), []byte(challenge)) == 1
}

// isUnreserved is RFC 3986 §2.3's unreserved set, which RFC 7636 draws the verifier from.
func isUnreserved(character byte) bool {
	switch {
	case 'a' <= character && character <= 'z', 'A' <= character && character <= 'Z', '0' <= character && character <= '9':
		return true
	default:
		return character == '-' || character == '.' || character == '_' || character == '~'
	}
}
