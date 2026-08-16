package session

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
)

// The header names follow the Device Bound Session Credentials protocol, which renamed them from
// Sec-Session-* to Secure-Session-* during its second origin trial. Chrome ignores a registration
// header it does not recognise, so the old names left the mechanism silently inactive.
const (
	DbscSessionRegistrationHeaderName = "Secure-Session-Registration"
	DbscSessionResponseHeaderName     = "Secure-Session-Response"
	DbscSessionChallengeHeaderName    = "Secure-Session-Challenge"
	DbscSessionIdHeaderName           = "Sec-Secure-Session-Id"
)

func GenerateDbscChallenge() (string, error) {
	challenge := make([]byte, 64)
	if _, err := rand.Read(challenge); err != nil {
		return "", motmedelErrors.NewWithTrace(fmt.Errorf("rand read: %w", err))
	}

	return base64.URLEncoding.EncodeToString(challenge), nil
}
