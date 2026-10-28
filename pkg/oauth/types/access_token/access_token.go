// Package access_token is an OAuth access token as the authorization server issues it: a JWT
// (RFC 9068) for one resource, signed with a key of its own.
//
// It is made so that nothing but its resource accepts it. Its type is at+jwt, its audience the
// resource's URL, and it carries no authentication methods, no roles and no email address -- each
// of which a session token has and a service accepting sessions requires -- and it is signed with
// a key no such service verifies with.
package access_token

import (
	"fmt"
	"strings"
	"time"

	altshiftCryptoInterfaces "github.com/altshiftab/utils_go/pkg/crypto/interfaces"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	altshiftJwtToken "github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/token"
	"github.com/altshiftab/utils_go/pkg/schema"
	"github.com/altshiftab/utils_go/pkg/utils"
)

// Type is the token's JOSE type (RFC 9068 section 2.1), which no session token has.
const Type = "at+jwt"

// Token is an access token's claims.
type Token struct {
	Issuer string
	// Subject is the account the token acts for, by its id alone.
	Subject  string
	Audience string
	ClientId string
	// Scopes are the scopes granted, kept apart; the token carries them space-separated.
	Scopes    []string
	Id        string
	IssuedAt  time.Time
	ExpiresAt time.Time
	// KeyThumbprint binds the token to a key (RFC 9449 section 6), for a client that has one.
	KeyThumbprint string
}

// GetUser is the user the request log names for a request carrying the token: by the account id.
func (t *Token) GetUser() *schema.User {
	return &schema.User{Id: t.Subject}
}

// HasScope says whether the token was granted the scope.
func (t *Token) HasScope(scope string) bool {
	for _, granted := range t.Scopes {
		if granted == scope {
			return true
		}
	}
	return false
}

// Mint signs the token with the signer, naming the key by keyId.
func Mint(token *Token, signer altshiftCryptoInterfaces.NamedSigner, keyId string) (string, error) {
	if token == nil {
		return "", altshiftErrors.NewWithTrace(nil_error.New("token"))
	}
	if signer == nil || utils.IsNil(signer) {
		return "", altshiftErrors.NewWithTrace(nil_error.New("signer"))
	}
	for name, value := range map[string]string{
		"issuer": token.Issuer, "subject": token.Subject, "audience": token.Audience,
		"client id": token.ClientId, "id": token.Id,
	} {
		if value == "" {
			return "", altshiftErrors.NewWithTrace(empty_error.New(name))
		}
	}
	if token.ExpiresAt.IsZero() || token.IssuedAt.IsZero() {
		return "", altshiftErrors.NewWithTrace(empty_error.New("times"))
	}

	header := map[string]any{"typ": Type}
	if keyId != "" {
		header["kid"] = keyId
	}

	payload := map[string]any{
		"iss":       token.Issuer,
		"sub":       token.Subject,
		"aud":       token.Audience,
		"client_id": token.ClientId,
		"jti":       token.Id,
		"iat":       token.IssuedAt.Unix(),
		"exp":       token.ExpiresAt.Unix(),
	}
	if len(token.Scopes) != 0 {
		payload["scope"] = strings.Join(token.Scopes, " ")
	}
	if token.KeyThumbprint != "" {
		payload["cnf"] = map[string]any{"jkt": token.KeyThumbprint}
	}

	encoded, err := (&altshiftJwtToken.Token{Header: header, Payload: payload}).Encode(signer)
	if err != nil {
		return "", altshiftErrors.New(fmt.Errorf("token encode: %w", err))
	}

	return encoded, nil
}

// FromPayload reads a verified token's claims back.
func FromPayload(payload map[string]any) (*Token, error) {
	if payload == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("payload"))
	}

	str := func(name string) string {
		value, _ := payload[name].(string)
		return value
	}
	unix := func(name string) time.Time {
		switch value := payload[name].(type) {
		case float64:
			return time.Unix(int64(value), 0)
		case int64:
			return time.Unix(value, 0)
		}
		return time.Time{}
	}

	token := &Token{
		Issuer:    str("iss"),
		Subject:   str("sub"),
		ClientId:  str("client_id"),
		Id:        str("jti"),
		IssuedAt:  unix("iat"),
		ExpiresAt: unix("exp"),
	}

	switch audience := payload["aud"].(type) {
	case string:
		token.Audience = audience
	case []any:
		// A token of this server's names one audience; several is none of its making.
		if len(audience) == 1 {
			token.Audience, _ = audience[0].(string)
		}
	}

	if scope := str("scope"); scope != "" {
		token.Scopes = strings.Fields(scope)
	}
	if confirmation, ok := payload["cnf"].(map[string]any); ok {
		token.KeyThumbprint, _ = confirmation["jkt"].(string)
	}

	if token.Subject == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("subject"))
	}
	if token.Audience == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("audience"))
	}

	return token, nil
}
