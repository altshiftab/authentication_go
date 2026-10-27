package session_token

import (
	"encoding/json/v2"
	"fmt"
	"log/slog"
	"strings"
	"time"

	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	"github.com/altshiftab/authentication_go/pkg/session/errors"
	"github.com/altshiftab/utils_go/pkg/crypto/interfaces"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claims/session_claims"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/numeric_date"
	altshiftJwtToken "github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/token"
	"github.com/altshiftab/utils_go/pkg/schema"
	altshiftTime "github.com/altshiftab/utils_go/pkg/time"
	"github.com/altshiftab/utils_go/pkg/utils"
)

type Token struct {
	Claims              *session_claims.Claims
	AuthenticationId    string
	SessionId           string
	SubjectId           string
	SubjectEmailAddress string
	TenantId            string
	TenantName          string
	Roles               []string

	// KeyThumbprint is the "cnf.jkt" of RFC 9449 §6.1: the RFC 7638 thumbprint of the key the token
	// is bound to, which every request presenting it must carry a proof by. Empty for a token that is
	// bound to nothing, as every browser session is.
	//
	// It sits beside Claims rather than in them because session_claims is utils_go's and does not
	// know the claim: Encode writes it into the payload, and ParsePayload reads it back.
	KeyThumbprint string
}

func (t *Token) GetUser() *schema.User {
	user := &schema.User{
		Id:    t.SubjectId,
		Email: t.SubjectEmailAddress,
	}

	if t.TenantId != "" || t.TenantName != "" {
		user.Group = &schema.Group{
			Id:   t.TenantId,
			Name: t.TenantName,
		}
	}

	user.Roles = t.Roles

	return user
}

func (t *Token) UserAttributes() []any {
	roles := t.Roles
	if len(roles) == 0 {
		roles = make([]string, 0)
	}

	attrs := []any{
		slog.String("id", t.SubjectId),
		slog.String("email", t.SubjectEmailAddress),
		slog.Any("roles", roles),
	}

	var groupAttrs []any

	if tenantId := t.TenantId; tenantId != "" {
		groupAttrs = append(groupAttrs, slog.String("id", tenantId))
	}

	if tenantName := t.TenantName; tenantName != "" {
		groupAttrs = append(groupAttrs, slog.String("name", tenantName))
	}

	if len(groupAttrs) > 0 {
		attrs = append(attrs, slog.Group("group", groupAttrs...))
	}

	return attrs
}

func (t *Token) Encode(signer interfaces.NamedSigner) (string, error) {
	if utils.IsNil(signer) {
		return "", altshiftErrors.NewWithTrace(nil_error.New("signer"))
	}

	data, err := json.Marshal(t.Claims)
	if err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("json marshal (claims): %w", err), t.Claims)
	}

	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("json unmarshal (claims data): %w", err), data)
	}

	if keyThumbprint := t.KeyThumbprint; keyThumbprint != "" {
		if payload == nil {
			return "", altshiftErrors.NewWithTrace(nil_error.New("payload"))
		}
		payload["cnf"] = map[string]any{"jkt": keyThumbprint}
	}

	token := altshiftJwtToken.Token{Payload: payload}

	tokenString, err := token.Encode(signer)
	if err != nil {
		return "", altshiftErrors.New(fmt.Errorf("token encode: %w", err), token, signer)
	}

	return tokenString, nil
}

// VerifyAuthentication reports whether an authentication may still stand behind a session: it must
// not have ended or expired, and its account must not be locked. The failures are
// errors.ErrEndedAuthentication, errors.ErrExpiredAuthentication and errors.ErrLockedAccount.
//
// It is the one statement of those rules, for a refresh deciding whether to issue a new token and
// for a check deciding whether a token already issued may still be acted on.
func VerifyAuthentication(authentication *authenticationPkg.Authentication) error {
	if authentication == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("authentication"))
	}

	authenticationExpiresAt := authentication.ExpiresAt
	if authenticationExpiresAt == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("authentication expires at"))
	}

	if authentication.Ended {
		return errors.ErrEndedAuthentication
	}

	if time.Now().After(*authenticationExpiresAt) {
		return errors.ErrExpiredAuthentication
	}

	account := authentication.Account
	if account == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("authentication account"))
	}

	if account.Locked {
		return errors.ErrLockedAccount
	}

	return nil
}

func (t *Token) Refresh(
	authentication *authenticationPkg.Authentication,
	sessionDuration time.Duration,
	authenticationMethod string,
) (*Token, error) {
	if authentication == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("authentication"))
	}

	if authenticationMethod == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("authentication method"))
	}

	claims := t.Claims
	if claims == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("session token claims"))
	}

	if err := VerifyAuthentication(authentication); err != nil {
		return nil, err
	}

	// VerifyAuthentication has established both.
	authenticationExpiresAt := authentication.ExpiresAt
	account := authentication.Account

	newSessionExpiresAtTime := altshiftTime.Min(authenticationExpiresAt, new(time.Now().Add(sessionDuration)))
	if newSessionExpiresAtTime == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("new session expires at"))
	}

	newSessionClaims := *claims
	newSessionClaims.AuthenticationMethods = []string{authenticationMethod}
	newSessionClaims.ExpiresAt = numeric_date.New(*newSessionExpiresAtTime)
	newSessionClaims.NotBefore = numeric_date.New(time.Now())
	// Roles come from the account row, not the old token, so role changes take
	// effect at the next refresh rather than at the next login.
	newSessionClaims.Roles = account.Roles

	newSessionToken := *t
	newSessionToken.Claims = &newSessionClaims
	newSessionToken.Roles = account.Roles

	return &newSessionToken, nil
}

// ParsePayload reads a token from a verified token's payload: its session claims, as Parse does, and
// the key the token is bound to, if any.
//
// A "cnf" that is there and cannot be read is a parse error, not a token without a binding: a
// confirmation this library cannot check must never come out as a bearer token. RFC 7800 allows
// members other than "jkt"; they are ignored, and "jkt" is required.
func ParsePayload(payload map[string]any) (*Token, error) {
	if payload == nil {
		return nil, nil
	}

	claims, err := session_claims.New(payload)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("session claims new: %w", err), payload)
	}
	if claims == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("session claims"))
	}

	token, err := Parse(claims)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if token == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("session token"))
	}

	if confirmation, ok := payload["cnf"]; ok {
		confirmationMap, ok := confirmation.(map[string]any)
		if !ok {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: the cnf claim is not an object", altshiftErrors.ErrParseError),
				confirmation,
			)
		}

		keyThumbprint, ok := confirmationMap["jkt"].(string)
		if !ok || keyThumbprint == "" {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: the cnf claim holds no key thumbprint", altshiftErrors.ErrParseError),
				confirmationMap,
			)
		}

		token.KeyThumbprint = keyThumbprint
	}

	return token, nil
}

func Parse(claims *session_claims.Claims) (*Token, error) {
	if claims == nil {
		return nil, nil
	}

	var authenticationId, sessionId string
	if id := claims.Id; id != "" {
		var found bool
		authenticationId, sessionId, found = strings.Cut(id, ":")
		if !found {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: %w (jti)", altshiftErrors.ErrParseError, altshiftErrors.ErrBadSplit),
			)
		}
	}

	var subjectId, subjectEmailAddress string
	if sub := claims.Subject; sub != "" {
		var found bool
		subjectId, subjectEmailAddress, found = strings.Cut(sub, ":")
		if !found {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: %w (sub)", altshiftErrors.ErrParseError, altshiftErrors.ErrBadSplit),
			)
		}
	}

	var tenantId, tenantName string
	if azp := claims.AuthorizedParty; azp != "" {
		var found bool
		tenantId, tenantName, found = strings.Cut(azp, ":")
		if !found {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: %w (azp)", altshiftErrors.ErrParseError, altshiftErrors.ErrBadSplit),
			)
		}
	}

	return &Token{
		Claims:              claims,
		AuthenticationId:    authenticationId,
		SessionId:           sessionId,
		SubjectId:           subjectId,
		SubjectEmailAddress: subjectEmailAddress,
		TenantId:            tenantId,
		TenantName:          tenantName,
		Roles:               claims.Roles,
	}, nil
}
