package session_token

import (
	"encoding/json/v2"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/Motmedel/utils_go/pkg/crypto/interfaces"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/claims/session_claims"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/numeric_date"
	motmedelJwtToken "github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/token"
	"github.com/Motmedel/utils_go/pkg/schema"
	motmedelTime "github.com/Motmedel/utils_go/pkg/time"
	"github.com/Motmedel/utils_go/pkg/utils"
	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	"github.com/altshiftab/authentication_go/pkg/session/errors"
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
		return "", motmedelErrors.NewWithTrace(nil_error.New("signer"))
	}

	data, err := json.Marshal(t.Claims)
	if err != nil {
		return "", motmedelErrors.NewWithTrace(fmt.Errorf("json marshal (claims): %w", err), t.Claims)
	}

	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return "", motmedelErrors.NewWithTrace(fmt.Errorf("json unmarshal (claims data): %w", err), data)
	}

	token := motmedelJwtToken.Token{Payload: payload}

	tokenString, err := token.Encode(signer)
	if err != nil {
		return "", motmedelErrors.New(fmt.Errorf("token encode: %w", err), token, signer)
	}

	return tokenString, nil
}

func (t *Token) Refresh(
	authentication *authenticationPkg.Authentication,
	sessionDuration time.Duration,
	authenticationMethod string,
) (*Token, error) {
	if authentication == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("authentication"))
	}

	if authenticationMethod == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("authentication method"))
	}

	claims := t.Claims
	if claims == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("session token claims"))
	}

	authenticationExpiresAt := authentication.ExpiresAt
	if authenticationExpiresAt == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("authentication expires at"))
	}

	if authentication.Ended {
		return nil, errors.ErrEndedAuthentication
	}

	if time.Now().After(*authenticationExpiresAt) {
		return nil, errors.ErrExpiredAuthentication
	}

	account := authentication.Account
	if account == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("authentication account"))
	}

	if account.Locked {
		return nil, errors.ErrLockedAccount
	}

	newSessionExpiresAtTime := motmedelTime.Min(authenticationExpiresAt, new(time.Now().Add(sessionDuration)))
	if newSessionExpiresAtTime == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("new session expires at"))
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

func Parse(claims *session_claims.Claims) (*Token, error) {
	if claims == nil {
		return nil, nil
	}

	var authenticationId, sessionId string
	if id := claims.Id; id != "" {
		var found bool
		authenticationId, sessionId, found = strings.Cut(id, ":")
		if !found {
			return nil, motmedelErrors.NewWithTrace(
				fmt.Errorf("%w: %w (jti)", motmedelErrors.ErrParseError, motmedelErrors.ErrBadSplit),
			)
		}
	}

	var subjectId, subjectEmailAddress string
	if sub := claims.Subject; sub != "" {
		var found bool
		subjectId, subjectEmailAddress, found = strings.Cut(sub, ":")
		if !found {
			return nil, motmedelErrors.NewWithTrace(
				fmt.Errorf("%w: %w (sub)", motmedelErrors.ErrParseError, motmedelErrors.ErrBadSplit),
			)
		}
	}

	var tenantId, tenantName string
	if azp := claims.AuthorizedParty; azp != "" {
		var found bool
		tenantId, tenantName, found = strings.Cut(azp, ":")
		if !found {
			return nil, motmedelErrors.NewWithTrace(
				fmt.Errorf("%w: %w (azp)", motmedelErrors.ErrParseError, motmedelErrors.ErrBadSplit),
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
