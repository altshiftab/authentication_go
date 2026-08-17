package session_manager

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	databaseErrors "github.com/altshiftab/authentication_go/pkg/database/errors"
	accountPkg "github.com/altshiftab/authentication_go/pkg/database/types/account"
	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	"github.com/altshiftab/authentication_go/pkg/session"
	sessionErrors "github.com/altshiftab/authentication_go/pkg/session/errors"
	"github.com/altshiftab/authentication_go/pkg/session/types/authentication_method"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_cookie"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_cookie/session_cookie_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_manager/session_manager_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
	altshiftCryptoInterfaces "github.com/altshiftab/utils_go/pkg/crypto/interfaces"
	altshiftDatabase "github.com/altshiftab/utils_go/pkg/database"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	altshiftHttpTypes "github.com/altshiftab/utils_go/pkg/http/types"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	"github.com/altshiftab/utils_go/pkg/iso3166"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claim_strings"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claims/registered_claims"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claims/session_claims"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/numeric_date"
	altshiftTime "github.com/altshiftab/utils_go/pkg/time"
	"github.com/altshiftab/utils_go/pkg/utils"
	altshiftUuid "github.com/altshiftab/utils_go/pkg/uuid"
)

const setCookieHeaderName = "Set-Cookie"

type Manager struct {
	Signer       altshiftCryptoInterfaces.NamedSigner
	Issuer       string
	CookieDomain string
	Db           *sql.DB

	CookieName                string
	InitialSessionDuration    time.Duration
	AuthenticationDuration    time.Duration
	DbscChallengeDuration     time.Duration
	DbscRegisterPath          string
	DbscAlgs                  []string
	SessionCookieOptions      []session_cookie_config.Option
	selectEmailAddressAccount func(ctx context.Context, emailAddress string, database *sql.DB) (*accountPkg.Account, error)
	insertAuthentication      func(ctx context.Context, accountId string, idTokenHash []byte, expirationDuration time.Duration, metadata *authenticationPkg.ClientMetadata, database *sql.DB) (*authenticationPkg.Authentication, error)
	insertDbscChallenge       func(ctx context.Context, challenge string, authenticationId string, expirationDuration time.Duration, db *sql.DB) error
}

// clientMetadataFromContext derives the client information persisted with an
// authentication from the HTTP context carried on ctx. The client IP is taken
// from the first X-Forwarded-For entry (the real client behind the GCP load
// balancer), falling back to RemoteAddr; geo fields come from the load
// balancer's X-Client-Geo-* headers. It returns nil when no HTTP context is
// present (e.g. non-HTTP callers), which InsertAuthentication stores as NULLs.
func clientMetadataFromContext(ctx context.Context) *authenticationPkg.ClientMetadata {
	httpContext, ok := ctx.Value(muxPkg.MuxHttpContextContextKey).(*altshiftHttpTypes.HttpContext)
	if !ok || httpContext == nil {
		return nil
	}

	request := httpContext.Request
	if request == nil {
		return nil
	}

	metadata := &authenticationPkg.ClientMetadata{UserAgent: request.UserAgent()}

	if header := request.Header; header != nil {
		if xForwardedFor := header.Get("X-Forwarded-For"); xForwardedFor != "" {
			client := strings.TrimSpace(strings.Split(xForwardedFor, ",")[0])
			if net.ParseIP(client) != nil {
				metadata.IpAddress = client
			}
		}

		metadata.IpAddressCity = header.Get("X-Client-Geo-City-Name")

		if countryIsoCode := header.Get("X-Client-Geo-Country-Iso-Code"); countryIsoCode != "" {
			metadata.IpAddressCountry = iso3166.CountryName(countryIsoCode)
		}
	}

	if metadata.IpAddress == "" {
		if remoteAddr := request.RemoteAddr; remoteAddr != "" {
			if host, _, err := net.SplitHostPort(remoteAddr); err == nil && net.ParseIP(host) != nil {
				metadata.IpAddress = host
			}
		}
	}

	return metadata
}

func (m *Manager) CreateSession(ctx context.Context, authMethod string, emailAddress string, idTokenHash []byte) (*response.Response, *response_error.ResponseError) {
	if authMethod == "" {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(empty_error.New("authentication method")),
		}
	}

	signer := m.Signer
	if utils.IsNil(signer) {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("signer")),
		}
	}

	dbscAlgs := m.DbscAlgs
	if len(dbscAlgs) == 0 {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(empty_error.New("dbsc algs")),
		}
	}

	dbscRegisterPath := m.DbscRegisterPath
	if dbscRegisterPath == "" {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(empty_error.New("dbsc register path")),
		}
	}

	audience := m.CookieDomain
	if audience == "" {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(empty_error.New("audience (cookie domain)")),
		}
	}

	if emailAddress == "" {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(empty_error.New("email address")),
		}
	}

	selectAccountCtx, selectAccountCtxCancel := altshiftDatabase.MakeTimeoutCtx(ctx)
	defer selectAccountCtxCancel()
	account, err := m.selectEmailAddressAccount(selectAccountCtx, emailAddress, m.Db)
	wrappedErr := altshiftErrors.New(fmt.Errorf("select email address account: %w", err), emailAddress)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &response_error.ResponseError{
				ClientError: wrappedErr,
				ProblemDetail: problem_detail.New(
					http.StatusForbidden,
					problem_detail_config.WithDetail("The email address is not associated with an account."),
				),
			}
		}
		return nil, &response_error.ResponseError{ServerError: wrappedErr}
	}
	if account == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("account")),
		}
	}
	accountId := account.Id
	if accountId == "" {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(empty_error.New("account id")),
		}
	}

	accountEmailAddress := account.EmailAddress
	if accountEmailAddress == "" {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(empty_error.New("authentication account email address")),
		}
	}

	var authorizedParty string
	customer := account.Customer
	if customer != nil {
		customerId := customer.Id
		if customerId == "" {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(empty_error.New("authentication account customer id")),
			}
		}

		customerName := customer.Name
		if customerName == "" {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(empty_error.New("authentication account customer name")),
			}
		}

		authorizedParty = strings.Join([]string{customerId, customerName}, ":")
	}

	if account.Locked {
		return nil, &response_error.ResponseError{
			ProblemDetail: problem_detail.New(
				http.StatusForbidden,
				problem_detail_config.WithDetail("The account is locked."),
			),
		}
	}

	clientMetadata := clientMetadataFromContext(ctx)

	insertDbCtx, insertDbCancel := altshiftDatabase.MakeTimeoutCtx(ctx)
	defer insertDbCancel()

	authentication, err := m.insertAuthentication(insertDbCtx, accountId, idTokenHash, m.AuthenticationDuration, clientMetadata, m.Db)
	if err != nil {
		wrappedErr := altshiftErrors.New(fmt.Errorf("insert authentication: %w", err))
		if errors.Is(err, databaseErrors.ErrIdTokenAlreadyUsed) {
			return nil, &response_error.ResponseError{
				ClientError: wrappedErr,
				ProblemDetail: problem_detail.New(
					http.StatusConflict,
					problem_detail_config.WithDetail("This sign-in link has already been used."),
				),
			}
		}
		return nil, &response_error.ResponseError{ServerError: wrappedErr}
	}
	if authentication == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("authentication")),
		}
	}

	authenticationId := authentication.Id
	if authenticationId == "" {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(empty_error.New("authentication id")),
		}
	}

	dbscChallenge, err := session.GenerateDbscChallenge()
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("generate dbsc challenge: %w", err)),
		}
	}
	if dbscChallenge == "" {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(empty_error.New("dbsc challenge")),
		}
	}

	dbInsertCtx, dbInsertCtxCancel := altshiftDatabase.MakeTimeoutCtx(ctx)
	defer dbInsertCtxCancel()
	err = m.insertDbscChallenge(dbInsertCtx, dbscChallenge, authenticationId, m.DbscChallengeDuration, m.Db)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.New(
				fmt.Errorf("insert dbsc challenge: %w", err),
				authenticationId,
				dbscChallenge,
			),
		}
	}

	authenticationExpiresAt := authentication.ExpiresAt
	if authenticationExpiresAt == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("authentication expires at")),
		}
	}

	authenticationCreatedAt := authentication.CreatedAt
	if authenticationCreatedAt == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("authentication created at")),
		}
	}

	issuedAt := numeric_date.New(time.Now())

	sessionExpiresAt := altshiftTime.Min(new(time.Now().Add(m.InitialSessionDuration)), authenticationExpiresAt)
	if sessionExpiresAt == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("session expires at")),
		}
	}

	audienceClaimString, err := claim_strings.Convert(audience)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.New(fmt.Errorf("claim strings convert: %w", err), audience),
		}
	}

	sessionClaims := &session_claims.Claims{
		Claims: registered_claims.Claims{
			Id:        strings.Join([]string{authenticationId, altshiftUuid.NewString()}, ":"),
			Issuer:    m.Issuer,
			Audience:  audienceClaimString,
			Subject:   strings.Join([]string{accountId, accountEmailAddress}, ":"),
			ExpiresAt: numeric_date.New(*sessionExpiresAt),
			NotBefore: issuedAt,
			IssuedAt:  issuedAt,
		},
		AuthenticationMethods: []string{authMethod},
		AuthenticatedAt:       numeric_date.New(*authenticationCreatedAt),
		AuthorizedParty:       authorizedParty,
		Roles:                 account.Roles,
	}
	sessionToken, err := session_token.Parse(sessionClaims)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.New(fmt.Errorf("session token parse: %w", err), sessionClaims),
		}
	}
	if sessionToken == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("session token")),
		}
	}

	sessionTokenString, err := sessionToken.Encode(m.Signer)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.New(
				fmt.Errorf("new session token encode: %w", err),
				sessionToken, signer,
			),
		}
	}

	// The cookie outlives the session token it carries: the token is short-lived and renewed
	// through the refresh endpoint, which is reachable only for as long as the browser keeps
	// sending the cookie. Expiring the cookie with the token would end the session at the first
	// token expiry, making the authentication's own lifetime unreachable.
	sessionCookie, err := session_cookie.New(
		sessionTokenString,
		*authenticationExpiresAt,
		m.CookieName,
		m.CookieDomain,
		m.SessionCookieOptions...,
	)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.New(
				fmt.Errorf("session cookie new: %w", err),
				sessionTokenString, authenticationExpiresAt, m.CookieName, m.CookieDomain,
			),
		}
	}
	if sessionCookie == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("session cookie")),
		}
	}

	return &response.Response{
		Headers: []*response.HeaderEntry{
			{
				Name:  setCookieHeaderName,
				Value: sessionCookie.String(),
			},
			{
				Name: session.DbscSessionRegistrationHeaderName,
				Value: fmt.Sprintf(
					"(%s); path=\"%s\"; challenge=\"%s\"",
					strings.Join(dbscAlgs, " "),
					dbscRegisterPath,
					dbscChallenge,
				),
			},
		},
	}, nil
}

func (m *Manager) RefreshSession(
	authentication *authenticationPkg.Authentication,
	sessionToken *session_token.Token,
	authenticationMethod string,
	sessionDuration time.Duration,
) (*response.Response, *response_error.ResponseError) {
	if authentication == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("authentication")),
		}
	}

	if sessionToken == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("session token")),
		}
	}

	if authenticationMethod == "" {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(empty_error.New("authentication method")),
		}
	}

	signer := m.Signer
	if utils.IsNil(signer) {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("signer")),
		}
	}

	newSessionToken, err := sessionToken.Refresh(authentication, sessionDuration, authenticationMethod)
	if err != nil {
		if errors.Is(err, sessionErrors.ErrEndedAuthentication) {
			return nil, &response_error.ResponseError{
				Headers: []*response.HeaderEntry{{Name: "Clear-Site-Data", Value: `"cookies"`}},
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The session's authentication has ended."),
				),
			}
		} else if errors.Is(err, sessionErrors.ErrExpiredAuthentication) {
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The session's authentication has expired."),
				),
			}
		} else if errors.Is(err, sessionErrors.ErrLockedAccount) {
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusForbidden,
					problem_detail_config.WithDetail("The account is locked."),
				),
			}
		}

		return nil, &response_error.ResponseError{ServerError: fmt.Errorf("session token refresh: %w", err)}
	}
	if newSessionToken == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("new session token")),
		}
	}

	newSessionTokenClaims := newSessionToken.Claims
	if newSessionTokenClaims == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("new session token claims")),
		}
	}
	newSessionTokenExpiresAt := newSessionTokenClaims.ExpiresAt
	if newSessionTokenExpiresAt == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("new session token claims expires at")),
		}
	}

	newSessionTokenString, err := newSessionToken.Encode(signer)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.New(
				fmt.Errorf("new session token encode: %w", err),
				newSessionToken, signer,
			),
		}
	}

	authenticationExpiresAt := authentication.ExpiresAt
	if authenticationExpiresAt == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("authentication expires at")),
		}
	}

	// As when the session is created, the cookie outlives the token it carries and expires with
	// the authentication instead, so that a client can reach the refresh endpoint with an expired
	// token. A DBSC-bound session is the exception: there the browser performs the refresh when
	// the cookie expires, so its cookie must keep expiring with the token to stay armed.
	cookieExpiresAt := *authenticationExpiresAt
	if authenticationMethod == authentication_method.Dbsc {
		cookieExpiresAt = newSessionTokenExpiresAt.Time
	}

	sessionCookie, err := session_cookie.New(
		newSessionTokenString,
		cookieExpiresAt,
		m.CookieName,
		m.CookieDomain,
		m.SessionCookieOptions...,
	)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.New(
				fmt.Errorf("session cookie new: %w", err),
				newSessionTokenString, cookieExpiresAt, m.CookieName, m.CookieDomain,
			),
		}
	}
	if sessionCookie == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("session cookie")),
		}
	}

	return &response.Response{
		Headers: []*response.HeaderEntry{{Name: setCookieHeaderName, Value: sessionCookie.String()}},
	}, nil
}

// MintSession issues a session for an authentication that presents no session token, and returns the
// response carrying it as a cookie. A DBSC refresh arrives without the bound cookie — that is what
// triggers it — so there is no previous token whose claims could be carried over, as RefreshSession
// does. The authentication is verified the same way: it must not have ended or expired, and the
// account must not be locked.
//
// As elsewhere, the cookie expires with the token when the session is device bound, so that the
// browser keeps refreshing it.
func (m *Manager) MintSession(
	authentication *authenticationPkg.Authentication,
	authenticationMethod string,
	sessionDuration time.Duration,
) (*response.Response, *response_error.ResponseError) {
	if authentication == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("authentication")),
		}
	}

	if authenticationMethod == "" {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(empty_error.New("authentication method")),
		}
	}

	signer := m.Signer
	if utils.IsNil(signer) {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("signer")),
		}
	}

	audience := m.CookieDomain
	if audience == "" {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(empty_error.New("audience (cookie domain)")),
		}
	}

	authenticationId := authentication.Id
	if authenticationId == "" {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(empty_error.New("authentication id")),
		}
	}

	authenticationExpiresAt := authentication.ExpiresAt
	if authenticationExpiresAt == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("authentication expires at")),
		}
	}

	authenticationCreatedAt := authentication.CreatedAt
	if authenticationCreatedAt == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("authentication created at")),
		}
	}

	if authentication.Ended {
		return nil, &response_error.ResponseError{
			Headers: []*response.HeaderEntry{{Name: "Clear-Site-Data", Value: `"cookies"`}},
			ProblemDetail: problem_detail.New(
				http.StatusBadRequest,
				problem_detail_config.WithDetail("The session's authentication has ended."),
			),
		}
	}

	if time.Now().After(*authenticationExpiresAt) {
		return nil, &response_error.ResponseError{
			ProblemDetail: problem_detail.New(
				http.StatusBadRequest,
				problem_detail_config.WithDetail("The session's authentication has expired."),
			),
		}
	}

	account := authentication.Account
	if account == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("authentication account")),
		}
	}

	if account.Locked {
		return nil, &response_error.ResponseError{
			ProblemDetail: problem_detail.New(
				http.StatusForbidden,
				problem_detail_config.WithDetail("The account is locked."),
			),
		}
	}

	accountId := account.Id
	if accountId == "" {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(empty_error.New("authentication account id")),
		}
	}

	accountEmailAddress := account.EmailAddress
	if accountEmailAddress == "" {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(empty_error.New("authentication account email address")),
		}
	}

	var authorizedParty string
	if customer := account.Customer; customer != nil {
		if customer.Id == "" {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(empty_error.New("authentication account customer id")),
			}
		}
		if customer.Name == "" {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(empty_error.New("authentication account customer name")),
			}
		}
		authorizedParty = strings.Join([]string{customer.Id, customer.Name}, ":")
	}

	sessionExpiresAt := altshiftTime.Min(new(time.Now().Add(sessionDuration)), authenticationExpiresAt)
	if sessionExpiresAt == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("session expires at")),
		}
	}

	audienceClaimString, err := claim_strings.Convert(audience)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.New(fmt.Errorf("claim strings convert: %w", err), audience),
		}
	}

	issuedAt := numeric_date.New(time.Now())

	sessionClaims := &session_claims.Claims{
		Claims: registered_claims.Claims{
			Id:        strings.Join([]string{authenticationId, altshiftUuid.NewString()}, ":"),
			Issuer:    m.Issuer,
			Audience:  audienceClaimString,
			Subject:   strings.Join([]string{accountId, accountEmailAddress}, ":"),
			ExpiresAt: numeric_date.New(*sessionExpiresAt),
			NotBefore: issuedAt,
			IssuedAt:  issuedAt,
		},
		AuthenticationMethods: []string{authenticationMethod},
		AuthenticatedAt:       numeric_date.New(*authenticationCreatedAt),
		AuthorizedParty:       authorizedParty,
		Roles:                 account.Roles,
	}

	sessionToken, err := session_token.Parse(sessionClaims)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.New(fmt.Errorf("session token parse: %w", err), sessionClaims),
		}
	}
	if sessionToken == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("session token")),
		}
	}

	sessionTokenString, err := sessionToken.Encode(signer)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.New(fmt.Errorf("session token encode: %w", err), sessionToken),
		}
	}

	cookieExpiresAt := *authenticationExpiresAt
	if authenticationMethod == authentication_method.Dbsc {
		cookieExpiresAt = *sessionExpiresAt
	}

	sessionCookie, err := session_cookie.New(
		sessionTokenString,
		cookieExpiresAt,
		m.CookieName,
		m.CookieDomain,
		m.SessionCookieOptions...,
	)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.New(
				fmt.Errorf("session cookie new: %w", err),
				cookieExpiresAt, m.CookieName, m.CookieDomain,
			),
		}
	}
	if sessionCookie == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("session cookie")),
		}
	}

	return &response.Response{
		Headers: []*response.HeaderEntry{{Name: setCookieHeaderName, Value: sessionCookie.String()}},
	}, nil
}

func New(
	signer altshiftCryptoInterfaces.NamedSigner,
	db *sql.DB,
	issuer string,
	cookieDomain string,
	options ...session_manager_config.Option,
) (*Manager, error) {
	if utils.IsNil(signer) {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("signer"))
	}

	if db == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("db"))
	}

	if issuer == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("issuer"))
	}

	if cookieDomain == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("cookie domain"))
	}

	config := session_manager_config.New(options...)

	return &Manager{
		Signer:                    signer,
		Db:                        db,
		Issuer:                    issuer,
		CookieDomain:              cookieDomain,
		CookieName:                config.CookieName,
		InitialSessionDuration:    config.InitialSessionDuration,
		AuthenticationDuration:    config.AuthenticationDuration,
		DbscChallengeDuration:     config.DbscChallengeDuration,
		DbscRegisterPath:          config.DbscRegisterPath,
		DbscAlgs:                  config.DbscAlgs,
		SessionCookieOptions:      config.SessionCookieOptions,
		selectEmailAddressAccount: config.SelectEmailAddressAccount,
		insertAuthentication:      config.InsertAuthentication,
		insertDbscChallenge:       config.InsertDbscChallenge,
	}, nil
}
