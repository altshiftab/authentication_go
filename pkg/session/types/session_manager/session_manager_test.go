package session_manager

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	databaseErrors "github.com/altshiftab/authentication_go/pkg/database/errors"
	accountPkg "github.com/altshiftab/authentication_go/pkg/database/types/account"
	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	"github.com/altshiftab/authentication_go/pkg/database/types/customer"
	"github.com/altshiftab/authentication_go/pkg/session/types/authentication_method"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_manager/session_manager_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
	altshiftCryptoEddsa "github.com/altshiftab/utils_go/pkg/crypto/eddsa"
	altshiftCryptoInterfaces "github.com/altshiftab/utils_go/pkg/crypto/interfaces"
	altshiftSqlTesting "github.com/altshiftab/utils_go/pkg/database/sql/testing"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claim_strings"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claims/registered_claims"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claims/session_claims"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/numeric_date"
)

const (
	testIssuer       = "test-issuer"
	testCookieDomain = "example.com"
	testEmail        = "user@example.com"
	testAccountId    = "test-account-id"
	testAuthId       = "test-authentication-id"
)

func newTestSigner(t *testing.T) *altshiftCryptoEddsa.Method {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}
	return &altshiftCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey}
}

type stubs struct {
	account        *accountPkg.Account
	selectErr      error
	authentication *authenticationPkg.Authentication
	insertAuthErr  error
	insertDbscErr  error
	dbscChallenges []string
	insertedAuth   int
}

func newManager(t *testing.T, signer altshiftCryptoInterfaces.NamedSigner, s *stubs) *Manager {
	t.Helper()

	db := altshiftSqlTesting.NewDb()

	m, err := New(
		signer,
		db,
		testIssuer,
		testCookieDomain,
		session_manager_config.WithSelectEmailAddressAccount(
			func(_ context.Context, _ string, _ *sql.DB) (*accountPkg.Account, error) {
				if s.selectErr != nil {
					return nil, s.selectErr
				}
				return s.account, nil
			},
		),
		session_manager_config.WithInsertAuthentication(
			func(_ context.Context, _ string, _ []byte, _ time.Duration, _ *authenticationPkg.ClientMetadata, _ *sql.DB) (*authenticationPkg.Authentication, error) {
				s.insertedAuth++
				if s.insertAuthErr != nil {
					return nil, s.insertAuthErr
				}
				return s.authentication, nil
			},
		),
		session_manager_config.WithInsertDbscChallenge(
			func(_ context.Context, challenge string, _ string, _ time.Duration, _ *sql.DB) error {
				s.dbscChallenges = append(s.dbscChallenges, challenge)
				return s.insertDbscErr
			},
		),
	)
	if err != nil {
		t.Fatalf("session manager new: %v", err)
	}
	return m
}

func newAccount() *accountPkg.Account {
	return &accountPkg.Account{
		Id:           testAccountId,
		EmailAddress: testEmail,
		Roles:        []string{"role"},
	}
}

func newAccountWithCustomer() *accountPkg.Account {
	a := newAccount()
	a.Customer = &customer.Customer{Id: "cust-id", Name: "Acme"}
	return a
}

func newAuthentication() *authenticationPkg.Authentication {
	now := time.Now()
	expires := now.Add(time.Hour)
	return &authenticationPkg.Authentication{
		Id:        testAuthId,
		Account:   newAccount(),
		CreatedAt: &now,
		ExpiresAt: &expires,
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	signer := newTestSigner(t)
	db := altshiftSqlTesting.NewDb()
	defer db.Close()

	tests := []struct {
		name         string
		signer       altshiftCryptoInterfaces.NamedSigner
		db           *sql.DB
		issuer       string
		cookieDomain string
		wantErr      bool
	}{
		{name: "success", signer: signer, db: db, issuer: testIssuer, cookieDomain: testCookieDomain},
		{name: "nil signer", signer: nil, db: db, issuer: testIssuer, cookieDomain: testCookieDomain, wantErr: true},
		{name: "nil db", signer: signer, db: nil, issuer: testIssuer, cookieDomain: testCookieDomain, wantErr: true},
		{name: "empty issuer", signer: signer, db: db, issuer: "", cookieDomain: testCookieDomain, wantErr: true},
		{name: "empty cookie domain", signer: signer, db: db, issuer: testIssuer, cookieDomain: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := New(tt.signer, tt.db, tt.issuer, tt.cookieDomain)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestManager_CreateSession(t *testing.T) {
	t.Parallel()

	signer := newTestSigner(t)

	tests := []struct {
		name          string
		authMethod    string
		emailAddress  string
		mutateManager func(*Manager)
		stubs         *stubs

		wantStatus int
		wantDetail string
		wantHeader []string
		wantBareOK bool
	}{
		{
			name:         "success",
			authMethod:   authentication_method.Sso,
			emailAddress: testEmail,
			stubs: &stubs{
				account:        newAccount(),
				authentication: newAuthentication(),
			},
			wantBareOK: true,
			wantHeader: []string{"Set-Cookie", "Secure-Session-Registration"},
		},
		{
			name:         "success with customer",
			authMethod:   authentication_method.Sso,
			emailAddress: testEmail,
			stubs: &stubs{
				account:        newAccountWithCustomer(),
				authentication: newAuthentication(),
			},
			wantBareOK: true,
			wantHeader: []string{"Set-Cookie", "Secure-Session-Registration"},
		},
		{
			name:         "empty auth method",
			authMethod:   "",
			emailAddress: testEmail,
			stubs:        &stubs{account: newAccount(), authentication: newAuthentication()},
		},
		{
			name:          "nil signer",
			authMethod:    authentication_method.Sso,
			emailAddress:  testEmail,
			mutateManager: func(m *Manager) { m.Signer = nil },
			stubs:         &stubs{account: newAccount(), authentication: newAuthentication()},
		},
		{
			name:          "empty dbsc algs",
			authMethod:    authentication_method.Sso,
			emailAddress:  testEmail,
			mutateManager: func(m *Manager) { m.DbscAlgs = nil },
			stubs:         &stubs{account: newAccount(), authentication: newAuthentication()},
		},
		{
			name:          "empty dbsc register path",
			authMethod:    authentication_method.Sso,
			emailAddress:  testEmail,
			mutateManager: func(m *Manager) { m.DbscRegisterPath = "" },
			stubs:         &stubs{account: newAccount(), authentication: newAuthentication()},
		},
		{
			name:          "empty cookie domain",
			authMethod:    authentication_method.Sso,
			emailAddress:  testEmail,
			mutateManager: func(m *Manager) { m.CookieDomain = "" },
			stubs:         &stubs{account: newAccount(), authentication: newAuthentication()},
		},
		{
			name:         "empty email",
			authMethod:   authentication_method.Sso,
			emailAddress: "",
			stubs:        &stubs{account: newAccount(), authentication: newAuthentication()},
		},
		{
			name:         "account not found",
			authMethod:   authentication_method.Sso,
			emailAddress: testEmail,
			stubs:        &stubs{selectErr: sql.ErrNoRows},
			wantStatus:   403,
			wantDetail:   "The email address is not associated with an account.",
		},
		{
			name:         "select account error",
			authMethod:   authentication_method.Sso,
			emailAddress: testEmail,
			stubs:        &stubs{selectErr: errors.New("boom")},
		},
		{
			name:         "nil account from selector",
			authMethod:   authentication_method.Sso,
			emailAddress: testEmail,
			stubs:        &stubs{account: nil, authentication: newAuthentication()},
		},
		{
			name:         "empty account id",
			authMethod:   authentication_method.Sso,
			emailAddress: testEmail,
			stubs: &stubs{
				account:        &accountPkg.Account{EmailAddress: testEmail},
				authentication: newAuthentication(),
			},
		},
		{
			name:         "empty account email",
			authMethod:   authentication_method.Sso,
			emailAddress: testEmail,
			stubs: &stubs{
				account:        &accountPkg.Account{Id: testAccountId},
				authentication: newAuthentication(),
			},
		},
		{
			name:         "customer empty id",
			authMethod:   authentication_method.Sso,
			emailAddress: testEmail,
			stubs: &stubs{
				account: &accountPkg.Account{
					Id:           testAccountId,
					EmailAddress: testEmail,
					Customer:     &customer.Customer{Name: "Acme"},
				},
				authentication: newAuthentication(),
			},
		},
		{
			name:         "customer empty name",
			authMethod:   authentication_method.Sso,
			emailAddress: testEmail,
			stubs: &stubs{
				account: &accountPkg.Account{
					Id:           testAccountId,
					EmailAddress: testEmail,
					Customer:     &customer.Customer{Id: "cust-id"},
				},
				authentication: newAuthentication(),
			},
		},
		{
			name:         "locked account",
			authMethod:   authentication_method.Sso,
			emailAddress: testEmail,
			stubs: &stubs{
				account:        &accountPkg.Account{Id: testAccountId, EmailAddress: testEmail, Locked: true},
				authentication: newAuthentication(),
			},
			wantStatus: 403,
			wantDetail: "The account is locked.",
		},
		{
			name:         "id token reuse",
			authMethod:   authentication_method.Sso,
			emailAddress: testEmail,
			stubs:        &stubs{account: newAccount(), insertAuthErr: databaseErrors.ErrIdTokenAlreadyUsed},
			wantStatus:   409,
			wantDetail:   "This sign-in link has already been used.",
		},
		{
			name:         "insert authentication error",
			authMethod:   authentication_method.Sso,
			emailAddress: testEmail,
			stubs:        &stubs{account: newAccount(), insertAuthErr: errors.New("db down")},
		},
		{
			name:         "nil authentication from inserter",
			authMethod:   authentication_method.Sso,
			emailAddress: testEmail,
			stubs:        &stubs{account: newAccount(), authentication: nil},
		},
		{
			name:         "empty authentication id",
			authMethod:   authentication_method.Sso,
			emailAddress: testEmail,
			stubs: &stubs{
				account: newAccount(),
				authentication: &authenticationPkg.Authentication{
					CreatedAt: ptrTime(time.Now()),
					ExpiresAt: ptrTime(time.Now().Add(time.Hour)),
				},
			},
		},
		{
			name:         "insert dbsc challenge error",
			authMethod:   authentication_method.Sso,
			emailAddress: testEmail,
			stubs:        &stubs{account: newAccount(), authentication: newAuthentication(), insertDbscErr: errors.New("dbsc boom")},
		},
		{
			name:         "nil authentication expires at",
			authMethod:   authentication_method.Sso,
			emailAddress: testEmail,
			stubs: &stubs{
				account: newAccount(),
				authentication: &authenticationPkg.Authentication{
					Id:        testAuthId,
					CreatedAt: ptrTime(time.Now()),
				},
			},
		},
		{
			name:         "nil authentication created at",
			authMethod:   authentication_method.Sso,
			emailAddress: testEmail,
			stubs: &stubs{
				account: newAccount(),
				authentication: &authenticationPkg.Authentication{
					Id:        testAuthId,
					ExpiresAt: ptrTime(time.Now().Add(time.Hour)),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := newManager(t, signer, tt.stubs)
			defer m.Db.Close()

			if tt.mutateManager != nil {
				tt.mutateManager(m)
			}

			resp, respErr := m.CreateSession(context.Background(), tt.authMethod, tt.emailAddress, []byte("hash"))

			if tt.wantBareOK {
				if respErr != nil {
					t.Fatalf("expected ok, got response error: %+v", respErr)
				}
				if resp == nil {
					t.Fatalf("expected response, got nil")
				}
				seen := map[string]bool{}
				for _, h := range resp.Headers {
					seen[h.Name] = true
				}
				for _, want := range tt.wantHeader {
					if !seen[want] {
						t.Errorf("missing expected header %q", want)
					}
				}
				return
			}

			if respErr == nil {
				t.Fatalf("expected response error, got nil (response=%+v)", resp)
			}
			if tt.wantStatus != 0 {
				if respErr.ProblemDetail == nil {
					t.Fatalf("expected problem detail, got nil")
				}
				if respErr.ProblemDetail.Status != tt.wantStatus {
					t.Errorf("status: got %d, want %d", respErr.ProblemDetail.Status, tt.wantStatus)
				}
				if tt.wantDetail != "" && respErr.ProblemDetail.Detail != tt.wantDetail {
					t.Errorf("detail: got %q, want %q", respErr.ProblemDetail.Detail, tt.wantDetail)
				}
			} else if respErr.ServerError == nil {
				t.Errorf("expected server error, got %+v", respErr)
			}
		})
	}
}

func makeSessionToken(t *testing.T, mutate func(*session_claims.Claims)) *session_token.Token {
	t.Helper()
	now := time.Now()
	claims := &session_claims.Claims{
		Claims: registered_claims.Claims{
			Id:        testAuthId + ":session-id",
			Issuer:    testIssuer,
			Subject:   testAccountId + ":" + testEmail,
			Audience:  claim_strings.ClaimStrings{testCookieDomain},
			ExpiresAt: numeric_date.New(now.Add(time.Hour)),
			NotBefore: numeric_date.New(now),
			IssuedAt:  numeric_date.New(now),
		},
		AuthenticationMethods: []string{authentication_method.Sso},
		AuthenticatedAt:       numeric_date.New(now),
		Roles:                 []string{"role"},
	}
	if mutate != nil {
		mutate(claims)
	}
	tok, err := session_token.Parse(claims)
	if err != nil {
		t.Fatalf("session_token.Parse: %v", err)
	}
	return tok
}

func TestManager_RefreshSession(t *testing.T) {
	t.Parallel()

	signer := newTestSigner(t)

	validAuth := newAuthentication()
	endedAuth := &authenticationPkg.Authentication{
		Id:        testAuthId,
		ExpiresAt: ptrTime(time.Now().Add(time.Hour)),
		Ended:     true,
	}
	expiredAuth := &authenticationPkg.Authentication{
		Id:        testAuthId,
		ExpiresAt: ptrTime(time.Now().Add(-time.Hour)),
	}
	lockedAccountAuth := newAuthentication()
	lockedAccountAuth.Account.Locked = true
	nilAccountAuth := newAuthentication()
	nilAccountAuth.Account = nil
	tokenNoClaims := &session_token.Token{}

	tests := []struct {
		name           string
		authentication *authenticationPkg.Authentication
		sessionToken   *session_token.Token
		authMethod     string
		mutateManager  func(*Manager)

		wantStatus int
		wantDetail string
		wantOK     bool
	}{
		{
			name:           "success",
			authentication: validAuth,
			sessionToken:   makeSessionToken(t, nil),
			authMethod:     authentication_method.Refresh,
			wantOK:         true,
		},
		{
			name:           "nil authentication",
			authentication: nil,
			sessionToken:   makeSessionToken(t, nil),
			authMethod:     authentication_method.Refresh,
		},
		{
			name:           "nil session token",
			authentication: validAuth,
			sessionToken:   nil,
			authMethod:     authentication_method.Refresh,
		},
		{
			name:           "empty auth method",
			authentication: validAuth,
			sessionToken:   makeSessionToken(t, nil),
			authMethod:     "",
		},
		{
			name:           "nil signer",
			authentication: validAuth,
			sessionToken:   makeSessionToken(t, nil),
			authMethod:     authentication_method.Refresh,
			mutateManager:  func(m *Manager) { m.Signer = nil },
		},
		{
			name:           "ended authentication",
			authentication: endedAuth,
			sessionToken:   makeSessionToken(t, nil),
			authMethod:     authentication_method.Refresh,
			wantStatus:     400,
			wantDetail:     "The session's authentication has ended.",
		},
		{
			name:           "expired authentication",
			authentication: expiredAuth,
			sessionToken:   makeSessionToken(t, nil),
			authMethod:     authentication_method.Refresh,
			wantStatus:     400,
			wantDetail:     "The session's authentication has expired.",
		},
		{
			name:           "locked account",
			authentication: lockedAccountAuth,
			sessionToken:   makeSessionToken(t, nil),
			authMethod:     authentication_method.Refresh,
			wantStatus:     403,
			wantDetail:     "The account is locked.",
		},
		{
			name:           "nil account",
			authentication: nilAccountAuth,
			sessionToken:   makeSessionToken(t, nil),
			authMethod:     authentication_method.Refresh,
		},
		{
			name:           "session token without claims",
			authentication: validAuth,
			sessionToken:   tokenNoClaims,
			authMethod:     authentication_method.Refresh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			m := newManager(t, signer, &stubs{account: newAccount(), authentication: newAuthentication()})
			defer m.Db.Close()
			if tt.mutateManager != nil {
				tt.mutateManager(m)
			}

			resp, respErr := m.RefreshSession(tt.authentication, tt.sessionToken, tt.authMethod, time.Hour)

			if tt.wantOK {
				if respErr != nil {
					t.Fatalf("expected ok, got response error: %+v", respErr)
				}
				if resp == nil {
					t.Fatalf("expected response, got nil")
				}
				return
			}

			if respErr == nil {
				t.Fatalf("expected response error, got nil (response=%+v)", resp)
			}
			if tt.wantStatus != 0 {
				if respErr.ProblemDetail == nil {
					t.Fatalf("expected problem detail, got nil")
				}
				if respErr.ProblemDetail.Status != tt.wantStatus {
					t.Errorf("status: got %d, want %d", respErr.ProblemDetail.Status, tt.wantStatus)
				}
				if tt.wantDetail != "" && respErr.ProblemDetail.Detail != tt.wantDetail {
					t.Errorf("detail: got %q, want %q", respErr.ProblemDetail.Detail, tt.wantDetail)
				}
			} else if respErr.ServerError == nil {
				t.Errorf("expected server error, got %+v", respErr)
			}
		})
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

func TestManager_RefreshSession_RolesFromAccount(t *testing.T) {
	t.Parallel()

	signer := newTestSigner(t)
	m := newManager(t, signer, &stubs{})
	defer m.Db.Close()

	authentication := newAuthentication()
	authentication.Account.Roles = []string{"updated-role"}

	resp, respErr := m.RefreshSession(
		authentication,
		makeSessionToken(t, nil),
		authentication_method.Refresh,
		time.Hour,
	)
	if respErr != nil {
		t.Fatalf("expected ok, got response error: %+v", respErr)
	}
	if resp == nil {
		t.Fatalf("expected response, got nil")
	}

	var setCookie string
	for _, header := range resp.Headers {
		if header.Name == "Set-Cookie" {
			setCookie = header.Value
		}
	}
	if setCookie == "" {
		t.Fatalf("missing Set-Cookie header")
	}

	cookiePair, _, _ := strings.Cut(setCookie, ";")
	_, tokenString, found := strings.Cut(cookiePair, "=")
	if !found {
		t.Fatalf("malformed cookie pair: %q", cookiePair)
	}

	tokenParts := strings.Split(tokenString, ".")
	if len(tokenParts) != 3 {
		t.Fatalf("unexpected jwt part count: %d", len(tokenParts))
	}
	payloadData, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
	if err != nil {
		t.Fatalf("base64 decode jwt payload: %v", err)
	}
	var payload struct {
		Roles []string `json:"roles"`
	}
	if err := json.Unmarshal(payloadData, &payload); err != nil {
		t.Fatalf("json unmarshal jwt payload: %v", err)
	}

	if want := []string{"updated-role"}; !slices.Equal(payload.Roles, want) {
		t.Errorf("roles: got %v, want %v", payload.Roles, want)
	}
}

// sessionCookieAndTokenExpiry returns the session cookie's expiry and the expiry of the session
// token it carries.
func sessionCookieAndTokenExpiry(t *testing.T, headers []*response.HeaderEntry) (time.Time, time.Time) {
	t.Helper()

	var setCookie string
	for _, header := range headers {
		if header != nil && header.Name == "Set-Cookie" {
			setCookie = header.Value
		}
	}
	if setCookie == "" {
		t.Fatalf("missing Set-Cookie header")
	}

	cookie, err := http.ParseSetCookie(setCookie)
	if err != nil {
		t.Fatalf("parse set cookie: %v", err)
	}

	tokenParts := strings.Split(cookie.Value, ".")
	if len(tokenParts) != 3 {
		t.Fatalf("unexpected jwt part count: %d", len(tokenParts))
	}
	payloadData, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
	if err != nil {
		t.Fatalf("base64 decode jwt payload: %v", err)
	}
	var payload struct {
		ExpiresAt int64 `json:"exp"`
	}
	if err := json.Unmarshal(payloadData, &payload); err != nil {
		t.Fatalf("json unmarshal jwt payload: %v", err)
	}

	return cookie.Expires, time.Unix(payload.ExpiresAt, 0)
}

// TestManager_CookieOutlivesSessionToken asserts that the session cookie expires with the
// authentication rather than with the short-lived session token it carries. Expiring it with the
// token would end the session at the first token expiry, leaving the refresh endpoint unreachable
// and the authentication's own lifetime unused.
func TestManager_CookieOutlivesSessionToken(t *testing.T) {
	t.Parallel()

	const sessionDuration = 15 * time.Minute

	signer := newTestSigner(t)
	authenticationExpiresAt := time.Now().Add(7 * 24 * time.Hour)

	testCases := []struct {
		name    string
		refresh bool
		// A DBSC-bound session is refreshed by the browser when the cookie expires, so its cookie
		// must keep expiring with the token rather than outliving it.
		dbsc bool
	}{
		{name: "create session"},
		{name: "refresh session", refresh: true},
		{name: "dbsc refresh session", refresh: true, dbsc: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			authentication := newAuthentication()
			authentication.ExpiresAt = &authenticationExpiresAt

			m := newManager(t, signer, &stubs{account: newAccount(), authentication: authentication})
			defer m.Db.Close()
			m.InitialSessionDuration = sessionDuration

			var headers []*response.HeaderEntry
			if testCase.refresh {
				refreshMethod := authentication_method.Refresh
				if testCase.dbsc {
					refreshMethod = authentication_method.Dbsc
				}

				resp, respErr := m.RefreshSession(
					authentication,
					makeSessionToken(t, nil),
					refreshMethod,
					sessionDuration,
				)
				if respErr != nil {
					t.Fatalf("refresh session: %+v", respErr)
				}
				headers = resp.Headers
			} else {
				resp, respErr := m.CreateSession(
					context.Background(),
					authentication_method.Sso,
					testEmail,
					[]byte("hash"),
				)
				if respErr != nil {
					t.Fatalf("create session: %+v", respErr)
				}
				headers = resp.Headers
			}

			cookieExpiresAt, tokenExpiresAt := sessionCookieAndTokenExpiry(t, headers)

			if testCase.dbsc {
				if cookieExpiresAt.Sub(tokenExpiresAt).Abs() > time.Minute {
					t.Errorf(
						"cookie expiry %s, expected the session token expiry %s",
						cookieExpiresAt, tokenExpiresAt,
					)
				}
				return
			}

			if cookieExpiresAt.Sub(authenticationExpiresAt).Abs() > time.Minute {
				t.Errorf(
					"cookie expiry %s, expected the authentication expiry %s",
					cookieExpiresAt, authenticationExpiresAt,
				)
			}

			if !tokenExpiresAt.Before(cookieExpiresAt) {
				t.Errorf(
					"session token expiry %s is not before the cookie expiry %s",
					tokenExpiresAt, cookieExpiresAt,
				)
			}

			if expected := time.Now().Add(sessionDuration); tokenExpiresAt.Sub(expected).Abs() > time.Minute {
				t.Errorf("session token expiry %s, expected roughly %s", tokenExpiresAt, expected)
			}
		})
	}
}

// TestManager_MintSession covers issuing a session for an authentication that presents no session
// token, which is how a device bound session is refreshed.
func TestManager_MintSession(t *testing.T) {
	t.Parallel()

	signer := newTestSigner(t)

	testCases := []struct {
		name           string
		mutate         func(*authenticationPkg.Authentication)
		wantOk         bool
		wantStatusCode int
	}{
		{name: "success", wantOk: true},
		{
			name:           "ended authentication",
			mutate:         func(a *authenticationPkg.Authentication) { a.Ended = true },
			wantStatusCode: 400,
		},
		{
			name:           "expired authentication",
			mutate:         func(a *authenticationPkg.Authentication) { a.ExpiresAt = ptrTime(time.Now().Add(-time.Hour)) },
			wantStatusCode: 400,
		},
		{
			name:           "locked account",
			mutate:         func(a *authenticationPkg.Authentication) { a.Account.Locked = true },
			wantStatusCode: 403,
		},
		{
			name:   "missing account identity",
			mutate: func(a *authenticationPkg.Authentication) { a.Account.EmailAddress = "" },
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			authentication := newAuthentication()
			if testCase.mutate != nil {
				testCase.mutate(authentication)
			}

			m := newManager(t, signer, &stubs{account: newAccount(), authentication: authentication})
			defer m.Db.Close()

			resp, respErr := m.MintSession(authentication, authentication_method.Dbsc, 15*time.Minute)

			if !testCase.wantOk {
				if respErr == nil {
					t.Fatalf("expected a response error")
				}
				if problemDetail := respErr.ProblemDetail; problemDetail != nil {
					if problemDetail.Status != testCase.wantStatusCode {
						t.Errorf("got status %d, expected %d", problemDetail.Status, testCase.wantStatusCode)
					}
				} else if testCase.wantStatusCode != 0 {
					t.Errorf("expected a problem detail with status %d", testCase.wantStatusCode)
				}
				return
			}

			if respErr != nil {
				t.Fatalf("mint session: %+v", respErr)
			}

			cookieExpiresAt, tokenExpiresAt := sessionCookieAndTokenExpiry(t, resp.Headers)

			// The session is device bound, so the cookie must expire with the token to keep the
			// browser refreshing it.
			if cookieExpiresAt.Sub(tokenExpiresAt).Abs() > time.Minute {
				t.Errorf("cookie expiry %s, expected the token expiry %s", cookieExpiresAt, tokenExpiresAt)
			}

			if expected := time.Now().Add(15 * time.Minute); tokenExpiresAt.Sub(expected).Abs() > time.Minute {
				t.Errorf("token expiry %s, expected roughly %s", tokenExpiresAt, expected)
			}
		})
	}
}
