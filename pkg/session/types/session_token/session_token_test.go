package session_token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	accountPkg "github.com/altshiftab/authentication_go/pkg/database/types/account"
	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	sessionErrors "github.com/altshiftab/authentication_go/pkg/session/errors"
	altshiftCryptoEddsa "github.com/altshiftab/utils_go/pkg/crypto/eddsa"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claims/registered_claims"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claims/session_claims"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/numeric_date"
)

func makeClaims(id, subject, authorizedParty string, roles []string) *session_claims.Claims {
	now := time.Now()
	return &session_claims.Claims{
		Claims: registered_claims.Claims{
			Issuer:    "test-issuer",
			Subject:   subject,
			ExpiresAt: numeric_date.New(now.Add(time.Hour)),
			IssuedAt:  numeric_date.New(now),
			Id:        id,
		},
		Roles: roles,
	}
}

func TestParse(t *testing.T) {
	t.Parallel()

	t.Run("nil claims", func(t *testing.T) {
		t.Parallel()

		token, err := Parse(nil)
		if token != nil || err != nil {
			t.Errorf("expected nil token and error, got (%v, %v)", token, err)
		}
	})

	t.Run("full claims", func(t *testing.T) {
		t.Parallel()

		claims := makeClaims("auth-id:session-id", "subject-id:test@example.com", "", []string{"role-a"})
		claims.AuthorizedParty = "tenant-id:Tenant Name"

		token, err := Parse(claims)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if token == nil {
			t.Fatalf("nil token")
		}

		if token.AuthenticationId != "auth-id" || token.SessionId != "session-id" {
			t.Errorf("id fields: got %q, %q", token.AuthenticationId, token.SessionId)
		}
		if token.SubjectId != "subject-id" || token.SubjectEmailAddress != "test@example.com" {
			t.Errorf("subject fields: got %q, %q", token.SubjectId, token.SubjectEmailAddress)
		}
		if token.TenantId != "tenant-id" || token.TenantName != "Tenant Name" {
			t.Errorf("tenant fields: got %q, %q", token.TenantId, token.TenantName)
		}
		if !slices.Equal(token.Roles, []string{"role-a"}) {
			t.Errorf("roles: got %v", token.Roles)
		}
	})

	t.Run("empty optional claims", func(t *testing.T) {
		t.Parallel()

		token, err := Parse(&session_claims.Claims{})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if token == nil {
			t.Fatalf("nil token")
		}

		if token.AuthenticationId != "" || token.SubjectId != "" || token.TenantId != "" {
			t.Errorf("expected empty fields, got %+v", token)
		}
	})

	badSplitCases := []struct {
		name   string
		claims *session_claims.Claims
	}{
		{name: "bad jti", claims: makeClaims("no-separator", "", "", nil)},
		{name: "bad sub", claims: makeClaims("", "no-separator", "", nil)},
		{
			name: "bad azp",
			claims: func() *session_claims.Claims {
				claims := makeClaims("", "", "", nil)
				claims.AuthorizedParty = "no-separator"
				return claims
			}(),
		},
	}

	for _, testCase := range badSplitCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if _, err := Parse(testCase.claims); !errors.Is(err, altshiftErrors.ErrParseError) {
				t.Errorf("expected parse error, got %v", err)
			}
		})
	}
}

func TestGetUser(t *testing.T) {
	t.Parallel()

	t.Run("with tenant", func(t *testing.T) {
		t.Parallel()

		token := &Token{
			SubjectId:           "subject-id",
			SubjectEmailAddress: "test@example.com",
			TenantId:            "tenant-id",
			TenantName:          "Tenant Name",
			Roles:               []string{"role-a"},
		}

		user := token.GetUser()
		if user == nil {
			t.Fatalf("nil user")
		}
		if user.Id != "subject-id" || user.Email != "" {
			t.Errorf("user fields: got %+v, want the id and no email address", user)
		}
		if user.Group == nil || user.Group.Id != "tenant-id" || user.Group.Name != "Tenant Name" {
			t.Errorf("group: got %+v", user.Group)
		}
		if !slices.Equal(user.Roles, []string{"role-a"}) {
			t.Errorf("roles: got %v", user.Roles)
		}
	})

	t.Run("without tenant", func(t *testing.T) {
		t.Parallel()

		user := (&Token{SubjectId: "subject-id"}).GetUser()
		if user == nil {
			t.Fatalf("nil user")
		}
		if user.Group != nil {
			t.Errorf("unexpected group: %+v", user.Group)
		}
	})
}

func TestUserAttributes(t *testing.T) {
	t.Parallel()

	t.Run("with tenant", func(t *testing.T) {
		t.Parallel()

		token := &Token{
			SubjectId:           "subject-id",
			SubjectEmailAddress: "test@example.com",
			TenantId:            "tenant-id",
			TenantName:          "Tenant Name",
			Roles:               []string{"role-a"},
		}

		attributes := token.UserAttributes()
		if attributeCount := len(attributes); attributeCount != 3 {
			t.Errorf("attributes: got %d, want 3", attributeCount)
		}
		if written := fmt.Sprint(attributes...); strings.Contains(written, "test@example.com") {
			t.Errorf("the email address is among the attributes: %s", written)
		}
	})

	t.Run("without tenant", func(t *testing.T) {
		t.Parallel()

		if attributeCount := len((&Token{}).UserAttributes()); attributeCount != 2 {
			t.Errorf("attributes: got %d, want 2", attributeCount)
		}
	})
}

func TestEncode(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}
	signer := &altshiftCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey}

	t.Run("nil signer", func(t *testing.T) {
		t.Parallel()

		if _, err := (&Token{}).Encode(nil); err == nil {
			t.Errorf("expected error")
		}
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		claims := makeClaims("auth-id:session-id", "subject-id:test@example.com", "", []string{"role-a"})
		token, err := Parse(claims)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}

		tokenString, err := token.Encode(signer)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}

		tokenParts := strings.Split(tokenString, ".")
		if len(tokenParts) != 3 {
			t.Fatalf("jwt part count: got %d", len(tokenParts))
		}

		payloadData, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
		if err != nil {
			t.Fatalf("base64 decode payload: %v", err)
		}

		var payload struct {
			Subject string   `json:"sub"`
			Id      string   `json:"jti"`
			Roles   []string `json:"roles"`
		}
		if err := json.Unmarshal(payloadData, &payload); err != nil {
			t.Fatalf("json unmarshal payload: %v", err)
		}

		if payload.Subject != "subject-id:test@example.com" || payload.Id != "auth-id:session-id" {
			t.Errorf("payload: got %+v", payload)
		}
		if !slices.Equal(payload.Roles, []string{"role-a"}) {
			t.Errorf("roles: got %v", payload.Roles)
		}
	})
}

func makeAuthentication(expiresAt time.Time) *authenticationPkg.Authentication {
	return &authenticationPkg.Authentication{
		Id:        "auth-id",
		ExpiresAt: &expiresAt,
		Account:   &accountPkg.Account{Roles: []string{"account-role"}},
	}
}

func TestRefresh(t *testing.T) {
	t.Parallel()

	baseToken := &Token{Claims: makeClaims("auth-id:session-id", "subject-id:test@example.com", "", []string{"old-role"})}

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		authentication := makeAuthentication(time.Now().Add(24 * time.Hour))
		refreshed, err := baseToken.Refresh(authentication, time.Hour, "refresh")
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}
		if refreshed == nil || refreshed.Claims == nil {
			t.Fatalf("nil refreshed token or claims")
		}

		if !slices.Equal(refreshed.Roles, []string{"account-role"}) {
			t.Errorf("roles: got %v", refreshed.Roles)
		}
		if !slices.Equal(refreshed.Claims.Roles, []string{"account-role"}) {
			t.Errorf("claims roles: got %v", refreshed.Claims.Roles)
		}
		if !slices.Equal(refreshed.Claims.AuthenticationMethods, []string{"refresh"}) {
			t.Errorf("authentication methods: got %v", refreshed.Claims.AuthenticationMethods)
		}

		// The session must not outlive its duration when the authentication expiry is far away.
		expiresAt := refreshed.Claims.ExpiresAt.Time
		if remaining := time.Until(expiresAt); remaining > time.Hour || remaining < 55*time.Minute {
			t.Errorf("expires at: got %v", expiresAt)
		}
	})

	t.Run("session capped by authentication expiry", func(t *testing.T) {
		t.Parallel()

		authenticationExpiresAt := time.Now().Add(10 * time.Minute)
		refreshed, err := baseToken.Refresh(makeAuthentication(authenticationExpiresAt), time.Hour, "refresh")
		if err != nil {
			t.Fatalf("refresh: %v", err)
		}

		// numeric_date truncates to second precision.
		expiresAt := refreshed.Claims.ExpiresAt.Time
		if difference := expiresAt.Sub(authenticationExpiresAt).Abs(); difference >= time.Second {
			t.Errorf("expires at: got %v, want %v", expiresAt, authenticationExpiresAt)
		}
	})

	errorCases := []struct {
		name           string
		token          *Token
		authentication *authenticationPkg.Authentication
		method         string
		expectedErr    error
	}{
		{name: "nil authentication", token: baseToken, method: "refresh"},
		{
			name:           "empty method",
			token:          baseToken,
			authentication: makeAuthentication(time.Now().Add(time.Hour)),
		},
		{
			name:           "nil claims",
			token:          &Token{},
			authentication: makeAuthentication(time.Now().Add(time.Hour)),
			method:         "refresh",
		},
		{
			name:           "nil expires at",
			token:          baseToken,
			authentication: &authenticationPkg.Authentication{Account: &accountPkg.Account{}},
			method:         "refresh",
		},
		{
			name:  "ended authentication",
			token: baseToken,
			authentication: func() *authenticationPkg.Authentication {
				authentication := makeAuthentication(time.Now().Add(time.Hour))
				authentication.Ended = true
				return authentication
			}(),
			method:      "refresh",
			expectedErr: sessionErrors.ErrEndedAuthentication,
		},
		{
			name:           "expired authentication",
			token:          baseToken,
			authentication: makeAuthentication(time.Now().Add(-time.Hour)),
			method:         "refresh",
			expectedErr:    sessionErrors.ErrExpiredAuthentication,
		},
		{
			name:  "nil account",
			token: baseToken,
			authentication: func() *authenticationPkg.Authentication {
				authentication := makeAuthentication(time.Now().Add(time.Hour))
				authentication.Account = nil
				return authentication
			}(),
			method: "refresh",
		},
		{
			name:  "locked account",
			token: baseToken,
			authentication: func() *authenticationPkg.Authentication {
				authentication := makeAuthentication(time.Now().Add(time.Hour))
				authentication.Account.Locked = true
				return authentication
			}(),
			method:      "refresh",
			expectedErr: sessionErrors.ErrLockedAccount,
		},
	}

	for _, testCase := range errorCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, err := testCase.token.Refresh(testCase.authentication, time.Hour, testCase.method)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if testCase.expectedErr != nil && !errors.Is(err, testCase.expectedErr) {
				t.Errorf("expected %v, got %v", testCase.expectedErr, err)
			}
		})
	}
}

func TestVerifyAuthentication(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		authentication func() *authenticationPkg.Authentication
		wantErr        bool
		expectedErr    error
	}{
		{
			name:           "standing",
			authentication: func() *authenticationPkg.Authentication { return makeAuthentication(time.Now().Add(time.Hour)) },
		},
		{
			name:           "nil authentication",
			authentication: func() *authenticationPkg.Authentication { return nil },
			wantErr:        true,
		},
		{
			name: "nil expires at",
			authentication: func() *authenticationPkg.Authentication {
				return &authenticationPkg.Authentication{Account: &accountPkg.Account{}}
			},
			wantErr: true,
		},
		{
			name: "ended",
			authentication: func() *authenticationPkg.Authentication {
				authentication := makeAuthentication(time.Now().Add(time.Hour))
				authentication.Ended = true
				return authentication
			},
			wantErr:     true,
			expectedErr: sessionErrors.ErrEndedAuthentication,
		},
		{
			name:           "expired",
			authentication: func() *authenticationPkg.Authentication { return makeAuthentication(time.Now().Add(-time.Hour)) },
			wantErr:        true,
			expectedErr:    sessionErrors.ErrExpiredAuthentication,
		},
		{
			name: "nil account",
			authentication: func() *authenticationPkg.Authentication {
				authentication := makeAuthentication(time.Now().Add(time.Hour))
				authentication.Account = nil
				return authentication
			},
			wantErr: true,
		},
		{
			name: "locked",
			authentication: func() *authenticationPkg.Authentication {
				authentication := makeAuthentication(time.Now().Add(time.Hour))
				authentication.Account.Locked = true
				return authentication
			},
			wantErr:     true,
			expectedErr: sessionErrors.ErrLockedAccount,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := VerifyAuthentication(testCase.authentication())
			if !testCase.wantErr {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error")
			}
			if testCase.expectedErr != nil && !errors.Is(err, testCase.expectedErr) {
				t.Errorf("expected %v, got %v", testCase.expectedErr, err)
			}
		})
	}
}

// decodePayload reads an encoded token's payload without verifying it, as the tests of what Encode
// writes need.
func decodePayload(t *testing.T, tokenString string) map[string]any {
	t.Helper()

	tokenParts := strings.Split(tokenString, ".")
	if len(tokenParts) != 3 {
		t.Fatalf("jwt part count: got %d", len(tokenParts))
	}

	payloadData, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
	if err != nil {
		t.Fatalf("base64 decode payload: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadData, &payload); err != nil {
		t.Fatalf("json unmarshal payload: %v", err)
	}

	return payload
}

func TestEncode_KeyThumbprint(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}
	signer := &altshiftCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey}

	testCases := []struct {
		name          string
		keyThumbprint string
		wantCnf       any
	}{
		{name: "a bound token", keyThumbprint: "thumbprint", wantCnf: map[string]any{"jkt": "thumbprint"}},
		{name: "a bearer token", keyThumbprint: ""},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			token, err := Parse(makeClaims("auth-id:session-id", "subject-id:test@example.com", "", nil))
			if err != nil {
				t.Fatalf("%s: parse: %v", testCase.name, err)
			}
			token.KeyThumbprint = testCase.keyThumbprint

			tokenString, err := token.Encode(signer)
			if err != nil {
				t.Fatalf("%s: encode: %v", testCase.name, err)
			}

			cnf, ok := decodePayload(t, tokenString)["cnf"]
			if testCase.wantCnf == nil {
				if ok {
					t.Errorf("%s: cnf = %v, want none", testCase.name, cnf)
				}
				return
			}
			cnfMap, _ := cnf.(map[string]any)
			wantMap, _ := testCase.wantCnf.(map[string]any)
			if cnfMap == nil || cnfMap["jkt"] != wantMap["jkt"] || len(cnfMap) != len(wantMap) {
				t.Errorf("%s: cnf = %v, want %v", testCase.name, cnf, testCase.wantCnf)
			}
		})
	}
}

func TestParsePayload(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}
	signer := &altshiftCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey}

	// The payload of a real token, so that what ParsePayload reads is what Encode writes.
	payloadWith := func(cnf any, hasCnf bool) map[string]any {
		claims := makeClaims("auth-id:session-id", "subject-id:test@example.com", "", []string{"role-a"})
		// Set here, as makeClaims leaves its authorizedParty argument unused.
		claims.AuthorizedParty = "tenant-id:tenant-name"
		token, err := Parse(claims)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		tokenString, err := token.Encode(signer)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		payload := decodePayload(t, tokenString)
		if hasCnf {
			payload["cnf"] = cnf
		}
		return payload
	}

	testCases := []struct {
		name              string
		payload           map[string]any
		wantKeyThumbprint string
		wantErr           error
	}{
		{name: "no cnf", payload: payloadWith(nil, false)},
		{
			name:              "a key thumbprint",
			payload:           payloadWith(map[string]any{"jkt": "thumbprint"}, true),
			wantKeyThumbprint: "thumbprint",
		},
		{
			// RFC 7800 allows other confirmation members; "jkt" is the one this library checks.
			name:              "a key thumbprint and another member",
			payload:           payloadWith(map[string]any{"jkt": "thumbprint", "x5t#S256": "other"}, true),
			wantKeyThumbprint: "thumbprint",
		},
		{name: "cnf as a string", payload: payloadWith("thumbprint", true), wantErr: altshiftErrors.ErrParseError},
		{name: "cnf as null", payload: payloadWith(nil, true), wantErr: altshiftErrors.ErrParseError},
		{name: "cnf empty", payload: payloadWith(map[string]any{}, true), wantErr: altshiftErrors.ErrParseError},
		{
			// Bound by a method this library cannot check: refused rather than read as a bearer token.
			name:    "cnf without jkt",
			payload: payloadWith(map[string]any{"x5t#S256": "other"}, true),
			wantErr: altshiftErrors.ErrParseError,
		},
		{name: "jkt empty", payload: payloadWith(map[string]any{"jkt": ""}, true), wantErr: altshiftErrors.ErrParseError},
		{name: "jkt a number", payload: payloadWith(map[string]any{"jkt": 1.0}, true), wantErr: altshiftErrors.ErrParseError},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			token, err := ParsePayload(testCase.payload)

			if testCase.wantErr != nil {
				if !errors.Is(err, testCase.wantErr) {
					t.Errorf("%s: got %v, want %v", testCase.name, err, testCase.wantErr)
				}
				if token != nil {
					t.Errorf("%s: a token came back with the refusal", testCase.name)
				}
				return
			}

			if err != nil {
				t.Fatalf("%s: unexpected error: %v", testCase.name, err)
			}
			if token == nil {
				t.Fatalf("%s: no token", testCase.name)
			}
			if token.KeyThumbprint != testCase.wantKeyThumbprint {
				t.Errorf("%s: key thumbprint %q, want %q", testCase.name, token.KeyThumbprint, testCase.wantKeyThumbprint)
			}
			// The session claims are read as Parse reads them.
			if token.AuthenticationId != "auth-id" || token.SubjectId != "subject-id" || token.TenantId != "tenant-id" {
				t.Errorf("%s: claims not read: %+v", testCase.name, token)
			}
		})
	}
}

func TestRefresh_KeyThumbprint(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		keyThumbprint string
	}{
		{name: "a bound token stays bound", keyThumbprint: "thumbprint"},
		{name: "a bearer token stays unbound"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			token, err := Parse(makeClaims("auth-id:session-id", "subject-id:test@example.com", "", nil))
			if err != nil {
				t.Fatalf("%s: parse: %v", testCase.name, err)
			}
			token.KeyThumbprint = testCase.keyThumbprint

			refreshed, err := token.Refresh(makeAuthentication(time.Now().Add(time.Hour)), time.Hour, "refresh")
			if err != nil {
				t.Fatalf("%s: refresh: %v", testCase.name, err)
			}
			if refreshed.KeyThumbprint != testCase.keyThumbprint {
				t.Errorf("%s: key thumbprint %q, want %q", testCase.name, refreshed.KeyThumbprint, testCase.keyThumbprint)
			}
		})
	}
}
