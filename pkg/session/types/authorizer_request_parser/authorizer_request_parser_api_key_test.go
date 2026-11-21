package authorizer_request_parser

import (
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	sessionErrors "github.com/altshiftab/authentication_go/pkg/session/errors"
	"github.com/altshiftab/authentication_go/pkg/session/types/authentication_method"
	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser/authorizer_request_parser_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
	altshiftCryptoEddsa "github.com/altshiftab/utils_go/pkg/crypto/eddsa"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/token_cookie_extractor/token_cookie_extractor_config"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claim_strings"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claims/registered_claims"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claims/session_claims"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/numeric_date"
	altshiftJwtToken "github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/token"
)

// makeCookieWithClientId is a key's session whose "client_id" is whatever value is given, as no
// login of this library writes it.
func makeCookieWithClientId(t *testing.T, signer *altshiftCryptoEddsa.Method, clientId any) string {
	t.Helper()

	now := time.Now()
	sessionToken, err := session_token.Parse(&session_claims.Claims{
		Claims: registered_claims.Claims{
			Issuer:    issuer,
			Subject:   "test-subject-id:test@example.com",
			Audience:  claim_strings.ClaimStrings{audience},
			ExpiresAt: numeric_date.New(now.Add(time.Hour)),
			NotBefore: numeric_date.New(now),
			IssuedAt:  numeric_date.New(now),
			Id:        strings.Join([]string{authenticationId, sessionId}, ":"),
		},
		AuthenticationMethods: []string{authentication_method.ApiKey},
		AuthenticatedAt:       numeric_date.New(now),
		Roles:                 []string{role},
	})
	if err != nil || sessionToken == nil {
		t.Fatalf("session token parse: %v", err)
		return ""
	}

	data, err := json.Marshal(sessionToken.Claims)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil || payload == nil {
		t.Fatalf("json unmarshal: %v", err)
		return ""
	}
	payload["client_id"] = clientId

	tokenString, err := (&altshiftJwtToken.Token{Payload: payload}).Encode(signer)
	if err != nil {
		t.Fatalf("token encode: %v", err)
	}

	return token_cookie_extractor_config.DefaultName + "=" + tokenString
}

/*
 * Every key of an account mints the same session but for the "client_id" naming it, so this is what
 * keeps one job's key out of the endpoints meant for another's. The restriction concerns the sessions
 * minted against a key and no others, and is not lifted by a super admin role: it is about the
 * credential, not about who holds it.
 */
func TestParser_ParseApiKeyIds(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}
	method := &altshiftCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey}

	keyMethods := []string{authentication_method.ApiKey}

	testCases := []struct {
		name string
		// The token's "amr" and the key its "client_id" names.
		tokenMethods []string
		tokenKey     string
		// A cookie of the test's own, in place of one made of the above.
		cookie func(t *testing.T) string
		// The authorizer's methods, beside the api key restriction's options.
		parserMethods []string
		options       []authorizer_request_parser_config.Option
		// 0 admits.
		wantStatus int
	}{
		{
			name:         "a key's session, by an authorizer restricted to no keys",
			tokenMethods: keyMethods, tokenKey: "key-c",
		},
		{
			// Minted by a library from before the claim, by an authorizer that never asks.
			name:         "a session naming no key, by an authorizer restricted to no keys",
			tokenMethods: keyMethods,
		},
		{
			name:         "a listed key",
			tokenMethods: keyMethods, tokenKey: "key-b",
			options: []authorizer_request_parser_config.Option{authorizer_request_parser_config.WithApiKeyIds("key-a", "key-b")},
		},
		{
			name:         "a key not listed",
			tokenMethods: keyMethods, tokenKey: "key-c",
			options:    []authorizer_request_parser_config.Option{authorizer_request_parser_config.WithApiKeyIds("key-a", "key-b")},
			wantStatus: http.StatusForbidden,
		},
		{
			// Minted by a login from before the claim: which key it was cannot be told.
			name:         "a key's session naming no key",
			tokenMethods: keyMethods,
			options:      []authorizer_request_parser_config.Option{authorizer_request_parser_config.WithApiKeyIds("key-a")},
			wantStatus:   http.StatusForbidden,
		},
		{
			// An endpoint whose key is not registered yet.
			name:         "restricted to no key at all",
			tokenMethods: keyMethods, tokenKey: "key-a",
			options:    []authorizer_request_parser_config.Option{authorizer_request_parser_config.WithApiKeyIds()},
			wantStatus: http.StatusForbidden,
		},
		{
			name:         "a key not listed, holding a super admin role",
			tokenMethods: keyMethods, tokenKey: "key-c",
			options: []authorizer_request_parser_config.Option{
				authorizer_request_parser_config.WithApiKeyIds("key-a"),
				authorizer_request_parser_config.WithSuperAdminRoles(role),
			},
			wantStatus: http.StatusForbidden,
		},
		{
			// The methods decide which sessions come at all; the keys only which of the keys'.
			name:          "a browser session, by an authorizer for both restricted to a key",
			tokenMethods:  []string{authentication_method.Sso},
			parserMethods: []string{authentication_method.Sso, authentication_method.ApiKey},
			options:       []authorizer_request_parser_config.Option{authorizer_request_parser_config.WithApiKeyIds("key-a")},
		},
		{
			name:          "a session of a key and another method, the key not listed",
			tokenMethods:  []string{authentication_method.Sso, authentication_method.ApiKey},
			tokenKey:      "key-c",
			parserMethods: []string{authentication_method.Sso, authentication_method.ApiKey},
			options:       []authorizer_request_parser_config.Option{authorizer_request_parser_config.WithApiKeyIds("key-a")},
			wantStatus:    http.StatusForbidden,
		},
		{
			// Unreadable rather than naming no key: not authenticated at all.
			name:       "a client_id that names nothing",
			cookie:     func(t *testing.T) string { return makeCookieWithClientId(t, method, 1.0) },
			options:    []authorizer_request_parser_config.Option{authorizer_request_parser_config.WithApiKeyIds("key-a")},
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			var cookie string
			if testCase.cookie != nil {
				cookie = testCase.cookie(t)
			} else {
				cookie = makeCookieOfKey(method, testCase.tokenKey, testCase.tokenMethods...)
			}
			request.Header.Set("Cookie", cookie)

			parserMethods := testCase.parserMethods
			if parserMethods == nil {
				parserMethods = keyMethods
			}
			options := append(
				[]authorizer_request_parser_config.Option{authorizer_request_parser_config.WithAuthenticationMethods(parserMethods...)},
				testCase.options...,
			)
			parser, err := New(method, issuer, audience, options...)
			if err != nil {
				t.Fatalf("%s: new parser: %v", testCase.name, err)
			}

			sessionToken, responseError := parser.Parse(request)

			if testCase.wantStatus == 0 {
				if responseError != nil {
					t.Fatalf("%s: refused: %+v", testCase.name, responseError)
				}
				if sessionToken == nil || sessionToken.ApiKeyId != testCase.tokenKey {
					t.Errorf("%s: admitted %+v", testCase.name, sessionToken)
				}
				return
			}

			if responseError == nil || responseError.ProblemDetail == nil {
				t.Fatalf("%s: admitted, or refused without a problem detail: %+v", testCase.name, responseError)
			}
			if sessionToken != nil {
				t.Errorf("%s: a token came back with the refusal", testCase.name)
			}
			if status := responseError.ProblemDetail.Status; status != testCase.wantStatus {
				t.Errorf("%s: status %d, want %d", testCase.name, status, testCase.wantStatus)
			}
			if responseError.ServerError != nil {
				t.Errorf("%s: a server error: %v", testCase.name, responseError.ServerError)
			}
			// The key refused is told the log, for comparing with the ids configured.
			wantErr := sessionErrors.ErrApiKeyNotAllowed
			if testCase.wantStatus == http.StatusUnauthorized {
				wantErr = altshiftErrors.ErrParseError
			}
			if !errors.Is(responseError.ClientError, wantErr) {
				t.Errorf("%s: client error %v, want %v", testCase.name, responseError.ClientError, wantErr)
			}
		})
	}
}
