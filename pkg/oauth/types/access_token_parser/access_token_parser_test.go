package access_token_parser

import (
	"crypto/ed25519"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/altshiftab/authentication_go/pkg/oauth/types/access_token"
	"github.com/altshiftab/authentication_go/pkg/session/types/authentication_method"
	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser"
	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser/authorizer_request_parser_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
	altshiftCryptoEddsa "github.com/altshiftab/utils_go/pkg/crypto/eddsa"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/token_header_extractor"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claim_strings"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claims/registered_claims"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claims/session_claims"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/numeric_date"
	altshiftJwtToken "github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/token"
)

const (
	issuer              = "https://login.vvvp.se"
	resource            = "https://vocab.vvvp.se/mcp"
	scope               = "vocab"
	resourceMetadataUrl = "https://vocab.vvvp.se/.well-known/oauth-protected-resource/mcp"
	accountId           = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
	// registeredDomain is the audience every vvvp.se service holds a session token to.
	registeredDomain = "vvvp.se"
)

func newMethod(t *testing.T) *altshiftCryptoEddsa.Method {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}
	return &altshiftCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey}
}

func validToken() *access_token.Token {
	now := time.Now()
	return &access_token.Token{
		Issuer:    issuer,
		Subject:   accountId,
		Audience:  resource,
		ClientId:  "https://claude.ai/oauth/mcp-client-metadata",
		Scopes:    []string{scope},
		Id:        "a-token-id",
		IssuedAt:  now,
		ExpiresAt: now.Add(15 * time.Minute),
	}
}

func mint(t *testing.T, method *altshiftCryptoEddsa.Method, mutate func(*access_token.Token)) string {
	t.Helper()

	token := validToken()
	if mutate != nil {
		mutate(token)
	}
	encoded, err := access_token.Mint(token, method, "oauth-1")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return encoded
}

// sessionToken is a session token as the sign-in service mints one: what every vvvp.se service
// accepts.
func sessionToken(t *testing.T, method *altshiftCryptoEddsa.Method) string {
	t.Helper()

	now := time.Now()
	claims := &session_claims.Claims{
		Claims: registered_claims.Claims{
			Issuer:    issuer,
			Subject:   accountId + ":person@example.com",
			Audience:  claim_strings.ClaimStrings{registeredDomain},
			ExpiresAt: numeric_date.New(now.Add(time.Hour)),
			NotBefore: numeric_date.New(now),
			IssuedAt:  numeric_date.New(now),
			Id:        "an-authentication-id:a-session-id",
		},
		AuthenticationMethods: []string{authentication_method.Sso},
		AuthenticatedAt:       numeric_date.New(now),
		Roles:                 []string{"admin"},
	}
	token, err := session_token.Parse(claims)
	if err != nil {
		t.Fatalf("session token parse: %v", err)
	}
	if token == nil {
		t.Fatal("no session token")
	}
	encoded, err := token.Encode(method)
	if err != nil {
		t.Fatalf("session token encode: %v", err)
	}
	return encoded
}

func request(t *testing.T, authorization string) *http.Request {
	t.Helper()

	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, resource, nil)
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	return request
}

func TestParser_Parse(t *testing.T) {
	t.Parallel()

	oauthMethod := newMethod(t)
	sessionMethod := newMethod(t)

	parser, err := New(&altshiftCryptoEddsa.Method{PublicKey: oauthMethod.PublicKey}, issuer, resource, scope, resourceMetadataUrl)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if parser == nil {
		t.Fatal("no parser")
	}

	// The claims of a valid token, as a plain JWT rather than an access token.
	plainJwt := func() string {
		token := validToken()
		encoded, err := (&altshiftJwtToken.Token{
			Header: map[string]any{"typ": "JWT"},
			Payload: map[string]any{
				"iss": token.Issuer, "sub": token.Subject, "aud": token.Audience, "client_id": token.ClientId,
				"scope": scope, "jti": token.Id, "iat": token.IssuedAt.Unix(), "exp": token.ExpiresAt.Unix(),
			},
		}).Encode(oauthMethod)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		return encoded
	}

	testCases := []struct {
		name          string
		authorization string
		wantStatus    int
		wantError     string
	}{
		{name: "an access token for the resource", authorization: "Bearer " + mint(t, oauthMethod, nil)},
		{name: "the scheme in lower case", authorization: "bearer " + mint(t, oauthMethod, nil)},
		{name: "no token", wantStatus: http.StatusUnauthorized},
		{name: "another scheme", authorization: "Basic dXNlcjpwYXNz", wantStatus: http.StatusUnauthorized, wantError: "invalid_request"},
		{
			name:          "a token for another resource",
			authorization: "Bearer " + mint(t, oauthMethod, func(token *access_token.Token) { token.Audience = "https://feeds.vvvp.se/mcp" }),
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_token",
		},
		{
			name:          "a token of another issuer",
			authorization: "Bearer " + mint(t, oauthMethod, func(token *access_token.Token) { token.Issuer = "https://login.example.com" }),
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_token",
		},
		{
			name: "an expired token",
			authorization: "Bearer " + mint(t, oauthMethod, func(token *access_token.Token) {
				token.IssuedAt = time.Now().Add(-time.Hour)
				token.ExpiresAt = time.Now().Add(-time.Minute)
			}),
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_token",
		},
		{
			// The OAuth claims, but signed with the session key.
			name:          "a token signed with another key",
			authorization: "Bearer " + mint(t, sessionMethod, nil),
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_token",
		},
		{name: "a plain jwt of the right claims", authorization: "Bearer " + plainJwt(), wantStatus: http.StatusUnauthorized, wantError: "invalid_token"},
		{
			name:          "a session token",
			authorization: "Bearer " + sessionToken(t, sessionMethod),
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_token",
		},
		{
			name:          "a session token signed with the access token key",
			authorization: "Bearer " + sessionToken(t, oauthMethod),
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_token",
		},
		{
			name:          "a token without the scope",
			authorization: "Bearer " + mint(t, oauthMethod, func(token *access_token.Token) { token.Scopes = []string{"other"} }),
			wantStatus:    http.StatusForbidden,
			wantError:     "insufficient_scope",
		},
		{
			name:          "a token bound to a key, as a bearer token",
			authorization: "Bearer " + mint(t, oauthMethod, func(token *access_token.Token) { token.KeyThumbprint = "a-thumbprint" }),
			wantStatus:    http.StatusUnauthorized,
			wantError:     "invalid_token",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			token, responseError := parser.Parse(request(t, testCase.authorization))
			if testCase.wantStatus == 0 {
				if responseError != nil {
					t.Fatalf("%s: refused: %+v", testCase.name, responseError.ProblemDetail)
				}
				if token == nil || token.Subject != accountId || token.Audience != resource || token.GetUser().Id != accountId {
					t.Errorf("%s: got %+v", testCase.name, token)
				}
				return
			}

			if responseError == nil || responseError.ProblemDetail == nil {
				t.Fatalf("%s: accepted: %+v", testCase.name, token)
			}
			if responseError.ProblemDetail.Status != testCase.wantStatus {
				t.Errorf("%s: status %d, want %d", testCase.name, responseError.ProblemDetail.Status, testCase.wantStatus)
			}

			var challenge string
			for _, header := range responseError.Headers {
				if header != nil && header.Name == "WWW-Authenticate" {
					challenge = header.Value
				}
			}
			if !strings.HasPrefix(challenge, "Bearer ") || !strings.Contains(challenge, `resource_metadata="`+resourceMetadataUrl+`"`) {
				t.Errorf("%s: challenge %q does not name the resource metadata", testCase.name, challenge)
			}
			switch {
			case testCase.wantError == "" && strings.Contains(challenge, "error="):
				t.Errorf("%s: challenge %q names an error for a request with no token", testCase.name, challenge)
			case testCase.wantError != "" && !strings.Contains(challenge, fmt.Sprintf(`error=%q`, testCase.wantError)):
				t.Errorf("%s: challenge %q, want error %q", testCase.name, challenge, testCase.wantError)
			}
		})
	}
}

/*
 * The other way round: an access token is no way into a vvvp.se service. Every one of them
 * authorizes as below -- the session key, the issuer, the registered domain as the audience, a
 * role -- and none of them accepts an access token, whichever key it is signed with. A session token
 * is accepted, so that the authorizer is known to be one that accepts what it should.
 */
func TestSessionAuthorizer_RefusesAccessTokens(t *testing.T) {
	t.Parallel()

	oauthMethod := newMethod(t)
	sessionMethod := newMethod(t)

	authorizer, err := authorizer_request_parser.New(
		&altshiftCryptoEddsa.Method{PublicKey: sessionMethod.PublicKey},
		issuer,
		registeredDomain,
		authorizer_request_parser_config.WithTokenExtractor(token_header_extractor.New()),
		authorizer_request_parser_config.WithAllowedRoles("admin"),
	)
	if err != nil {
		t.Fatalf("authorizer request parser new: %v", err)
	}
	if authorizer == nil {
		t.Fatal("no authorizer")
	}

	testCases := []struct {
		name       string
		token      string
		wantAccept bool
	}{
		{name: "a session token", token: sessionToken(t, sessionMethod), wantAccept: true},
		{name: "an access token", token: mint(t, oauthMethod, nil)},
		{name: "an access token signed with the session key", token: mint(t, sessionMethod, nil)},
		{
			name:  "an access token for the registered domain, signed with the session key",
			token: mint(t, sessionMethod, func(token *access_token.Token) { token.Audience = registeredDomain }),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, responseError := authorizer.Parse(request(t, "Bearer "+testCase.token))
			if accepted := responseError == nil; accepted != testCase.wantAccept {
				t.Errorf("%s: accepted %t, want %t (%+v)", testCase.name, accepted, testCase.wantAccept, responseError)
			}
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	verifier := &altshiftCryptoEddsa.Method{PublicKey: newMethod(t).PublicKey}
	testCases := []struct {
		name                                 string
		issuer, resource, scope, metadataUrl string
	}{
		{name: "no issuer", resource: resource, scope: scope, metadataUrl: resourceMetadataUrl},
		{name: "no resource", issuer: issuer, scope: scope, metadataUrl: resourceMetadataUrl},
		{name: "no scope", issuer: issuer, resource: resource, metadataUrl: resourceMetadataUrl},
		{name: "no metadata url", issuer: issuer, resource: resource, scope: scope},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if _, err := New(verifier, testCase.issuer, testCase.resource, testCase.scope, testCase.metadataUrl); err == nil {
				t.Errorf("%s: made a parser", testCase.name)
			}
		})
	}
	if _, err := New(nil, issuer, resource, scope, resourceMetadataUrl); err == nil {
		t.Error("made a parser without a verifier")
	}
}
