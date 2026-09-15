package authorizer_request_parser

import (
	"crypto/ed25519"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/altshiftab/authentication_go/pkg/session/types/authentication_method"
	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser/authorizer_request_parser_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_cookie"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
	altshiftCryptoEddsa "github.com/altshiftab/utils_go/pkg/crypto/eddsa"
	"github.com/altshiftab/utils_go/pkg/crypto/interfaces"
	altshiftCryptoInterfaces "github.com/altshiftab/utils_go/pkg/crypto/interfaces"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/token_cookie_extractor/token_cookie_extractor_config"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claim_strings"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claims/registered_claims"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claims/session_claims"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/numeric_date"
	altshiftTestingCmp "github.com/altshiftab/utils_go/pkg/testing/cmp"
	"github.com/altshiftab/utils_go/pkg/utils"
)

const (
	tenantId         = "test-tenant-id"
	authenticationId = "test-authentication-id"
	sessionId        = "test-session-id"
	audience         = "test-audience"
	issuer           = "test-issuer"
	domain           = "example.com"
	role             = "test-role"
)

func makeCookie(signer altshiftCryptoInterfaces.NamedSigner) string {
	return makeCookieWithMethods(signer, authentication_method.Sso)
}

// makeCookieWithMethods is makeCookie with the "amr" the token carries spelled out, which is what
// decides whether an authorizer accepts it at all.
func makeCookieWithMethods(signer altshiftCryptoInterfaces.NamedSigner, methods ...string) string {
	if utils.IsNil(signer) {
		panic(altshiftErrors.NewWithTrace(nil_error.New("signer")))
	}

	exp := time.Now().Add(time.Hour)

	sessionClaims := &session_claims.Claims{
		Claims: registered_claims.Claims{
			Issuer:    issuer,
			Subject:   fmt.Sprintf("test-subject-id:test@example.com"),
			Audience:  claim_strings.ClaimStrings{audience},
			ExpiresAt: numeric_date.New(exp),
			NotBefore: numeric_date.New(time.Now()),
			IssuedAt:  numeric_date.New(time.Now()),
			Id:        strings.Join([]string{authenticationId, sessionId}, ":"),
		},
		AuthenticationMethods: methods,
		// NOTE: Not checked anywhere.
		AuthenticatedAt: numeric_date.New(time.Now()),
		AuthorizedParty: fmt.Sprintf("%s:test-tenant-name", tenantId),
		Roles:           []string{role},
	}
	sessionToken, err := session_token.Parse(sessionClaims)
	if err != nil {
		panic(altshiftErrors.New(fmt.Errorf("session token parse: %w", err), sessionClaims))
	}
	if sessionToken == nil {
		panic(altshiftErrors.NewWithTrace(nil_error.New("session token")))
	}

	sessionTokenString, err := sessionToken.Encode(signer)
	if err != nil {
		panic(altshiftErrors.New(fmt.Errorf("new session token encode: %w", err), sessionToken, signer))
	}

	sessionCookie, err := session_cookie.New(sessionTokenString, exp, token_cookie_extractor_config.DefaultName, "example.com")
	if err != nil {
		panic(altshiftErrors.New(fmt.Errorf("new session cookie: %w", err), sessionTokenString, exp, token_cookie_extractor_config.DefaultName, domain))
	}

	return sessionCookie.String()
}

func TestParser_Parse(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}

	method := &altshiftCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey}

	problemDetailOpts := []altshiftTestingCmp.Option{
		altshiftTestingCmp.IgnoreFields(problem_detail.Detail{}, "Type", "Instance"),
	}

	testCases := []struct {
		name                  string
		parserTenantId        string
		parserRoles           []string
		parserSuperAdminRoles []string
		wantServerError       error
		wantClientError       error
		wantProblemDetail     *problem_detail.Detail
		unauthenticated       bool
	}{
		{
			name:            "unauthenticated request",
			unauthenticated: true,
		},
		{
			name: "authenticated request, no restrictions",
		},
		{
			name:           "authenticated request, tenant id match",
			parserTenantId: tenantId,
		},
		{
			name:        "authenticated request, role match",
			parserRoles: []string{"other-role-1", role, "other-role-2"},
		},
		{
			name:                  "authenticated request, super admin role match",
			parserRoles:           []string{"other-role"},
			parserSuperAdminRoles: []string{role},
		},
		{
			name: "authenticated request, tenant id no match",
			wantProblemDetail: &problem_detail.Detail{
				Status: http.StatusForbidden,
				Detail: "The session token's tenant id does not match the allowed tenant id.",
			},
			parserTenantId: "other-tenant-id",
		},
		{
			name: "authenticated request, roles no match",
			wantProblemDetail: &problem_detail.Detail{
				Status: http.StatusForbidden,
				Detail: "None of the session token's roles match the allowed roles.",
			},
			parserRoles: []string{"other-role"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			request, err := http.NewRequest(http.MethodGet, "/", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}

			if !testCase.unauthenticated {
				request.Header.Set(
					"Cookie",
					makeCookie(method),
				)
			}

			parser, err := New(
				method,
				issuer,
				audience,
				authorizer_request_parser_config.WithAllowedTenantId(testCase.parserTenantId),
				authorizer_request_parser_config.WithAllowedRoles(testCase.parserRoles...),
				authorizer_request_parser_config.WithSuperAdminRoles(testCase.parserSuperAdminRoles...),
			)
			if err != nil {
				t.Fatalf("new parser: %v", err)
			}

			_, gotResponseError := parser.Parse(request)

			if testCase.unauthenticated {
				if gotResponseError == nil {
					t.Fatalf("expected response error, got none")
				}
				return
			}

			if gotResponseError == nil && (testCase.wantServerError != nil || testCase.wantClientError != nil || testCase.wantProblemDetail != nil) {
				t.Fatalf("expected response error, got none")
			}

			if gotResponseError != nil {
				altshiftTestingCmp.CompareErr(t, gotResponseError.ServerError, testCase.wantServerError)
				altshiftTestingCmp.CompareErr(t, gotResponseError.ClientError, testCase.wantClientError)

				if testCase.wantProblemDetail != nil {
					testCase.wantProblemDetail.Title = http.StatusText(testCase.wantProblemDetail.Status)
				}

				if diff := altshiftTestingCmp.Diff(gotResponseError.ProblemDetail, testCase.wantProblemDetail, problemDetailOpts...); diff != "" {
					t.Errorf("response error problem detail mismatch (-expected +got):\n%s", diff)
				}
			}
		})
	}

}

func TestParser_Verifier(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}
	method := &altshiftCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey}

	// The parser is constructed via New (not by setting the field directly) so
	// this also guards against the constructor dropping the verifier: New is
	// given a verifier, and Verifier() must return that same verifier.
	type args struct {
		verifier altshiftCryptoInterfaces.NamedVerifier
		issuer   string
		audience string
		options  []authorizer_request_parser_config.Option
	}
	tests := []struct {
		name string
		args args
		want altshiftCryptoInterfaces.NamedVerifier
	}{
		{
			name: "verifier passed to New is returned by the getter",
			args: args{verifier: method, issuer: issuer, audience: audience},
			want: method,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			parser, err := New(testCase.args.verifier, testCase.args.issuer, testCase.args.audience, testCase.args.options...)
			if err != nil {
				t.Fatalf("new parser: %v", err)
			}

			if got := parser.Verifier(); !reflect.DeepEqual(got, testCase.want) {
				t.Errorf("Verifier() = %v, want %v", got, testCase.want)
			}
		})
	}
}

func TestNew(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(fmt.Errorf("ed25519 generate key: %w", err))
	}

	validMethod := &altshiftCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey}
	const (
		audience = "test-audience"
		issuer   = "test-issuer"
	)

	opts := []altshiftTestingCmp.Option{
		altshiftTestingCmp.IgnoreFields(Parser{}, "verifier", "JwtExtractor"),
	}

	type args struct {
		verifier interfaces.NamedVerifier
		issuer   string
		audience string
		options  []authorizer_request_parser_config.Option
	}
	tests := []struct {
		name    string
		args    args
		want    *Parser
		wantErr error
	}{
		{
			name: "valid arguments",
			args: args{verifier: validMethod, issuer: issuer, audience: audience},
			want: &Parser{
				AllowedRoles:    nil,
				AllowedTenantId: "",
				SuperAdminRoles: nil,
			},
		},
		{
			name:    "nil verifier",
			args:    args{verifier: nil, audience: audience, issuer: issuer},
			wantErr: nil_error.New("verifier"),
		},
		{
			name:    "empty issuer",
			args:    args{verifier: validMethod, audience: audience, issuer: ""},
			wantErr: empty_error.New("issuer"),
		},
		{
			name:    "empty audience",
			args:    args{verifier: validMethod, audience: "", issuer: issuer},
			wantErr: empty_error.New("audience"),
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, gotErr := New(testCase.args.verifier, testCase.args.issuer, testCase.args.audience, testCase.args.options...)

			if gotErr != nil {
				altshiftTestingCmp.CompareErr(t, gotErr, testCase.wantErr)
			}

			if diff := altshiftTestingCmp.Diff(testCase.want, got, opts...); diff != "" {
				t.Errorf("parser mismatch (-expected +got):\n%s", diff)
			}
		})
	}
}

/*
 * How the holder came by a token decides which authorizers take it. A browser session and a token
 * minted against a key the account registered are both valid session tokens signed by the same
 * key, for the same account, with the same audience: the "amr" claim is the whole of what separates
 * them, so this is what keeps an API key out of the endpoints meant for a signed-in person, and a
 * session cookie out of the endpoints meant for API keys.
 *
 * The default set matters as much as the option: an authorizer written before a method existed
 * refuses it, rather than admitting whatever the library learns to mint next.
 */
func TestParser_ParseAuthenticationMethods(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}

	method := &altshiftCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey}

	testCases := []struct {
		name string
		// The "amr" the token carries.
		tokenMethods []string
		// The methods the authorizer is built for; none means the default set.
		parserMethods []string
		accepted      bool
	}{
		{
			name:         "a browser session, by an authorizer that says nothing",
			tokenMethods: []string{authentication_method.Sso},
			accepted:     true,
		},
		{
			name:         "a refreshed session, by an authorizer that says nothing",
			tokenMethods: []string{authentication_method.Refresh},
			accepted:     true,
		},
		{
			name:         "a device bound session, by an authorizer that says nothing",
			tokenMethods: []string{authentication_method.Dbsc},
			accepted:     true,
		},
		{
			name:         "a magic link session, by an authorizer that says nothing",
			tokenMethods: []string{authentication_method.MagicLink},
			accepted:     true,
		},
		{
			// The reason the default is an allow-list: this authorizer was written before API
			// keys existed and refuses one without having been told to.
			name:         "an api key token, by an authorizer that says nothing",
			tokenMethods: []string{authentication_method.ApiKey},
			accepted:     false,
		},
		{
			name:          "an api key token, by an authorizer built for it",
			tokenMethods:  []string{authentication_method.ApiKey},
			parserMethods: []string{authentication_method.ApiKey},
			accepted:      true,
		},
		{
			// The other direction: a session cookie's value pasted into a bearer header is still
			// refused by the endpoints that take API keys.
			name:          "a browser session, by an authorizer built for api keys",
			tokenMethods:  []string{authentication_method.Sso},
			parserMethods: []string{authentication_method.ApiKey},
			accepted:      false,
		},
		{
			name:          "either, by an authorizer built for both",
			tokenMethods:  []string{authentication_method.ApiKey},
			parserMethods: []string{authentication_method.Sso, authentication_method.ApiKey},
			accepted:      true,
		},
		{
			// One match is enough, as the claim is a list of what was done.
			name:          "a token carrying several methods, one of them accepted",
			tokenMethods:  []string{authentication_method.ApiKey, authentication_method.Sso},
			parserMethods: []string{authentication_method.Sso},
			accepted:      true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			request.Header.Set("Cookie", makeCookieWithMethods(method, testCase.tokenMethods...))

			options := []authorizer_request_parser_config.Option{}
			if testCase.parserMethods != nil {
				options = append(
					options,
					authorizer_request_parser_config.WithAuthenticationMethods(testCase.parserMethods...),
				)
			}

			parser, err := New(method, issuer, audience, options...)
			if err != nil {
				t.Fatalf("new parser: %v", err)
			}

			sessionToken, gotResponseError := parser.Parse(request)

			if testCase.accepted {
				if gotResponseError != nil {
					t.Fatalf("expected the token to be accepted, got %+v", gotResponseError)
				}
				if sessionToken == nil {
					t.Fatal("The token was accepted but none came back.")
				}
				return
			}

			if gotResponseError == nil {
				t.Fatal("The token was accepted by an authorizer that does not take its method.")
			}
			if sessionToken != nil {
				t.Error("A token came back alongside the refusal.")
			}

			problemDetail := gotResponseError.ProblemDetail
			if problemDetail == nil {
				t.Fatalf("expected a problem detail, got %+v", gotResponseError)
			}
			// Refused as a token that does not authenticate, not as a fault: nothing is wrong with
			// the request beyond the credential it carries.
			if problemDetail.Status != http.StatusUnauthorized {
				t.Errorf("got status %d, want %d", problemDetail.Status, http.StatusUnauthorized)
			}
			if gotResponseError.ServerError != nil {
				t.Errorf("got a server error: %v", gotResponseError.ServerError)
			}
		})
	}
}
