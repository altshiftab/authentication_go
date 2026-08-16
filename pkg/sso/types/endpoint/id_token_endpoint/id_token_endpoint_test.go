package id_token_endpoint

import (
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	motmedelCryptoEcdsa "github.com/Motmedel/utils_go/pkg/crypto/ecdsa"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	muxPkg "github.com/Motmedel/utils_go/pkg/http/mux"
	muxTesting "github.com/Motmedel/utils_go/pkg/http/mux/testing"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/authenticator"
	motmedelJwtToken "github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/token"
	motmedelTestingCmp "github.com/Motmedel/utils_go/pkg/testing/cmp"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_manager"
	ssoTesting "github.com/altshiftab/authentication_go/pkg/sso/testing"
)

const (
	defaultPath = "/id-token"
)

var sessionManager *session_manager.Manager
var idTokenAuthenticator *authenticator.AuthenticatorWithKeyHandler
var idTokenMethod *motmedelCryptoEcdsa.Method

func TestMain(m *testing.M) {
	sessionManager, idTokenAuthenticator, _, idTokenMethod = ssoTesting.SetUp()

	code := m.Run()
	_ = sessionManager.Db.Close()

	os.Exit(code)
}

func TestEndpoint(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                   string
		args                   *muxTesting.Args
		invalidIdToken         bool
		unverifiedEmailAddress bool
		emptyEmailAddress      bool
		skipIdToken            bool
	}{
		{
			name: "success",
			args: &muxTesting.Args{
				ExpectedStatusCode:     http.StatusNoContent,
				ExpectedHeadersPresent: []string{"Set-Cookie"},
			},
		},
		{
			name: "skip id token",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail:    "Missing token header.",
					Extension: map[string]any{"header": "Authorization"},
				},
			},
			skipIdToken: true,
		},
		{
			name: "invalid id token",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "Invalid id token.",
				},
			},
			invalidIdToken: true,
		},
		{
			name: "unverified email address",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusForbidden,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The email address that is tied to the id token is unverified or invalid.",
				},
			},
			unverifiedEmailAddress: true,
		},
		{
			name: "empty email address",
			args: &muxTesting.Args{
				ExpectedStatusCode:    http.StatusInternalServerError,
				ExpectedProblemDetail: &problem_detail.Detail{},
			},
			emptyEmailAddress: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint, err := New[*ssoTesting.ProviderClaims](defaultPath)
			if err != nil {
				t.Fatalf("new endpoint: %v", err)
			}

			if err := testEndpoint.Initialize(idTokenAuthenticator, sessionManager); err != nil {
				t.Fatalf("test endpoint initialize: %v", err)
			}

			mux := &muxPkg.Mux{}
			mux.Add(testEndpoint.Endpoint.Endpoint)
			httpServer := httptest.NewServer(mux)
			defer httpServer.Close()

			var tokenString string

			if !testCase.skipIdToken {
				if testCase.invalidIdToken {
					tokenString = "[]"
				} else {
					tokenPayload := map[string]any{
						"iss":      "aux",
						"aud":      "test-client",
						"iat":      time.Now().Add(-1 * time.Minute).Unix(),
						"nbf":      time.Now().Add(-1 * time.Minute).Unix(),
						"exp":      time.Now().Add(10 * time.Minute).Unix(),
						"verified": !testCase.unverifiedEmailAddress,
					}

					var tokenEmailAddress string
					if !testCase.emptyEmailAddress {
						tokenEmailAddress = ssoTesting.EmailAddress
					}
					tokenPayload["email_address"] = tokenEmailAddress

					token := motmedelJwtToken.Token{
						Header: map[string]any{
							"typ": "JWT",
							"kid": ssoTesting.KeyId,
						},
						Payload: tokenPayload,
					}
					tokenString, err = token.Encode(idTokenMethod)
					if err != nil {
						t.Fatalf("token encode: %v", err)
					}
				}
			}

			testCase.args.Path = testEndpoint.Path
			testCase.args.Method = testEndpoint.Method
			if !testCase.skipIdToken {
				testCase.args.Headers = append(
					testCase.args.Headers,
					[2]string{"Authorization", fmt.Sprintf("Bearer %s", tokenString)},
				)
			}

			muxTesting.TestArgs(t, testCase.args, httpServer.URL)
		})
	}
}

func TestInitialize(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                 string
		idTokenAuthenticator *authenticator.AuthenticatorWithKeyHandler
		sessionManager       *session_manager.Manager
		wantErr              error
	}{
		{
			name:                 "valid arguments",
			idTokenAuthenticator: idTokenAuthenticator,
			sessionManager:       sessionManager,
		},
		{
			name:                 "nil id token authenticator",
			idTokenAuthenticator: nil,
			sessionManager:       sessionManager,
			wantErr:              nil_error.New("id token authenticator"),
		},
		{
			name:                 "nil session manager",
			idTokenAuthenticator: idTokenAuthenticator,
			sessionManager:       nil,
			wantErr:              nil_error.New("session manager"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint, err := New[*ssoTesting.ProviderClaims](defaultPath)
			if err != nil {
				t.Fatalf("new endpoint: %v", err)
			}

			err = testEndpoint.Initialize(testCase.idTokenAuthenticator, testCase.sessionManager)
			motmedelTestingCmp.CompareErr(t, err, testCase.wantErr)
		})
	}
}

func TestEndpointIdTokenReuse(t *testing.T) {
	t.Parallel()

	testEndpoint, err := New[*ssoTesting.ProviderClaims](defaultPath)
	if err != nil {
		t.Fatalf("new endpoint: %v", err)
	}

	if err := testEndpoint.Initialize(idTokenAuthenticator, sessionManager); err != nil {
		t.Fatalf("test endpoint initialize: %v", err)
	}

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint.Endpoint.Endpoint)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	token := motmedelJwtToken.Token{
		Header: map[string]any{
			"typ": "JWT",
			"kid": ssoTesting.KeyId,
		},
		Payload: map[string]any{
			"iss":           "aux",
			"aud":           "test-client",
			"iat":           time.Now().Add(-1 * time.Minute).Unix(),
			"nbf":           time.Now().Add(-1 * time.Minute).Unix(),
			"exp":           time.Now().Add(10 * time.Minute).Unix(),
			"verified":      true,
			"email_address": ssoTesting.EmailAddress,
		},
	}
	tokenString, err := token.Encode(idTokenMethod)
	if err != nil {
		t.Fatalf("token encode: %v", err)
	}

	authorizationHeader := [2]string{"Authorization", fmt.Sprintf("Bearer %s", tokenString)}

	muxTesting.TestArgs(t, &muxTesting.Args{
		Path:                   testEndpoint.Path,
		Method:                 testEndpoint.Method,
		Headers:                [][2]string{authorizationHeader},
		ExpectedStatusCode:     http.StatusNoContent,
		ExpectedHeadersPresent: []string{"Set-Cookie"},
	}, httpServer.URL)

	muxTesting.TestArgs(t, &muxTesting.Args{
		Path:               testEndpoint.Path,
		Method:             testEndpoint.Method,
		Headers:            [][2]string{authorizationHeader},
		ExpectedStatusCode: http.StatusConflict,
		ExpectedProblemDetail: &problem_detail.Detail{
			Detail: "This sign-in link has already been used.",
		},
	}, httpServer.URL)
}

// TestEndpointAlgNoneWithValidKid guards against a JWT "alg:none" / algorithm-confusion bypass:
// a token that carries a *valid* key id (so a signing key is actually resolved) but declares
// "alg":"none" and ships no signature. Its claims are otherwise valid and verified, so if the
// signature step were ever skipped the endpoint would mint a session (204 + Set-Cookie, cf. the
// "success" case). It must not. The resolved verifier is bound to the key's algorithm (ES256),
// and authenticated_token.New rejects "none" != "ES256" as a verification error before any
// signature check runs, so the endpoint returns 400 "Invalid id token." and issues no session.
func TestEndpointAlgNoneWithValidKid(t *testing.T) {
	t.Parallel()

	testEndpoint, err := New[*ssoTesting.ProviderClaims](defaultPath)
	if err != nil {
		t.Fatalf("new endpoint: %v", err)
	}

	if err := testEndpoint.Initialize(idTokenAuthenticator, sessionManager); err != nil {
		t.Fatalf("test endpoint initialize: %v", err)
	}

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint.Endpoint.Endpoint)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	// Forge an unsigned token: a valid kid (so a verifier is resolved) with otherwise-valid,
	// verified claims for the test account, but with "alg":"none".
	headerBytes, err := json.Marshal(map[string]any{
		"typ": "JWT",
		"alg": "none",
		"kid": ssoTesting.KeyId,
	})
	if err != nil {
		t.Fatalf("json marshal (header): %v", err)
	}
	payloadBytes, err := json.Marshal(map[string]any{
		"iss":           "aux",
		"aud":           "test-client",
		"iat":           time.Now().Add(-1 * time.Minute).Unix(),
		"nbf":           time.Now().Add(-1 * time.Minute).Unix(),
		"exp":           time.Now().Add(10 * time.Minute).Unix(),
		"verified":      true,
		"email_address": ssoTesting.EmailAddress,
	})
	if err != nil {
		t.Fatalf("json marshal (payload): %v", err)
	}

	// Unsigned JWS compact serialization: header.payload with an empty signature segment.
	tokenString := base64.RawURLEncoding.EncodeToString(headerBytes) + "." +
		base64.RawURLEncoding.EncodeToString(payloadBytes) + "."

	muxTesting.TestArgs(t, &muxTesting.Args{
		Path:               testEndpoint.Path,
		Method:             testEndpoint.Method,
		Headers:            [][2]string{{"Authorization", fmt.Sprintf("Bearer %s", tokenString)}},
		ExpectedStatusCode: http.StatusBadRequest,
		ExpectedProblemDetail: &problem_detail.Detail{
			Detail: "Invalid id token.",
		},
		ExpectedHeadersNotPresent: []string{"Set-Cookie"},
	}, httpServer.URL)
}

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{name: "success", path: defaultPath},
		{name: "empty path", path: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := New[*ssoTesting.ProviderClaims](tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() err = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// TODO: Implement tests
//	- Provider claims unmarshal
//	- Create session error
