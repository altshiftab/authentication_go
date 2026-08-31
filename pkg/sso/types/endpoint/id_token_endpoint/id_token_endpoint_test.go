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

	"github.com/altshiftab/authentication_go/pkg/session/types/session_manager"
	ssoTesting "github.com/altshiftab/authentication_go/pkg/sso/testing"
	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/id_token_endpoint/id_token_endpoint_config"
	altshiftCryptoEcdsa "github.com/altshiftab/utils_go/pkg/crypto/ecdsa"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
	muxTesting "github.com/altshiftab/utils_go/pkg/http/mux/testing"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/authenticator"
	altshiftJwtToken "github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/token"
	altshiftTestingCmp "github.com/altshiftab/utils_go/pkg/testing/cmp"
)

const (
	defaultPath = "/id-token"
)

var sessionManager *session_manager.Manager
var idTokenAuthenticator *authenticator.AuthenticatorWithKeyHandler
var idTokenMethod *altshiftCryptoEcdsa.Method

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

					token := altshiftJwtToken.Token{
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
			altshiftTestingCmp.CompareErr(t, err, testCase.wantErr)
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

	token := altshiftJwtToken.Token{
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

// TestEndpointRequireOrganization covers refusing an account that belongs to no organization —
// a personal account, which nobody administers and on which therefore no authentication policy can
// be required. The authorization code flow's callback refuses one; this endpoint mints a session
// for the same account without going through that flow, so the requirement has to hold here too or
// the route it is not enforced on is the one an account uses.
func TestEndpointRequireOrganization(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		options      []id_token_endpoint_config.Option
		organization string
		args         *muxTesting.Args
	}{
		{
			name:         "required and present",
			options:      []id_token_endpoint_config.Option{id_token_endpoint_config.WithRequireOrganization(true)},
			organization: ssoTesting.Organization,
			args: &muxTesting.Args{
				ExpectedStatusCode:     http.StatusNoContent,
				ExpectedHeadersPresent: []string{"Set-Cookie"},
			},
		},
		{
			name:    "required and absent",
			options: []id_token_endpoint_config.Option{id_token_endpoint_config.WithRequireOrganization(true)},
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusForbidden,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The account does not belong to an organization.",
				},
				// No session may be minted for a refused sign-in.
				ExpectedHeadersNotPresent: []string{"Set-Cookie"},
			},
		},
		{
			// The default is unchanged: a deployment that has not asked for the requirement keeps
			// admitting an account without an organization.
			name:         "not required and absent",
			organization: "",
			args: &muxTesting.Args{
				ExpectedStatusCode:     http.StatusNoContent,
				ExpectedHeadersPresent: []string{"Set-Cookie"},
			},
		},
	}

	for index, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint, err := New[*ssoTesting.ProviderClaims](defaultPath, testCase.options...)
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

			tokenPayload := map[string]any{
				"iss": "aux",
				"aud": "test-client",
				"iat": time.Now().Add(-1 * time.Minute).Unix(),
				"nbf": time.Now().Add(-1 * time.Minute).Unix(),
				// Distinct per case so that no two tokens hash alike; the session manager refuses a
				// reused id token.
				"exp":           time.Now().Add(time.Duration(20+index) * time.Minute).Unix(),
				"verified":      true,
				"email_address": ssoTesting.EmailAddress,
				"sub":           ssoTesting.Subject,
			}
			if testCase.organization != "" {
				tokenPayload["organization"] = testCase.organization
			}

			token := altshiftJwtToken.Token{
				Header:  map[string]any{"typ": "JWT", "kid": ssoTesting.KeyId},
				Payload: tokenPayload,
			}
			tokenString, err := token.Encode(idTokenMethod)
			if err != nil {
				t.Fatalf("token encode: %v", err)
			}

			testCase.args.Path = testEndpoint.Path
			testCase.args.Method = testEndpoint.Method
			testCase.args.Headers = append(
				testCase.args.Headers,
				[2]string{"Authorization", fmt.Sprintf("Bearer %s", tokenString)},
			)

			muxTesting.TestArgs(t, testCase.args, httpServer.URL)
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                    string
		path                    string
		options                 []id_token_endpoint_config.Option
		wantRequireOrganization bool
		wantErr                 bool
	}{
		{name: "success", path: defaultPath},
		{name: "empty path", path: "", wantErr: true},
		{
			// The options are applied rather than accepted and discarded.
			name:                    "require organization",
			path:                    defaultPath,
			options:                 []id_token_endpoint_config.Option{id_token_endpoint_config.WithRequireOrganization(true)},
			wantRequireOrganization: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			testEndpoint, err := New[*ssoTesting.ProviderClaims](tt.path, tt.options...)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() err = %v, wantErr = %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if testEndpoint.RequireOrganization != tt.wantRequireOrganization {
				t.Errorf(
					"RequireOrganization = %v, want %v",
					testEndpoint.RequireOrganization,
					tt.wantRequireOrganization,
				)
			}
		})
	}
}

// TODO: Implement tests
//	- Provider claims unmarshal
//	- Create session error
