package testing

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"encoding/json/v2"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"time"

	motmedelCryptoEcdsa "github.com/Motmedel/utils_go/pkg/crypto/ecdsa"
	motmedelCryptoEddsa "github.com/Motmedel/utils_go/pkg/crypto/eddsa"
	motmedelSqlTesting "github.com/Motmedel/utils_go/pkg/database/sql/testing"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	muxPkg "github.com/Motmedel/utils_go/pkg/http/mux"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	muxRespnose "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	"github.com/Motmedel/utils_go/pkg/http/types/http_context_extractor"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwk/types/key"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwk/types/key/ec"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwk/types/key_handler"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwk/types/key_set"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/authenticator"
	motmedelJwtToken "github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/token"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	motmedelContextLogger "github.com/Motmedel/utils_go/pkg/log/context_logger"
	motmedelOauth2Config "github.com/Motmedel/utils_go/pkg/oauth2/types/config"
	motmedelOauth2Endpoint "github.com/Motmedel/utils_go/pkg/oauth2/types/endpoint"
	databaseErrors "github.com/altshiftab/authentication_go/pkg/database/errors"
	accountPkg "github.com/altshiftab/authentication_go/pkg/database/types/account"
	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	loginTesting "github.com/altshiftab/authentication_go/pkg/session/testing"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_manager"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_manager/session_manager_config"
	"github.com/altshiftab/authentication_go/pkg/sso/errors"
	"github.com/altshiftab/authentication_go/pkg/sso/types/provider_claims"
)

const (
	RedirectUrl = "https://example.com/redirect"
	State       = "test-state"
	OauthCode   = "test-code"
	OauthFlowId = "test-oauth-flow-id"

	Domain           = "example.com"
	EmailAddress     = "test@example.com"
	KeyId            = "test-key-id"
	Role             = "test-role"
	AccountId        = "test-account-id"
	AuthenticationId = "test-authentication-id"
	Subject          = "test-provider-subject"

	OauthErrorCode                  = "oauth_error"
	OauthStrongAuthenticationCode   = "strong_authentication"
	OauthOrganizationCode           = "organization"
	Organization                    = "example-organization"
	OauthSkipIdTokenCode            = "skip_id_token"
	OauthInvalidIdTokenCode         = "invalid_id_token"
	OauthUnverifiedEmailAddressCode = "unverified_email_address"
	OauthEmptyEmailAddressCode      = "empty_email_address"

	JwksPath  = "/.well-known/jwks.json"
	TokenPath = "/oauth/token"
)

var (
	testAccount = &accountPkg.Account{Id: AccountId, EmailAddress: EmailAddress, Roles: []string{Role}}
)

type ProviderClaims struct {
	EmailAddress string   `json:"email_address"`
	Verified     bool     `json:"verified"`
	Amr          []string `json:"amr,omitzero"`
	Organization string   `json:"organization,omitzero"`
	Sub          string   `json:"sub,omitzero"`
}

func (c *ProviderClaims) Subject() string {
	return c.Sub
}

func (c *ProviderClaims) OrganizationIdentifier() string {
	return c.Organization
}

func (c *ProviderClaims) AuthenticationContext() *provider_claims.AuthenticationContext {
	return &provider_claims.AuthenticationContext{MethodReferences: c.Amr}
}

func (c *ProviderClaims) VerifiedEmailAddress() (string, error) {
	if !c.Verified {
		return "", errors.ErrForbiddenUser
	}
	return c.EmailAddress, nil
}

func SetUp() (*session_manager.Manager, *authenticator.AuthenticatorWithKeyHandler, *motmedelOauth2Config.Config, *motmedelCryptoEcdsa.Method) {
	httpContextExtractor := http_context_extractor.New()
	slog.SetDefault(
		motmedelContextLogger.New(
			slog.NewJSONHandler(
				os.Stdout,
				&slog.HandlerOptions{Level: slog.LevelInfo},
			),
			&motmedelLog.ErrorContextExtractor{
				ContextExtractors: []motmedelLog.ContextExtractor{
					httpContextExtractor,
				},
			},
			httpContextExtractor,
		),
	)

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(fmt.Errorf("ed25519 generate key: %w", err))
	}
	sessionMethod := &motmedelCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey}

	db := motmedelSqlTesting.NewDb()
	var usedIdTokenHashes sync.Map
	sessionManager, err := session_manager.New(
		sessionMethod,
		db,
		loginTesting.Issuer,
		loginTesting.RegisteredDomain,
		session_manager_config.WithSelectEmailAddressAccount(
			func(ctx context.Context, emailAddress string, database *sql.DB) (*accountPkg.Account, error) {
				return testAccount, nil
			},
		),
		session_manager_config.WithInsertAuthentication(
			func(ctx context.Context, accountId string, idTokenHash []byte, expirationDuration time.Duration, metadata *authenticationPkg.ClientMetadata, database *sql.DB) (*authenticationPkg.Authentication, error) {
				if len(idTokenHash) > 0 {
					if _, loaded := usedIdTokenHashes.LoadOrStore(string(idTokenHash), struct{}{}); loaded {
						return nil, databaseErrors.ErrIdTokenAlreadyUsed
					}
				}

				createdAt := time.Now()
				expiresAt := createdAt.Add(expirationDuration)

				return &authenticationPkg.Authentication{
					Id:        AuthenticationId,
					Account:   testAccount,
					CreatedAt: &createdAt,
					ExpiresAt: &expiresAt,
				}, nil
			},
		),
		session_manager_config.WithInsertDbscChallenge(
			func(ctx context.Context, challenge string, authenticationId string, expirationDuration time.Duration, db *sql.DB) error {
				return nil
			},
		),
	)
	if err != nil {
		panic(fmt.Errorf("session manager new: %w", err))
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Errorf("ecdsa generate key: %w", err))
	}

	idTokenMethod, err := motmedelCryptoEcdsa.New(ecdsaKey, &ecdsaKey.PublicKey)
	if err != nil {
		panic(fmt.Errorf("ecdsa new: %w", err))
	}

	ecKey, err := ec.NewFromPublicKey(&ecdsaKey.PublicKey)
	if err != nil {
		panic(fmt.Errorf("ec new from public key: %w", err))
	}

	keySetData, err := json.Marshal(
		key_set.KeySet{
			Keys: []*key.Key{
				{
					Alg:      "ES256",
					Kty:      "EC",
					Kid:      KeyId,
					Use:      "sig",
					Material: ecKey,
				},
			},
		},
	)
	if err != nil {
		panic(fmt.Errorf("json marshal (key set): %w", err))
	}

	auxMux := &muxPkg.Mux{}
	auxMux.Add(
		&endpoint.Endpoint{
			Path:   "/.well-known/jwks.json",
			Method: http.MethodGet,
			Public: true,
			Handler: func(request *http.Request, i []byte) (*muxRespnose.Response, *response_error.ResponseError) {
				return &muxRespnose.Response{
					Headers: []*muxRespnose.HeaderEntry{
						{
							Name:  "Content-Type",
							Value: "application/json; charset=UTF-8",
						},
						{
							Name:  "Expires",
							Value: time.Now().Add(time.Hour * 24).Format(time.RFC1123),
						},
					},
					Body: keySetData,
				}, nil
			},
		},
		&endpoint.Endpoint{
			Path:   TokenPath,
			Method: http.MethodPost,
			Public: true,
			Handler: func(request *http.Request, body []byte) (*muxRespnose.Response, *response_error.ResponseError) {
				values, err := url.ParseQuery(string(body))
				if err != nil {
					panic(motmedelErrors.New(fmt.Errorf("url parse query: %w", err), body))
				}

				inputCode := values.Get("code")

				if inputCode == OauthErrorCode {
					return &muxRespnose.Response{
						Headers: []*muxRespnose.HeaderEntry{
							{
								Name:  "Content-Type",
								Value: "application/json; charset=UTF-8",
							},
						},
						Body: []byte(`{"error": "invalid_grant", "error_description": "invalid code"}`),
					}, nil
				}

				responseMap := map[string]any{
					"access_token": "at",
					"token_type":   "Bearer",
					"expires_in":   3600,
				}

				if inputCode != OauthSkipIdTokenCode {
					var tokenString string

					if inputCode == OauthInvalidIdTokenCode {
						tokenString = "invalid-id-token"
					} else {
						tokenPayload := map[string]any{
							"iss":      "aux",
							"aud":      "test-client",
							"iat":      time.Now().Add(-1 * time.Minute).Unix(),
							"nbf":      time.Now().Add(-1 * time.Minute).Unix(),
							"exp":      time.Now().Add(10 * time.Minute).Unix(),
							"verified": inputCode != OauthUnverifiedEmailAddressCode,
						}

						var tokenEmailAddress string
						if inputCode != OauthEmptyEmailAddressCode {
							tokenEmailAddress = EmailAddress
						}
						tokenPayload["email_address"] = tokenEmailAddress
						tokenPayload["sub"] = Subject

						// Providers state the methods used only when asked, so the default token
						// carries none: that is the case a multi-factor requirement must refuse.
						if inputCode == OauthStrongAuthenticationCode {
							tokenPayload["amr"] = []string{"pwd", "mfa"}
						}

						// An account with no organization carries no identifier, which is the
						// consumer account case.
						if inputCode == OauthOrganizationCode {
							tokenPayload["organization"] = Organization
						}

						token := motmedelJwtToken.Token{
							Header: map[string]any{
								"typ": "JWT",
								"kid": KeyId,
							},
							Payload: tokenPayload,
						}
						tokenString, err = token.Encode(idTokenMethod)
						if err != nil {
							panic(motmedelErrors.New(fmt.Errorf("token encode: %w", err), token, idTokenMethod))
						}
					}

					responseMap["id_token"] = tokenString
				}

				responseData, err := json.Marshal(responseMap)
				if err != nil {
					return nil, &response_error.ResponseError{
						ServerError: motmedelErrors.New(
							fmt.Errorf("json marshal (response data): %w", err),
							responseMap,
						),
					}
				}

				return &muxRespnose.Response{
					Headers: []*muxRespnose.HeaderEntry{{Name: "Content-Type", Value: "application/json"}},
					Body:    responseData,
				}, nil
			},
		},
	)
	auxHttpServer := httptest.NewServer(auxMux)

	jwksURL, err := url.Parse(auxHttpServer.URL + JwksPath)
	if err != nil {
		panic(fmt.Errorf("url parse: %w", err))
	}
	keyHandler, err := key_handler.New(jwksURL)
	if err != nil {
		panic(fmt.Errorf("key handler new: %w", err))
	}

	oauthConfig := &motmedelOauth2Config.Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Endpoint: motmedelOauth2Endpoint.Endpoint{
			TokenURL: auxHttpServer.URL + TokenPath,
		},
		Scopes: []string{"openid", "email"},
	}

	idTokenAuthenticator, err := authenticator.NewWithKeyHandler(keyHandler)
	if err != nil {
		panic(fmt.Errorf("authenticator new with key handler: %w", err))
	}

	return sessionManager, idTokenAuthenticator, oauthConfig, idTokenMethod
}
