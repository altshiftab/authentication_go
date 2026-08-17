package testing

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/json/v2"
	"fmt"
	altshiftCryptoEcdsa "github.com/altshiftab/utils_go/pkg/crypto/ecdsa"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwk/types/key/ec"
	altshiftJwtToken "github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/token"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_cookie"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
	altshiftCryptoEddsa "github.com/altshiftab/utils_go/pkg/crypto/eddsa"
	altshiftCryptoInterfaces "github.com/altshiftab/utils_go/pkg/crypto/interfaces"
	altshiftSqlTesting "github.com/altshiftab/utils_go/pkg/database/sql/testing"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/token_cookie_extractor/token_cookie_extractor_config"
	"github.com/altshiftab/utils_go/pkg/http/types/http_context_extractor"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claim_strings"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claims/registered_claims"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claims/session_claims"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/numeric_date"
	altshiftLog "github.com/altshiftab/utils_go/pkg/log"
	altshiftContextLogger "github.com/altshiftab/utils_go/pkg/log/context_logger"
	"github.com/altshiftab/utils_go/pkg/utils"
)

const (
	AuthenticationId = "test-authentication-id"
	Issuer           = "test-issuer"
	Audience         = "test-audience"
	SessionId        = "test-session-id"
	RegisteredDomain = "example.com"
)

func MakeCookieExplicit(
	authenticationId string,
	signer altshiftCryptoInterfaces.NamedSigner,
	authenticationMethods []string,
	exp, nbf time.Time,
) string {
	if utils.IsNil(signer) {
		panic(altshiftErrors.NewWithTrace(nil_error.New("signer")))
	}

	iat := time.Now()

	sessionClaims := &session_claims.Claims{
		Claims: registered_claims.Claims{
			Issuer:    Issuer,
			Subject:   "test-subject-id:test@example.com",
			Audience:  claim_strings.ClaimStrings{Audience},
			ExpiresAt: numeric_date.New(exp),
			NotBefore: numeric_date.New(nbf),
			IssuedAt:  numeric_date.New(iat),
			Id:        strings.Join([]string{authenticationId, SessionId}, ":"),
		},
		AuthenticationMethods: authenticationMethods,
		// NOTE: Not checked anywhere.
		AuthenticatedAt: numeric_date.New(iat.Add(-1 * 7 * 24 * time.Hour)),
		AuthorizedParty: "example.com:Test",
		Roles:           []string{"test-role"},
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

	domain := "example.com"
	sessionCookie, err := session_cookie.New(sessionTokenString, exp, token_cookie_extractor_config.DefaultName, domain)
	if err != nil {
		panic(altshiftErrors.New(fmt.Errorf("new session cookie: %w", err), sessionTokenString, exp, token_cookie_extractor_config.DefaultName, domain))
	}

	return sessionCookie.String()
}

func MakeStandardCookie(authenticationId string, signer altshiftCryptoInterfaces.NamedSigner) string {
	now := time.Now()
	return MakeCookieExplicit(authenticationId, signer, []string{"ext"}, now.Add(1*time.Hour), now)
}

func SetUp() (*authorizer_request_parser.Parser, *altshiftCryptoEddsa.Method, *sql.DB) {
	httpContextExtractor := http_context_extractor.New()
	slog.SetDefault(
		altshiftContextLogger.New(
			slog.NewJSONHandler(
				os.Stdout,
				&slog.HandlerOptions{Level: slog.LevelInfo},
			),
			&altshiftLog.ErrorContextExtractor{
				ContextExtractors: []altshiftLog.ContextExtractor{
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

	method := &altshiftCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey}
	authorizerRequestParser, err := authorizer_request_parser.New(method, Issuer, Audience)
	if err != nil {
		panic(fmt.Errorf("authorizer request parser new: %w", err))
	}

	testDb := altshiftSqlTesting.NewDb()

	return authorizerRequestParser, method, testDb
}

// MakeDbscProof mints a device bound session proof of the shape a browser sends: the public key
// carried in the JWT header as "jwk", and the challenge as the only payload claim. It returns the
// serialised token together with the DER encoded public key the server derives from it.
func MakeDbscProof(challenge string, extraClaims ...map[string]any) (string, []byte) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(altshiftErrors.NewWithTrace(fmt.Errorf("ecdsa generate key: %w", err)))
	}

	signer, err := altshiftCryptoEcdsa.FromPrivateKey(privateKey)
	if err != nil {
		panic(altshiftErrors.New(fmt.Errorf("ecdsa from private key: %w", err)))
	}

	jwkKey, err := ec.NewFromPublicKey(&privateKey.PublicKey)
	if err != nil {
		panic(altshiftErrors.New(fmt.Errorf("ec new from public key: %w", err)))
	}

	jwkData, err := json.Marshal(jwkKey)
	if err != nil {
		panic(altshiftErrors.NewWithTrace(fmt.Errorf("json marshal (jwk): %w", err)))
	}

	var jwk map[string]any
	if err := json.Unmarshal(jwkData, &jwk); err != nil {
		panic(altshiftErrors.NewWithTrace(fmt.Errorf("json unmarshal (jwk): %w", err)))
	}
	if jwk == nil {
		panic(altshiftErrors.NewWithTrace(nil_error.New("jwk")))
	}
	// The key type belongs to the JWK itself; the EC value carries only the curve and coordinates.
	jwk["kty"] = "EC"

	payload := map[string]any{"jti": challenge}
	for _, claims := range extraClaims {
		for name, value := range claims {
			payload[name] = value
		}
	}

	tokenString, err := (&altshiftJwtToken.Token{
		Header:  map[string]any{"typ": "dbsc+jwt", "jwk": jwk},
		Payload: payload,
	}).Encode(signer)
	if err != nil {
		panic(altshiftErrors.New(fmt.Errorf("token encode: %w", err)))
	}

	derEncodedPublicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		panic(altshiftErrors.NewWithTrace(fmt.Errorf("x509 marshal pkix public key: %w", err)))
	}

	return tokenString, derEncodedPublicKey
}
