package dbsc_session_response_processor

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	motmedelCryptoEcdsa "github.com/Motmedel/utils_go/pkg/crypto/ecdsa"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	"github.com/Motmedel/utils_go/pkg/interfaces/comparer"
	motmedelJwkKey "github.com/Motmedel/utils_go/pkg/json/jose/jwk/types/key"
	motmedelJwtToken "github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/token"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/token/authenticated_token"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/token/authenticated_token/authenticated_token_config"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/validator"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/validator/header_validator"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/validator/registered_claims_validator"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/validator/setting"
	"github.com/Motmedel/utils_go/pkg/utils"
	"github.com/altshiftab/authentication_go/pkg/database/types/dbsc_challenge"
	"github.com/altshiftab/authentication_go/pkg/session/types/dbsc_session_response_processor/dbsc_session_response_processor_config"
)

type Input struct {
	TokenString      string
	AuthenticationId string
	DbscSessionId    string
	// PublicKey is the DER encoded key already registered for the session. A refresh proof carries
	// no key of its own — the browser only signs the challenge — so it is verified against this.
	// Registration proofs leave it empty and carry the key in the token header instead.
	PublicKey []byte
}

type Output struct {
	PublicKey []byte
	UserId    string
}

type Processor struct {
	TokenValidator *validator.Validator
	Db             *sql.DB

	popDbscChallenge func(ctx context.Context, challenge string, authenticationId string, db *sql.DB) (*dbsc_challenge.Challenge, error)
}

// processWithRegisteredKey validates a proof against the key already registered for the session,
// which is how a refresh is authenticated: the browser signs the challenge with the device bound
// key and sends no key material of its own.
func (p *Processor) processWithRegisteredKey(ctx context.Context, input *Input, tokenString string) ([]byte, *response_error.ResponseError) {
	publicKey, err := x509.ParsePKIXPublicKey(input.PublicKey)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("x509 parse pkix public key: %w", err)),
		}
	}

	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(
				fmt.Errorf("%w: the registered key is not an ecdsa key", motmedelErrors.ErrValidationError),
			),
		}
	}

	namedVerifier, err := motmedelCryptoEcdsa.FromPublicKey(ecdsaPublicKey)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.New(fmt.Errorf("ecdsa from public key: %w", err)),
		}
	}

	authenticatedToken, err := authenticated_token.New(
		tokenString,
		authenticated_token_config.WithTokenValidator(p.TokenValidator),
		authenticated_token_config.WithSignatureVerifier(namedVerifier),
	)
	if err != nil {
		wrappedErr := motmedelErrors.New(fmt.Errorf("authenticated jwt token new: %w", err), tokenString)
		if motmedelErrors.IsAny(wrappedErr, motmedelErrors.ErrValidationError, motmedelErrors.ErrVerificationError, motmedelErrors.ErrParseError) {
			return nil, &response_error.ResponseError{
				ClientError: wrappedErr,
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("Invalid token."),
				),
			}
		}
		return nil, &response_error.ResponseError{ServerError: wrappedErr}
	}
	if authenticatedToken == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("authenticated jwt token")),
		}
	}

	if responseError := p.consumeChallenge(ctx, authenticatedToken.Payload, input.AuthenticationId); responseError != nil {
		return nil, responseError
	}

	return input.PublicKey, nil
}

func (p *Processor) Process(ctx context.Context, input *Input) ([]byte, *response_error.ResponseError) {
	if input == nil {
		return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(nil_error.New("input"))}
	}

	tokenString := input.TokenString
	if tokenString == "" {
		return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(empty_error.New("token string"))}
	}

	authenticationId := input.AuthenticationId
	if authenticationId == "" {
		return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(empty_error.New("authentication id"))}
	}

	token, err := motmedelJwtToken.New(tokenString)
	if err != nil {
		wrappedErr := motmedelErrors.New(fmt.Errorf("new token: %w", err), tokenString)
		if errors.Is(err, motmedelErrors.ErrParseError) {
			return nil, &response_error.ResponseError{
				ClientError: wrappedErr,
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("Invalid token."),
				),
			}
		}
		return nil, &response_error.ResponseError{ServerError: wrappedErr}
	}
	if token == nil {
		return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(nil_error.New("jwt token"))}
	}

	tokenPayload := token.Payload
	if tokenPayload == nil {
		return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(nil_error.New("jwt token payload"))}
	}

	tokenHeader := token.Header
	if tokenHeader == nil {
		return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(nil_error.New("jwt token header"))}
	}

	// A refresh proves possession of the key registered earlier, so it is verified against that key
	// rather than one the token supplies.
	if len(input.PublicKey) != 0 {
		return p.processWithRegisteredKey(ctx, input, tokenString)
	}

	// The browser carries its public key in the JWT header as "jwk". An earlier revision of the
	// protocol placed it in the payload as "key"; a browser speaking the current one sends neither
	// that claim nor "aud" and "iat", so requiring them rejected every registration.
	key, err := utils.MapGetConvert[map[string]any](tokenHeader, "jwk")
	if err != nil {
		wrappedErr := motmedelErrors.New(fmt.Errorf("map get convert: %w", err), tokenPayload)
		if motmedelErrors.IsAny(err, motmedelErrors.ErrConversionNotOk, motmedelErrors.ErrNotInMap) {
			return nil, &response_error.ResponseError{
				ClientError: wrappedErr,
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("Invalid token; no jwk object."),
				),
			}
		}
		return nil, &response_error.ResponseError{ServerError: wrappedErr}
	}
	if key == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("token key object")),
			ProblemDetail: problem_detail.New(
				http.StatusBadRequest,
				problem_detail_config.WithDetail("Invalid token; nil key object."),
			),
		}
	}

	jwkKey, err := motmedelJwkKey.New(key)
	if err != nil {
		wrappedErr := motmedelErrors.New(fmt.Errorf("jwk key new: %w", err), key)
		if errors.Is(err, motmedelErrors.ErrValidationError) {
			return nil, &response_error.ResponseError{
				ClientError: wrappedErr,
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("Invalid token; bad key object."),
				),
			}
		}
		return nil, &response_error.ResponseError{ServerError: wrappedErr}
	}
	if jwkKey == nil {
		return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(nil_error.New("jwk key"))}
	}

	material := jwkKey.Material
	if utils.IsNil(material) {
		return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(nil_error.New("jwk key material"))}
	}

	namedVerifier, err := jwkKey.NamedVerifier()
	if err != nil {
		wrappedErr := motmedelErrors.New(fmt.Errorf("jwk key named verifier: %w", err), key)
		if emptyError, ok := errors.AsType[*empty_error.Error](err); ok && emptyError.Field == "alg" {
			return nil, &response_error.ResponseError{
				ClientError: wrappedErr,
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("Invalid token; empty or missing alg in key."),
				),
			}
		}
		return nil, &response_error.ResponseError{ServerError: wrappedErr}
	}
	if utils.IsNil(namedVerifier) {
		return nil, &response_error.ResponseError{ServerError: motmedelErrors.NewWithTrace(nil_error.New("named verifier"))}
	}

	publicKey, err := material.PublicKey()
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(
				fmt.Errorf("jwk key material public key: %w", err),
			),
		}
	}

	derEncodedKeyMaterial, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(
				fmt.Errorf("%w: x509 marshal pkix public key: %w", motmedelErrors.ErrValidationError, err),
				key,
			),
		}
	}
	if len(derEncodedKeyMaterial) == 0 {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(empty_error.New("x509 marshal pkix public key material")),
		}
	}

	authenticatedToken, err := authenticated_token.New(
		tokenString,
		authenticated_token_config.WithTokenValidator(p.TokenValidator),
		authenticated_token_config.WithSignatureVerifier(namedVerifier),
	)
	if err != nil {
		wrappedErr := motmedelErrors.New(
			fmt.Errorf("authenticated jwt token new: %w", err),
			tokenString, authenticationId,
		)
		if motmedelErrors.IsAny(wrappedErr, motmedelErrors.ErrValidationError, motmedelErrors.ErrVerificationError, motmedelErrors.ErrParseError) {
			return nil, &response_error.ResponseError{
				ClientError: wrappedErr,
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("Invalid token."),
				),
			}
		}

		return nil, &response_error.ResponseError{ServerError: wrappedErr}
	}
	if authenticatedToken == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("authenticated jwt token")),
		}
	}

	authenticatedTokenPayload := authenticatedToken.Payload
	if authenticatedTokenPayload == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("authenticated jwt token payload")),
		}
	}

	if responseError := p.consumeChallenge(ctx, authenticatedTokenPayload, authenticationId); responseError != nil {
		return nil, responseError
	}

	return derEncodedKeyMaterial, nil
}

// consumeChallenge redeems the challenge the proof answers, which must exist for the session and
// not have expired. It is single use, which is what binds a proof to one refresh.
func (p *Processor) consumeChallenge(ctx context.Context, payload map[string]any, authenticationId string) *response_error.ResponseError {
	jti, err := utils.MapGetConvert[string](payload, "jti")
	if err != nil {
		return &response_error.ResponseError{
			ServerError: motmedelErrors.New(fmt.Errorf("map get convert (jti): %w", err), payload),
		}
	}

	dbscChallenge, err := p.popDbscChallenge(ctx, jti, authenticationId, p.Db)
	if err != nil {
		return &response_error.ResponseError{
			ServerError: motmedelErrors.New(fmt.Errorf("get challenge: %w", err), jti, authenticationId),
		}
	}
	if dbscChallenge == nil {
		return &response_error.ResponseError{
			ProblemDetail: problem_detail.New(
				http.StatusBadRequest,
				problem_detail_config.WithDetail("No challenge was found matching the JTI and authentication ID."),
			),
		}
	}

	expiresAt := dbscChallenge.ExpiresAt
	if expiresAt == nil {
		return &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("dbsc challenge expires at")),
		}
	}
	if time.Now().After(*expiresAt) {
		return &response_error.ResponseError{
			ProblemDetail: problem_detail.New(
				http.StatusBadRequest,
				problem_detail_config.WithDetail("The challenge has expired."),
			),
		}
	}

	return nil
}

func New(audience string, db *sql.DB, options ...dbsc_session_response_processor_config.Option) (*Processor, error) {
	if audience == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("audience"))
	}

	if db == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("db"))
	}

	config := dbsc_session_response_processor_config.New(options...)

	tokenValidator := &validator.Validator{
		HeaderValidator: &header_validator.Validator{
			Settings: map[string]setting.Setting{
				"alg": setting.Required,
				"typ": setting.Required,
			},
			Expected: &header_validator.ExpectedFields{
				Alg: comparer.NewEqualComparer(config.Algs...),
				Typ: comparer.NewEqualComparer("dbsc+jwt"),
			},
		},
		PayloadValidator: &registered_claims_validator.Validator{
			// The proof carries only the challenge; it is bound to the session by that challenge
			// being server issued and single use. Audience and issued-at are checked when present,
			// which a browser speaking the current protocol does not send.
			Settings: map[string]setting.Setting{
				"aud": setting.Optional,
				"iat": setting.Optional,
				"jti": setting.Required,
			},
			Expected: &registered_claims_validator.ExpectedClaims{
				AudienceComparer: comparer.NewEqualComparer(audience),
			},
		},
	}

	return &Processor{TokenValidator: tokenValidator, Db: db, popDbscChallenge: config.PopDbscChallenge}, nil
}
