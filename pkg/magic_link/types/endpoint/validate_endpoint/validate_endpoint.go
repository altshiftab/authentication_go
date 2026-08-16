package validate_endpoint

import (
	"context"
	"crypto/sha256"
	stdErrors "errors"
	"fmt"
	"net/http"
	"net/url"

	motmedelCryptoInterfaces "github.com/Motmedel/utils_go/pkg/crypto/interfaces"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/missing_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	processorPkg "github.com/Motmedel/utils_go/pkg/http/mux/types/processor"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/Motmedel/utils_go/pkg/http/mux/utils"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	jwtErrors "github.com/Motmedel/utils_go/pkg/json/jose/jwt/errors"
	authenticatorPkg "github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/authenticator"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/authenticator/authenticator_config"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/claims/registered_claims"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/validator/registered_claims_validator"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/validator/setting"
	motmedelReflect "github.com/Motmedel/utils_go/pkg/reflect"
	"github.com/Motmedel/utils_go/pkg/utils"
	"github.com/altshiftab/authentication_go/pkg/magic_link/types/endpoint/validate_endpoint/validate_endpoint_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/authentication_method"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_manager"
)

type UrlInput struct {
	Token string `json:"token"`
}

type VerifiedToken struct {
	EmailAddress string
	NonceHash    [sha256.Size]byte
	RedirectUrl  string
}

func MakeVerifyProcessor(authenticator *authenticatorPkg.Authenticator) processorPkg.Processor[*VerifiedToken, *UrlInput] {
	return processorPkg.New(func(ctx context.Context, input *UrlInput) (*VerifiedToken, *response_error.ResponseError) {
		if input == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(nil_error.New("url input")),
			}
		}

		tokenString := input.Token
		if tokenString == "" {
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The token is empty."),
				),
			}
		}

		authenticatedToken, err := authenticator.Authenticate(ctx, tokenString)
		if err != nil {
			wrappedErr := motmedelErrors.New(fmt.Errorf("authenticator authenticate: %w", err), tokenString)

			if stdErrors.Is(err, jwtErrors.ErrExpExpired) {
				return nil, &response_error.ResponseError{
					ClientError: wrappedErr,
					ProblemDetail: problem_detail.New(
						http.StatusBadRequest,
						problem_detail_config.WithDetail("The token has expired."),
					),
				}
			}

			if missingErr, ok := stdErrors.AsType[*missing_error.Error](err); ok {
				return nil, &response_error.ResponseError{
					ClientError: wrappedErr,
					ProblemDetail: problem_detail.New(
						http.StatusBadRequest,
						problem_detail_config.WithDetail(fmt.Sprintf("The token %s claim is missing.", missingErr.Field)),
					),
				}
			}

			if stdErrors.Is(err, motmedelErrors.ErrParseError) || stdErrors.Is(err, motmedelErrors.ErrVerificationError) || stdErrors.Is(err, motmedelErrors.ErrValidationError) {
				return nil, &response_error.ResponseError{
					ClientError: wrappedErr,
					ProblemDetail: problem_detail.New(
						http.StatusBadRequest,
						problem_detail_config.WithDetail("The token is invalid."),
					),
				}
			}

			return nil, &response_error.ResponseError{ServerError: wrappedErr}
		}
		if authenticatedToken == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(nil_error.New("authenticated token")),
			}
		}

		claims, err := registered_claims.New(authenticatedToken.Payload)
		if err != nil {
			return nil, &response_error.ResponseError{
				ClientError: motmedelErrors.New(fmt.Errorf("registered claims new: %w", err), authenticatedToken.Payload),
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The token claims are malformed."),
				),
			}
		}
		if claims == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(nil_error.New("registered claims")),
			}
		}

		emailAddress := claims.Subject
		if emailAddress == "" {
			return nil, &response_error.ResponseError{
				ClientError: motmedelErrors.NewWithTrace(empty_error.New("token sub claim")),
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The token sub claim is empty."),
				),
			}
		}

		nonce := claims.Id
		if nonce == "" {
			return nil, &response_error.ResponseError{
				ClientError: motmedelErrors.NewWithTrace(empty_error.New("token jti claim")),
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The token jti claim is empty."),
				),
			}
		}

		var redirectUrl string
		if v, ok := authenticatedToken.Payload["redirect"]; ok && v != nil {
			converted, err := utils.Convert[string](v)
			if err != nil {
				return nil, &response_error.ResponseError{
					ClientError: motmedelErrors.New(fmt.Errorf("convert (redirect): %w", err), v),
					ProblemDetail: problem_detail.New(
						http.StatusBadRequest,
						problem_detail_config.WithDetail("The token redirect claim is invalid."),
					),
				}
			}
			redirectUrl = converted
		}

		return &VerifiedToken{
			EmailAddress: emailAddress,
			NonceHash:    sha256.Sum256([]byte(nonce)),
			RedirectUrl:  redirectUrl,
		}, nil
	})
}

type Endpoint struct {
	*initialization_endpoint.Endpoint
}

func (e *Endpoint) Initialize(
	verifier motmedelCryptoInterfaces.NamedVerifier,
	sessionManager *session_manager.Manager,
	redirectUrl *url.URL,
) error {
	if utils.IsNil(verifier) {
		return motmedelErrors.NewWithTrace(nil_error.New("verifier"))
	}

	if sessionManager == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("session manager"))
	}

	if redirectUrl == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("redirect url"))
	}

	redirectUrlString := redirectUrl.String()
	if redirectUrlString == "" {
		return motmedelErrors.NewWithTrace(empty_error.New("redirect url"))
	}

	e.UrlParser = adapter.New(
		request_parser.NewWithProcessor(
			query_extractor.New[*UrlInput](),
			MakeVerifyProcessor(
				authenticatorPkg.New(
					authenticator_config.WithSignatureVerifier(verifier),
					authenticator_config.WithClaimsValidator(
						&registered_claims_validator.Validator{
							Settings: map[string]setting.Setting{
								"sub": setting.Required,
								"jti": setting.Required,
								"exp": setting.Required,
							},
						},
					),
				),
			),
		),
	)

	e.Handler = func(request *http.Request, _ []byte) (*muxResponse.Response, *response_error.ResponseError) {
		ctx := request.Context()

		verifiedToken, responseError := muxUtils.GetServerNonZeroParsedRequestUrl[*VerifiedToken](ctx)
		if responseError != nil {
			return nil, responseError
		}

		nonceHash := verifiedToken.NonceHash

		response, responseError := sessionManager.CreateSession(ctx, authentication_method.MagicLink, verifiedToken.EmailAddress, nonceHash[:])
		if responseError != nil {
			return nil, responseError
		}
		if response == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(nil_error.New("response")),
			}
		}

		location := redirectUrlString
		if verifiedToken.RedirectUrl != "" {
			location = verifiedToken.RedirectUrl
		}

		response.StatusCode = http.StatusSeeOther
		response.Headers = append(
			response.Headers,
			&muxResponse.HeaderEntry{Name: "Location", Value: location},
		)

		return response, nil
	}

	e.Initialized = true

	return nil
}

func New(options ...validate_endpoint_config.Option) *Endpoint {
	config := validate_endpoint_config.New(options...)
	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:   config.Path,
				Method: http.MethodPost,
				Public: true,
				Hint: &endpoint.Hint{
					UrlInputType: motmedelReflect.TypeOf[UrlInput](),
				},
			},
		},
	}
}
