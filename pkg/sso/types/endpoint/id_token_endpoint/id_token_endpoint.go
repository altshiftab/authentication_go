package id_token_endpoint

import (
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/altshiftab/authentication_go/pkg/session/types/authentication_method"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_manager"
	ssoErrors "github.com/altshiftab/authentication_go/pkg/sso/errors"
	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/id_token_endpoint/id_token_endpoint_config"
	"github.com/altshiftab/authentication_go/pkg/sso/types/provider_claims"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/body_loader"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/body_loader/body_setting"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/token_header_extractor"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/token_header_extractor/token_header_extractor_config"
	muxResponse "github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/utils"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	altshiftJws "github.com/altshiftab/utils_go/pkg/json/jose/jws"
	authenticatorPkg "github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/authenticator"
)

type Endpoint[T provider_claims.ProviderClaims] struct {
	*initialization_endpoint.Endpoint
}

var idTokenHeaderExtractor = token_header_extractor.New(
	token_header_extractor_config.WithProblemDetailStatusCode(http.StatusBadRequest),
)

func (e *Endpoint[T]) Initialize(
	idTokenAuthenticator *authenticatorPkg.AuthenticatorWithKeyHandler,
	sessionManager *session_manager.Manager,
) error {
	if idTokenAuthenticator == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("id token authenticator"))
	}

	if sessionManager == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("session manager"))
	}

	e.Handler = func(request *http.Request, _ []byte) (*muxResponse.Response, *response_error.ResponseError) {
		ctx := request.Context()

		idToken, responseError := utils.GetServerNonZeroParsedRequestHeaders[string](ctx)
		if responseError != nil {
			return nil, responseError
		}

		if idToken == "" {
			return nil, &response_error.ResponseError{
				ClientError: altshiftErrors.NewWithTrace(empty_error.New("id token")),
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The id token is empty."),
				),
			}
		}

		authenticatedIdToken, err := idTokenAuthenticator.Authenticate(ctx, idToken)
		if err != nil {
			wrappedErr := altshiftErrors.New(fmt.Errorf("authenticator with key handler authenticate: %w", err), idToken)
			if altshiftErrors.IsAny(err, altshiftErrors.ErrParseError, altshiftErrors.ErrValidationError, altshiftErrors.ErrVerificationError) {
				return nil, &response_error.ResponseError{
					ClientError: wrappedErr,
					ProblemDetail: problem_detail.New(
						http.StatusBadRequest,
						problem_detail_config.WithDetail("Invalid id token."),
					),
				}
			}
			return nil, &response_error.ResponseError{ServerError: wrappedErr}
		}
		if authenticatedIdToken == nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(nil_error.New("authenticated id token")),
			}
		}

		_, idTokenPayload, _, err := altshiftJws.Parse(idToken)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("jwt parse: %w", err), idToken),
			}
		}
		if len(idTokenPayload) == 0 {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(empty_error.New("id token payload")),
			}
		}

		var providerClaims T
		if err := json.Unmarshal(idTokenPayload, &providerClaims); err != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(
					fmt.Errorf("json unmarshal (id token payload): %w", err),
					idTokenPayload,
				),
			}
		}

		emailAddress, err := providerClaims.VerifiedEmailAddress()
		if err != nil {
			wrappedErr := altshiftErrors.New(
				fmt.Errorf("provider claims verified email address: %w", err),
				providerClaims,
			)
			if errors.Is(err, ssoErrors.ErrForbiddenUser) {
				return nil, &response_error.ResponseError{
					ProblemDetail: problem_detail.New(
						http.StatusForbidden,
						problem_detail_config.WithDetail("The email address that is tied to the id token is unverified or invalid."),
					),
				}
			}
			return nil, &response_error.ResponseError{ServerError: wrappedErr}
		}
		if emailAddress == "" {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(empty_error.New("email address")),
			}
		}

		idTokenHash := sha256.Sum256([]byte(idToken))

		response, responseError := sessionManager.CreateSession(ctx, authentication_method.Sso, strings.ToLower(emailAddress), idTokenHash[:])
		if responseError != nil {
			return nil, responseError
		}
		if response == nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(nil_error.New("response")),
			}
		}

		return response, nil
	}

	e.Initialized = true
	return nil
}

func New[T provider_claims.ProviderClaims](path string, options ...id_token_endpoint_config.Option) (*Endpoint[T], error) {
	if path == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("path"))
	}

	return &Endpoint[T]{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:         path,
				Method:       http.MethodPost,
				UrlParser:    adapter.New(query_extractor.Empty),
				HeaderParser: adapter.New(idTokenHeaderExtractor),
				BodyLoader:   &body_loader.Loader{Setting: body_setting.Forbidden},
				Public:       true,
			},
		},
	}, nil
}
