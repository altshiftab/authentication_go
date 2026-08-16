package landing_endpoint

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	motmedelCryptoInterfaces "github.com/Motmedel/utils_go/pkg/crypto/interfaces"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/Motmedel/utils_go/pkg/http/mux/utils"
	motmedelHttpTypes "github.com/Motmedel/utils_go/pkg/http/types"
	"github.com/Motmedel/utils_go/pkg/http/types/accept_language"
	authenticatorPkg "github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/authenticator"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/authenticator/authenticator_config"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/validator/registered_claims_validator"
	"github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/validator/setting"
	motmedelReflect "github.com/Motmedel/utils_go/pkg/reflect"
	"github.com/Motmedel/utils_go/pkg/utils"
	"github.com/altshiftab/authentication_go/pkg/magic_link/types/endpoint/landing_endpoint/landing_endpoint_config"
	"github.com/altshiftab/authentication_go/pkg/magic_link/types/endpoint/validate_endpoint"
)

type Endpoint struct {
	*initialization_endpoint.Endpoint
	PageBuilder           landing_endpoint_config.PageBuilder
	ContentSecurityPolicy string
}

func (e *Endpoint) Initialize(verifier motmedelCryptoInterfaces.NamedVerifier) error {
	if utils.IsNil(verifier) {
		return motmedelErrors.NewWithTrace(nil_error.New("verifier"))
	}

	if e.PageBuilder == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("page builder"))
	}

	e.UrlParser = adapter.New(
		request_parser.NewWithProcessor(
			query_extractor.New[*validate_endpoint.UrlInput](),
			validate_endpoint.MakeVerifyProcessor(
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

		if _, responseError := muxUtils.GetServerNonZeroParsedRequestUrl[*validate_endpoint.VerifiedToken](ctx); responseError != nil {
			return nil, responseError
		}

		formAction := (&url.URL{Path: request.URL.Path, RawQuery: request.URL.RawQuery}).String()

		var acceptLanguage *motmedelHttpTypes.AcceptLanguage
		if raw := strings.TrimSpace(request.Header.Get("Accept-Language")); raw != "" {
			if parsed, parseErr := accept_language.Parse([]byte(raw)); parseErr == nil {
				acceptLanguage = parsed
			}
		}

		body, err := e.PageBuilder(formAction, acceptLanguage)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("page builder: %w", err)),
			}
		}

		headers := []*muxResponse.HeaderEntry{
			{Name: "Content-Type", Value: "text/html; charset=utf-8"},
			{Name: "Cache-Control", Value: "no-store"},
			{Name: "Referrer-Policy", Value: "no-referrer"},
		}
		if e.ContentSecurityPolicy != "" {
			headers = append(headers, &muxResponse.HeaderEntry{
				Name:      "Content-Security-Policy",
				Value:     e.ContentSecurityPolicy,
				Overwrite: true,
			})
		}

		return &muxResponse.Response{
			StatusCode: http.StatusOK,
			Headers:    headers,
			Body:       body,
		}, nil
	}

	e.Initialized = true

	return nil
}

func New(options ...landing_endpoint_config.Option) *Endpoint {
	config := landing_endpoint_config.New(options...)
	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:   config.Path,
				Method: http.MethodGet,
				Public: true,
				Hint: &endpoint.Hint{
					UrlInputType: motmedelReflect.TypeOf[validate_endpoint.UrlInput](),
				},
			},
		},
		PageBuilder:           config.PageBuilder,
		ContentSecurityPolicy: config.ContentSecurityPolicy,
	}
}
