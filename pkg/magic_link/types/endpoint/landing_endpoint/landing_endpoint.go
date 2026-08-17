package landing_endpoint

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/altshiftab/authentication_go/pkg/magic_link/types/endpoint/landing_endpoint/landing_endpoint_config"
	"github.com/altshiftab/authentication_go/pkg/magic_link/types/endpoint/validate_endpoint"
	altshiftCryptoInterfaces "github.com/altshiftab/utils_go/pkg/crypto/interfaces"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	muxResponse "github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/altshiftab/utils_go/pkg/http/mux/utils"
	altshiftHttpTypes "github.com/altshiftab/utils_go/pkg/http/types"
	"github.com/altshiftab/utils_go/pkg/http/types/accept_language"
	authenticatorPkg "github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/authenticator"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/authenticator/authenticator_config"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/validator/registered_claims_validator"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/validator/setting"
	altshiftReflect "github.com/altshiftab/utils_go/pkg/reflect"
	"github.com/altshiftab/utils_go/pkg/utils"
)

type Endpoint struct {
	*initialization_endpoint.Endpoint
	PageBuilder           landing_endpoint_config.PageBuilder
	ContentSecurityPolicy string
}

func (e *Endpoint) Initialize(verifier altshiftCryptoInterfaces.NamedVerifier) error {
	if utils.IsNil(verifier) {
		return altshiftErrors.NewWithTrace(nil_error.New("verifier"))
	}

	if e.PageBuilder == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("page builder"))
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

		var acceptLanguage *altshiftHttpTypes.AcceptLanguage
		if raw := strings.TrimSpace(request.Header.Get("Accept-Language")); raw != "" {
			if parsed, parseErr := accept_language.Parse([]byte(raw)); parseErr == nil {
				acceptLanguage = parsed
			}
		}

		body, err := e.PageBuilder(formAction, acceptLanguage)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("page builder: %w", err)),
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
					UrlInputType: altshiftReflect.TypeOf[validate_endpoint.UrlInput](),
				},
			},
		},
		PageBuilder:           config.PageBuilder,
		ContentSecurityPolicy: config.ContentSecurityPolicy,
	}
}
