package landing_endpoint

import (
	"context"
	stdErrors "errors"
	"fmt"
	"log/slog"
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
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	muxResponse "github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/altshiftab/utils_go/pkg/http/mux/utils"
	altshiftHttpTypes "github.com/altshiftab/utils_go/pkg/http/types"
	"github.com/altshiftab/utils_go/pkg/http/types/accept_language"
	jwtErrors "github.com/altshiftab/utils_go/pkg/json/jose/jwt/errors"
	authenticatorPkg "github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/authenticator"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/authenticator/authenticator_config"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/validator/registered_claims_validator"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/validator/setting"
	altshiftReflect "github.com/altshiftab/utils_go/pkg/reflect"
	"github.com/altshiftab/utils_go/pkg/utils"
)

// SpentChecker reports whether the token whose nonce hash is given was already used to sign in.
type SpentChecker func(ctx context.Context, nonceHash []byte) (bool, error)

type Endpoint struct {
	*initialization_endpoint.Endpoint
	PageBuilder landing_endpoint_config.PageBuilder
	// UnusablePageBuilder, when set, answers a link that can no longer sign anyone in -- expired, or
	// spent according to SpentChecker -- with a page of its own rather than a problem detail, which a
	// browser shows as raw XML. Nil keeps the problem detail.
	UnusablePageBuilder landing_endpoint_config.PageBuilder
	// SpentChecker turns a spent link away here, before the user is offered a button that can only
	// fail. It requires UnusablePageBuilder.
	SpentChecker          SpentChecker
	ContentSecurityPolicy string
}

func (e *Endpoint) Initialize(verifier altshiftCryptoInterfaces.NamedVerifier) error {
	if utils.IsNil(verifier) {
		return altshiftErrors.NewWithTrace(nil_error.New("verifier"))
	}

	if e.PageBuilder == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("page builder"))
	}

	if e.SpentChecker != nil && e.UnusablePageBuilder == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("unusable page builder (required by the spent checker)"))
	}

	// Verified in the handler rather than by the URL parser, so that an expired link can be answered
	// with a page; a refusal from the parser can only be a problem detail.
	e.UrlParser = adapter.New(query_extractor.New[*validate_endpoint.UrlInput]())

	verifyProcessor := validate_endpoint.MakeVerifyProcessor(
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
	)

	e.Handler = func(request *http.Request, _ []byte) (*muxResponse.Response, *response_error.ResponseError) {
		ctx := request.Context()

		urlInput, responseError := muxUtils.GetServerNonZeroParsedRequestUrl[*validate_endpoint.UrlInput](ctx)
		if responseError != nil {
			return nil, responseError
		}

		acceptLanguage := parseAcceptLanguage(request)

		verifiedToken, responseError := verifyProcessor.Process(ctx, urlInput)
		if responseError != nil {
			if e.UnusablePageBuilder != nil && stdErrors.Is(responseError.ClientError, jwtErrors.ErrExpExpired) {
				return e.makePageResponse(e.UnusablePageBuilder, http.StatusGone, "", acceptLanguage)
			}
			return nil, responseError
		}
		if verifiedToken == nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(nil_error.New("verified token")),
			}
		}

		// Advisory: the submission's own refusal of a used token is what decides. A failed check
		// therefore offers the form, which a transient database error would otherwise turn into a
		// dead link.
		if e.SpentChecker != nil {
			spent, err := e.SpentChecker(ctx, verifiedToken.NonceHash[:])
			if err != nil {
				slog.WarnContext(
					ctx,
					"An error occurred when checking whether a magic link was spent.",
					slog.Any("error", altshiftErrors.New(fmt.Errorf("spent checker: %w", err))),
				)
			} else if spent {
				return e.makePageResponse(e.UnusablePageBuilder, http.StatusGone, "", acceptLanguage)
			}
		}

		formAction := (&url.URL{Path: request.URL.Path, RawQuery: request.URL.RawQuery}).String()

		return e.makePageResponse(e.PageBuilder, http.StatusOK, formAction, acceptLanguage)
	}

	e.Initialized = true

	return nil
}

func parseAcceptLanguage(request *http.Request) *altshiftHttpTypes.AcceptLanguage {
	raw := strings.TrimSpace(request.Header.Get("Accept-Language"))
	if raw == "" {
		return nil
	}

	parsed, err := accept_language.Parse([]byte(raw))
	if err != nil {
		return nil
	}

	return parsed
}

func (e *Endpoint) makePageResponse(
	pageBuilder landing_endpoint_config.PageBuilder,
	statusCode int,
	formAction string,
	acceptLanguage *altshiftHttpTypes.AcceptLanguage,
) (*muxResponse.Response, *response_error.ResponseError) {
	body, err := pageBuilder(formAction, acceptLanguage)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("page builder: %w", err)),
		}
	}

	headers := []*muxResponse.HeaderEntry{
		{Name: "Content-Type", Value: "text/html; charset=utf-8"},
		{Name: "Cache-Control", Value: "no-store"},
		// Overwritten, as the mux's default would otherwise stand: the page's address carries the
		// token, which every subresource request would send on as its referrer. strict-origin rather
		// than no-referrer, under which the form's submission would carry Origin: null.
		{Name: "Referrer-Policy", Value: "strict-origin", Overwrite: true},
	}
	if e.ContentSecurityPolicy != "" {
		headers = append(headers, &muxResponse.HeaderEntry{
			Name:      "Content-Security-Policy",
			Value:     e.ContentSecurityPolicy,
			Overwrite: true,
		})
	}

	return &muxResponse.Response{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       body,
	}, nil
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
		UnusablePageBuilder:   config.UnusablePageBuilder,
		ContentSecurityPolicy: config.ContentSecurityPolicy,
	}
}
