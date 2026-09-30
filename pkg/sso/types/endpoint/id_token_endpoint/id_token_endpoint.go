package id_token_endpoint

import (
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/altshiftab/authentication_go/pkg/session/types/authentication_method"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_manager"
	ssoErrors "github.com/altshiftab/authentication_go/pkg/sso/errors"
	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/id_token_endpoint/id_token_endpoint_config"
	"github.com/altshiftab/authentication_go/pkg/sso/types/provider_claims"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
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
	altshiftHttpTypes "github.com/altshiftab/utils_go/pkg/http/types"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	altshiftJws "github.com/altshiftab/utils_go/pkg/json/jose/jws"
	authenticatorPkg "github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/authenticator"
	"github.com/altshiftab/utils_go/pkg/schema"
)

type Endpoint[T provider_claims.ProviderClaims] struct {
	*initialization_endpoint.Endpoint

	// RequireOrganization refuses an account belonging to no organization; see the config.
	RequireOrganization bool
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

		organizationIdentifier := providerClaims.OrganizationIdentifier()

		// Resolved before the session is created, so that a refusal from the session manager — an
		// address with no account, a locked account — is attributed to the same user as a success.
		// Attached to the HTTP context rather than to one message, so it reaches the request log
		// too and correlates with the rest of the service by the same fields.
		if httpContext, ok := ctx.Value(muxPkg.MuxHttpContextContextKey).(*altshiftHttpTypes.HttpContext); ok && httpContext != nil {
			httpContext.User = &schema.User{
				Id:     providerClaims.Subject(),
				Email:  emailAddress,
				Domain: organizationIdentifier,
			}
		}

		// The same message as the authorization code flow's, so that one query answers who signed
		// in regardless of which route they took.
		logAttributes := []any{
			slog.Group(
				"user",
				slog.String("id", providerClaims.Subject()),
				slog.String("email", emailAddress),
			),
			slog.Group("organization", slog.String("id", organizationIdentifier)),
		}

		// Written only when the provider stated something. Unlike the authorization code flow, the
		// token here is minted for the front end and carries no authentication context at all from
		// some providers — Google has no "amr" claim and no configuration adds one. Reporting
		// strong_authentication:false in that case would read as a weak sign-in, when what happened
		// is that the provider was silent; absent fields say that without asserting it.
		if authenticationContext := providerClaims.AuthenticationContext(); authenticationContext != nil {
			if methodReferences := authenticationContext.MethodReferences; len(methodReferences) != 0 {
				logAttributes = append(
					logAttributes,
					slog.Any("authentication_method_references", methodReferences),
					slog.Bool("strong_authentication", authenticationContext.StrongAuthentication()),
				)
			}
			if contextClass := authenticationContext.ContextClass; contextClass != "" {
				logAttributes = append(logAttributes, slog.String("authentication_context_class", contextClass))
			}
			if authenticatedAt := authenticationContext.AuthenticatedAt; authenticatedAt != 0 {
				logAttributes = append(
					logAttributes,
					slog.Time("authenticated_at", time.Unix(authenticatedAt, 0).UTC()),
				)
			}
		}
		slog.InfoContext(ctx, "An identity provider authenticated a user.", logAttributes...)

		// A personal account belongs to no organization and so carries no identifier, which is what
		// makes this keep consumer accounts out. Refused after the sign-in is logged, so that the
		// refusal names the account it concerned.
		if e.RequireOrganization && organizationIdentifier == "" {
			return nil, &response_error.ResponseError{
				ClientError: altshiftErrors.NewWithTrace(ssoErrors.ErrForbiddenUser, organizationIdentifier),
				ProblemDetail: problem_detail.New(
					http.StatusForbidden,
					problem_detail_config.WithDetail("The account does not belong to an organization."),
				),
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

	config := id_token_endpoint_config.New(options...)
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
		RequireOrganization: config.RequireOrganization,
	}, nil
}
