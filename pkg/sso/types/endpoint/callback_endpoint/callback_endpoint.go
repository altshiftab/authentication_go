package callback_endpoint

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"github.com/altshiftab/utils_go/pkg/schema"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/altshiftab/authentication_go/pkg/database/types/oauth_flow"
	"github.com/altshiftab/authentication_go/pkg/session/types/authentication_method"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_manager"
	ssoErrors "github.com/altshiftab/authentication_go/pkg/sso/errors"
	"github.com/altshiftab/authentication_go/pkg/sso/errors/oauth_error"
	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/callback_endpoint/callback_endpoint_config"
	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/problem_detail_endpoint/access_denied_endpoint"
	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/problem_detail_endpoint/sign_in_cancelled_endpoint"
	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/problem_detail_endpoint/sign_in_failed_endpoint"
	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/problem_detail_endpoint/sign_in_unavailable_endpoint"
	"github.com/altshiftab/authentication_go/pkg/sso/types/provider_claims"
	altshiftContext "github.com/altshiftab/utils_go/pkg/context"
	altshiftDatabase "github.com/altshiftab/utils_go/pkg/database"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	altshiftHttpContext "github.com/altshiftab/utils_go/pkg/http/context"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/query_extractor/query_extractor_config"
	muxResponse "github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/altshiftab/utils_go/pkg/http/mux/utils"
	altshiftHttpTypes "github.com/altshiftab/utils_go/pkg/http/types"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	altshiftJws "github.com/altshiftab/utils_go/pkg/json/jose/jws"
	authenticatorPkg "github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/authenticator"
	altshiftOauth2 "github.com/altshiftab/utils_go/pkg/oauth2"
	altshiftOauth2Config "github.com/altshiftab/utils_go/pkg/oauth2/types/config"
	altshiftReflect "github.com/altshiftab/utils_go/pkg/reflect"
	"github.com/altshiftab/utils_go/pkg/utils"
)

// categoryProblemPaths maps an OAuth error category to the canonical path of its
// problem page. Redirect targets are these paths resolved against the origin
// passed to Initialize, so the problem endpoints must be mounted at these paths.
var categoryProblemPaths = map[oauth_error.Category]string{
	oauth_error.CategoryCancelled:    sign_in_cancelled_endpoint.DefaultType,
	oauth_error.CategoryAccessDenied: access_denied_endpoint.DefaultType,
	oauth_error.CategoryUnavailable:  sign_in_unavailable_endpoint.DefaultType,
	oauth_error.CategoryFailed:       sign_in_failed_endpoint.DefaultType,
}

type UrlInput struct {
	State        string `json:"state"`
	Code         string `json:"code,omitzero"`
	Scope        string `json:"scope,omitzero"`
	AuthUser     int    `json:"authuser,omitzero"`
	HostedDomain string `json:"hd,omitzero"`
	Prompt       string `json:"prompt,omitzero"`
	SessionState string `json:"session_state,omitzero"`

	// OAuth 2.0 authorization error response parameters (RFC 6749 §4.1.2.1). The
	// provider sets these instead of `code` when authorization does not succeed,
	// e.g. when the user declines consent or cancels (error=access_denied).
	// ErrorSubcode is a Microsoft extension (e.g. error_subcode=cancel).
	Error            string `json:"error,omitzero"`
	ErrorSubcode     string `json:"error_subcode,omitzero"`
	ErrorDescription string `json:"error_description,omitzero"`
	ErrorUri         string `json:"error_uri,omitzero"`
}

var urlInputParser = query_extractor.New[*UrlInput](query_extractor_config.WithAllowAdditionalParameters(true))

type Endpoint[T provider_claims.ProviderClaims] struct {
	*initialization_endpoint.Endpoint
	CallbackCookieName                   string
	DbscChallengeDuration                time.Duration
	RequireStrongAuthentication          bool
	StrongAuthenticationMethodReferences []string
	RequireOrganization                  bool
	AllowedOrganizations                 []string
	popOauthFlow                         func(ctx context.Context, id string, database *sql.DB) (*oauth_flow.Flow, error)
	problemRedirectUrls                  map[oauth_error.Category]string
	classifyOauthError                   func(*oauth_error.Error) oauth_error.Category
}

// Initialize wires the endpoint's runtime dependencies. origin is the base URL
// (scheme and host, e.g. "https://admin.example.com") that the problem page
// paths are resolved against to form the error redirect targets; an empty origin
// yields same-origin relative redirects. The problem endpoints must be mounted
// at the paths in categoryProblemPaths.
func (e *Endpoint[T]) Initialize(
	origin string,
	oauthConfig *altshiftOauth2Config.Config,
	idTokenAuthenticator *authenticatorPkg.AuthenticatorWithKeyHandler,
	sessionManager *session_manager.Manager,
) error {
	if oauthConfig == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("oauth config"))
	}

	if idTokenAuthenticator == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("id token authenticator"))
	}

	if sessionManager == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("session manager"))
	}

	origin = strings.TrimRight(origin, "/")
	problemRedirectUrls := make(map[oauth_error.Category]string, len(categoryProblemPaths))
	for category, path := range categoryProblemPaths {
		problemRedirectUrls[category] = origin + path
	}
	e.problemRedirectUrls = problemRedirectUrls

	db := sessionManager.Db
	if db == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("session manager sql db"))
	}

	e.Handler = func(request *http.Request, body []byte) (*muxResponse.Response, *response_error.ResponseError) {
		ctx := request.Context()

		urlInput, responseError := muxUtils.GetServerNonZeroParsedRequestUrl[*UrlInput](ctx)
		if responseError != nil {
			return nil, responseError
		}

		callbackCookie, err := request.Cookie(e.CallbackCookieName)
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				return nil, &response_error.ResponseError{
					ProblemDetail: problem_detail.New(
						http.StatusBadRequest,
						problem_detail_config.WithDetail("No callback cookie."),
					),
				}
			}
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("request cookie: %w", err), e.CallbackCookieName),
			}
		}
		if callbackCookie == nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(nil_error.NewWithInstance("cookie", "callback")),
			}
		}

		oauthFlowId := callbackCookie.Value
		if oauthFlowId == "" {
			return nil, &response_error.ResponseError{
				ClientError: altshiftErrors.NewWithTrace(empty_error.New("callback cookie value")),
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("Empty callback cookie."),
				),
			}
		}

		dbPopCtx, dbPopCtxCancel := altshiftDatabase.MakeTimeoutCtx(ctx)
		defer dbPopCtxCancel()

		oauthFlow, err := e.popOauthFlow(dbPopCtx, oauthFlowId, db)
		if err != nil {
			wrappedErr := altshiftErrors.New(fmt.Errorf("get oauth flow: %w", err), oauthFlowId)
			if errors.Is(err, sql.ErrNoRows) {
				return nil, &response_error.ResponseError{
					ClientError: wrappedErr,
					ProblemDetail: problem_detail.New(
						http.StatusBadRequest,
						problem_detail_config.WithDetail("No OAuth flow matches the callback cookie value."),
					),
				}
			}
			return nil, &response_error.ResponseError{ServerError: wrappedErr}
		}
		if oauthFlow == nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.New(nil_error.New("oauth flow")),
			}
		}

		oauthFlowExpiresAt := oauthFlow.ExpiresAt
		if oauthFlowExpiresAt == nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(nil_error.New("oauth flow expires at")),
			}
		}

		if oauthFlowExpiresAt.Before(time.Now()) {
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The OAuth flow has expired."),
				),
			}
		}

		if oauthFlow.State != urlInput.State {
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The OAuth flow state and url state do not match."),
				),
			}
		}

		clearedCallbackCookie := http.Cookie{
			Name:     e.CallbackCookieName,
			Path:     e.Path,
			Expires:  time.Unix(0, 0),
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}

		// If the provider returned an error instead of an authorization code (e.g.
		// the user declined consent or cancelled: error=access_denied), this is an
		// expected outcome rather than a server fault. Classify it, clear the
		// callback cookie, and redirect to the matching problem page. Categories
		// that are not recoverable (denials, misconfiguration) deliberately land on
		// a terminal page rather than the originating URL, which could otherwise
		// re-trigger the login flow and loop.
		if urlInput.Error != "" {
			oauthError := oauth_error.New(
				urlInput.Error,
				urlInput.ErrorSubcode,
				urlInput.ErrorDescription,
				urlInput.ErrorUri,
			)

			category := oauthError.Category()
			if e.classifyOauthError != nil {
				category = e.classifyOauthError(oauthError)
			}

			// Bridge the mux's HTTP context onto the logging context so the
			// registered http_context_extractor populates the ECS http/url/client/...
			// fields. The mux only does this automatically when it handles a
			// ResponseError, which is deliberately avoided here.
			logCtx := ctx
			if httpContext, ok := ctx.Value(muxPkg.MuxHttpContextContextKey).(*altshiftHttpTypes.HttpContext); ok {
				logCtx = altshiftHttpContext.WithHttpContextValue(ctx, httpContext)
			}

			slog.WarnContext(
				altshiftContext.WithError(logCtx, altshiftErrors.NewWithTrace(oauthError)),
				"An OAuth error occurred.",
				slog.Group(
					"event",
					slog.String("reason", "An OAuth error occurred."),
					slog.String("action", "log_oauth_error"),
				),
			)

			// Resolve the redirect target: the category-specific problem page, then
			// the catch-all problem page, then the originating URL as a last resort
			// (preserving the legacy behavior when no problem pages are configured).
			redirectUrl := e.problemRedirectUrls[category]
			if redirectUrl == "" {
				redirectUrl = e.problemRedirectUrls[oauth_error.CategoryFailed]
			}
			if redirectUrl == "" {
				redirectUrl = oauthFlow.RedirectUrl
			}

			return &muxResponse.Response{
				StatusCode: http.StatusSeeOther,
				Headers: []*muxResponse.HeaderEntry{
					{Name: "Location", Value: redirectUrl},
					{Name: "Set-Cookie", Value: clearedCallbackCookie.String()},
				},
			}, nil
		}

		if urlInput.Code == "" {
			return nil, &response_error.ResponseError{
				ClientError: altshiftErrors.NewWithTrace(empty_error.New("code")),
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("Missing authorization code."),
				),
			}
		}

		token, err := oauthConfig.Exchange(ctx, urlInput.Code, altshiftOauth2.VerifierOption(oauthFlow.CodeVerifier))
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("oauth config exchange: %w", err)),
			}
		}
		if token == nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(nil_error.New("oauth token")),
			}
		}

		idTokenAny := token.Extra("id_token")
		idToken, err := utils.ConvertToNonZero[string](idTokenAny)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.New(fmt.Errorf("convert to non zero (id token): %w", err), idTokenAny),
			}
		}

		authenticatedIdToken, err := idTokenAuthenticator.Authenticate(ctx, idToken)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.New(
					fmt.Errorf("authenticator with key handler authenticate: %w", err),
					idToken,
				),
			}
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
					fmt.Errorf("json unmarshal (authenticated id token raw): %w", err),
					idTokenPayload,
				),
			}
		}

		// Resolved before anything is logged or refused, so that every line about this sign-in —
		// including a refusal — says which account it concerned. Attached to the HTTP context
		// rather than to one message, so it reaches the request log too and correlates with the
		// rest of the service by the same fields.
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

		if httpContext, ok := ctx.Value(muxPkg.MuxHttpContextContextKey).(*altshiftHttpTypes.HttpContext); ok && httpContext != nil {
			httpContext.User = &schema.User{
				Id:     providerClaims.Subject(),
				Email:  emailAddress,
				Domain: organizationIdentifier,
			}
		}

		// Logged for every sign-in, not just when a strong method is required: how the provider
		// authenticated the user, and when, is the context that makes a sign-in explicable
		// afterwards.
		authenticationContext := providerClaims.AuthenticationContext()
		strongAuthentication := authenticationContext.HasAnyMethodReference(e.StrongAuthenticationMethodReferences)

		// Named on the message itself as well as on the HTTP context: the context is read by the
		// logger when the request completes, which does not help a line written mid-handler.
		logAttributes := []any{
			slog.Group(
				"user",
				slog.String("id", providerClaims.Subject()),
				slog.String("email", emailAddress),
			),
			slog.Bool("strong_authentication", strongAuthentication),
			slog.Bool("strong_authentication_required", e.RequireStrongAuthentication),
			slog.Bool("organization_required", e.RequireOrganization),
			slog.String("organization", organizationIdentifier),
		}
		if authenticationContext != nil {
			logAttributes = append(
				logAttributes,
				slog.Any("authentication_method_references", authenticationContext.MethodReferences),
				slog.String("authentication_context_class", authenticationContext.ContextClass),
			)
			if authenticatedAt := authenticationContext.AuthenticatedAt; authenticatedAt != 0 {
				logAttributes = append(
					logAttributes,
					slog.Time("authenticated_at", time.Unix(authenticatedAt, 0).UTC()),
				)
			}
		}
		slog.InfoContext(ctx, "An identity provider authenticated a user.", logAttributes...)

		// A personal account belongs to no organization and so carries no identifier, which is what
		// makes this keep consumer accounts out.
		if e.RequireOrganization && organizationIdentifier == "" {
			return nil, &response_error.ResponseError{
				ClientError: altshiftErrors.NewWithTrace(ssoErrors.ErrForbiddenUser, organizationIdentifier),
				ProblemDetail: problem_detail.New(
					http.StatusForbidden,
					problem_detail_config.WithDetail("The account does not belong to an organization."),
				),
			}
		}

		// An account with no organization is never on the list, so an allow list also excludes
		// personal accounts whether or not an organization is separately required.
		if allowedOrganizations := e.AllowedOrganizations; len(allowedOrganizations) != 0 {
			if organizationIdentifier == "" || !slices.Contains(allowedOrganizations, organizationIdentifier) {
				return nil, &response_error.ResponseError{
					ClientError: altshiftErrors.NewWithTrace(ssoErrors.ErrForbiddenUser, organizationIdentifier),
					ProblemDetail: problem_detail.New(
						http.StatusForbidden,
						problem_detail_config.WithDetail(
							"The account does not belong to an organization that is allowed to sign in.",
						),
					),
				}
			}
		}

		if e.RequireStrongAuthentication && !strongAuthentication {
			return nil, &response_error.ResponseError{
				ClientError: altshiftErrors.NewWithTrace(ssoErrors.ErrForbiddenUser),
				ProblemDetail: problem_detail.New(
					http.StatusForbidden,
					problem_detail_config.WithDetail(
						"The identity provider did not state that a strong enough authentication method was used.",
					),
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

		response.StatusCode = http.StatusSeeOther

		response.Headers = append(
			response.Headers,
			&muxResponse.HeaderEntry{
				Name:  "Location",
				Value: oauthFlow.RedirectUrl,
			},
			&muxResponse.HeaderEntry{
				Name:  "Set-Cookie",
				Value: clearedCallbackCookie.String(),
			},
		)

		return response, nil
	}

	e.Initialized = true

	return nil
}

func New[T provider_claims.ProviderClaims](path string, options ...callback_endpoint_config.Option) (*Endpoint[T], error) {
	if path == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("path"))
	}

	config := callback_endpoint_config.New(options...)
	return &Endpoint[T]{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:      path,
				Method:    http.MethodGet,
				UrlParser: adapter.New(urlInputParser),
				Public:    true,
				Hint: &endpoint.Hint{
					InputType: altshiftReflect.TypeOf[UrlInput](),
				},
			},
		},
		CallbackCookieName:                   config.CallbackCookieName,
		RequireStrongAuthentication:          config.RequireStrongAuthentication,
		StrongAuthenticationMethodReferences: config.StrongAuthenticationMethodReferences,
		RequireOrganization:                  config.RequireOrganization,
		AllowedOrganizations:                 config.AllowedOrganizations,
		popOauthFlow:                         config.PopOauthFlow,
		classifyOauthError:                   config.ClassifyOauthError,
	}, nil
}
