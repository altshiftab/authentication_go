package callback_endpoint

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"github.com/altshiftab/authentication_go/pkg/log_masking"
	"github.com/altshiftab/authentication_go/pkg/log_options"
	"github.com/altshiftab/utils_go/pkg/http/types/http_context_extractor/http_context_extractor_config"
	"github.com/altshiftab/utils_go/pkg/schema"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"uuid"

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

// How many cookies of the callback name are tried. More than one arrives when
// the front end forwards a single cookie name and the session cookie shares it;
// a list longer than this is not a browser doing that.
const maxCallbackCookieValues = 4

// The login endpoint's parameter naming where a sign-in is bound, as login_endpoint.UrlInput reads it.
const loginRedirectParameter = "redirect"

var (
	errInvalidLoginPath   = errors.New("login path is not a plain absolute path")
	errUnexpiredOauthFlow = errors.New("unexpired oauth flow popped as expired")
)

const (
	locationHeaderName  = "Location"
	setCookieHeaderName = "Set-Cookie"
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
	RequireEmailDomainOwnerVerified      bool

	// Log is what the sign-in's lines and the request log say about the person signing in, and what
	// the service adds to them; see callback_endpoint_config.WithLog.
	Log *log_options.Config

	// LoginPath is the path of the login endpoint whose flows this completes; see callback_endpoint_config.
	LoginPath string

	popOauthFlow               func(ctx context.Context, id string, database *sql.DB) (*oauth_flow.Flow, error)
	popExpiredOauthFlowByState func(ctx context.Context, state string, now time.Time, database *sql.DB) (*oauth_flow.Flow, error)
	problemRedirectUrls        map[oauth_error.Category]string
	classifyOauthError         func(*oauth_error.Error) oauth_error.Category

	// loginUrl is LoginPath resolved against the origin by Initialize; nil without a LoginPath.
	loginUrl *url.URL

	// tokenEndpoint is the provider's token URL, as the log's body masks name it; set by Initialize.
	tokenEndpoint *schema.Url
}

// Initialize wires the endpoint's runtime dependencies. origin is the base URL
// (scheme and host, e.g. "https://admin.example.com") that the problem page
// paths are resolved against to form the error redirect targets; an empty origin
// yields same-origin relative redirects. The problem endpoints must be mounted
// at the paths in categoryProblemPaths. LoginPath is resolved against the same origin.
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

	// Refused here rather than met at the first sign-in: a token URL that does not parse is one the
	// exchange cannot reach either, and the log could not be told what to mask of it.
	tokenUrl, err := url.Parse(oauthConfig.Endpoint.TokenURL)
	if err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("url parse (token url): %w", err), oauthConfig.Endpoint.TokenURL)
	}
	if tokenUrl.Hostname() == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("token url host"))
	}
	e.tokenEndpoint = &schema.Url{Domain: tokenUrl.Hostname(), Path: tokenUrl.Path}

	origin = strings.TrimRight(origin, "/")
	problemRedirectUrls := make(map[oauth_error.Category]string, len(categoryProblemPaths))
	for category, path := range categoryProblemPaths {
		problemRedirectUrls[category] = origin + path
	}
	e.problemRedirectUrls = problemRedirectUrls

	e.loginUrl = nil
	if loginPath := e.LoginPath; loginPath != "" {
		// Anything more than a path could take the restart to another origin: "//host/login" is one.
		loginPathUrl, err := url.Parse(loginPath)
		if err != nil {
			return altshiftErrors.NewWithTrace(fmt.Errorf("url parse (login path): %w", err), loginPath)
		}
		if loginPathUrl.Scheme != "" || loginPathUrl.Host != "" || loginPathUrl.RawQuery != "" ||
			loginPathUrl.Fragment != "" || !strings.HasPrefix(loginPath, "/") || strings.Contains(loginPath, `\`) {
			return altshiftErrors.NewWithTrace(errInvalidLoginPath, loginPath)
		}
		originUrl, err := url.Parse(origin)
		if err != nil {
			return altshiftErrors.NewWithTrace(fmt.Errorf("url parse (origin): %w", err), origin)
		}
		e.loginUrl = originUrl.ResolveReference(&url.URL{Path: loginPath})
	}

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

		clearedCallbackCookie := http.Cookie{
			Name:     e.CallbackCookieName,
			Path:     e.Path,
			Expires:  time.Unix(0, 0),
			MaxAge:   -1,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}

		// Every cookie of the name is tried, rather than the first. A deployment
		// behind a front end that forwards only one cookie name -- Firebase
		// Hosting forwards only `__session` -- has to give this cookie that name
		// too, which is also the session cookie's. The two remain distinct
		// cookies, this one host-only and scoped to the callback path and the
		// session one domain-scoped at "/", but a signed-in browser sends both and
		// which of them arrives first is not a thing to depend on.
		callbackCookies := request.CookiesNamed(e.CallbackCookieName)
		if len(callbackCookies) == 0 {
			return nil, e.refuseOrRestart(ctx, urlInput, db, &clearedCallbackCookie, &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("No callback cookie."),
				),
			})
		}

		var callbackCookieValues []string
		for _, callbackCookie := range callbackCookies {
			if callbackCookie == nil || callbackCookie.Value == "" {
				continue
			}
			callbackCookieValues = append(callbackCookieValues, callbackCookie.Value)
			if len(callbackCookieValues) == maxCallbackCookieValues {
				break
			}
		}
		if len(callbackCookieValues) == 0 {
			return nil, e.refuseOrRestart(ctx, urlInput, db, &clearedCallbackCookie, &response_error.ResponseError{
				ClientError: altshiftErrors.NewWithTrace(empty_error.New("callback cookie value")),
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("Empty callback cookie."),
				),
			})
		}

		if len(callbackCookieValues) > 1 {
			// Counted, never written out: one of these values is liable to be a
			// live session token.
			slog.WarnContext(ctx, "Several callback cookies.", "count", len(callbackCookieValues))
		}

		dbPopCtx, dbPopCtxCancel := altshiftDatabase.MakeTimeoutCtx(ctx)
		defer dbPopCtxCancel()

		var oauthFlow *oauth_flow.Flow
		var popErr error
		for _, callbackCookieValue := range callbackCookieValues {
			// A flow id is a uuid, so anything else -- a session token sharing the name -- is not
			// put to the store, whose refusal of its syntax would read as the store failing. It is
			// put in canonical form, since the parser accepts forms the store does not.
			flowId, err := uuid.Parse(callbackCookieValue)
			if err != nil {
				continue
			}

			// A pop that matches nothing removes nothing, so the values can be tried in turn. None of
			// them is named in an error: see above. An error moves on to the next value too, and the
			// last is kept so that a store failing outright is a server error, not a bad request.
			poppedOauthFlow, err := e.popOauthFlow(dbPopCtx, flowId.String(), db)
			if err != nil {
				if !errors.Is(err, sql.ErrNoRows) {
					popErr = err
				}
				continue
			}
			if poppedOauthFlow == nil {
				return nil, &response_error.ResponseError{
					ServerError: altshiftErrors.New(nil_error.New("oauth flow")),
				}
			}

			oauthFlow = poppedOauthFlow
			break
		}
		if oauthFlow == nil && popErr != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.New(fmt.Errorf("get oauth flow: %w", popErr)),
			}
		}
		if oauthFlow == nil {
			// No sign-in is completed from here: the cookie is what binds the callback to the browser
			// that began the flow, and the state in the URL is had by whoever holds the link.
			return nil, e.refuseOrRestart(ctx, urlInput, db, &clearedCallbackCookie, &response_error.ResponseError{
				ClientError: altshiftErrors.NewWithTrace(
					ssoErrors.ErrNoMatchingOauthFlow,
					len(callbackCookieValues),
				),
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("No OAuth flow matches the callback cookie value."),
				),
			})
		}

		oauthFlowExpiresAt := oauthFlow.ExpiresAt
		if oauthFlowExpiresAt == nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(nil_error.New("oauth flow expires at")),
			}
		}

		if oauthFlowExpiresAt.Before(time.Now()) {
			// A provider error is an answer -- a decline, say -- that a restart would ask for again.
			if e.loginUrl != nil && urlInput.Error == "" {
				return nil, restartSignIn(e.loginUrl, oauthFlow.RedirectUrl, &clearedCallbackCookie)
			}
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

			// What the identity provider said, with the request it came on, for the service's own log:
			// the error with its description. The mux's HTTP context is bridged onto the logging
			// context so the registered http_context_extractor populates the ECS http/url/client/...
			// fields; the mux only does that when it handles a ResponseError, which is deliberately
			// avoided here. The line carries no event, so that it is not taken for the record below.
			logCtx := ctx
			if httpContext, ok := ctx.Value(muxPkg.MuxHttpContextContextKey).(*altshiftHttpTypes.HttpContext); ok {
				logCtx = altshiftHttpContext.WithHttpContextValue(ctx, httpContext)
			}
			slog.WarnContext(altshiftContext.WithError(logCtx, oauthError), "An OAuth error occurred.")

			// The record of it: the identity provider did not authenticate the user -- they declined,
			// or it refused them. A service may keep its records longer than its log, so the record
			// carries the error's codes alone, not the description, which is the provider's free text
			// and can name the account, nor the request, which the success's record does not carry
			// either.
			slog.WarnContext(
				altshiftContext.WithError(ctx, oauthError.Summary()),
				"An identity provider did not authenticate a user.",
				e.Log.Attrs(
					e.Log.Event(
						[]string{log_options.CategoryAuthentication},
						[]string{log_options.TypeStart},
						"identity_provider_authentication",
						log_options.OutcomeFailure,
						"An OAuth error occurred.",
					),
				)...,
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
					{Name: locationHeaderName, Value: redirectUrl},
					{Name: setCookieHeaderName, Value: clearedCallbackCookie.String()},
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
				ServerError: altshiftErrors.New(fmt.Errorf("convert to non zero (id token): %w", err)),
			}
		}

		authenticatedIdToken, err := idTokenAuthenticator.Authenticate(ctx, idToken)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.New(fmt.Errorf("authenticator with key handler authenticate: %w", err)),
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
				ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("jwt parse: %w", err)),
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
				ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("json unmarshal (authenticated id token raw): %w", err)),
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
				providerClaims.Subject(),
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
			user := e.Log.User(providerClaims.Subject(), emailAddress)
			user.Domain = organizationIdentifier
			httpContext.User = user
		}

		// Logged for every sign-in, not just when a strong method is required: how the provider
		// authenticated the user, and when, is the context that makes a sign-in explicable
		// afterwards.
		authenticationContext := providerClaims.AuthenticationContext()
		strongAuthentication := authenticationContext.HasAnyMethodReference(e.StrongAuthenticationMethodReferences)

		// Named on the message itself as well as on the HTTP context: the context is read by the
		// logger when the request completes, which does not help a line written mid-handler. How the
		// address is named -- by its hash, by itself, or not at all -- is the service's to say.
		//
		// What the line records is the identity provider's authentication, not the sign-in: the
		// checks below can still refuse the user, and do so after it is written.
		logAttributes := []any{
			e.Log.Event(
				[]string{log_options.CategoryAuthentication},
				[]string{log_options.TypeStart},
				"identity_provider_authentication",
				log_options.OutcomeSuccess,
				"",
			),
			slog.Group("user", e.Log.UserAttrs(providerClaims.Subject(), emailAddress)...),
			slog.Bool("strong_authentication", strongAuthentication),
			slog.Bool("strong_authentication_required", e.RequireStrongAuthentication),
			slog.Bool("organization_required", e.RequireOrganization),
			slog.Group("organization", slog.String("id", organizationIdentifier)),
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
		// Whether the account's organization verified the domain of its address, where the provider
		// says so (Microsoft's xms_edov), and whether that is required, as below.
		emailDomainOwnerVerified := ""
		if verifier, ok := any(providerClaims).(provider_claims.EmailDomainOwnerVerifier); ok {
			emailDomainOwnerVerified = verifier.EmailDomainOwnerVerified()
			logAttributes = append(
				logAttributes,
				slog.String("email_domain_owner_verified", emailDomainOwnerVerified),
				slog.Bool("email_domain_owner_verified_required", e.RequireEmailDomainOwnerVerified),
			)
		}
		slog.InfoContext(ctx, "An identity provider authenticated a user.", e.Log.Attrs(logAttributes...)...)

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

		// An address in a domain the account's organization has not verified can be anyone's, and
		// the account is found by its address. New takes the requirement only of claims that can say;
		// claims that cannot are refused here too, rather than admitted unchecked.
		if e.RequireEmailDomainOwnerVerified && emailDomainOwnerVerified != provider_claims.FlagTrue {
			return nil, &response_error.ResponseError{
				ClientError: altshiftErrors.NewWithTrace(ssoErrors.ErrForbiddenUser, emailDomainOwnerVerified),
				ProblemDetail: problem_detail.New(
					http.StatusForbidden,
					problem_detail_config.WithDetail(
						"The organization the account belongs to has not verified the domain of its email address.",
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
				Name:  locationHeaderName,
				Value: oauthFlow.RedirectUrl,
			},
			&muxResponse.HeaderEntry{
				Name:  setCookieHeaderName,
				Value: clearedCallbackCookie.String(),
			},
		)

		return response, nil
	}

	e.Initialized = true

	return nil
}

// refuseOrRestart answers a callback that no flow cookie completes: with the refusal, unless the
// state names a flow that expired, which is removed and its sign-in restarted. The state can restart
// a sign-in but never completes one, and a live flow is never restarted, so a browser that cannot
// keep the cookie is refused rather than sent round again. A provider error is never restarted: it
// is an answer -- a decline, say -- that a restart would ask for again.
func (e *Endpoint[T]) refuseOrRestart(
	ctx context.Context,
	urlInput *UrlInput,
	db *sql.DB,
	clearedCallbackCookie *http.Cookie,
	refusal *response_error.ResponseError,
) *response_error.ResponseError {
	if e.loginUrl == nil || urlInput == nil || urlInput.State == "" || urlInput.Error != "" {
		return refusal
	}

	dbCtx, dbCtxCancel := altshiftDatabase.MakeTimeoutCtx(ctx)
	defer dbCtxCancel()

	// The state is not named in an error: it correlates a sign-in, as the log's masks say.
	now := time.Now()
	expiredOauthFlow, err := e.popExpiredOauthFlowByState(dbCtx, urlInput.State, now, db)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return refusal
		}
		return &response_error.ResponseError{
			ServerError: altshiftErrors.New(fmt.Errorf("pop expired oauth flow by state: %w", err)),
		}
	}
	if expiredOauthFlow == nil {
		return &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("expired oauth flow")),
		}
	}

	// Checked here as well as in the store, since a store is configurable and a live flow must not restart.
	expiresAt := expiredOauthFlow.ExpiresAt
	if expiresAt == nil {
		return &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("expired oauth flow expires at")),
		}
	}
	if expiresAt.After(now) {
		return &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(errUnexpiredOauthFlow, *expiresAt),
		}
	}

	return restartSignIn(e.loginUrl, expiredOauthFlow.RedirectUrl, clearedCallbackCookie)
}

// restartSignIn sends the browser to the login endpoint to sign in again, bound where the expired
// flow was. The problem detail stays, and the Location header makes the mux answer 303.
func restartSignIn(loginUrl *url.URL, redirectUrl string, clearedCallbackCookie *http.Cookie) *response_error.ResponseError {
	if loginUrl == nil {
		return &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("login url")),
		}
	}

	restartUrl := *loginUrl
	query := restartUrl.Query()
	query.Set(loginRedirectParameter, redirectUrl)
	restartUrl.RawQuery = query.Encode()

	return &response_error.ResponseError{
		ClientError: altshiftErrors.NewWithTrace(ssoErrors.ErrExpiredOauthFlow),
		ProblemDetail: problem_detail.New(
			http.StatusBadRequest,
			problem_detail_config.WithDetail("The OAuth flow has expired; the sign-in is restarted."),
		),
		Headers: []*muxResponse.HeaderEntry{
			{Name: locationHeaderName, Value: restartUrl.String()},
			{Name: setCookieHeaderName, Value: clearedCallbackCookie.String()},
		},
	}
}

func New[T provider_claims.ProviderClaims](path string, options ...callback_endpoint_config.Option) (*Endpoint[T], error) {
	if path == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("path"))
	}

	config := callback_endpoint_config.New(options...)

	// Required of claims that cannot say, it would be enforced nowhere, which is refused here rather
	// than found out when a sign-in is admitted without it.
	if config.RequireEmailDomainOwnerVerified {
		var claims T
		if _, ok := any(claims).(provider_claims.EmailDomainOwnerVerifier); !ok {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: %T", ssoErrors.ErrEmailDomainOwnerNotSaid, claims))
		}
	}

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
		RequireEmailDomainOwnerVerified:      config.RequireEmailDomainOwnerVerified,
		LoginPath:                            config.LoginPath,
		Log:                                  config.Log,
		popOauthFlow:                         config.PopOauthFlow,
		popExpiredOauthFlowByState:           config.PopExpiredOauthFlowByState,
		classifyOauthError:                   config.ClassifyOauthError,
	}, nil
}

// MaskedUrlParams is what of the callback's URL the log masks: the authorization code, which is a
// credential until it is redeemed, the state that correlates it, and the session state some
// providers add. The access log writes the URL of every request, so the callback's would carry them.
func (e *Endpoint[T]) MaskedUrlParams() []*schema.Url {
	return []*schema.Url{{Path: e.Path, Query: "code&state&session_state"}}
}

// MaskedBodyFields are the credentials of the exchange with the provider's token endpoint: its
// request's client secret, code and verifier, and its response's tokens, a failed exchange being
// logged with both. The rest is kept -- the grant asked for, and the error a refusal says it with.
// The endpoint is known once the endpoint is initialized, and asking before is an error.
func (e *Endpoint[T]) MaskedBodyFields() (*log_masking.BodyFields, error) {
	if e.tokenEndpoint == nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("not initialized: %w", nil_error.New("token endpoint")))
	}
	return &log_masking.BodyFields{
		Request: []*http_context_extractor_config.MaskedBodyFields{
			{Url: e.tokenEndpoint, Fields: altshiftOauth2.TokenRequestCredentialFields()},
		},
		Response: []*http_context_extractor_config.MaskedBodyFields{
			{Url: e.tokenEndpoint, Fields: altshiftOauth2.TokenResponseCredentialFields()},
		},
	}, nil
}

// MaskedHeaders is empty: nothing in this endpoint's request headers needs more than the log's own
// masking.
func (e *Endpoint[T]) MaskedHeaders() []*http_context_extractor_config.MaskedHeader {
	return nil
}
