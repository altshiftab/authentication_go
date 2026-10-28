// Package authorize_endpoint is the authorization endpoint (RFC 6749 section 3.1, OAuth 2.1): where
// a client sends the user to be asked whether it may act for them on a resource.
//
// The user is who their session says, through the sign-in the service already has -- someone with
// no session is sent to it, and back here after. What the client asks for is checked before anything
// is shown: a client the server does not know, or a redirect URI it does not have, is refused with a
// page and never redirected to, since sending the user to an address that is no client's would make
// the server an open redirector; anything else is sent back to the client as an OAuth error. What
// passes is held until the user answers the consent page.
package authorize_endpoint

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/altshiftab/authentication_go/pkg/oauth"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/client"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/endpoint/decision_endpoint"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/page"
	"github.com/altshiftab/authentication_go/pkg/pkce"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/query_extractor/query_extractor_config"
	muxResponse "github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/altshiftab/utils_go/pkg/http/mux/utils"
	altshiftReflect "github.com/altshiftab/utils_go/pkg/reflect"
	"github.com/altshiftab/utils_go/pkg/utils"
)

const (
	DefaultPath = "/oauth/authorize"
	// DefaultDecisionPath is where the consent page's answer is sent.
	DefaultDecisionPath = decision_endpoint.DefaultPath
	// RequestLifetime is how long the user has to answer the consent page.
	RequestLifetime = 5 * time.Minute
)

type UrlInput struct {
	ResponseType        string `json:"response_type,omitzero"`
	ClientId            string `json:"client_id,omitzero"`
	RedirectUri         string `json:"redirect_uri,omitzero"`
	State               string `json:"state,omitzero"`
	CodeChallenge       string `json:"code_challenge,omitzero"`
	CodeChallengeMethod string `json:"code_challenge_method,omitzero"`
	Scope               string `json:"scope,omitzero"`
	Resource            string `json:"resource,omitzero"`
}

var urlInputParser = query_extractor.New[*UrlInput](query_extractor_config.WithAllowAdditionalParameters(true))

// ClientResolver is how the endpoint knows a client.
type ClientResolver interface {
	Resolve(ctx context.Context, clientId string) (*client.Client, error)
}

type Endpoint struct {
	*initialization_endpoint.Endpoint
	DecisionPath string
	now          func() time.Time
}

// Initialize has the endpoint take the user from the authorizer -- which should send someone with no
// session to sign in -- know clients through the resolver, hold requests in the store, and allow
// tokens for the resources only.
func (e *Endpoint) Initialize(
	authorizer request_parser.RequestParser[*session_token.Token],
	issuer string,
	clients ClientResolver,
	store oauth.Store,
	resources []*oauth.Resource,
) error {
	if utils.IsNil(authorizer) {
		return altshiftErrors.NewWithTrace(nil_error.New("authorizer"))
	}
	if issuer == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("issuer"))
	}
	if utils.IsNil(clients) {
		return altshiftErrors.NewWithTrace(nil_error.New("client resolver"))
	}
	if utils.IsNil(store) {
		return altshiftErrors.NewWithTrace(nil_error.New("store"))
	}
	if len(resources) == 0 {
		return altshiftErrors.NewWithTrace(empty_error.New("resources"))
	}
	if e.now == nil {
		e.now = time.Now
	}

	e.AuthenticationParser = adapter.New(authorizer)
	e.Handler = func(request *http.Request, _ []byte) (*muxResponse.Response, *response_error.ResponseError) {
		ctx := request.Context()

		sessionToken, responseError := muxUtils.GetServerNonZeroParsedRequestAuthentication[*session_token.Token](ctx)
		if responseError != nil {
			return nil, responseError
		}
		input, responseError := muxUtils.GetServerNonZeroParsedRequestUrl[*UrlInput](ctx)
		if responseError != nil {
			return nil, responseError
		}

		// Who the client is, and where it may be sent, before anything is sent there.
		if input.ClientId == "" {
			return refusedPage(ctx, "The application did not say who it is.", "no client id")
		}
		resolved, err := clients.Resolve(ctx, input.ClientId)
		if err != nil {
			if errors.Is(err, altshiftErrors.ErrValidationError) {
				return refusedPage(ctx, "The application is not one this service knows.", "unknown client")
			}
			return nil, &response_error.ResponseError{ServerError: altshiftErrors.New(fmt.Errorf("client resolver resolve: %w", err))}
		}
		if resolved == nil {
			return nil, &response_error.ResponseError{ServerError: altshiftErrors.NewWithTrace(nil_error.New("client"))}
		}
		if !resolved.AllowsRedirectUri(input.RedirectUri) {
			return refusedPage(ctx, "The application asked to be answered at an address it does not have.", "redirect uri not registered")
		}

		refuse := func(errorCode string, description string) (*muxResponse.Response, *response_error.ResponseError) {
			slog.InfoContext(ctx, "An OAuth authorization request was refused.",
				slog.Group("oauth", slog.String("error", errorCode), slog.String("client_id", input.ClientId)))
			return redirect(input.RedirectUri, issuer, map[string]string{
				"error": errorCode, "error_description": description, "state": input.State,
			})
		}

		if input.ResponseType != "code" {
			return refuse("unsupported_response_type", "Only the authorization code flow is supported.")
		}
		// No state is required: OAuth 2.1 has the challenge do what a state did against a forged
		// response, and one sent is returned as it came.
		if input.CodeChallengeMethod != pkce.MethodS256 || !pkce.ValidChallenge(input.CodeChallenge) {
			return refuse("invalid_request", "A PKCE challenge by S256 is required.")
		}

		resource := oauth.FindResource(resources, input.Resource)
		if resource == nil {
			return refuse("invalid_target", "The resource is not one this server issues tokens for.")
		}
		scopes := strings.Fields(input.Scope)
		if len(scopes) == 0 {
			scopes = resource.Scopes
		}
		if !resource.AllowsScopes(scopes) {
			return refuse("invalid_scope", "The scope is not one the resource has.")
		}
		scope := strings.Join(scopes, " ")

		requestId, err := store.InsertAuthorizationRequest(ctx, &oauth.AuthorizationRequest{
			AccountId:     sessionToken.SubjectId,
			ClientId:      resolved.Id,
			ClientName:    resolved.Name,
			RedirectUri:   input.RedirectUri,
			State:         input.State,
			CodeChallenge: input.CodeChallenge,
			Resource:      resource.Url,
			Scope:         scope,
			ExpiresAt:     e.now().Add(RequestLifetime),
		})
		if err != nil {
			return nil, &response_error.ResponseError{ServerError: altshiftErrors.New(fmt.Errorf("store insert authorization request: %w", err))}
		}

		body, headers, err := page.RenderConsent(&page.Consent{
			ClientName:     resolved.Name,
			ClientId:       resolved.Id,
			SelfRegistered: resolved.SelfRegistered,
			RedirectUri:    input.RedirectUri,
			ResourceName:   resource.Name,
			ResourceUrl:    resource.Url,
			Scope:          scope,
			RequestId:      requestId,
			DecisionPath:   e.DecisionPath,
		})
		if err != nil {
			return nil, &response_error.ResponseError{ServerError: altshiftErrors.New(fmt.Errorf("page render consent: %w", err))}
		}

		return &muxResponse.Response{Body: body, Headers: headers}, nil
	}

	e.Initialized = true

	return nil
}

// refusedPage refuses a request that cannot be sent back to its client.
func refusedPage(ctx context.Context, detail string, reason string) (*muxResponse.Response, *response_error.ResponseError) {
	slog.InfoContext(ctx, "An OAuth authorization request was refused.", slog.Group("oauth", slog.String("error", reason)))

	body, headers, err := page.RenderMessage("The application's request was refused", detail)
	if err != nil {
		return nil, &response_error.ResponseError{ServerError: altshiftErrors.New(fmt.Errorf("page render message: %w", err))}
	}
	return &muxResponse.Response{StatusCode: http.StatusBadRequest, Body: body, Headers: headers}, nil
}

// redirect sends the user back to the client with the response's parameters.
func redirect(redirectUri string, issuer string, parameters map[string]string) (*muxResponse.Response, *response_error.ResponseError) {
	location, err := oauth.AuthorizationResponseUrl(redirectUri, issuer, parameters)
	if err != nil {
		return nil, &response_error.ResponseError{ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("authorization response url: %w", err))}
	}
	return &muxResponse.Response{
		StatusCode: http.StatusSeeOther,
		Headers: []*muxResponse.HeaderEntry{
			{Name: "Location", Value: location},
			{Name: "Cache-Control", Value: "no-store", Overwrite: true},
		},
	}, nil
}

func New() *Endpoint {
	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:      DefaultPath,
				Method:    http.MethodGet,
				UrlParser: adapter.New(urlInputParser),
				Hint: &endpoint.Hint{
					InputType:         altshiftReflect.TypeOf[UrlInput](),
					OutputContentType: "text/html",
				},
			},
		},
		DecisionPath: DefaultDecisionPath,
	}
}
