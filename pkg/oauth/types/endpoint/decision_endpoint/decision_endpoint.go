// Package decision_endpoint takes the user's answer to the consent page: on allowing, an
// authorization code for the client; on denying, the refusal. Either way the user is sent back to
// the client.
//
// The request answered is taken by its id, which only the consent page shown to its own user had,
// and must be that user's: a request is answered once, by the one it was made for. That is also
// what keeps another site from answering it on the user's behalf.
package decision_endpoint

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/altshiftab/authentication_go/pkg/log_masking"
	"github.com/altshiftab/authentication_go/pkg/oauth"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/page"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/body_loader"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/body_loader/body_setting"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	muxResponse "github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/altshiftab/utils_go/pkg/http/mux/utils"
	"github.com/altshiftab/utils_go/pkg/http/types/http_context_extractor/http_context_extractor_config"
	"github.com/altshiftab/utils_go/pkg/schema"
	"github.com/altshiftab/utils_go/pkg/utils"
)

const (
	DefaultPath = "/oauth/authorize/decision"
	// CodeLifetime is how long a code is good for: the client redeems it as it arrives.
	CodeLifetime = time.Minute
)

type Endpoint struct {
	*initialization_endpoint.Endpoint
	now func() time.Time
}

func (e *Endpoint) Initialize(authorizer request_parser.RequestParser[*session_token.Token], issuer string, store oauth.Store) error {
	if utils.IsNil(authorizer) {
		return altshiftErrors.NewWithTrace(nil_error.New("authorizer"))
	}
	if issuer == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("issuer"))
	}
	if utils.IsNil(store) {
		return altshiftErrors.NewWithTrace(nil_error.New("store"))
	}
	if e.now == nil {
		e.now = time.Now
	}

	e.AuthenticationParser = adapter.New(authorizer)
	e.Handler = func(request *http.Request, body []byte) (*muxResponse.Response, *response_error.ResponseError) {
		ctx := request.Context()

		sessionToken, responseError := muxUtils.GetServerNonZeroParsedRequestAuthentication[*session_token.Token](ctx)
		if responseError != nil {
			return nil, responseError
		}

		form, err := url.ParseQuery(string(body))
		if err != nil {
			return refusedPage(http.StatusBadRequest, "The answer could not be read.")
		}
		requestId, decision := form.Get("request_id"), form.Get("decision")
		if requestId == "" {
			return refusedPage(http.StatusBadRequest, "The answer did not say which request it answers.")
		}

		authorizationRequest, err := store.PopAuthorizationRequest(ctx, requestId)
		if errors.Is(err, oauth.ErrNotFound) {
			return refusedPage(http.StatusBadRequest, "The request has been answered already, or never was. Start again from the application.")
		}
		if err != nil {
			return nil, &response_error.ResponseError{ServerError: altshiftErrors.New(fmt.Errorf("store pop authorization request: %w", err))}
		}
		if authorizationRequest == nil {
			return nil, &response_error.ResponseError{ServerError: altshiftErrors.NewWithTrace(nil_error.New("authorization request"))}
		}
		if authorizationRequest.AccountId != sessionToken.SubjectId {
			return refusedPage(http.StatusForbidden, "The request was made for someone else.")
		}
		if !e.now().Before(authorizationRequest.ExpiresAt) {
			return refusedPage(http.StatusBadRequest, "The request has expired. Start again from the application.")
		}

		logAttributes := []any{
			slog.Group("user", slog.String("id", sessionToken.SubjectId)),
			slog.Group("oauth",
				slog.String("client_id", authorizationRequest.ClientId),
				slog.String("resource", authorizationRequest.Resource),
				slog.String("scope", authorizationRequest.Scope),
			),
		}

		switch decision {
		case "deny":
			slog.InfoContext(ctx, "An OAuth client was refused authorization.", logAttributes...)
			return redirect(authorizationRequest.RedirectUri, issuer, map[string]string{
				"error": "access_denied", "error_description": "The user denied the request.", "state": authorizationRequest.State,
			})
		case "allow":
		default:
			return refusedPage(http.StatusBadRequest, "The answer was neither to allow nor to deny.")
		}

		code, err := oauth.NewSecret()
		if err != nil {
			return nil, &response_error.ResponseError{ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("new secret: %w", err))}
		}
		if err := store.InsertAuthorizationCode(ctx, oauth.HashSecret(code), &oauth.AuthorizationCode{
			AccountId:     authorizationRequest.AccountId,
			ClientId:      authorizationRequest.ClientId,
			RedirectUri:   authorizationRequest.RedirectUri,
			CodeChallenge: authorizationRequest.CodeChallenge,
			Resource:      authorizationRequest.Resource,
			Scope:         authorizationRequest.Scope,
			ExpiresAt:     e.now().Add(CodeLifetime),
		}); err != nil {
			return nil, &response_error.ResponseError{ServerError: altshiftErrors.New(fmt.Errorf("store insert authorization code: %w", err))}
		}

		slog.InfoContext(ctx, "An OAuth client was authorized.", logAttributes...)

		return redirect(authorizationRequest.RedirectUri, issuer, map[string]string{"code": code, "state": authorizationRequest.State})
	}

	e.Initialized = true

	return nil
}

func refusedPage(status int, detail string) (*muxResponse.Response, *response_error.ResponseError) {
	body, headers, err := page.RenderMessage("The answer was not taken", detail)
	if err != nil {
		return nil, &response_error.ResponseError{ServerError: altshiftErrors.New(fmt.Errorf("page render message: %w", err))}
	}
	return &muxResponse.Response{StatusCode: status, Body: body, Headers: headers}, nil
}

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

// MaskedUrlParams is empty: the answer is sent in the body.
func (e *Endpoint) MaskedUrlParams() []*schema.Url {
	return nil
}

// MaskedBodyFields is nothing: the answer carries no secret, the request id being single-use and
// the user's own.
func (e *Endpoint) MaskedBodyFields() (*log_masking.BodyFields, error) {
	return nil, nil
}

// MaskedHeaders is the response's Location, which carries the authorization code to the client.
func (e *Endpoint) MaskedHeaders() []*http_context_extractor_config.MaskedHeader {
	return []*http_context_extractor_config.MaskedHeader{{Url: &schema.Url{Path: e.Path}, Headers: []string{"Location"}}}
}

func New() *Endpoint {
	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:      DefaultPath,
				Method:    http.MethodPost,
				UrlParser: adapter.New(query_extractor.Empty),
				BodyLoader: &body_loader.Loader{
					ContentType: "application/x-www-form-urlencoded",
					Setting:     body_setting.Required,
					MaxBytes:    4 * 1024,
				},
				Hint: &endpoint.Hint{OutputContentType: "text/html"},
			},
		},
	}
}
