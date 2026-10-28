// Package revocation_endpoint is the revocation endpoint (RFC 7009): where a client gives up what
// it was granted, as Claude does when the user removes a connector.
//
// A refresh token revokes its grant, and with it every token the grant renews. An access token is
// left to expire, being short-lived and recorded nowhere to revoke it by; the request is answered
// as done all the same, as it is for a token not known, the RFC having the client told nothing it
// could learn tokens by.
package revocation_endpoint

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/altshiftab/authentication_go/pkg/log_masking"
	"github.com/altshiftab/authentication_go/pkg/oauth"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/body_loader"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/body_loader/body_setting"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	muxResponse "github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	"github.com/altshiftab/utils_go/pkg/http/types/http_context_extractor/http_context_extractor_config"
	"github.com/altshiftab/utils_go/pkg/schema"
	"github.com/altshiftab/utils_go/pkg/utils"
)

const DefaultPath = "/oauth/revoke"

// ErrorResponse is an error response (RFC 7009 section 2.2.1, as RFC 6749 section 5.2).
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitzero"`
}

type Endpoint struct {
	*initialization_endpoint.Endpoint
}

func (e *Endpoint) Initialize(store oauth.Store) error {
	if utils.IsNil(store) {
		return altshiftErrors.NewWithTrace(nil_error.New("store"))
	}

	e.Handler = func(request *http.Request, body []byte) (*muxResponse.Response, *response_error.ResponseError) {
		ctx := request.Context()

		form, err := url.ParseQuery(string(body))
		if err != nil {
			return refuse(ctx, "invalid_request", "The request body is no form.")
		}
		for name, values := range form {
			if len(values) > 1 {
				return refuse(ctx, "invalid_request", fmt.Sprintf("The %s parameter is repeated.", name))
			}
		}
		token := form.Get("token")
		if token == "" {
			return refuse(ctx, "invalid_request", "A token is required.")
		}

		// The hint is only that: a refresh token is looked for whatever it says, and anything else
		// is found to be no refresh token.
		if err := store.RevokeRefreshToken(ctx, oauth.HashSecret(token)); err != nil {
			return nil, &response_error.ResponseError{ServerError: altshiftErrors.New(fmt.Errorf("store revoke refresh token: %w", err))}
		}

		slog.InfoContext(ctx, "An OAuth token was revoked.",
			slog.Group("oauth", slog.String("client_id", form.Get("client_id")), slog.String("token_type_hint", form.Get("token_type_hint"))))

		// 200 as RFC 7009 has it, which the mux would answer as 204 for there being no body.
		return &muxResponse.Response{StatusCode: http.StatusOK, Headers: headers()}, nil
	}

	e.Initialized = true

	return nil
}

func refuse(ctx context.Context, errorCode string, description string) (*muxResponse.Response, *response_error.ResponseError) {
	slog.InfoContext(ctx, "An OAuth revocation request was refused.",
		slog.Group("oauth", slog.String("error", errorCode), slog.String("error_description", description)))

	body, err := json.Marshal(&ErrorResponse{Error: errorCode, ErrorDescription: description})
	if err != nil {
		return nil, &response_error.ResponseError{ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("json marshal (error response): %w", err))}
	}
	return &muxResponse.Response{
		StatusCode: http.StatusBadRequest,
		Body:       body,
		Headers:    append(headers(), &muxResponse.HeaderEntry{Name: "Content-Type", Value: "application/json"}),
	}, nil
}

func headers() []*muxResponse.HeaderEntry {
	return []*muxResponse.HeaderEntry{
		{Name: "Cache-Control", Value: "no-store", Overwrite: true},
		{Name: "Pragma", Value: "no-cache"},
	}
}

// MaskedUrlParams is empty: a revocation request is sent in the body.
func (e *Endpoint) MaskedUrlParams() []*schema.Url {
	return nil
}

// MaskedBodyFields is the request's token.
func (e *Endpoint) MaskedBodyFields() (*log_masking.BodyFields, error) {
	return &log_masking.BodyFields{
		Request: []*http_context_extractor_config.MaskedBodyFields{{Url: &schema.Url{Path: e.Path}, Fields: []string{"token"}}},
	}, nil
}

// MaskedHeaders is nothing: a public client sends no credential in a header.
func (e *Endpoint) MaskedHeaders() []*http_context_extractor_config.MaskedHeader {
	return nil
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
					MaxBytes:    16 * 1024,
				},
				Public: true,
			},
		},
	}
}
