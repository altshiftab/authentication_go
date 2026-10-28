// Package registration_endpoint is the client registration endpoint (RFC 7591): where a client
// with no metadata document of its own -- Gemini's -- registers, and is given an id.
//
// What may register is the registrar's to decide, by where a client may be sent back to; this
// reads the request and answers it.
package registration_endpoint

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/altshiftab/authentication_go/pkg/log_masking"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/client_registrar"
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
	altshiftReflect "github.com/altshiftab/utils_go/pkg/reflect"
	"github.com/altshiftab/utils_go/pkg/schema"
)

const (
	DefaultPath = "/oauth/register"

	jsonContentType = "application/json"
)

// Response is a client information response (RFC 7591 section 3.2.1).
type Response struct {
	ClientId                string   `json:"client_id"`
	ClientIdIssuedAt        int64    `json:"client_id_issued_at"`
	ClientName              string   `json:"client_name"`
	RedirectUris            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
}

// ErrorResponse is a client registration error response (RFC 7591 section 3.2.2).
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitzero"`
}

type Endpoint struct {
	*initialization_endpoint.Endpoint
}

func (e *Endpoint) Initialize(registrar *client_registrar.Registrar) error {
	if registrar == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("registrar"))
	}

	e.Handler = func(request *http.Request, body []byte) (*muxResponse.Response, *response_error.ResponseError) {
		ctx := request.Context()

		// Metadata it does not understand is ignored, as the RFC has it.
		var metadata client_registrar.Metadata
		if err := json.Unmarshal(body, &metadata); err != nil {
			return refuse(ctx, "invalid_client_metadata", "The body is not client metadata.")
		}

		registered, issuedAt, err := registrar.Register(&metadata)
		if refused, ok := errors.AsType[*client_registrar.RefusalError](err); ok && refused != nil {
			if errors.Is(refused.Sentinel, client_registrar.ErrInvalidRedirectUri) {
				return refuse(ctx, "invalid_redirect_uri", "A redirect URI is not one a client may register: "+refused.Reason+".")
			}
			return refuse(ctx, "invalid_client_metadata", "The client metadata is refused: "+refused.Reason+".")
		}
		switch {
		case err != nil:
			return nil, &response_error.ResponseError{ServerError: altshiftErrors.New(fmt.Errorf("client registrar register: %w", err))}
		case registered == nil:
			return nil, &response_error.ResponseError{ServerError: altshiftErrors.NewWithTrace(nil_error.New("registered client"))}
		}

		var hosts []string
		for _, redirectUri := range registered.RedirectUris {
			if u, err := url.Parse(redirectUri); err == nil {
				hosts = append(hosts, u.Host)
			}
		}
		slog.InfoContext(ctx, "An OAuth client registered.",
			slog.Group("oauth", slog.String("client_name", registered.Name), slog.Any("redirect_hosts", hosts)))

		out, err := json.Marshal(&Response{
			ClientId:                registered.Id,
			ClientIdIssuedAt:        issuedAt,
			ClientName:              registered.Name,
			RedirectUris:            registered.RedirectUris,
			TokenEndpointAuthMethod: "none",
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			ResponseTypes:           []string{"code"},
		})
		if err != nil {
			return nil, &response_error.ResponseError{ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("json marshal (registration response): %w", err))}
		}
		return &muxResponse.Response{StatusCode: http.StatusCreated, Body: out, Headers: headers()}, nil
	}

	e.Initialized = true

	return nil
}

func refuse(ctx context.Context, errorCode string, description string) (*muxResponse.Response, *response_error.ResponseError) {
	slog.InfoContext(ctx, "An OAuth client registration was refused.",
		slog.Group("oauth", slog.String("error", errorCode), slog.String("error_description", description)))

	body, err := json.Marshal(&ErrorResponse{Error: errorCode, ErrorDescription: description})
	if err != nil {
		return nil, &response_error.ResponseError{ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("json marshal (error response): %w", err))}
	}
	return &muxResponse.Response{StatusCode: http.StatusBadRequest, Body: body, Headers: headers()}, nil
}

func headers() []*muxResponse.HeaderEntry {
	return []*muxResponse.HeaderEntry{
		{Name: "Content-Type", Value: jsonContentType},
		{Name: "Cache-Control", Value: "no-store", Overwrite: true},
		{Name: "Pragma", Value: "no-cache"},
	}
}

// MaskedUrlParams is empty: the metadata is sent in the body.
func (e *Endpoint) MaskedUrlParams() []*schema.Url {
	return nil
}

// MaskedBodyFields is nothing: a public client's registration carries no secret, and the id it is
// given is no credential.
func (e *Endpoint) MaskedBodyFields() (*log_masking.BodyFields, error) {
	return nil, nil
}

// MaskedHeaders is nothing.
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
					ContentType: jsonContentType,
					Setting:     body_setting.Required,
					MaxBytes:    16 * 1024,
				},
				Public: true,
				Hint: &endpoint.Hint{
					OutputType:        altshiftReflect.TypeOf[Response](),
					OutputContentType: jsonContentType,
				},
			},
		},
	}
}
