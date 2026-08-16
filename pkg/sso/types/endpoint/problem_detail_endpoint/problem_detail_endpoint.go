package problem_detail_endpoint

import (
	"fmt"
	"net/http"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	muxContext "github.com/Motmedel/utils_go/pkg/http/mux/context"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	motmedelHttpTypes "github.com/Motmedel/utils_go/pkg/http/types"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	motmedelReflect "github.com/Motmedel/utils_go/pkg/reflect"
	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/problem_detail_endpoint/problem_detail_endpoint_config"
)

// New returns a public GET endpoint that serves a single, static RFC 9457
// problem detail document. The serialization format (application/problem+json,
// application/problem+xml or text/plain) is selected by content negotiation
// against the request's `Accept` header.
//
// The document is identical for every request, so it is served with a cacheable
// `Cache-Control` and a `Vary: Accept` header; the response writer omits `Vary`
// (and compresses) only for `no-store` responses, so a cacheable value here is
// what produces correct caching semantics.
func New(options ...problem_detail_endpoint_config.Option) (*endpoint.Endpoint, error) {
	config := problem_detail_endpoint_config.New(options...)

	if config.Path == "" {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("path"))
	}

	if config.Status == 0 {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("status"))
	}

	// Default to the HTML-capable converter so browsers get a readable page (with
	// a back link when a BackUrl is configured) while API clients still negotiate
	// problem+json / problem+xml / text/plain.
	converter := config.Converter
	if converter == nil {
		converter = HtmlConverter(config.BackUrl, config.BackLabel)
	}

	// The problem detail is static; build it once and serialize per request.
	detail := problem_detail.New(
		config.Status,
		problem_detail_config.WithType(config.Type),
		problem_detail_config.WithDetail(config.Detail),
	)
	if config.Title != "" {
		detail.Title = config.Title
	}

	cacheControl := config.CacheControl

	handler := func(request *http.Request, _ []byte) (*muxResponse.Response, *response_error.ResponseError) {
		contentNegotiation, _ := request.Context().
			Value(muxContext.ContentNegotiationContextKey).(*motmedelHttpTypes.ContentNegotiation)

		body, contentType, err := converter.Convert(detail, contentNegotiation)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.New(fmt.Errorf("problem detail converter convert: %w", err), detail),
			}
		}

		headers := []*muxResponse.HeaderEntry{{Name: "Vary", Value: "Accept"}}
		if cacheControl != "" {
			headers = append(
				headers,
				&muxResponse.HeaderEntry{Name: "Cache-Control", Value: cacheControl, Overwrite: true},
			)
		}
		if contentType != "" {
			headers = append(headers, &muxResponse.HeaderEntry{Name: "Content-Type", Value: contentType})
		}

		return &muxResponse.Response{
			StatusCode: detail.Status,
			Body:       body,
			Headers:    headers,
		}, nil
	}

	return &endpoint.Endpoint{
		Path:      config.Path,
		Method:    http.MethodGet,
		UrlParser: adapter.New(query_extractor.Empty),
		Public:    true,
		Handler:   handler,
		Hint: &endpoint.Hint{
			OutputType:        motmedelReflect.TypeOf[problem_detail.Detail](),
			OutputContentType: "application/problem+json",
		},
	}, nil
}
