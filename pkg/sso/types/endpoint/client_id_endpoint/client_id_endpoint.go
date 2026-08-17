package client_id_endpoint

import (
	"net/http"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	muxResponse "github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	altshiftReflect "github.com/altshiftab/utils_go/pkg/reflect"
)

type Endpoint struct {
	*initialization_endpoint.Endpoint
	ClientId string
}

func (e *Endpoint) Initialize(clientId string) error {
	if clientId == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("client id"))
	}

	e.ClientId = clientId

	e.Handler = func(request *http.Request, bytes []byte) (*muxResponse.Response, *response_error.ResponseError) {
		return &muxResponse.Response{
			Body: []byte(e.ClientId),
			Headers: []*muxResponse.HeaderEntry{
				{
					Name:  "Content-Type",
					Value: "text/plain",
				},
			},
		}, nil
	}

	e.Initialized = true

	return nil
}

func New(path string) (*Endpoint, error) {
	if path == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("path"))
	}

	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:      path,
				Method:    http.MethodGet,
				UrlParser: adapter.New(query_extractor.Empty),
				Public:    true,
				Hint: &endpoint.Hint{
					OutputType:        altshiftReflect.TypeOf[string](),
					OutputContentType: "text/plain",
				},
			},
		},
	}, nil
}
