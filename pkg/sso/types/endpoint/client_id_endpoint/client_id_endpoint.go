package client_id_endpoint

import (
	"net/http"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	motmedelReflect "github.com/Motmedel/utils_go/pkg/reflect"
)

type Endpoint struct {
	*initialization_endpoint.Endpoint
	ClientId string
}

func (e *Endpoint) Initialize(clientId string) error {
	if clientId == "" {
		return motmedelErrors.NewWithTrace(empty_error.New("client id"))
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
		return nil, motmedelErrors.NewWithTrace(empty_error.New("path"))
	}

	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:      path,
				Method:    http.MethodGet,
				UrlParser: adapter.New(query_extractor.Empty),
				Public:    true,
				Hint: &endpoint.Hint{
					OutputType:        motmedelReflect.TypeOf[string](),
					OutputContentType: "text/plain",
				},
			},
		},
	}, nil
}
