// Package read_own_api_keys_endpoint lists the keys the signed-in account registered.
//
// Takes no input: the account is the session token's subject, and the cruder's query carries it, so
// there is no request that lists another account's keys. The key material is not in the answer --
// what the settings page shows is which key, what it does, and whether it still works.
package read_own_api_keys_endpoint

import (
	"database/sql"
	"encoding/json/v2"
	"fmt"
	"net/http"

	"github.com/altshiftab/authentication_go/pkg/api_key/api_key_cruder"
	apiKeyTypes "github.com/altshiftab/authentication_go/pkg/api_key/types"
	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
	altshiftDatabase "github.com/altshiftab/utils_go/pkg/database"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/altshiftab/utils_go/pkg/http/mux/utils"
	altshiftReflect "github.com/altshiftab/utils_go/pkg/reflect"
)

type Endpoint struct {
	*initialization_endpoint.Endpoint
}

func (e *Endpoint) Initialize(authorizer *authorizer_request_parser.Parser, db *sql.DB) error {
	if authorizer == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("authorizer"))
	}
	if db == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("sql database"))
	}

	e.AuthenticationParser = adapter.New(authorizer)
	e.UrlParser = adapter.New(query_extractor.Empty)

	e.Handler = func(request *http.Request, _ []byte) (*response.Response, *response_error.ResponseError) {
		ctx := request.Context()

		sessionToken, responseError := muxUtils.GetServerNonZeroParsedRequestAuthentication[*session_token.Token](ctx)
		if responseError != nil {
			return nil, responseError
		}

		apiKeyCruder := &api_key_cruder.Cruder{Database: db}

		dbCtx, cancel := altshiftDatabase.MakeTimeoutCtx(ctx)
		defer cancel()

		keys, err := apiKeyCruder.ReadBulkForAccount(dbCtx, sessionToken.SubjectId)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.New(
					fmt.Errorf("api key cruder read bulk for account: %w", err),
					apiKeyCruder,
				),
			}
		}

		// The empty list rather than null, so a page can render it without a guard.
		if keys == nil {
			keys = []*apiKeyTypes.ApiKey{}
		}

		data, err := json.Marshal(keys)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.New(fmt.Errorf("json marshal (api keys): %w", err), keys),
			}
		}

		return &response.Response{
			Headers: []*response.HeaderEntry{{Name: "Content-Type", Value: "application/json"}},
			Body:    data,
		}, nil
	}

	e.Initialized = true
	return nil
}

func New() *Endpoint {
	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:   DefaultPath,
				Method: http.MethodGet,
				Hint: &endpoint.Hint{
					OutputType:        altshiftReflect.TypeOf[[]*apiKeyTypes.ApiKey](),
					OutputContentType: "application/json",
				},
			},
		},
	}
}

const DefaultPath = "/api/account/me/api-keys"
