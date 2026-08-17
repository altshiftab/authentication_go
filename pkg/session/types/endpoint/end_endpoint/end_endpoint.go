package end_endpoint

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"

	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser"
	"github.com/altshiftab/authentication_go/pkg/session/types/endpoint/end_endpoint/end_endpoint_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
	altshiftDatabase "github.com/altshiftab/utils_go/pkg/database"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/body_loader"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/body_loader/body_setting"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/cors_configurator"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	muxResponse "github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	muxResponseError "github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/altshiftab/utils_go/pkg/http/mux/utils"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail/problem_detail_config"
)

type Endpoint struct {
	*initialization_endpoint.Endpoint
	updateAuthenticationWithEnded func(ctx context.Context, id string, database *sql.DB) error
}

func (e *Endpoint) Initialize(authorizerRequestParser *authorizer_request_parser.Parser, corsConfigurator *cors_configurator.Configurator, db *sql.DB) error {
	if authorizerRequestParser == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("authorizer request parser"))
	}

	if corsConfigurator == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("cors configurator"))
	}

	if db == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("sql db"))
	}

	e.AuthenticationParser = adapter.New(authorizerRequestParser)

	e.CorsParser = corsConfigurator

	e.Handler = func(request *http.Request, body []byte) (*muxResponse.Response, *response_error.ResponseError) {
		ctx := request.Context()

		sessionToken, responseError := muxUtils.GetServerNonZeroParsedRequestAuthentication[*session_token.Token](ctx)
		if responseError != nil {
			return nil, responseError
		}

		authenticationId := sessionToken.AuthenticationId
		if authenticationId == "" {
			return nil, &muxResponseError.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("Missing authentication id in the session token."),
				),
			}
		}

		dbCtx, dbCtxCancel := altshiftDatabase.MakeTimeoutCtx(ctx)
		defer dbCtxCancel()
		if err := e.updateAuthenticationWithEnded(dbCtx, authenticationId, db); err != nil {
			return nil, &muxResponseError.ResponseError{
				ServerError: altshiftErrors.New(fmt.Errorf("update authentication with ended: %w", err), authenticationId),
			}
		}

		return &muxResponse.Response{
			Headers: []*muxResponse.HeaderEntry{{Name: "Clear-Site-Data", Value: `"cookies"`}},
		}, nil
	}

	e.Initialized = true

	return nil
}

func New(options ...end_endpoint_config.Option) *Endpoint {
	config := end_endpoint_config.New(options...)
	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:       config.Path,
				Method:     http.MethodPost,
				UrlParser:  adapter.New(query_extractor.Empty),
				BodyLoader: &body_loader.Loader{Setting: body_setting.Forbidden},
			},
		},
		updateAuthenticationWithEnded: config.UpdateAuthenticationWithEnded,
	}
}
