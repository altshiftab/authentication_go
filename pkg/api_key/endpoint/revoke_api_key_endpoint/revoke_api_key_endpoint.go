// Package revoke_api_key_endpoint takes one of the account's keys out of use.
//
// Revocation is where API access ends, so it does two things at once: the key stops minting, and
// the sign-ins it minted are ended. What was already minted keeps working until it expires --
// consumers validate a token by its signature and its expiry, so a token's lifetime is the
// revocation window, and that lifetime is minutes.
package revoke_api_key_endpoint

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"github.com/altshiftab/authentication_go/pkg/api_key/api_key_cruder"
	"github.com/altshiftab/authentication_go/pkg/session/types/active_session_processor"
	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
	altshiftDatabase "github.com/altshiftab/utils_go/pkg/database"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/body_loader"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/body_loader/body_setting"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/altshiftab/utils_go/pkg/http/mux/utils"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	altshiftReflect "github.com/altshiftab/utils_go/pkg/reflect"
)

type Endpoint struct {
	*initialization_endpoint.Endpoint
}

type UrlInput struct {
	Id string `json:"id" query:"id"`
}

var urlParser = query_extractor.New[*UrlInput]()

func (e *Endpoint) Initialize(authorizer *authorizer_request_parser.Parser, db *sql.DB) error {
	if authorizer == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("authorizer"))
	}
	if db == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("sql database"))
	}

	// The token is checked against the database as well as by its signature: a sign-in that has
	// ended, a locked account and a role taken away are refused here at once, rather than when the
	// token expires.
	activeSessionProcessor, err := active_session_processor.New(authorizer, db)
	if err != nil {
		return fmt.Errorf("active session processor new: %w", err)
	}
	e.AuthenticationParser = adapter.New(request_parser.NewWithProcessor(authorizer, activeSessionProcessor))
	e.UrlParser = adapter.New(urlParser)

	e.Handler = func(request *http.Request, _ []byte) (*response.Response, *response_error.ResponseError) {
		ctx := request.Context()

		sessionToken, responseError := muxUtils.GetServerNonZeroParsedRequestAuthentication[*session_token.Token](ctx)
		if responseError != nil {
			return nil, responseError
		}

		idInput, responseError := muxUtils.GetServerNonZeroParsedRequestUrl[*UrlInput](ctx)
		if responseError != nil {
			return nil, responseError
		}

		apiKeyCruder := &api_key_cruder.Cruder{Database: db}

		dbCtx, cancel := altshiftDatabase.MakeTimeoutCtx(ctx)
		defer cancel()

		err := apiKeyCruder.RevokeForAccount(dbCtx, sessionToken.SubjectId, idInput.Id)
		if err != nil {
			wrappedErr := altshiftErrors.New(
				fmt.Errorf("api key cruder revoke for account: %w", err),
				idInput.Id,
			)
			// A key that is somebody else's, one that never existed and one already revoked are one
			// answer: an account may not learn from here that another's key id is real.
			if errors.Is(err, sql.ErrNoRows) {
				return nil, &response_error.ResponseError{
					ProblemDetail: problem_detail.New(
						http.StatusNotFound,
						problem_detail_config.WithDetail("No key of yours was found with the provided id."),
					),
					ClientError: wrappedErr,
				}
			}
			return nil, &response_error.ResponseError{ServerError: wrappedErr}
		}

		return &response.Response{StatusCode: http.StatusNoContent}, nil
	}

	e.Initialized = true
	return nil
}

func New() *Endpoint {
	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:       DefaultPath,
				Method:     http.MethodPost,
				BodyLoader: &body_loader.Loader{Setting: body_setting.Forbidden},
				Hint: &endpoint.Hint{
					// The id rides in the query of a POST, so it is the URL input rather than the
					// input: the client generator renders a plain input as a body for anything but
					// GET, HEAD and DELETE.
					UrlInputType: altshiftReflect.TypeOf[UrlInput](),
				},
			},
		},
	}
}

const DefaultPath = "/api/account/me/api-keys/revoke"
