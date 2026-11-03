// Package create_api_key_endpoint registers a public key for the signed-in account.
//
// The account presents a public key and a name for it, and nothing else: no proof that it holds the
// private half, as no service taking an SSH key asks for one either. Such a proof stops only a key
// being registered by somebody who talked the account into pasting theirs -- an attacker holding
// the session registers a key of their own and proves it perfectly well -- while costing every
// honest registration a trip through a terminal.
package create_api_key_endpoint

import (
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"

	"github.com/altshiftab/authentication_go/pkg/api_key/api_key_cruder"
	"github.com/altshiftab/authentication_go/pkg/api_key/public_key"
	"github.com/altshiftab/authentication_go/pkg/api_key/types"
	"github.com/altshiftab/authentication_go/pkg/session/types/active_session_processor"
	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
	altshiftDatabase "github.com/altshiftab/utils_go/pkg/database"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/body_loader"
	bodyParserAdapter "github.com/altshiftab/utils_go/pkg/http/mux/types/body_parser/adapter"
	jsonSchemaBodyParser "github.com/altshiftab/utils_go/pkg/http/mux/types/body_parser/json_schema_body_parser"
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

// A name is what the account picks a key out by later, so it is required and bounded rather than
// free text of any length.
const maximumNameLength = 100

const contentTypeJson = "application/json"

type Endpoint struct {
	*initialization_endpoint.Endpoint
}

type BodyInput = types.CreateApiKey

var bodyParser *jsonSchemaBodyParser.Parser[*BodyInput]

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
	e.UrlParser = adapter.New(query_extractor.Empty)

	e.Handler = func(request *http.Request, _ []byte) (*response.Response, *response_error.ResponseError) {
		ctx := request.Context()

		sessionToken, responseError := muxUtils.GetServerNonZeroParsedRequestAuthentication[*session_token.Token](ctx)
		if responseError != nil {
			return nil, responseError
		}

		body, responseError := muxUtils.GetServerNonZeroParsedRequestBody[*BodyInput](ctx)
		if responseError != nil {
			return nil, responseError
		}

		if body.Name == "" || len(body.Name) > maximumNameLength {
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The key needs a name, of at most 100 characters."),
				),
			}
		}

		key, err := public_key.Parse(body.PublicKey)
		if err != nil {
			// Everything Parse refuses is the registrant's to fix, and saying which is the
			// difference between pasting the right thing next time and guessing.
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail(
						"The public key must be PEM, holding an Ed25519 or P-256 public key.",
					),
				),
				ClientError: altshiftErrors.New(fmt.Errorf("public key parse: %w", err)),
			}
		}

		apiKeyCruder := &api_key_cruder.Cruder{Database: db}

		dbCtx, cancel := altshiftDatabase.MakeTimeoutCtx(ctx)
		defer cancel()

		created, err := apiKeyCruder.Create(dbCtx, sessionToken.SubjectId, key, body.Name, body.ExpiresAt)
		if err != nil {
			wrappedErr := altshiftErrors.New(fmt.Errorf("api key cruder create: %w", err), key.Id)
			// The key is registered already -- to this account or another, in use or revoked. A
			// revoked key is the case worth spelling out, since it can never come back.
			if errors.Is(err, altshiftErrors.ErrValidationError) {
				return nil, &response_error.ResponseError{
					ProblemDetail: problem_detail.New(
						http.StatusConflict,
						problem_detail_config.WithDetail(
							"This key is already registered. A key that was revoked cannot be registered again; generate a new one.",
						),
					),
					ClientError: wrappedErr,
				}
			}
			return nil, &response_error.ResponseError{ServerError: wrappedErr}
		}

		data, err := json.Marshal(created)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.New(fmt.Errorf("json marshal (api key): %w", err), created),
			}
		}

		return &response.Response{
			StatusCode: http.StatusCreated,
			Headers:    []*response.HeaderEntry{{Name: "Content-Type", Value: contentTypeJson}},
			Body:       data,
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
				Method: http.MethodPost,
				BodyLoader: &body_loader.Loader{
					Parser:      bodyParserAdapter.New(bodyParser),
					ContentType: contentTypeJson,
				},
				Hint: &endpoint.Hint{
					InputType:         altshiftReflect.TypeOf[BodyInput](),
					OutputType:        altshiftReflect.TypeOf[types.ApiKey](),
					OutputContentType: contentTypeJson,
				},
			},
		},
	}
}

func init() {
	var err error
	bodyParser, err = jsonSchemaBodyParser.New[*BodyInput]()
	if err != nil {
		panic(fmt.Errorf("json schema body parser: %w", err))
	}
}

const DefaultPath = "/api/account/me/api-keys"
