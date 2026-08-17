package dbsc_refresh_endpoint

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"time"

	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	"github.com/altshiftab/authentication_go/pkg/session"
	"github.com/altshiftab/authentication_go/pkg/session/types/authentication_method"
	"github.com/altshiftab/authentication_go/pkg/session/types/dbsc_session_response_processor"
	"github.com/altshiftab/authentication_go/pkg/session/types/endpoint/dbsc_refresh_endpoint/dbsc_refresh_endpoint_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_instructions"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_manager"
	altshiftDatabase "github.com/altshiftab/utils_go/pkg/database"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	altshiftHttpErrors "github.com/altshiftab/utils_go/pkg/http/errors"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	muxResponse "github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	"github.com/altshiftab/utils_go/pkg/http/utils"
)

// Use centralized DBSC header constants from the session package.
const (
	sessionResponseHeaderName  = session.DbscSessionResponseHeaderName
	sessionChallengeHeaderName = session.DbscSessionChallengeHeaderName
	sessionIdHeaderName        = session.DbscSessionIdHeaderName
)

type Endpoint struct {
	*initialization_endpoint.Endpoint
	SessionDuration   time.Duration
	ChallengeDuration time.Duration

	insertDbscChallenge         func(ctx context.Context, challenge string, authenticationId string, challengeDuration time.Duration, db *sql.DB) error
	selectRefreshAuthentication func(ctx context.Context, id string, database *sql.DB) (*authenticationPkg.Authentication, error)
	generateDbscChallenge       func() (string, error)
}

// endedSessionResponse tells the browser to stop applying the session and discard its key. A
// session whose authentication is gone, ended or expired can never be refreshed again, so ending it
// is more useful to the browser than an error it would keep retrying.
func endedSessionResponse() (*muxResponse.Response, *response_error.ResponseError) {
	body, err := json.Marshal(session_instructions.Ended())
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("json marshal (session instructions): %w", err)),
		}
	}

	return &muxResponse.Response{
		Headers: []*muxResponse.HeaderEntry{{Name: "Content-Type", Value: "application/json"}},
		Body:    body,
	}, nil
}

// Initialize wires the endpoint. It deliberately takes no session authorizer: a device bound
// session is refreshed when its bound cookie expires, so the request carries no session token. The
// session is identified by the Sec-Secure-Session-Id header and authenticated by a signature made
// with the device bound key registered for it.
func (e *Endpoint) Initialize(
	dbscSessionResponseProcessor *dbsc_session_response_processor.Processor,
	sessionManager *session_manager.Manager,
) error {
	if dbscSessionResponseProcessor == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("dbsc session response processor"))
	}

	if sessionManager == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("session manager"))
	}

	db := dbscSessionResponseProcessor.Db
	if db == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("dbsc session response processor sql db"))
	}

	e.Handler = func(request *http.Request, _ []byte) (*muxResponse.Response, *response_error.ResponseError) {
		ctx := request.Context()

		requestHeader := request.Header
		if requestHeader == nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(nil_error.New("http request header")),
			}
		}

		sessionId, err := utils.GetSingleHeader(sessionIdHeaderName, requestHeader)
		if err != nil {
			wrappedErr := altshiftErrors.New(fmt.Errorf("get single header: %w", err), sessionIdHeaderName)
			if errors.Is(err, altshiftHttpErrors.ErrMissingHeader) || errors.Is(err, altshiftHttpErrors.ErrMultipleHeaderValues) {
				return nil, &response_error.ResponseError{
					ClientError: wrappedErr,
					ProblemDetail: problem_detail.New(
						http.StatusBadRequest,
						problem_detail_config.WithDetail("A single session id is required."),
						problem_detail_config.WithExtension(map[string]any{"header": sessionIdHeaderName}),
					),
				}
			}
			return nil, &response_error.ResponseError{ServerError: wrappedErr}
		}
		if sessionId == "" {
			return nil, &response_error.ResponseError{
				ClientError: altshiftErrors.NewWithTrace(empty_error.New("session id")),
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The session id is empty."),
				),
			}
		}

		// The session identifier handed out at registration is the authentication id.
		authenticationId := sessionId

		sessionResponseValue, err := utils.GetSingleHeader(sessionResponseHeaderName, requestHeader)
		if err != nil && !errors.Is(err, altshiftHttpErrors.ErrMissingHeader) {
			wrappedErr := altshiftErrors.New(fmt.Errorf("get single header: %w", err), sessionResponseHeaderName)
			if errors.Is(err, altshiftHttpErrors.ErrMultipleHeaderValues) {
				return nil, &response_error.ResponseError{
					ClientError: wrappedErr,
					ProblemDetail: problem_detail.New(
						http.StatusBadRequest,
						problem_detail_config.WithDetail("Multiple header values."),
						problem_detail_config.WithExtension(map[string]any{"header": sessionResponseHeaderName}),
					),
				}
			}
			return nil, &response_error.ResponseError{ServerError: wrappedErr}
		}

		// Without a proof of possession, answer with a challenge for the browser to sign.
		if sessionResponseValue == "" {
			challenge, err := e.generateDbscChallenge()
			if err != nil {
				return nil, &response_error.ResponseError{
					ServerError: fmt.Errorf("generate challenge: %w", err),
				}
			}

			insertDbCtx, insertDbCtxCancel := altshiftDatabase.MakeTimeoutCtx(ctx)
			defer insertDbCtxCancel()

			if err := e.insertDbscChallenge(insertDbCtx, challenge, authenticationId, e.ChallengeDuration, db); err != nil {
				return nil, &response_error.ResponseError{
					ServerError: altshiftErrors.New(
						fmt.Errorf("insert dbsc challenge: %w", err),
						challenge, authenticationId,
					),
				}
			}

			return &muxResponse.Response{
				StatusCode: http.StatusForbidden,
				Headers: []*muxResponse.HeaderEntry{
					{
						Name:  sessionChallengeHeaderName,
						Value: fmt.Sprintf("\"%s\";id=\"%s\"", challenge, sessionId),
					},
				},
			}, nil
		}

		selectDbCtx, selectDbCtxCancel := altshiftDatabase.MakeTimeoutCtx(ctx)
		defer selectDbCtxCancel()

		authentication, err := e.selectRefreshAuthentication(selectDbCtx, authenticationId, db)
		if err != nil {
			wrappedErr := altshiftErrors.New(fmt.Errorf("select refresh authentication: %w", err), authenticationId)
			if errors.Is(err, sql.ErrNoRows) {
				return endedSessionResponse()
			}
			return nil, &response_error.ResponseError{ServerError: wrappedErr}
		}
		if authentication == nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(nil_error.New("authentication")),
			}
		}

		if authentication.Ended {
			return endedSessionResponse()
		}
		if expiresAt := authentication.ExpiresAt; expiresAt != nil && time.Now().After(*expiresAt) {
			return endedSessionResponse()
		}

		authenticationPublicKey := authentication.DbscPublicKey
		if len(authenticationPublicKey) == 0 {
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("No public key for authentication."),
				),
			}
		}

		if _, responseError := dbscSessionResponseProcessor.Process(
			ctx,
			&dbsc_session_response_processor.Input{
				TokenString:      sessionResponseValue,
				DbscSessionId:    sessionId,
				AuthenticationId: authenticationId,
				PublicKey:        authenticationPublicKey,
			},
		); responseError != nil {
			return nil, responseError
		}

		return sessionManager.MintSession(authentication, authentication_method.Dbsc, e.SessionDuration)
	}

	e.Initialized = true

	return nil
}

func New(options ...dbsc_refresh_endpoint_config.Option) *Endpoint {
	config := dbsc_refresh_endpoint_config.New(options...)
	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:   config.Path,
				Method: http.MethodPost,
				// Authentication is the device bound signature, not a session token.
				Public:    true,
				UrlParser: adapter.New(query_extractor.Empty),
			},
		},
		SessionDuration:             config.SessionDuration,
		ChallengeDuration:           config.ChallengeDuration,
		insertDbscChallenge:         config.InsertDbscChallenge,
		selectRefreshAuthentication: config.SelectRefreshAuthentication,
		generateDbscChallenge:       config.GenerateDbscChallenge,
	}
}
