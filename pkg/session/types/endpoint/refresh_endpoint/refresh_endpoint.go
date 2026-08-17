package refresh_endpoint

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"slices"
	"time"

	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	"github.com/altshiftab/authentication_go/pkg/session/types/authentication_method"
	"github.com/altshiftab/authentication_go/pkg/session/types/endpoint/refresh_endpoint/refresh_endpoint_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_manager"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/body_loader"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/body_loader/body_setting"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/cors_configurator"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	muxResponse "github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/altshiftab/utils_go/pkg/http/mux/utils"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	"github.com/altshiftab/utils_go/pkg/utils"
)

type Endpoint struct {
	*initialization_endpoint.Endpoint
	SessionDuration             time.Duration
	selectRefreshAuthentication func(ctx context.Context, id string, database *sql.DB) (*authenticationPkg.Authentication, error)
}

func (e *Endpoint) Initialize(
	authenticationParser request_parser.RequestParser[any],
	corsConfigurator *cors_configurator.Configurator,
	sessionManager *session_manager.Manager,
) error {
	if utils.IsNil(authenticationParser) {
		return altshiftErrors.NewWithTrace(nil_error.New("authorizer request parser"))
	}

	if corsConfigurator == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("cors configurator"))
	}

	if sessionManager == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("session manager"))
	}

	db := sessionManager.Db
	if db == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("session manager sql db"))
	}

	e.AuthenticationParser = authenticationParser

	e.CorsParser = corsConfigurator

	e.Handler = func(request *http.Request, bytes []byte) (*muxResponse.Response, *response_error.ResponseError) {
		ctx := request.Context()

		sessionToken, responseError := muxUtils.GetServerNonZeroParsedRequestAuthentication[*session_token.Token](ctx)
		if responseError != nil {
			return nil, responseError
		}

		authenticationId := sessionToken.AuthenticationId
		if authenticationId == "" {
			return nil, &response_error.ResponseError{
				ClientError: altshiftErrors.NewWithTrace(empty_error.New("authentication id")),
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The session token authentication id is empty."),
				),
			}
		}

		claims := sessionToken.Claims
		if claims == nil {
			return nil, &response_error.ResponseError{
				ClientError: altshiftErrors.NewWithTrace(nil_error.New("session token claims")),
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The session token claims are empty."),
				),
			}
		}

		sessionExpiresAt := claims.ExpiresAt
		if sessionExpiresAt == nil {
			return nil, &response_error.ResponseError{
				ClientError: altshiftErrors.NewWithTrace(nil_error.New("session token claims expires at")),
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The session token expires at is empty."),
				),
			}
		}

		sessionNotBefore := claims.NotBefore
		if sessionNotBefore == nil {
			return nil, &response_error.ResponseError{
				ClientError: altshiftErrors.NewWithTrace(nil_error.New("session token claims not before")),
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The session token not before is empty."),
				),
			}
		}

		// Don't refresh if the refresh is handled by the DBSC mechanism.
		if slices.Contains(claims.AuthenticationMethods, authentication_method.Dbsc) {
			return nil, nil
		}

		// An expired session token is the normal case here: the token is short-lived, and the
		// cookie carrying it outlives it so that the session can be renewed. What must still hold
		// is that the authentication has not ended or expired, which RefreshSession validates.
		//
		// The session token should be refreshed if one third or less of its expiration duration
		// remains. Clients poll in proportion to that duration, so this is checked before the
		// authentication is read: most calls need no refresh and should not reach the database.
		if remainingExpirationDuration := time.Until(sessionExpiresAt.Time); remainingExpirationDuration > (sessionExpiresAt.Sub(sessionNotBefore.Time) / 3) {
			return nil, nil
		}

		authentication, err := e.selectRefreshAuthentication(ctx, authenticationId, db)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.New(fmt.Errorf("get authentication: %w", err), authenticationId),
			}
		}
		if authentication == nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(nil_error.New("authentication")),
			}
		}

		// Don't refresh if this is the first session and DBSC has been added.
		if slices.Contains(claims.AuthenticationMethods, authentication_method.Sso) && len(authentication.DbscPublicKey) > 0 {
			return nil, nil
		}

		return sessionManager.RefreshSession(authentication, sessionToken, authentication_method.Refresh, e.SessionDuration)
	}

	e.Initialized = true

	return nil
}

func New(options ...refresh_endpoint_config.Option) *Endpoint {
	config := refresh_endpoint_config.New(options...)
	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:       config.Path,
				Method:     http.MethodPost,
				UrlParser:  adapter.New(query_extractor.Empty),
				BodyLoader: &body_loader.Loader{Setting: body_setting.Forbidden},
			},
		},
		SessionDuration:             config.SessionDuration,
		selectRefreshAuthentication: config.SelectRefreshAuthentication,
	}
}
