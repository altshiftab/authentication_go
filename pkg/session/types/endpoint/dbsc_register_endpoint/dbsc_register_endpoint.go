package dbsc_register_endpoint

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"fmt"
	"net"
	"net/http"
	"net/url"

	motmedelDatabase "github.com/Motmedel/utils_go/pkg/database"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/header_extractor"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/request_parser/token_cookie_extractor"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/Motmedel/utils_go/pkg/http/mux/utils"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	"github.com/Motmedel/utils_go/pkg/utils"
	"github.com/altshiftab/authentication_go/pkg/session"
	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser"
	"github.com/altshiftab/authentication_go/pkg/session/types/dbsc_session_response_processor"
	"github.com/altshiftab/authentication_go/pkg/session/types/endpoint/dbsc_register_endpoint/dbsc_register_endpoint_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_cookie"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_cookie/session_cookie_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_instructions"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
)

// Use centralized DBSC header constants from the session package.
const (
	sessionResponseHeaderName = session.DbscSessionResponseHeaderName
)

type (
	Scope      = session_instructions.Scope
	Credential = session_instructions.Credential
	Response   = session_instructions.Instructions
)

var sessionResponseRequestParser *header_extractor.Parser

type Endpoint struct {
	*initialization_endpoint.Endpoint
	RefreshPath                           string
	IncludeSite                           bool
	Origin                                string
	ScopeSpecification                    []*session_instructions.ScopeSpecification
	AllowedRefreshInitiators              []string
	updateAuthenticationWithDbscPublicKey func(ctx context.Context, id string, key []byte, database *sql.DB) error
}

// requestOrigin derives the origin actually being served from the request rather than an assumed
// one: behind a load balancer the scheme is only visible in X-Forwarded-Proto, and the host carries
// any port and subdomain. That origin is the scope of an origin-scoped session; a session that
// includes the site names the site instead, see siteOrigin.
func requestOrigin(request *http.Request) (string, error) {
	host := request.Host
	if host == "" {
		return "", motmedelErrors.NewWithTrace(empty_error.New("host"))
	}

	var scheme string
	if requestHeader := request.Header; requestHeader != nil {
		scheme = requestHeader.Get("X-Forwarded-Proto")
	}
	if scheme == "" {
		if request.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	return new(url.URL{Scheme: scheme, Host: host}).String(), nil
}

// siteOrigin replaces the host of an origin with registeredDomain, keeping the scheme and any port.
//
// A session that includes the site covers every origin on it, and the protocol requires it to say
// so: the scope origin's host must equal the registrable domain of the host serving registration
// ("create a session" in https://w3c.github.io/webappsec-dbsc/). Naming the subdomain that happens
// to serve the registration endpoint violates that, even though the session ends up covering the
// same requests either way, since inclusion is decided per site.
//
// The distinction is invisible in Chrome, which is why it invites being simplified away. Chrome
// never compares the scope origin against a registrable domain -- no such check exists in
// net/device_bound_sessions/session.cc -- so it accepts the subdomain and the session works. What
// the choice actually decides is consent. A subdomain claiming a whole site has to be authorised by
// that site, through /.well-known/device-bound-sessions served by the registrable domain, and
// Chrome decides whether to demand it by comparing hosts (net/device_bound_sessions/
// registration_fetcher.cc):
//
//	final_registration_url.host() != session->origin().host()
//
// Naming the subdomain makes those equal, so the check is skipped and the site is never asked.
// Naming the site is what turns the well-known file from decoration into enforcement.
//
// The registrable domain therefore has to serve that file before this reaches production: once the
// scope origin names the site, Chrome fetches it during registration and refuses the session unless
// it answers 200 with the registration endpoint's origin listed in "registering_origins".
func siteOrigin(origin string, registeredDomain string) (string, error) {
	if origin == "" {
		return "", motmedelErrors.NewWithTrace(empty_error.New("origin"))
	}
	if registeredDomain == "" {
		return "", motmedelErrors.NewWithTrace(empty_error.New("registered domain"))
	}

	parsedOrigin, err := url.Parse(origin)
	if err != nil {
		return "", motmedelErrors.NewWithTrace(fmt.Errorf("url parse: %w", err), origin)
	}

	host := registeredDomain
	if port := parsedOrigin.Port(); port != "" {
		host = net.JoinHostPort(registeredDomain, port)
	}

	return new(url.URL{Scheme: parsedOrigin.Scheme, Host: host}).String(), nil
}

// makeSessionCookieHeader reissues the session cookie carried by the request, unchanged except for
// expiring with the session token it carries rather than with the authentication.
func makeSessionCookieHeader(
	request *http.Request,
	sessionToken *session_token.Token,
	cookieName string,
	registeredDomain string,
	sessionCookieOptions ...session_cookie_config.Option,
) (*muxResponse.HeaderEntry, *response_error.ResponseError) {
	claims := sessionToken.Claims
	if claims == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("session token claims")),
		}
	}

	expiresAt := claims.ExpiresAt
	if expiresAt == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("session token claims expires at")),
		}
	}

	// The authorizer parsed the session token out of this cookie, so it is present.
	requestCookie, err := request.Cookie(cookieName)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("request cookie: %w", err), cookieName),
		}
	}

	sessionCookie, err := session_cookie.New(
		requestCookie.Value,
		expiresAt.Time,
		cookieName,
		registeredDomain,
		sessionCookieOptions...,
	)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.New(
				fmt.Errorf("session cookie new: %w", err),
				expiresAt.Time, cookieName, registeredDomain,
			),
		}
	}
	if sessionCookie == nil {
		return nil, &response_error.ResponseError{
			ServerError: motmedelErrors.NewWithTrace(nil_error.New("session cookie")),
		}
	}

	return &muxResponse.HeaderEntry{Name: "Set-Cookie", Value: sessionCookie.String()}, nil
}

func (e *Endpoint) Initialize(
	authorizerRequestParser *authorizer_request_parser.Parser,
	dbscSessionResponseProcessor *dbsc_session_response_processor.Processor,
	registeredDomain string,
	sessionCookieOptions ...session_cookie_config.Option,
) error {
	if authorizerRequestParser == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("authorizer request parser"))
	}

	jwtExtractor := authorizerRequestParser.JwtExtractor
	if jwtExtractor == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("jwt extractor"))
	}

	tokenExtractor := jwtExtractor.TokenExtractor
	if tokenExtractor == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("jwt token extractor"))
	}

	tokenCookieExtractor, err := utils.Convert[*token_cookie_extractor.Parser](tokenExtractor)
	if err != nil {
		return motmedelErrors.New(fmt.Errorf("convert (token cookie extractor): %w", err), tokenExtractor)
	}
	if tokenCookieExtractor == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("token cookie extractor"))
	}

	cookieName := tokenCookieExtractor.Name
	if cookieName == "" {
		return motmedelErrors.NewWithTrace(empty_error.New("cookie name"))
	}

	if dbscSessionResponseProcessor == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("dbsc session response processor"))
	}

	db := dbscSessionResponseProcessor.Db
	if db == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("dbsc session response processor sql db"))
	}

	e.AuthenticationParser = adapter.New(authorizerRequestParser)
	e.HeaderParser = request_parser.New(
		func(request *http.Request) (any, *response_error.ResponseError) {
			ctx := request.Context()
			sessionToken, responseError := muxUtils.GetServerNonZeroParsedRequestAuthentication[*session_token.Token](ctx)
			if responseError != nil {
				return nil, responseError
			}

			sessionResponseValue, responseError := sessionResponseRequestParser.Parse(request)
			if responseError != nil {
				return nil, responseError
			}

			return dbscSessionResponseProcessor.Process(
				ctx,
				&dbsc_session_response_processor.Input{
					TokenString:      sessionResponseValue,
					DbscSessionId:    sessionToken.SessionId,
					AuthenticationId: sessionToken.AuthenticationId,
				},
			)
		},
	)
	e.Handler = func(request *http.Request, _ []byte) (*muxResponse.Response, *response_error.ResponseError) {
		ctx := request.Context()

		sessionToken, responseError := muxUtils.GetServerNonZeroParsedRequestAuthentication[*session_token.Token](ctx)
		if responseError != nil {
			return nil, responseError
		}

		authenticationId := sessionToken.AuthenticationId
		if authenticationId == "" {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(empty_error.New("authentication id")),
			}
		}

		publicKey, responseError := muxUtils.GetServerParsedRequestHeaders[[]byte](ctx)
		if responseError != nil {
			return nil, responseError
		}
		if len(publicKey) == 0 {
			return nil, &response_error.ResponseError{
				ClientError: motmedelErrors.NewWithTrace(empty_error.New("public key")),
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The public key is empty."),
				),
			}
		}

		dbCtx, dbCtxCancel := motmedelDatabase.MakeTimeoutCtx(ctx)
		defer dbCtxCancel()
		if err := e.updateAuthenticationWithDbscPublicKey(dbCtx, authenticationId, publicKey, db); err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.New(
					fmt.Errorf("update authentication with dbsc public key: %w", err),
					authenticationId, publicKey,
				),
			}
		}

		origin := e.Origin
		if origin == "" {
			var err error
			if origin, err = requestOrigin(request); err != nil {
				return nil, &response_error.ResponseError{
					ServerError: motmedelErrors.New(fmt.Errorf("request origin: %w", err)),
				}
			}

			if e.IncludeSite {
				siteScopedOrigin, err := siteOrigin(origin, registeredDomain)
				if err != nil {
					return nil, &response_error.ResponseError{
						ServerError: motmedelErrors.New(
							fmt.Errorf("site origin: %w", err),
							origin, registeredDomain,
						),
					}
				}
				origin = siteScopedOrigin
			}
		}

		response := Response{
			SessionIdentifier: authenticationId,
			RefreshURL:        e.RefreshPath,
			Scope: &Scope{
				Origin:             origin,
				IncludeSite:        e.IncludeSite,
				ScopeSpecification: e.ScopeSpecification,
			},
			AllowedRefreshInitiators: e.AllowedRefreshInitiators,
			Credentials: []*Credential{
				{
					Type:       "cookie",
					Name:       cookieName,
					Attributes: session_cookie.Attributes(registeredDomain, sessionCookieOptions...),
				},
			},
		}

		responseData, err := json.Marshal(response)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.New(
					fmt.Errorf("json marshal (response data): %w", err),
					response,
				),
			}
		}

		// The browser refreshes a DBSC-bound session when the bound cookie expires, and from here
		// on it is the only thing that refreshes this session. The cookie set when the session was
		// created outlives its session token, so it is reissued with the token's own expiry;
		// otherwise the token would expire with nothing arranged to renew it.
		sessionCookieHeader, responseError := makeSessionCookieHeader(
			request,
			sessionToken,
			cookieName,
			registeredDomain,
			sessionCookieOptions...,
		)
		if responseError != nil {
			return nil, responseError
		}

		return &muxResponse.Response{
			Headers: []*muxResponse.HeaderEntry{
				{Name: "Content-Type", Value: "application/json"},
				sessionCookieHeader,
			},
			Body: responseData,
		}, nil
	}

	e.Initialized = true

	return nil
}

func New(options ...dbsc_register_endpoint_config.Option) *Endpoint {
	config := dbsc_register_endpoint_config.New(options...)
	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:      config.Path,
				Method:    http.MethodPost,
				UrlParser: adapter.New(query_extractor.Empty),
			},
		},
		RefreshPath:                           config.RefreshPath,
		IncludeSite:                           config.IncludeSite,
		Origin:                                config.Origin,
		ScopeSpecification:                    config.ScopeSpecification,
		AllowedRefreshInitiators:              config.AllowedRefreshInitiators,
		updateAuthenticationWithDbscPublicKey: config.UpdateAuthenticationWithDbscPublicKey,
	}
}

func init() {
	var err error
	sessionResponseRequestParser, err = header_extractor.New(sessionResponseHeaderName)
	if err != nil {
		panic(fmt.Errorf("header extractor new (session response): %w", err))
	}
}
