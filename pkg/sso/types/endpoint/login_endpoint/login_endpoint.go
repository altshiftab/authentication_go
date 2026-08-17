package login_endpoint

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/altshiftab/authentication_go/pkg/database"
	"github.com/altshiftab/authentication_go/pkg/database/types/oauth_flow"
	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/login_endpoint/login_endpoint_config"
	altshiftDatabase "github.com/altshiftab/utils_go/pkg/database"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/url_allower"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/url_allower/url_allower_config"
	muxResponse "github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/altshiftab/utils_go/pkg/http/mux/utils"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	altshiftNet "github.com/altshiftab/utils_go/pkg/net"
	altshiftOauth2 "github.com/altshiftab/utils_go/pkg/oauth2"
	"github.com/altshiftab/utils_go/pkg/oauth2/types/auth_code_option"
	altshiftOauth2Config "github.com/altshiftab/utils_go/pkg/oauth2/types/config"
	altshiftReflect "github.com/altshiftab/utils_go/pkg/reflect"
)

func makeCodeVerifier() (string, error) {
	challenge := make([]byte, 96)
	if _, err := rand.Read(challenge); err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("rand read: %w", err))
	}

	return base64.RawURLEncoding.EncodeToString(challenge), nil
}

func makeState() (string, error) {
	state := make([]byte, 32)
	if _, err := rand.Read(state); err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("rand read: %w", err))
	}
	return base64.RawURLEncoding.EncodeToString(state), nil
}

type UrlInput struct {
	RedirectUrl string `json:"redirect"`
}

func (u *UrlInput) URL() string {
	return u.RedirectUrl
}

type Endpoint struct {
	*initialization_endpoint.Endpoint
	CallbackCookieName string
	CallbackPath       string
	OauthFlowDuration  time.Duration

	makeState                             func() (string, error)
	makeCodeVerifier                      func() (string, error)
	insertOauthFlow                       func(ctx context.Context, state string, codeVerifier string, redirectUrl string, expirationDuration time.Duration, database *sql.DB) (*oauth_flow.Flow, error)
	RequestAuthenticationMethodReferences bool
}

func (e *Endpoint) Initialize(domain string, oauthConfig *altshiftOauth2Config.Config, db *sql.DB) error {
	if domain == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("domain"))
	}

	if oauthConfig == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("oauth config"))
	}

	if db == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("sql db"))
	}

	e.UrlParser = adapter.New(
		url_allower.New(
			query_extractor.New[*UrlInput](),
			url_allower_config.WithAllowLocalhost(altshiftNet.IsLocalhost(domain)),
			url_allower_config.WithAllowedRegisteredDomains([]string{domain}),
		),
	)

	e.Handler = func(request *http.Request, body []byte) (*muxResponse.Response, *response_error.ResponseError) {
		ctx := request.Context()

		redirectUrl, responseError := muxUtils.GetServerNonZeroParsedRequestUrl[*url.URL](ctx)
		if responseError != nil {
			return nil, responseError
		}

		redirectUrlString := redirectUrl.String()
		if redirectUrlString == "" {
			// NOTE: Should be impossible. Should be covered by `url_allower`.
			return nil, &response_error.ResponseError{
				ClientError: altshiftErrors.NewWithTrace(empty_error.New("redirect url")),
				ProblemDetail: problem_detail.New(
					http.StatusBadRequest,
					problem_detail_config.WithDetail("The redirect URL is empty."),
				),
			}
		}

		codeVerifier, err := e.makeCodeVerifier()
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("make code verifier: %w", err)),
			}
		}
		if codeVerifier == "" {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(empty_error.New("code verifier")),
			}
		}

		state, err := e.makeState()
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("make state: %w", err)),
			}
		}
		if state == "" {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(empty_error.New("state")),
			}
		}

		dbCtx, dbCtxCancel := altshiftDatabase.MakeTimeoutCtx(ctx)
		defer dbCtxCancel()

		oauthFlow, err := e.insertOauthFlow(
			dbCtx,
			state,
			codeVerifier,
			redirectUrlString,
			e.OauthFlowDuration,
			db,
		)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.New(fmt.Errorf("add oauth flow: %w", err), state, codeVerifier, redirectUrlString),
			}
		}
		if oauthFlow == nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(nil_error.New("oauth flow")),
			}
		}
		oauthFlowId := oauthFlow.Id
		if oauthFlowId == "" {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(empty_error.New("oauth flow id")),
			}
		}
		oauthFlowExpiresAt := oauthFlow.ExpiresAt
		if oauthFlowExpiresAt == nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(nil_error.New("oauth flow expires at")),
			}
		}

		authCodeOptions := altshiftOauth2.S256ChallengeOption(codeVerifier)
		if e.RequestAuthenticationMethodReferences {
			authCodeOptions = append(
				authCodeOptions,
				auth_code_option.New("claims", authenticationMethodReferencesClaimsParameter),
			)
		}

		callbackCookie := http.Cookie{
			Name:     e.CallbackCookieName,
			Value:    oauthFlowId,
			Path:     e.CallbackPath,
			Expires:  *oauthFlowExpiresAt,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}

		return &muxResponse.Response{
			StatusCode: http.StatusFound,
			Headers: []*muxResponse.HeaderEntry{
				{
					Name:  "Set-Cookie",
					Value: callbackCookie.String(),
				},
				{
					Name:  "Location",
					Value: oauthConfig.AuthCodeURL(state, authCodeOptions...),
				},
			},
		}, nil
	}

	e.Initialized = true

	return nil
}

// authenticationMethodReferencesClaimsParameter asks the provider to include the "amr" claim in the
// id token. Google omits it unless asked, and may omit it even then; Microsoft supplies it for
// OpenID Connect applications. It is requested as voluntary so that a provider unable to supply it
// still authenticates the user, leaving the decision to the caller.
const authenticationMethodReferencesClaimsParameter = `{"id_token":{"amr":null}}`

func New(path, callbackPath string, options ...login_endpoint_config.Option) (*Endpoint, error) {
	if path == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("path"))
	}

	if callbackPath == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("callback path"))
	}

	config := login_endpoint_config.New(options...)
	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:   path,
				Method: http.MethodGet,
				Public: true,
				Hint: &endpoint.Hint{
					InputType: altshiftReflect.TypeOf[UrlInput](),
				},
			},
		},
		CallbackCookieName: config.CallbackCookieName,
		CallbackPath:       callbackPath,
		OauthFlowDuration:  config.OauthFlowDuration,

		RequestAuthenticationMethodReferences: config.RequestAuthenticationMethodReferences,

		makeState:        makeState,
		makeCodeVerifier: makeCodeVerifier,
		insertOauthFlow:  database.InsertOauthFlow,
	}, nil
}
