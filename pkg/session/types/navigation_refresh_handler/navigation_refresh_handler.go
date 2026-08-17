// Package navigation_refresh_handler renews an expired session on a navigation to a sign-in page
// and sends the browser back where it came from, instead of asking someone to sign in again while
// their authentication is still valid.
//
// It exists because the session cookie outlives the token it carries. A token lasts minutes; the
// cookie lasts as long as the authentication, so that the session can be renewed without a fresh
// sign-in. Clients renew it by polling, which works only while a tab is open. Arriving from a
// bookmark, or waking a machine after the token has expired, produces a navigation that carries a
// perfectly good authentication and an expired token -- and, without this, a sign-in page.
//
// The other half of the mechanism is the redirector in utils_go, which is what turns the rejected
// navigation into a trip here with the original address in a query parameter. This handler reads
// that parameter, mints a new session, and returns a redirect to it.
//
// Attach it as the Handler of the sign-in page endpoint. The page keeps its static content: a
// handler that answers with a status of its own takes the request, and one that answers with
// nothing -- which is every case with no session to renew -- leaves the page to be served as usual.
package navigation_refresh_handler

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/altshiftab/authentication_go/pkg/session/types/authentication_method"
	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser"
	"github.com/altshiftab/authentication_go/pkg/session/types/navigation_refresh_handler/navigation_refresh_handler_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_manager"
	altshiftDatabase "github.com/altshiftab/utils_go/pkg/database"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
	muxResponse "github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	altshiftStrings "github.com/altshiftab/utils_go/pkg/strings"
)

const (
	secFetchModeHeaderName = "Sec-Fetch-Mode"
	navigateFetchMode      = "navigate"
	locationHeaderName     = "Location"
)

// redirectUrl accepts a redirect target only if it is on the site the session cookie is scoped to.
// The cookie is what is being handed back, so anywhere it would not be sent is somewhere this has
// no business sending the browser -- and a parameter that is followed unchecked is an open
// redirect. Requiring the scheme keeps a target like "javascript:" from being followed even if it
// were ever to present a matching host.
func redirectUrl(value string, cookieDomain string) (*url.URL, error) {
	if value == "" {
		return nil, nil
	}

	parsedUrl, err := url.Parse(value)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("url parse: %w", err), value)
	}

	if scheme := parsedUrl.Scheme; scheme != "https" && scheme != "http" {
		return nil, nil
	}

	// Hosts are compared case insensitively, a host being case insensitive; the parsed URL carries
	// whatever case it arrived in.
	host := strings.ToLower(parsedUrl.Hostname())
	if host != cookieDomain && !strings.HasSuffix(host, "."+cookieDomain) {
		return nil, nil
	}

	return parsedUrl, nil
}

// New returns a handler that renews an expired session on a navigation and redirects back to where
// the browser came from.
//
// authenticationParser has to tolerate an expired token -- an authorizer made with
// authorizer_request_parser_config.WithSkipExp(true) -- since an expired token is the whole subject
// of the exercise. One that does not will reject every token this is meant to act on, and the
// handler will simply never do anything.
func New(
	authenticationParser *authorizer_request_parser.Parser,
	sessionManager *session_manager.Manager,
	options ...navigation_refresh_handler_config.Option,
) (endpoint.Handler, error) {
	if authenticationParser == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("authentication parser"))
	}

	if sessionManager == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("session manager"))
	}

	database := sessionManager.Db
	if database == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("session manager sql db"))
	}

	cookieDomain := sessionManager.CookieDomain
	if cookieDomain == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("session manager cookie domain"))
	}

	config := navigation_refresh_handler_config.New(options...)

	sessionDuration := config.SessionDuration
	if sessionDuration <= 0 {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("session duration"))
	}

	redirectParameterName := config.RedirectParameterName
	if redirectParameterName == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("redirect parameter name"))
	}

	selectRefreshAuthentication := config.SelectRefreshAuthentication
	if selectRefreshAuthentication == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("select refresh authentication"))
	}

	return func(request *http.Request, _ []byte) (*muxResponse.Response, *response_error.ResponseError) {
		if request == nil {
			return nil, nil
		}

		// Only a navigation is sent back. A fetch or a preload asked for this page and should get
		// it; redirecting one would answer a question nobody asked.
		requestHeader := request.Header
		if requestHeader == nil || requestHeader.Get(secFetchModeHeaderName) != navigateFetchMode {
			return nil, nil
		}

		requestUrl := request.URL
		if requestUrl == nil {
			return nil, nil
		}

		parsedRedirectUrl, err := redirectUrl(requestUrl.Query().Get(redirectParameterName), cookieDomain)
		if err != nil || parsedRedirectUrl == nil {
			// There is nowhere to send the browser, so the page is the right answer. A parameter
			// that does not parse is the visitor's to fix, not something to fail the page over.
			return nil, nil
		}

		// A failure here means there is no session to renew, which is the ordinary case for
		// someone arriving to sign in. The page is served and the reason is not worth a log line.
		sessionToken, responseError := authenticationParser.Parse(request)
		if responseError != nil || sessionToken == nil {
			return nil, nil
		}

		claims := sessionToken.Claims
		if claims == nil {
			return nil, nil
		}

		expiresAt := claims.ExpiresAt
		if expiresAt == nil {
			return nil, nil
		}

		// Only an expired token is renewed, which is also what stops this looping: afterwards the
		// token is valid, so a second arrival cannot take this path. If the service that sent the
		// browser here rejects it again, it is over a role or a tenant, and a sign-in page is then
		// the honest answer rather than another trip around.
		if time.Now().Before(expiresAt.Time) {
			return nil, nil
		}

		// A device bound session is renewed by the browser against the refresh endpoint, with a
		// key held by the device. Renewing one from the cookie alone would hand back exactly the
		// capability the binding exists to withhold, so it is left to the browser.
		if slices.Contains(claims.AuthenticationMethods, authentication_method.Dbsc) {
			return nil, nil
		}

		authenticationId := sessionToken.AuthenticationId
		if authenticationId == "" {
			return nil, nil
		}

		databaseCtx, databaseCtxCancel := altshiftDatabase.MakeTimeoutCtx(request.Context())
		defer databaseCtxCancel()

		authentication, err := selectRefreshAuthentication(databaseCtx, authenticationId, database)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, nil
			}

			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.New(
					fmt.Errorf("select refresh authentication: %w", err),
					authenticationId,
				),
			}
		}
		if authentication == nil {
			return nil, nil
		}

		// The same reasoning as above, for a session whose token was issued before the device
		// binding was added to its authentication.
		if len(authentication.DbscPublicKey) != 0 {
			return nil, nil
		}

		refreshResponse, responseError := sessionManager.RefreshSession(
			authentication,
			sessionToken,
			authentication_method.Refresh,
			sessionDuration,
		)
		if responseError != nil {
			if responseError.ServerError != nil {
				return nil, responseError
			}

			// The authentication has ended or expired, or the account is locked. Signing in again
			// is the only way forward, so the page is served -- carrying whatever the refusal
			// wanted set, which is how Clear-Site-Data reaches the browser.
			return &muxResponse.Response{Headers: responseError.Headers}, nil
		}
		if refreshResponse == nil {
			return nil, nil
		}

		// Answering with a status takes the request from the page, which is what makes this a
		// redirect rather than a sign-in form. The renewed cookie rides along in the headers the
		// refresh produced.
		return &muxResponse.Response{
			StatusCode: http.StatusSeeOther,
			Headers: append(
				refreshResponse.Headers,
				&muxResponse.HeaderEntry{
					Name:  locationHeaderName,
					Value: altshiftStrings.HexEscapeNonASCII(parsedRedirectUrl.String()),
				},
			),
		}, nil
	}, nil
}
