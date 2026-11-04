// Package mint_token_endpoint mints an access token for a client that can sign for a registered key.
//
// This is the one endpoint here that no session reaches: the assertion in the Authorization header
// is the whole credential, which is the point of the scheme -- the service stores no secret, and a
// caller proves it holds a private key rather than repeating something it was given.
//
// What comes back is a short-lived session token, the same kind the browsers carry, marked in its
// "amr" as having been minted against a key. That mark is what keeps it out of the endpoints meant
// for a signed-in person: every authorizer takes the browser methods unless it says otherwise.
//
// It is not the OAuth token endpoint, pkg/oauth/types/endpoint/token_endpoint, which redeems what an
// authorization server granted; this one redeems nothing but a signature.
package mint_token_endpoint

import (
	"database/sql"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/altshiftab/authentication_go/pkg/api_key/api_key_cruder"
	"github.com/altshiftab/authentication_go/pkg/api_key/assertion"
	"github.com/altshiftab/authentication_go/pkg/api_key/public_key"
	apiKeyTypes "github.com/altshiftab/authentication_go/pkg/api_key/types"
	"github.com/altshiftab/authentication_go/pkg/log_masking"
	"github.com/altshiftab/authentication_go/pkg/session/types/authentication_method"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_manager"
	altshiftDatabase "github.com/altshiftab/utils_go/pkg/database"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/body_loader"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/body_loader/body_setting"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/token_header_extractor"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/token_header_extractor/token_header_extractor_config"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/altshiftab/utils_go/pkg/http/mux/utils"
	altshiftHttpTypes "github.com/altshiftab/utils_go/pkg/http/types"
	"github.com/altshiftab/utils_go/pkg/http/types/http_context_extractor/http_context_extractor_config"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	altshiftOauth2 "github.com/altshiftab/utils_go/pkg/oauth2"
	altshiftReflect "github.com/altshiftab/utils_go/pkg/reflect"
	"github.com/altshiftab/utils_go/pkg/schema"
)

// DefaultTokenLifetime is how long a minted token is good for.
//
// Short, and deliberately the same as a browser session's: consumers validate a token by its
// signature and its expiry without asking this service anything, so a token's lifetime is the
// window in which a revoked key's last token still works. A client re-mints; the key is the
// long-lived credential, and the token is not.
const DefaultTokenLifetime = 15 * time.Minute

// The assertion arrives as a bearer token. A missing or malformed header is the client's mistake
// rather than a refusal to authenticate -- there is no session to be missing here -- so it answers
// 400 as the id token endpoint's does.
var assertionHeaderExtractor = token_header_extractor.New(
	token_header_extractor_config.WithProblemDetailStatusCode(http.StatusBadRequest),
)

type Endpoint struct {
	*initialization_endpoint.Endpoint

	// Audience is what an assertion must name this service as: its origin, the same string the
	// tokens it issues carry as their issuer. It is what stops an assertion made for one
	// deployment being presented to another.
	Audience string

	// TokenLifetime is how long the minted token lasts.
	TokenLifetime time.Duration
}

func (e *Endpoint) Initialize(sessionManager *session_manager.Manager, db *sql.DB, audience string) error {
	if sessionManager == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("session manager"))
	}
	if db == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("sql database"))
	}
	if audience == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("audience"))
	}

	e.Audience = audience
	if e.TokenLifetime == 0 {
		e.TokenLifetime = DefaultTokenLifetime
	}

	e.HeaderParser = adapter.New(assertionHeaderExtractor)
	e.UrlParser = adapter.New(query_extractor.Empty)

	e.Handler = func(request *http.Request, _ []byte) (*response.Response, *response_error.ResponseError) {
		ctx := request.Context()

		assertionString, responseError := muxUtils.GetServerNonZeroParsedRequestHeaders[string](ctx)
		if responseError != nil {
			return nil, responseError
		}

		// One answer for everything that follows until the signature checks out: an assertion that
		// names a key nobody registered, one whose signature is not that key's, and one that is
		// malformed all look the same from outside. Knowing which would be a way to find out whose
		// keys exist.
		invalidAssertion := func(err error) *response_error.ResponseError {
			return &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusUnauthorized,
					problem_detail_config.WithDetail("The assertion is not valid."),
				),
				ClientError: err,
			}
		}
		revoked := func() *response_error.ResponseError {
			return &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusForbidden,
					problem_detail_config.WithDetail("The key has been revoked."),
				),
			}
		}

		keyId, err := assertion.Subject(assertionString)
		if err != nil {
			return nil, invalidAssertion(altshiftErrors.New(fmt.Errorf("assertion subject: %w", err)))
		}

		apiKeyCruder := &api_key_cruder.Cruder{Database: db}

		dbCtx, cancel := altshiftDatabase.MakeTimeoutCtx(ctx)
		defer cancel()

		key, err := apiKeyCruder.SelectForMint(dbCtx, keyId)
		if err != nil {
			wrappedErr := altshiftErrors.New(fmt.Errorf("api key cruder select for mint: %w", err), keyId)
			if errors.Is(err, sql.ErrNoRows) {
				return nil, invalidAssertion(wrappedErr)
			}
			return nil, &response_error.ResponseError{ServerError: wrappedErr}
		}

		now := time.Now()

		parsedKey, err := public_key.FromDer(key.PublicKey)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.New(fmt.Errorf("public key from der: %w", err), keyId),
			}
		}

		verifiedAssertion, err := assertion.Verify(assertionString, parsedKey, e.Audience, now)
		if err != nil {
			return nil, invalidAssertion(altshiftErrors.New(fmt.Errorf("assertion verify: %w", err), keyId))
		}

		// Revocation and expiry are said plainly, unlike the refusals above, and they are said only
		// here -- after the signature, where the holder has proved the key is theirs to be told
		// about. A client that cannot tell "revoked" from "the signature is wrong" cannot tell a
		// person what to do about it either.
		if key.Revoked() {
			return nil, revoked()
		}

		if key.Expired(now) {
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusForbidden,
					problem_detail_config.WithDetail("The key has expired."),
				),
			}
		}

		authentication, err := apiKeyCruder.RecordMint(
			dbCtx,
			key,
			verifiedAssertion.Jti,
			session_manager.ClientMetadataFromContext(ctx),
		)
		if err != nil {
			wrappedErr := altshiftErrors.New(fmt.Errorf("api key cruder record mint: %w", err), keyId)
			// The assertion has been presented before. Said as itself rather than as "not valid":
			// a client retrying a request must know to make a new assertion rather than to give up.
			// Revoked between the read above and the record: answered as if it had been seen there.
			if errors.Is(err, api_key_cruder.ErrKeyRevoked) {
				return nil, revoked()
			}
			if errors.Is(err, api_key_cruder.ErrAssertionAlreadyUsed) {
				return nil, &response_error.ResponseError{
					ProblemDetail: problem_detail.New(
						http.StatusBadRequest,
						problem_detail_config.WithDetail("The assertion has already been used."),
					),
					ClientError: wrappedErr,
				}
			}
			return nil, &response_error.ResponseError{ServerError: wrappedErr}
		}

		sessionToken, sessionTokenString, responseError := sessionManager.MintToken(
			authentication,
			authentication_method.ApiKey,
			e.TokenLifetime,
		)
		if responseError != nil {
			return nil, responseError
		}
		if sessionToken == nil || sessionToken.Claims == nil || sessionToken.Claims.ExpiresAt == nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(nil_error.New("session token")),
			}
		}

		// Who minted, attached to the HTTP context so it reaches the request log and correlates
		// with the rest of the service by the same fields.
		account := authentication.Account
		if httpContext, ok := ctx.Value(muxPkg.MuxHttpContextContextKey).(*altshiftHttpTypes.HttpContext); ok &&
			httpContext != nil && account != nil {
			httpContext.User = &schema.User{Id: account.Id, Email: account.EmailAddress}
		}

		if account != nil {
			slog.InfoContext(
				ctx,
				"An API key minted a token.",
				slog.Group("user", slog.String("id", account.Id), slog.String("email", account.EmailAddress)),
				slog.Group("api_key", slog.String("id", key.Id), slog.String("name", key.Name)),
			)
		}

		data, err := json.Marshal(&apiKeyTypes.Token{
			AccessToken: sessionTokenString,
			TokenType:   "Bearer",
			ExpiresIn:   int(time.Until(sessionToken.Claims.ExpiresAt.Time).Seconds()),
		})
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("json marshal (token): %w", err)),
			}
		}

		return &response.Response{
			Headers: []*response.HeaderEntry{
				{Name: "Content-Type", Value: "application/json"},
				// Nothing about a minted token may be kept by anything in between.
				{Name: "Cache-Control", Value: "no-store", Overwrite: true},
			},
			Body: data,
			// Never compressed, whatever its size: a token is what a compression side channel reads.
			SensitiveBody: true,
		}, nil
	}

	e.Initialized = true
	return nil
}

// MaskedUrlParams is empty: the assertion is sent in a header, and nothing in the URL.
func (e *Endpoint) MaskedUrlParams() []*schema.Url {
	return nil
}

// MaskedBodyFields is the token the endpoint answers with, which the log would otherwise write out
// whole: a session token good for its lifetime to whoever reads the log. Named as the OAuth token
// endpoint names its own, the answer being in the same shape.
func (e *Endpoint) MaskedBodyFields() (*log_masking.BodyFields, error) {
	return &log_masking.BodyFields{
		Response: []*http_context_extractor_config.MaskedBodyFields{
			{Url: &schema.Url{Path: e.Path}, Fields: altshiftOauth2.TokenResponseCredentialFields()},
		},
	}, nil
}

// MaskedHeaders is nothing: the log's own masking of a header already takes the assertion's
// signature, without which what is left of it cannot be presented again.
func (e *Endpoint) MaskedHeaders() []*http_context_extractor_config.MaskedHeader {
	return nil
}

func New() *Endpoint {
	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:   DefaultPath,
				Method: http.MethodPost,
				// Public in the sense the mux means: no session is required. The assertion is what
				// authenticates, and it is verified in the handler against a key that was stored.
				Public:     true,
				BodyLoader: &body_loader.Loader{Setting: body_setting.Forbidden},
				Hint: &endpoint.Hint{
					OutputType:        altshiftReflect.TypeOf[apiKeyTypes.Token](),
					OutputContentType: "application/json",
				},
			},
		},
	}
}

// DefaultPath is where pkg/api_key/client posts its assertions, client.TokenPath.
const DefaultPath = "/api/token"
