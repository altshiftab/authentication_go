// Package token_endpoint is the token endpoint (RFC 6749 section 3.2, OAuth 2.1): where a client
// redeems an authorization code, or a refresh token, for an access token to a resource.
//
// A code is redeemed once, by the client it was issued to, for the redirect URI it was sent to,
// with the verifier of the challenge it was asked with. A refresh token is spent as it is used and
// replaced, and one coming back after it was spent revokes its grant. A grant lasts as long as its
// refresh tokens are used, and never longer than its lifetime from when it was given.
package token_endpoint

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/altshiftab/authentication_go/pkg/log_masking"
	"github.com/altshiftab/authentication_go/pkg/oauth"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/access_token"
	"github.com/altshiftab/authentication_go/pkg/pkce"
	altshiftCryptoInterfaces "github.com/altshiftab/utils_go/pkg/crypto/interfaces"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/body_loader"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/body_loader/body_setting"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	muxResponse "github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	"github.com/altshiftab/utils_go/pkg/http/types/http_context_extractor/http_context_extractor_config"
	altshiftOauth2 "github.com/altshiftab/utils_go/pkg/oauth2"
	altshiftReflect "github.com/altshiftab/utils_go/pkg/reflect"
	"github.com/altshiftab/utils_go/pkg/schema"
	"github.com/altshiftab/utils_go/pkg/utils"
)

const (
	DefaultPath = "/oauth/token"

	// errorInvalidGrant is the error for a grant -- a code, a refresh token -- that is not good for
	// what was asked (RFC 6749 section 5.2).
	errorInvalidGrant = "invalid_grant"

	DefaultAccessTokenLifetime  = 15 * time.Minute
	DefaultRefreshTokenLifetime = 30 * 24 * time.Hour
	DefaultGrantLifetime        = 90 * 24 * time.Hour
)

// Response is a token response (RFC 6749 section 5.1).
type Response struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitzero"`
	Scope        string `json:"scope,omitzero"`
}

// ErrorResponse is a token error response (RFC 6749 section 5.2).
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitzero"`
}

type Endpoint struct {
	*initialization_endpoint.Endpoint
	AccessTokenLifetime  time.Duration
	RefreshTokenLifetime time.Duration
	GrantLifetime        time.Duration
	now                  func() time.Time
}

type issuer struct {
	issuer    string
	signer    altshiftCryptoInterfaces.NamedSigner
	keyId     string
	store     oauth.Store
	resources []*oauth.Resource
}

// Initialize has the endpoint issue tokens as the issuer, signed by the signer under keyId -- a key
// of their own, which no service accepting sessions verifies with -- for the resources only.
func (e *Endpoint) Initialize(
	issuerUrl string,
	signer altshiftCryptoInterfaces.NamedSigner,
	keyId string,
	store oauth.Store,
	resources []*oauth.Resource,
) error {
	if issuerUrl == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("issuer"))
	}
	if utils.IsNil(signer) {
		return altshiftErrors.NewWithTrace(nil_error.New("signer"))
	}
	if utils.IsNil(store) {
		return altshiftErrors.NewWithTrace(nil_error.New("store"))
	}
	if len(resources) == 0 {
		return altshiftErrors.NewWithTrace(empty_error.New("resources"))
	}
	if e.now == nil {
		e.now = time.Now
	}

	server := &issuer{issuer: issuerUrl, signer: signer, keyId: keyId, store: store, resources: resources}

	e.Handler = func(request *http.Request, body []byte) (*muxResponse.Response, *response_error.ResponseError) {
		ctx := request.Context()

		form, err := url.ParseQuery(string(body))
		if err != nil {
			return refuse(ctx, http.StatusBadRequest, "invalid_request", "The request body is no form.")
		}
		// No parameter may be sent twice (RFC 6749 section 3.2): which of the two counts would be a
		// guess.
		for name, values := range form {
			if len(values) > 1 {
				return refuse(ctx, http.StatusBadRequest, "invalid_request", fmt.Sprintf("The %s parameter is repeated.", name))
			}
		}

		switch form.Get("grant_type") {
		case "authorization_code":
			return e.redeemCode(ctx, server, form)
		case "refresh_token":
			return e.refresh(ctx, server, form)
		case "":
			return refuse(ctx, http.StatusBadRequest, "invalid_request", "A grant type is required.")
		default:
			return refuse(ctx, http.StatusBadRequest, "unsupported_grant_type", "The grant type is not supported.")
		}
	}

	e.Initialized = true

	return nil
}

func (e *Endpoint) redeemCode(ctx context.Context, server *issuer, form url.Values) (*muxResponse.Response, *response_error.ResponseError) {
	code, clientId, verifier := form.Get("code"), form.Get("client_id"), form.Get("code_verifier")
	if code == "" || clientId == "" || verifier == "" {
		return refuse(ctx, http.StatusBadRequest, "invalid_request", "A code, client id and code verifier are required.")
	}

	authorizationCode, err := server.store.PopAuthorizationCode(ctx, oauth.HashSecret(code))
	if errors.Is(err, oauth.ErrNotFound) {
		return refuse(ctx, http.StatusBadRequest, errorInvalidGrant, "The code is invalid or was redeemed already.")
	}
	if err != nil {
		return nil, &response_error.ResponseError{ServerError: altshiftErrors.New(fmt.Errorf("store pop authorization code: %w", err))}
	}
	if authorizationCode == nil {
		return nil, &response_error.ResponseError{ServerError: altshiftErrors.NewWithTrace(nil_error.New("authorization code"))}
	}

	// The redirect URI is held to the one the code was sent to where the client names one, as an
	// RFC 6749 client does; OAuth 2.1 has it left out, the verifier binding the code instead.
	now := e.now()
	switch redirectUri := form.Get("redirect_uri"); {
	case !now.Before(authorizationCode.ExpiresAt):
		return refuse(ctx, http.StatusBadRequest, errorInvalidGrant, "The code has expired.")
	case authorizationCode.ClientId != clientId:
		return refuse(ctx, http.StatusBadRequest, errorInvalidGrant, "The code was issued to another client.")
	case redirectUri != "" && authorizationCode.RedirectUri != redirectUri:
		return refuse(ctx, http.StatusBadRequest, errorInvalidGrant, "The redirect URI is not the one the code was sent to.")
	case !pkce.ValidVerifier(verifier) || !pkce.MatchesS256(verifier, authorizationCode.CodeChallenge):
		return refuse(ctx, http.StatusBadRequest, errorInvalidGrant, "The code verifier does not match the challenge.")
	}
	if resource := form.Get("resource"); resource != "" && resource != authorizationCode.Resource {
		return refuse(ctx, http.StatusBadRequest, "invalid_target", "The resource is not the one the code was issued for.")
	}

	grant := &oauth.Grant{
		AccountId: authorizationCode.AccountId,
		ClientId:  authorizationCode.ClientId,
		Resource:  authorizationCode.Resource,
		Scope:     authorizationCode.Scope,
		CreatedAt: now,
	}
	if err := e.checkGrant(ctx, server, grant); err != nil {
		return answer(ctx, err)
	}

	refreshToken, err := oauth.NewSecret()
	if err != nil {
		return nil, &response_error.ResponseError{ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("new secret: %w", err))}
	}
	scopes := strings.Fields(grant.Scope)
	// Minted before the grant is recorded, so that a grant is never recorded without its tokens
	// having been made.
	issued, err := e.mint(server, grant, scopes, refreshToken)
	if err != nil {
		return answer(ctx, err)
	}
	grantId, err := server.store.InsertGrant(ctx, grant, oauth.HashSecret(refreshToken), now.Add(e.refreshTokenLifetime()))
	if err != nil {
		return nil, &response_error.ResponseError{ServerError: altshiftErrors.New(fmt.Errorf("store insert grant: %w", err))}
	}
	grant.Id = grantId

	logIssued(ctx, grant, scopes, "authorization_code")
	return issued, nil
}

func (e *Endpoint) refresh(ctx context.Context, server *issuer, form url.Values) (*muxResponse.Response, *response_error.ResponseError) {
	refreshToken, clientId := form.Get("refresh_token"), form.Get("client_id")
	if refreshToken == "" || clientId == "" {
		return refuse(ctx, http.StatusBadRequest, "invalid_request", "A refresh token and client id are required.")
	}

	newRefreshToken, err := oauth.NewSecret()
	if err != nil {
		return nil, &response_error.ResponseError{ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("new secret: %w", err))}
	}

	// Everything that can refuse the request, and the minting of what answers it, is done before
	// the token is spent: a refusal, or a failure here, leaves the client the token it has, which
	// spent would come back on its retry and revoke the grant.
	now := e.now()
	var (
		scopes []string
		issued *muxResponse.Response
	)
	grant, err := server.store.RotateRefreshToken(
		ctx, oauth.HashSecret(refreshToken), oauth.HashSecret(newRefreshToken), now.Add(e.refreshTokenLifetime()), now,
		func(grant *oauth.Grant) error {
			if grant == nil {
				return altshiftErrors.NewWithTrace(nil_error.New("grant"))
			}
			if grant.ClientId != clientId {
				return &refusal{code: errorInvalidGrant, description: "The refresh token was issued to another client."}
			}
			if !now.Before(grant.CreatedAt.Add(e.grantLifetime())) {
				return &refusal{code: errorInvalidGrant, description: "The grant has expired."}
			}
			if resource := form.Get("resource"); resource != "" && resource != grant.Resource {
				return &refusal{code: "invalid_target", description: "The resource is not the one the grant is for."}
			}

			scopes = strings.Fields(grant.Scope)
			if requested := strings.Fields(form.Get("scope")); len(requested) != 0 {
				for _, scope := range requested {
					if !slices.Contains(scopes, scope) {
						return &refusal{code: "invalid_scope", description: "The scope is more than the grant's."}
					}
				}
				scopes = requested
			}

			if err := e.checkGrant(ctx, server, grant); err != nil {
				return err
			}

			minted, err := e.mint(server, grant, scopes, newRefreshToken)
			if err != nil {
				return err
			}
			issued = minted
			return nil
		},
	)
	switch {
	case errors.Is(err, oauth.ErrRefreshTokenReused):
		// Only one of the two presenting it can be the client, and which cannot be told: the grant
		// is revoked for both, and the client signs the user in again.
		slog.WarnContext(ctx, "A refresh token was presented after it was spent; its grant is revoked.",
			slog.Group("oauth", slog.String("client_id", clientId)))
		return refuse(ctx, http.StatusBadRequest, errorInvalidGrant, "The refresh token was spent already.")
	case errors.Is(err, oauth.ErrNotFound):
		return refuse(ctx, http.StatusBadRequest, errorInvalidGrant, "The refresh token is invalid or has expired.")
	case err != nil:
		return answer(ctx, err)
	case grant == nil || issued == nil:
		return nil, &response_error.ResponseError{ServerError: altshiftErrors.NewWithTrace(nil_error.New("renewed grant"))}
	}

	logIssued(ctx, grant, scopes, "refresh_token")
	return issued, nil
}

// refusal is a token request refused for what it asked, as against one the server failed to
// answer.
type refusal struct {
	code        string
	description string
}

func (r *refusal) Error() string {
	return r.code + ": " + r.description
}

// answer is the response to an error in answering: a refusal is told to the client, anything else
// is the server's.
func answer(ctx context.Context, err error) (*muxResponse.Response, *response_error.ResponseError) {
	if refused, ok := errors.AsType[*refusal](err); ok && refused != nil {
		return refuse(ctx, http.StatusBadRequest, refused.code, refused.description)
	}
	return nil, &response_error.ResponseError{ServerError: err}
}

// checkGrant refuses a grant whose resource is no longer served or whose account is no longer
// active, as either may have stopped being since the grant was given.
func (e *Endpoint) checkGrant(ctx context.Context, server *issuer, grant *oauth.Grant) error {
	if oauth.FindResource(server.resources, grant.Resource) == nil {
		return &refusal{code: "invalid_target", description: "The resource is no longer one this server issues tokens for."}
	}

	active, err := server.store.AccountActive(ctx, grant.AccountId)
	if err != nil {
		return altshiftErrors.New(fmt.Errorf("store account active: %w", err))
	}
	if !active {
		return &refusal{code: errorInvalidGrant, description: "The account is locked or no longer exists."}
	}

	return nil
}

// mint is the token response for the grant: an access token for its resource, and the refresh
// token that renews it.
func (e *Endpoint) mint(server *issuer, grant *oauth.Grant, scopes []string, refreshToken string) (*muxResponse.Response, error) {
	tokenId, err := oauth.NewSecret()
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("new secret: %w", err))
	}

	now := e.now()
	lifetime := e.accessTokenLifetime()
	accessToken, err := access_token.Mint(&access_token.Token{
		Issuer:        server.issuer,
		Subject:       grant.AccountId,
		Audience:      grant.Resource,
		ClientId:      grant.ClientId,
		Scopes:        scopes,
		Id:            tokenId,
		IssuedAt:      now,
		ExpiresAt:     now.Add(lifetime),
		KeyThumbprint: grant.KeyThumbprint,
	}, server.signer, server.keyId)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("access token mint: %w", err))
	}

	tokenType := "Bearer"
	if grant.KeyThumbprint != "" {
		tokenType = "DPoP"
	}

	body, err := json.Marshal(&Response{
		AccessToken:  accessToken,
		TokenType:    tokenType,
		ExpiresIn:    int64(lifetime / time.Second),
		RefreshToken: refreshToken,
		Scope:        strings.Join(scopes, " "),
	})
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("json marshal (token response): %w", err))
	}

	return &muxResponse.Response{Body: body, Headers: jsonHeaders(), SensitiveBody: true}, nil
}

func logIssued(ctx context.Context, grant *oauth.Grant, scopes []string, grantType string) {
	slog.InfoContext(ctx, "An OAuth access token was issued.",
		slog.Group("user", slog.String("id", grant.AccountId)),
		slog.Group("oauth",
			slog.String("grant_type", grantType),
			slog.String("client_id", grant.ClientId),
			slog.String("resource", grant.Resource),
			slog.String("scope", strings.Join(scopes, " ")),
		),
	)
}

// refuse answers with a token error response, which a client reads as RFC 6749 has it rather than
// as a problem detail.
func refuse(ctx context.Context, status int, errorCode string, description string) (*muxResponse.Response, *response_error.ResponseError) {
	slog.InfoContext(ctx, "An OAuth token request was refused.",
		slog.Group("oauth", slog.String("error", errorCode), slog.String("error_description", description)))

	body, err := json.Marshal(&ErrorResponse{Error: errorCode, ErrorDescription: description})
	if err != nil {
		return nil, &response_error.ResponseError{ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("json marshal (error response): %w", err))}
	}
	return &muxResponse.Response{StatusCode: status, Body: body, Headers: jsonHeaders()}, nil
}

func jsonHeaders() []*muxResponse.HeaderEntry {
	return []*muxResponse.HeaderEntry{
		{Name: "Content-Type", Value: "application/json"},
		{Name: "Cache-Control", Value: "no-store", Overwrite: true},
		{Name: "Pragma", Value: "no-cache"},
	}
}

func (e *Endpoint) accessTokenLifetime() time.Duration {
	if e.AccessTokenLifetime > 0 {
		return e.AccessTokenLifetime
	}
	return DefaultAccessTokenLifetime
}

func (e *Endpoint) refreshTokenLifetime() time.Duration {
	if e.RefreshTokenLifetime > 0 {
		return e.RefreshTokenLifetime
	}
	return DefaultRefreshTokenLifetime
}

func (e *Endpoint) grantLifetime() time.Duration {
	if e.GrantLifetime > 0 {
		return e.GrantLifetime
	}
	return DefaultGrantLifetime
}

// MaskedUrlParams is empty: a token request is sent in the body.
func (e *Endpoint) MaskedUrlParams() []*schema.Url {
	return nil
}

// MaskedBodyFields are the request's code, verifier and refresh token, and the response's tokens.
func (e *Endpoint) MaskedBodyFields() (*log_masking.BodyFields, error) {
	own := &schema.Url{Path: e.Path}
	return &log_masking.BodyFields{
		Request: []*http_context_extractor_config.MaskedBodyFields{
			{Url: own, Fields: altshiftOauth2.TokenRequestCredentialFields()},
		},
		Response: []*http_context_extractor_config.MaskedBodyFields{
			{Url: own, Fields: altshiftOauth2.TokenResponseCredentialFields()},
		},
	}, nil
}

// MaskedHeaders is nothing: a public client sends no credential in a header.
func (e *Endpoint) MaskedHeaders() []*http_context_extractor_config.MaskedHeader {
	return nil
}

func New() *Endpoint {
	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:      DefaultPath,
				Method:    http.MethodPost,
				UrlParser: adapter.New(query_extractor.Empty),
				BodyLoader: &body_loader.Loader{
					ContentType: "application/x-www-form-urlencoded",
					Setting:     body_setting.Required,
					MaxBytes:    16 * 1024,
				},
				Public: true,
				Hint: &endpoint.Hint{
					OutputType:        altshiftReflect.TypeOf[Response](),
					OutputContentType: "application/json",
				},
			},
		},
	}
}
