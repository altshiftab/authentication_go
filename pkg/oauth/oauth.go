// Package oauth is an OAuth 2.1 authorization server for the resources of the apps a sign-in
// service fronts -- an app's MCP server, say -- beside the service's own sessions rather than in
// place of them.
//
// Its tokens are for those resources alone. An access token names one resource as its audience
// and is signed with a key of its own, not the session key, so no service that accepts the
// sign-in service's sessions accepts one; and the flow that issues one never issues a session.
// The user is identified by the session they already have, through the sign-in the service
// already offers.
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"slices"
	"time"
)

// Resource is what an access token may be issued for: an app's protected resource, named by its
// URL (RFC 8707), which is the token's audience.
type Resource struct {
	Url string `json:"url"`
	// Name is what the consent page calls it.
	Name string `json:"name"`
	// Scopes are the scopes a token for it may carry; a request naming none is given all of them.
	Scopes []string `json:"scopes"`
}

// FindResource is the resource of the URL among resources. A request naming no resource is given
// the only one there is, and refused where there are several: guessing which would be guessing what
// the user is asked to consent to.
func FindResource(resources []*Resource, url string) *Resource {
	if url == "" {
		if len(resources) == 1 {
			return resources[0]
		}
		return nil
	}

	for _, resource := range resources {
		if resource != nil && resource.Url == url {
			return resource
		}
	}

	return nil
}

// AllowsScopes says whether every scope asked for is one the resource has.
func (r *Resource) AllowsScopes(scopes []string) bool {
	for _, scope := range scopes {
		if !slices.Contains(r.Scopes, scope) {
			return false
		}
	}
	return true
}

// AuthorizationRequest is an authorization request held between the consent page and the user's
// answer to it.
type AuthorizationRequest struct {
	Id            string
	AccountId     string
	ClientId      string
	ClientName    string
	RedirectUri   string
	State         string
	CodeChallenge string
	Resource      string
	Scope         string
	ExpiresAt     time.Time
}

// AuthorizationCode is what an authorization code stands for, held under the code's hash until
// it is redeemed.
type AuthorizationCode struct {
	AccountId     string
	ClientId      string
	RedirectUri   string
	CodeChallenge string
	Resource      string
	Scope         string
	ExpiresAt     time.Time
}

// Grant is a client's standing access to one resource on an account's behalf, which its refresh
// tokens renew and revoking ends.
type Grant struct {
	Id        string
	AccountId string
	ClientId  string
	Resource  string
	Scope     string
	// KeyThumbprint binds the grant's tokens to a key (RFC 9449), for a client that has one.
	KeyThumbprint string
	CreatedAt     time.Time
}

var (
	// ErrNotFound is a request, code, refresh token or grant that does not exist, has expired or
	// has been revoked: to the client, all the same.
	ErrNotFound = errors.New("not found")

	// ErrRefreshTokenReused is a refresh token presented after it was spent. Its grant is revoked:
	// only one of the two presenting it can be the client.
	ErrRefreshTokenReused = errors.New("refresh token reused")
)

// GrantCheck is what a grant must pass to be renewed. It is asked while the refresh token is held,
// and may ask the store about the account, so a store asks it without holding a lock of its own.
type GrantCheck func(grant *Grant) error

// Store keeps what the authorization server hands out. Codes and refresh tokens are kept by their
// hashes, never as themselves.
type Store interface {
	InsertAuthorizationRequest(ctx context.Context, request *AuthorizationRequest) (string, error)
	// PopAuthorizationRequest returns the request and removes it, or ErrNotFound.
	PopAuthorizationRequest(ctx context.Context, id string) (*AuthorizationRequest, error)

	InsertAuthorizationCode(ctx context.Context, codeHash []byte, code *AuthorizationCode) error
	// PopAuthorizationCode returns what the code stands for and removes it, or ErrNotFound: a code
	// is redeemed once.
	PopAuthorizationCode(ctx context.Context, codeHash []byte) (*AuthorizationCode, error)

	// InsertGrant records a grant and its first refresh token, returning the grant's id.
	InsertGrant(ctx context.Context, grant *Grant, refreshTokenHash []byte, refreshTokenExpiresAt time.Time) (string, error)
	// RotateRefreshToken spends a refresh token and records its successor in one step, returning
	// the grant it renews. A token spent before revokes the grant and is ErrRefreshTokenReused; one
	// unknown, expired, or of a revoked grant is ErrNotFound. check is asked of the grant before the
	// token is spent, and an error from it is returned with the token left as it was: a refusal must
	// not cost the client the only token it has.
	RotateRefreshToken(
		ctx context.Context,
		refreshTokenHash []byte,
		newRefreshTokenHash []byte,
		newExpiresAt time.Time,
		now time.Time,
		check GrantCheck,
	) (*Grant, error)
	// RevokeRefreshToken revokes the grant the refresh token renews, spent or not. A token not
	// known is no error: there is nothing left to revoke.
	RevokeRefreshToken(ctx context.Context, refreshTokenHash []byte) error

	// AccountActive says whether the account exists and is not locked.
	AccountActive(ctx context.Context, accountId string) (bool, error)
}

// AuthorizationResponseUrl is the redirect URI with the authorization response's parameters added
// to what query it has, and the issuer among them (RFC 9207), which tells a client talking to
// several servers which one answered.
func AuthorizationResponseUrl(redirectUri string, issuer string, parameters map[string]string) (string, error) {
	u, err := url.Parse(redirectUri)
	if err != nil {
		return "", err
	}

	query := u.Query()
	for name, value := range parameters {
		if value != "" {
			query.Set(name, value)
		}
	}
	query.Set("iss", issuer)
	u.RawQuery = query.Encode()

	return u.String(), nil
}

// NewSecret is a value the server hands out to be presented back -- a code or a refresh token: 32
// random bytes, base64url.
func NewSecret() (string, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// HashSecret is what a secret is kept as: its SHA-256. A store's copy is then nothing anyone could
// present.
func HashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}
