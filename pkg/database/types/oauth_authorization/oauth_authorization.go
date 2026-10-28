// Package oauth_authorization is what the OAuth authorization server keeps, as tables. Codes and
// refresh tokens are kept by their SHA-256 alone, so that no copy of the database holds anything a
// client could present.
package oauth_authorization

import (
	"time"

	"github.com/altshiftab/authentication_go/pkg/database/types/account"
)

// OauthAuthorizationRequest is an authorization request between the consent page and the user's
// answer to it, minutes long.
type OauthAuthorizationRequest struct {
	Id            string           `postgres:"id,primarykey,type:uuid,default:gen_random_uuid()"`
	Account       *account.Account `postgres:"account,ondelete:CASCADE"`
	ClientId      string           `postgres:"client_id"`
	ClientName    string           `postgres:"client_name"`
	RedirectUri   string           `postgres:"redirect_uri"`
	State         string           `postgres:"state"`
	CodeChallenge string           `postgres:"code_challenge"`
	Resource      string           `postgres:"resource"`
	Scope         string           `postgres:"scope"`
	ExpiresAt     *time.Time       `postgres:"expires_at"`
}

// OauthAuthorizationCode is an authorization code until it is redeemed, a minute at most.
type OauthAuthorizationCode struct {
	CodeHash      []byte           `postgres:"code_hash,primarykey"`
	Account       *account.Account `postgres:"account,ondelete:CASCADE"`
	ClientId      string           `postgres:"client_id"`
	RedirectUri   string           `postgres:"redirect_uri"`
	CodeChallenge string           `postgres:"code_challenge"`
	Resource      string           `postgres:"resource"`
	Scope         string           `postgres:"scope"`
	ExpiresAt     *time.Time       `postgres:"expires_at"`
}

// OauthGrant is a client's standing access to one resource on an account's behalf.
type OauthGrant struct {
	Id            string           `postgres:"id,primarykey,type:uuid,default:gen_random_uuid()"`
	Account       *account.Account `postgres:"account,ondelete:CASCADE"`
	ClientId      string           `postgres:"client_id"`
	Resource      string           `postgres:"resource"`
	Scope         string           `postgres:"scope"`
	KeyThumbprint string           `postgres:"key_thumbprint,nullable"`
	CreatedAt     *time.Time       `postgres:"created_at,default:now()"`
	Revoked       bool             `postgres:"revoked,default:false"`
}

// OauthRefreshToken is a grant's refresh token. A spent one is kept, marked used, so that its
// coming back is told from a token never issued.
type OauthRefreshToken struct {
	TokenHash  []byte      `postgres:"token_hash,primarykey"`
	OauthGrant *OauthGrant `postgres:"oauth_grant,ondelete:CASCADE"`
	ExpiresAt  *time.Time  `postgres:"expires_at"`
	UsedAt     *time.Time  `postgres:"used_at,nullable"`
}
