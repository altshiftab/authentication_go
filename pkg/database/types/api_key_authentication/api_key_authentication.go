// Package api_key_authentication links a sign-in to the key that minted it.
//
// A sign-in is a sign-in whether a person made it at the sign-in page or a script made it with a
// key: one table holds both, so the account page lists them together and the same checks decide
// whether either is still good. Which key minted one is recorded beside that table rather than in
// it, so that the table stays what it is for a service that registers no keys at all.
package api_key_authentication

import (
	"github.com/altshiftab/authentication_go/pkg/database/types/api_key"
	"github.com/altshiftab/authentication_go/pkg/database/types/authentication"
)

type ApiKeyAuthentication struct {
	// One row per sign-in: a sign-in is minted by one key or by none.
	Authentication *authentication.Authentication `postgres:"authentication,ondelete:CASCADE,unique"`

	// Cascading, so revoking a key that is later deleted outright cannot leave a row pointing at
	// nothing. Revocation itself keeps the key: see ApiKey.RevokedAt.
	ApiKey *api_key.ApiKey `postgres:"api_key,ondelete:CASCADE"`
}
