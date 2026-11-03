// Package api_key holds the public keys an account registers to mint tokens with.
//
// No secret for API access is stored: what is kept here is the public half of a key the
// account holds, and a token is minted only to a caller that can sign for it. A key that leaks
// from this table lets nobody in.
package api_key

import (
	"time"

	"github.com/altshiftab/authentication_go/pkg/database/types/account"
)

// The name is the table's: a type referenced from another table is emitted under its own name, so
// calling this Key would put the rows in one table and the references in a second one called "key".
type ApiKey struct {
	// Id is the key's RFC 7638 thumbprint, which is the key itself rather than a name for it: a
	// client library computes the same value from the same public key, and two accounts cannot
	// register one key under two ids. It is the primary key so that a revoked key can never be
	// registered again -- the row stays, and registering it a second time collides.
	Id string `postgres:"id,primarykey"`

	Account *account.Account `postgres:"account,ondelete:CASCADE"`

	// Name is what the account calls the key: the build runner, the laptop, the service that holds
	// it. It is what the activity list shows and what a revocation is chosen by.
	Name string `postgres:"name"`

	// Algorithm is the JOSE name of what the key signs with -- EdDSA or ES256 -- so an assertion is
	// verified against the algorithm the key was registered as, never the one the assertion claims.
	Algorithm string `postgres:"algorithm"`

	// PublicKey is the key in DER, as a PKIX SubjectPublicKeyInfo, which is what a PEM public key
	// carries and what crypto/x509 both reads and writes.
	PublicKey []byte `postgres:"public_key"`

	CreatedAt  *time.Time `postgres:"created_at,default:now()"`
	ExpiresAt  *time.Time `postgres:"expires_at,nullable"`
	LastUsedAt *time.Time `postgres:"last_used_at,nullable"`

	// RevokedAt is set rather than the row deleted. Revocation is where API access ends -- the
	// sign-ins a key minted are ended with it, and it can never be registered again.
	RevokedAt *time.Time `postgres:"revoked_at,nullable"`
}
