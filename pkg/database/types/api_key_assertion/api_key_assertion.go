// Package api_key_assertion remembers the assertions a key has already minted with, for as long as
// they could still be presented again.
//
// An assertion is a short-lived signed statement, and a copy of one is as good as the original
// until it expires -- which is what a replay is. Keeping the identifier until then makes the second
// presentation fail. The store is the database rather than the process because a service runs as
// several instances, and a replay that lands on another one must fail there too.
package api_key_assertion

import (
	"time"

	"github.com/altshiftab/authentication_go/pkg/database/types/api_key"
)

type ApiKeyAssertion struct {
	// Unique together: two keys may each use the identifier "1" without either being a replay.
	ApiKey *api_key.ApiKey `postgres:"api_key,ondelete:CASCADE,uniquecomposite"`
	Jti    string          `postgres:"jti,uniquecomposite"`

	// When the assertion stops being presentable, which is when this row stops being worth keeping.
	ExpiresAt *time.Time `postgres:"expires_at"`
}
