package dbsc_challenge

import (
	"time"

	"github.com/altshiftab/authentication_go/pkg/database/types/authentication"
)

type Challenge struct {
	Authentication *authentication.Authentication `postgres:"authentication,ondelete:CASCADE"`
	// Indexed: a proof redeems its challenge by it.
	Challenge []byte `postgres:"challenge,indexed"`
	// Indexed: every challenge issued removes the ones that have expired.
	ExpiresAt *time.Time `postgres:"expires_at,indexed"`
}
