package session_manager_config

import (
	"context"
	"database/sql"
	"time"

	"github.com/altshiftab/authentication_go/pkg/database"
	accountPkg "github.com/altshiftab/authentication_go/pkg/database/types/account"
	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	"github.com/altshiftab/authentication_go/pkg/session/types/endpoint/dbsc_refresh_endpoint/dbsc_refresh_endpoint_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/endpoint/dbsc_register_endpoint/dbsc_register_endpoint_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_cookie/session_cookie_config"
)

var (
	DefaultCookieName = "session"
	// The session token is short-lived: revocation is only enforced when a session is refreshed,
	// so the token's lifetime is how long a revoked session remains usable.
	//
	// A device bound session's first cookie expires with this token, so the two minute floor
	// described in dbsc_refresh_endpoint_config.DefaultSessionDuration applies here too.
	DefaultInitialSessionDuration = 15 * time.Minute
	DefaultAuthenticationDuration = 12 * time.Hour
	DefaultDbscChallengeDuration  = dbsc_refresh_endpoint_config.DefaultChallengeDuration
	DefaultDbscRegisterPath       = dbsc_register_endpoint_config.DefaultPath
	DefaultDbscAlgs               = []string{"ES256"}

	// Zero leaves a session renewable for as long as its authentication lasts, however long it has
	// sat unused. See WithIdleDuration.
	DefaultIdleDuration time.Duration = 0

	DefaultSelectEmailAddressAccount = database.SelectEmailAddressAccount
	DefaultInsertAuthentication      = database.InsertAuthentication
	DefaultInsertDbscChallenge       = database.InsertDbscChallenge
)

type Config struct {
	CookieName                string
	InitialSessionDuration    time.Duration
	AuthenticationDuration    time.Duration
	IdleDuration              time.Duration
	DbscChallengeDuration     time.Duration
	DbscRegisterPath          string
	DbscAlgs                  []string
	SelectEmailAddressAccount func(ctx context.Context, emailAddress string, database *sql.DB) (*accountPkg.Account, error)
	InsertAuthentication      func(ctx context.Context, accountId string, idTokenHash []byte, expirationDuration time.Duration, metadata *authenticationPkg.ClientMetadata, database *sql.DB) (*authenticationPkg.Authentication, error)
	InsertDbscChallenge       func(ctx context.Context, challenge string, authenticationId string, expirationDuration time.Duration, db *sql.DB) error
	SessionCookieOptions      []session_cookie_config.Option
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		CookieName:                DefaultCookieName,
		InitialSessionDuration:    DefaultInitialSessionDuration,
		AuthenticationDuration:    DefaultAuthenticationDuration,
		IdleDuration:              DefaultIdleDuration,
		DbscChallengeDuration:     DefaultDbscChallengeDuration,
		DbscRegisterPath:          DefaultDbscRegisterPath,
		DbscAlgs:                  DefaultDbscAlgs,
		SelectEmailAddressAccount: DefaultSelectEmailAddressAccount,
		InsertAuthentication:      DefaultInsertAuthentication,
		InsertDbscChallenge:       DefaultInsertDbscChallenge,
	}
	for _, option := range options {
		option(config)
	}

	return config
}

func WithCookieName(cookieName string) Option {
	return func(config *Config) {
		config.CookieName = cookieName
	}
}

func WithInitialSessionDuration(initialSessionDuration time.Duration) Option {
	return func(config *Config) {
		config.InitialSessionDuration = initialSessionDuration
	}
}

func WithAuthenticationDuration(authenticationDuration time.Duration) Option {
	return func(config *Config) {
		config.AuthenticationDuration = authenticationDuration
	}
}

// WithIdleDuration bounds how long a session token may have been expired and still be renewed
// from its cookie. The token is renewed for as long as the session is in use, so how long ago it
// expired is how long the session has sat idle; past this, signing in again is the only way back.
// Without it, a cookie copied at any point stays renewable until the authentication expires. Zero
// turns the bound off.
func WithIdleDuration(idleDuration time.Duration) Option {
	return func(config *Config) {
		config.IdleDuration = idleDuration
	}
}

func WithDbscChallengeDuration(dbscChallengeDuration time.Duration) Option {
	return func(config *Config) {
		config.DbscChallengeDuration = dbscChallengeDuration
	}
}

func WithDbscRegisterPath(dbscRegisterPath string) Option {
	return func(config *Config) {
		config.DbscRegisterPath = dbscRegisterPath
	}
}

func WithDbscAlgs(dbscAlgs []string) Option {
	return func(config *Config) {
		config.DbscAlgs = dbscAlgs
	}
}

func WithSelectEmailAddressAccount(selectEmailAddressAccount func(ctx context.Context, emailAddress string, database *sql.DB) (*accountPkg.Account, error)) Option {
	return func(config *Config) {
		config.SelectEmailAddressAccount = selectEmailAddressAccount
	}
}

func WithInsertAuthentication(insertAuthentication func(ctx context.Context, accountId string, idTokenHash []byte, expirationDuration time.Duration, metadata *authenticationPkg.ClientMetadata, database *sql.DB) (*authenticationPkg.Authentication, error)) Option {
	return func(config *Config) {
		config.InsertAuthentication = insertAuthentication
	}
}

func WithInsertDbscChallenge(insertDbscChallenge func(ctx context.Context, challenge string, authenticationId string, expirationDuration time.Duration, db *sql.DB) error) Option {
	return func(config *Config) {
		config.InsertDbscChallenge = insertDbscChallenge
	}
}

func WithSessionCookieOptions(sessionCookieOptions ...session_cookie_config.Option) Option {
	return func(config *Config) {
		config.SessionCookieOptions = sessionCookieOptions
	}
}
