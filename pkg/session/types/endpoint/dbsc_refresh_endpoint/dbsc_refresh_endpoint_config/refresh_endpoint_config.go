package dbsc_refresh_endpoint_config

import (
	"context"
	"database/sql"
	"time"

	"github.com/altshiftab/authentication_go/pkg/database"
	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	"github.com/altshiftab/authentication_go/pkg/session"
)

var (
	DefaultPath = "/api/session/dbsc/refresh"
	// The same fifteen minutes as an ordinary session: revocation is only enforced when a session
	// is refreshed, so this is how long a revoked session stays usable, and binding it to a device
	// does not change that.
	//
	// Keep this comfortably above two minutes. The browser does not wait for the bound cookie to
	// expire before refreshing: it refreshes once the cookie has two minutes or less remaining, per
	// kProactiveRefreshThreshold in Chromium's net/device_bound_sessions/session_service_impl.cc:
	//
	//	constexpr base::TimeDelta kProactiveRefreshThreshold = base::Seconds(120);
	//	if (minimum_cookie_lifetime > kProactiveRefreshThreshold) { return; }
	//
	// A duration at or below that leaves every request inside the window, so the browser refreshes
	// on essentially every request. Observed against Chrome 151: a three minute session refreshed
	// every ~65 seconds, a five minute session not at all within seventy seconds, and a thirty
	// second session on every request.
	DefaultSessionDuration             = 15 * time.Minute
	DefaultChallengeDuration           = 5 * time.Minute
	DefaultInsertDbscChallenge         = database.InsertDbscChallenge
	DefaultSelectRefreshAuthentication = database.SelectRefreshAuthentication
	DefaultGenerateDbscChallenge       = session.GenerateDbscChallenge
)

type Config struct {
	Path                        string
	SessionDuration             time.Duration
	ChallengeDuration           time.Duration
	InsertDbscChallenge         func(ctx context.Context, challenge string, authenticationId string, challengeDuration time.Duration, db *sql.DB) error
	SelectRefreshAuthentication func(ctx context.Context, id string, database *sql.DB) (*authenticationPkg.Authentication, error)
	GenerateDbscChallenge       func() (string, error)
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		Path:                        DefaultPath,
		SessionDuration:             DefaultSessionDuration,
		ChallengeDuration:           DefaultChallengeDuration,
		InsertDbscChallenge:         DefaultInsertDbscChallenge,
		SelectRefreshAuthentication: DefaultSelectRefreshAuthentication,
		GenerateDbscChallenge:       DefaultGenerateDbscChallenge,
	}
	for _, option := range options {
		option(config)
	}

	return config
}

func WithPath(path string) Option {
	return func(config *Config) {
		config.Path = path
	}
}

func WithSessionDuration(sessionDuration time.Duration) Option {
	return func(config *Config) {
		config.SessionDuration = sessionDuration
	}
}

func WithChallengeDuration(challengeDuration time.Duration) Option {
	return func(config *Config) {
		config.ChallengeDuration = challengeDuration
	}
}

func WithInsertDbscChallenge(
	insertDbscChallenge func(ctx context.Context, challenge string, authenticationId string, challengeDuration time.Duration, db *sql.DB) error,
) Option {
	return func(config *Config) {
		config.InsertDbscChallenge = insertDbscChallenge
	}
}

func WithSelectRefreshAuthentication(
	selectRefreshAuthentication func(ctx context.Context, id string, database *sql.DB) (*authenticationPkg.Authentication, error),
) Option {
	return func(config *Config) {
		config.SelectRefreshAuthentication = selectRefreshAuthentication
	}
}

func WithGenerateDbscChallenge(generateDbscChallenge func() (string, error)) Option {
	return func(config *Config) {
		config.GenerateDbscChallenge = generateDbscChallenge
	}
}
