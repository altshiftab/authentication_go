package database

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strings"
	"time"

	databaseErrors "github.com/altshiftab/authentication_go/pkg/database/errors"
	accountPkg "github.com/altshiftab/authentication_go/pkg/database/types/account"
	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	"github.com/altshiftab/authentication_go/pkg/database/types/customer"
	"github.com/altshiftab/authentication_go/pkg/database/types/dbsc_challenge"
	"github.com/altshiftab/authentication_go/pkg/database/types/oauth_flow"
	"github.com/altshiftab/utils_go/pkg/database/sql/postgres"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
)

// isIdTokenUniqueViolation reports whether err is a unique violation of the id token hash
// constraint. The constraint name only appears in the error message, not in any accessor.
func isIdTokenUniqueViolation(err error) bool {
	sqlState, ok := postgres.SqlState(err)
	return ok && sqlState == postgres.SqlStateUniqueViolation && strings.Contains(err.Error(), "id_token_hash")
}

const (
	authenticationInsertQuery        = `INSERT INTO authentication (account, created_at, expires_at, id_token_hash, ip_address, ip_address_country, ip_address_city, user_agent) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id;`
	authenticationSelectRefreshQuery = `SELECT au.ended, au.expires_at, au.created_at, au.dbsc_public_key, au.session_expires_at, a.id, a.email_address, a.locked, c.id, c.name, COALESCE(a.roles, '{}'::text[]) AS roles FROM authentication au JOIN account a ON a.id = au.account LEFT JOIN customer c ON c.id = a.customer WHERE au.id = $1;`
	// The key is written only where none is: a session bound to one device is never moved to another.
	authenticationUpdateWithDbscPublicKeyQuery       = `UPDATE authentication SET dbsc_public_key = $1 WHERE id = $2 AND dbsc_public_key IS NULL;`
	authenticationSelectDbscPublicKeyRegisteredQuery = `SELECT dbsc_public_key IS NOT NULL FROM authentication WHERE id = $1;`
	authenticationUpdateWithEndedQuery               = `UPDATE authentication SET ended = true, ended_at = now() WHERE id = $1;`
	authenticationUpdateWithSessionExpiresAtQuery    = `UPDATE authentication SET session_expires_at = $1 WHERE id = $2;`
	authenticationSelectIdTokenHashUsedQuery         = `SELECT EXISTS (SELECT 1 FROM authentication WHERE id_token_hash = $1);` //nolint:gosec // A query naming a column, not a credential.
)

func InsertAuthentication(
	ctx context.Context,
	accountId string,
	idTokenHash []byte,
	expirationDuration time.Duration,
	metadata *authenticationPkg.ClientMetadata,
	database *sql.DB,
) (*authenticationPkg.Authentication, error) {
	if accountId == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("account id"))
	}

	if database == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql database"))
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(expirationDuration)

	var idTokenHashArg any
	if len(idTokenHash) > 0 {
		idTokenHashArg = idTokenHash
	}

	// The columns are nullable and ip_address is an inet, which rejects the empty
	// string; store NULL when a value is absent (or, for the IP, not a valid
	// address) rather than failing the insert.
	var ipAddressArg any
	var ipAddressCountryArg any
	var ipAddressCityArg any
	var userAgentArg any
	if metadata != nil {
		if metadata.IpAddress != "" && net.ParseIP(metadata.IpAddress) != nil {
			ipAddressArg = metadata.IpAddress
		}
		if metadata.IpAddressCountry != "" {
			ipAddressCountryArg = metadata.IpAddressCountry
		}
		if metadata.IpAddressCity != "" {
			ipAddressCityArg = metadata.IpAddressCity
		}
		if metadata.UserAgent != "" {
			userAgentArg = metadata.UserAgent
		}
	}

	row := database.QueryRowContext(
		ctx,
		authenticationInsertQuery,
		accountId,
		now,
		expiresAt,
		idTokenHashArg,
		ipAddressArg,
		ipAddressCountryArg,
		ipAddressCityArg,
		userAgentArg,
	)
	if row == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql row"))
	}

	var authenticationId string
	if err := row.Scan(&authenticationId); err != nil {
		if isIdTokenUniqueViolation(err) {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: %w", databaseErrors.ErrIdTokenAlreadyUsed, err))
		}
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql row scan: %w", err))
	}

	authentication := &authenticationPkg.Authentication{
		Id:          authenticationId,
		CreatedAt:   &now,
		ExpiresAt:   &expiresAt,
		IdTokenHash: idTokenHash,
	}
	if metadata != nil {
		if ipAddressArg != nil {
			authentication.IpAddress = metadata.IpAddress
		}
		authentication.IpAddressCountry = metadata.IpAddressCountry
		authentication.IpAddressCity = metadata.IpAddressCity
		authentication.UserAgent = metadata.UserAgent
	}

	return authentication, nil
}

// SelectIdTokenHashUsed reports whether an authentication was already created from the token the hash
// names, which is what InsertAuthentication refuses a second time.
func SelectIdTokenHashUsed(ctx context.Context, idTokenHash []byte, database *sql.DB) (bool, error) {
	if len(idTokenHash) == 0 {
		return false, altshiftErrors.NewWithTrace(empty_error.New("id token hash"))
	}

	if database == nil {
		return false, altshiftErrors.NewWithTrace(nil_error.New("sql database"))
	}

	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("context err: %w", err)
	}

	row := database.QueryRowContext(ctx, authenticationSelectIdTokenHashUsedQuery, idTokenHash)
	if row == nil {
		return false, altshiftErrors.NewWithTrace(nil_error.New("sql row"))
	}

	var used bool
	if err := row.Scan(&used); err != nil {
		return false, altshiftErrors.NewWithTrace(fmt.Errorf("sql row scan: %w", err))
	}

	return used, nil
}

func SelectRefreshAuthentication(ctx context.Context, id string, database *sql.DB) (*authenticationPkg.Authentication, error) {
	if id == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("authentication id"))
	}

	if database == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql database"))
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	row := database.QueryRowContext(ctx, authenticationSelectRefreshQuery, id)
	if row == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql row"))
	}

	// The account identity is selected too, so that a session can be minted from the
	// authentication alone. A DBSC refresh arrives without the session cookie, so there is no
	// existing token to derive the new one from.
	var ended bool
	var expiresAt time.Time
	var createdAt time.Time
	var dbscPublicKey []byte
	var sessionExpiresAt sql.NullTime
	var accountId string
	var emailAddress string
	var locked bool
	var customerId sql.NullString
	var customerName sql.NullString
	var roles []string
	if err := row.Scan(
		&ended, &expiresAt, &createdAt, &dbscPublicKey, &sessionExpiresAt,
		&accountId, &emailAddress, &locked, &customerId, &customerName,
		postgres.TextArrayScanner{Target: &roles},
	); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql row scan: %w", err))
	}

	account := &accountPkg.Account{Id: accountId, EmailAddress: emailAddress, Locked: locked, Roles: roles}
	if customerId.Valid {
		account.Customer = &customer.Customer{Id: customerId.String, Name: customerName.String}
	}

	authentication := &authenticationPkg.Authentication{
		Id: id, Ended: ended,
		CreatedAt:     &createdAt,
		ExpiresAt:     &expiresAt,
		DbscPublicKey: dbscPublicKey,
		Account:       account,
	}
	if sessionExpiresAt.Valid {
		authentication.SessionExpiresAt = &sessionExpiresAt.Time
	}

	return authentication, nil
}

func SelectEmailAddressAccount(ctx context.Context, emailAddress string, database *sql.DB) (*accountPkg.Account, error) {
	if emailAddress == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("email address"))
	}

	if database == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql database"))
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	var (
		accountId    string
		locked       bool
		customerId   sql.NullString
		customerName sql.NullString
		roles        []string
	)

	row := database.QueryRowContext(
		ctx,
		`SELECT a.id, a.locked, c.id, c.name, COALESCE(a.roles, '{}'::text[]) AS roles FROM account a LEFT JOIN customer c ON c.id = a.customer WHERE a.email_address = $1;`,
		emailAddress,
	)
	if row == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql row"))
	}

	if err := row.Scan(&accountId, &locked, &customerId, &customerName, postgres.TextArrayScanner{Target: &roles}); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql row scan: %w", err))
	}

	account := &accountPkg.Account{Id: accountId, EmailAddress: emailAddress, Locked: locked, Roles: roles}
	if customerId.Valid {
		account.Customer = &customer.Customer{Id: customerId.String, Name: customerName.String}
	}

	return account, nil
}

// UpdateAuthenticationWithDbscPublicKey registers the device key a DBSC session is bound to. A key is
// registered once. Registration is authenticated by the session cookie alone, so replacing a key would
// let whoever holds a copy of the cookie move the session to a device of their own and lock the
// browser it belongs to out of its refreshes; a second registration is refused with
// ErrDbscPublicKeyRegistered instead, and sql.ErrNoRows says there is no such authentication.
func UpdateAuthenticationWithDbscPublicKey(ctx context.Context, id string, key []byte, database *sql.DB) error {
	if id == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("authentication id"))
	}

	if len(key) == 0 {
		return altshiftErrors.NewWithTrace(empty_error.New("dbsc public key"))
	}

	if database == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("sql database"))
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context err: %w", err)
	}

	result, err := database.ExecContext(ctx, authenticationUpdateWithDbscPublicKeyQuery, key, id)
	if err != nil {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf("sql database exec context: %w", err),
		)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf("sql database rows affected: %w", err),
			result,
		)
	}

	if rowsAffected != 0 {
		return nil
	}

	// Nothing was written, which the update alone cannot explain: asked after it, so that the refusal
	// stays the update's and this only says what it refused.
	row := database.QueryRowContext(ctx, authenticationSelectDbscPublicKeyRegisteredQuery, id)
	if row == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("sql row"))
	}

	var registered bool
	if err := row.Scan(&registered); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("sql row scan: %w", err))
	}
	if registered {
		return altshiftErrors.NewWithTrace(databaseErrors.ErrDbscPublicKeyRegistered)
	}

	return altshiftErrors.NewWithTrace(sql.ErrNoRows)
}

// UpdateAuthenticationWithSessionExpiresAt records when the session token a device bound session was
// just given expires, which its next refresh measures its idleness against.
func UpdateAuthenticationWithSessionExpiresAt(ctx context.Context, id string, sessionExpiresAt time.Time, database *sql.DB) error {
	if id == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("authentication id"))
	}

	if sessionExpiresAt.IsZero() {
		return altshiftErrors.NewWithTrace(empty_error.New("session expires at"))
	}

	if database == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("sql database"))
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context err: %w", err)
	}

	result, err := database.ExecContext(ctx, authenticationUpdateWithSessionExpiresAtQuery, sessionExpiresAt, id)
	if err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("sql database exec context: %w", err), sessionExpiresAt)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("sql database rows affected: %w", err), result)
	}

	if rowsAffected == 0 {
		return altshiftErrors.NewWithTrace(sql.ErrNoRows)
	}

	return nil
}

func UpdateAuthenticationWithEnded(ctx context.Context, id string, database *sql.DB) error {
	if id == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("authentication id"))
	}

	if database == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("sql database"))
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context err: %w", err)
	}

	result, err := database.ExecContext(ctx, authenticationUpdateWithEndedQuery, id)
	if err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("sql database exec: %w", err))
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("sql database rows affected: %w", err), result)
	}

	if rowsAffected == 0 {
		return altshiftErrors.NewWithTrace(sql.ErrNoRows)
	}

	return nil
}

// expiredOauthFlowRetention is how long a flow is kept after it expires. A callback that arrives after
// its flow expired restarts the sign-in from the flow its state names (PopExpiredOauthFlowByState),
// so expired flows are kept for a browser coming back late; past this, the callback is refused and
// the sign-in is begun again by hand. The flows a callback never completed are also the only record
// of when a failed sign-in began, since successful requests are not logged, so they are kept long
// enough for the nightly database dumps to hold them.
const expiredOauthFlowRetention = 30 * 24 * time.Hour

const (
	// Every flow begun removes those expired longer ago than expiredOauthFlowRetention, so that the
	// table holds only what began within about that time: a flow is begun by anyone who asks, and is
	// otherwise removed only by a callback that completes it.
	oauthFlowInsertQuery = `WITH purged AS (DELETE FROM oauth_flow WHERE expires_at <= $5) INSERT INTO oauth_flow (state, code_verifier, redirect_url, expires_at) VALUES ($1, $2, $3, $4) RETURNING id;`
	oauthFlowDeleteQuery = `DELETE FROM oauth_flow WHERE id = $1 RETURNING state, code_verifier, expires_at, redirect_url;`
	// The expiry is in the statement, not checked after it, so that a live flow is never removed by
	// its state alone.
	oauthFlowDeleteExpiredByStateQuery = `DELETE FROM oauth_flow WHERE state = $1 AND expires_at <= $2 RETURNING id, expires_at, redirect_url;`
)

func InsertOauthFlow(
	ctx context.Context,
	state string,
	codeVerifier string,
	redirectUrl string,
	expirationDuration time.Duration,
	database *sql.DB,
) (*oauth_flow.Flow, error) {
	if state == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("state"))
	}

	if codeVerifier == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("code verifier"))
	}

	// TODO: Use empty instance error?
	if redirectUrl == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("redirect url"))
	}

	if expirationDuration == 0 {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("expiration duration"))
	}

	if database == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql database"))
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(expirationDuration)
	row := database.QueryRowContext(
		ctx,
		oauthFlowInsertQuery,
		state, codeVerifier, redirectUrl, expiresAt,
		now.Add(-expiredOauthFlowRetention),
	)
	if row == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql row"))
	}

	var id string
	if err := row.Scan(&id); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql row scan: %w", err), row)
	}

	return &oauth_flow.Flow{
		Id:           id,
		State:        state,
		CodeVerifier: codeVerifier,
		RedirectUrl:  redirectUrl,
		ExpiresAt:    &expiresAt,
	}, nil
}

func PopOauthFlow(ctx context.Context, id string, db *sql.DB) (*oauth_flow.Flow, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if id == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("oauth flow id"))
	}

	if db == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql db"))
	}

	var flow oauth_flow.Flow

	row := db.QueryRowContext(ctx, oauthFlowDeleteQuery, id)
	if row == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql row"))
	}

	if err := row.Scan(&flow.State, &flow.CodeVerifier, &flow.ExpiresAt, &flow.RedirectUrl); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql row scan: %w", err))
	}

	return &flow, nil
}

// PopExpiredOauthFlowByState removes and returns the flow the state names if it expired by now; a
// live flow is neither removed nor returned. The code verifier is not returned: what is popped this
// way is never redeemed.
func PopExpiredOauthFlowByState(ctx context.Context, state string, now time.Time, db *sql.DB) (*oauth_flow.Flow, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if state == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("state"))
	}

	if db == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql db"))
	}

	flow := oauth_flow.Flow{State: state}

	row := db.QueryRowContext(ctx, oauthFlowDeleteExpiredByStateQuery, state, now)
	if row == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql row"))
	}

	if err := row.Scan(&flow.Id, &flow.ExpiresAt, &flow.RedirectUrl); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql row scan: %w", err))
	}

	return &flow, nil
}

const (
	// Every challenge issued removes those that have expired, which no proof can redeem: a challenge is
	// otherwise removed only by the proof that redeems it, and a browser signs only the last one it
	// was given.
	dbscChallengeInsertQuery = `WITH purged AS (DELETE FROM dbsc_challenge WHERE expires_at <= $4) INSERT INTO dbsc_challenge (challenge, authentication, expires_at) VALUES ($1, $2, $3);`
	dbscChallengeDeleteQuery = `DELETE FROM dbsc_challenge WHERE challenge = $1 AND authentication = $2 RETURNING expires_at;`
)

func InsertDbscChallenge(
	ctx context.Context,
	challenge string,
	authenticationId string,
	expirationDuration time.Duration,
	db *sql.DB,
) error {
	if challenge == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("dbsc challenge"))
	}

	if authenticationId == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("authentication id"))
	}

	if expirationDuration == 0 {
		return altshiftErrors.NewWithTrace(empty_error.New("expiration duration"))
	}

	if db == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("sql db"))
	}

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context err: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(expirationDuration)
	if _, err := db.ExecContext(ctx, dbscChallengeInsertQuery, []byte(challenge), authenticationId, expiresAt, now); err != nil {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf("sql db exec context: %w", err),
			expiresAt,
		)
	}

	return nil
}

func PopDbscChallenge(ctx context.Context, challenge string, authenticationId string, db *sql.DB) (*dbsc_challenge.Challenge, error) {
	if challenge == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("challenge"))
	}

	if authenticationId == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("authentication id"))
	}

	if db == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql db"))
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	var expiresAt time.Time

	row := db.QueryRowContext(ctx, dbscChallengeDeleteQuery, challenge, authenticationId)
	if row == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql row"))
	}

	if err := row.Scan(&expiresAt); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql row scan: %w", err))
	}

	return &dbsc_challenge.Challenge{
		Authentication: &authenticationPkg.Authentication{Id: authenticationId},
		Challenge:      []byte(challenge),
		ExpiresAt:      &expiresAt,
	}, nil
}
