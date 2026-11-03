// Package api_key_cruder reads and writes the keys an account registers, and records what they
// mint with.
//
// The account's own queries carry `account = $n` with the argument taken from the session token:
// listing, registering and revoking are things an account does to its own keys, and there is no
// query here that can be asked about another's.
//
// Minting is not one of those. It arrives with no session at all -- the assertion is the whole
// credential -- so its queries are keyed by the key's own id, and what they answer with is what the
// endpoint then checks: whether the key is revoked, whether it has expired, and whose account it
// belongs to.
package api_key_cruder

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/altshiftab/authentication_go/pkg/api_key/assertion"
	"github.com/altshiftab/authentication_go/pkg/api_key/public_key"
	apiKeyTypes "github.com/altshiftab/authentication_go/pkg/api_key/types"
	accountPkg "github.com/altshiftab/authentication_go/pkg/database/types/account"
	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	customerPkg "github.com/altshiftab/authentication_go/pkg/database/types/customer"
	altshiftContext "github.com/altshiftab/utils_go/pkg/context"
	"github.com/altshiftab/utils_go/pkg/database/sql/postgres"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
)

// ErrAssertionAlreadyUsed says an assertion has been presented before: the identifier it carries is
// already stored against its key, which is what a replay looks like from here.
var ErrAssertionAlreadyUsed = errors.New("the assertion has already been used")

// ErrKeyRevoked says the key was revoked by the time its mint was recorded, after the caller read it.
var ErrKeyRevoked = errors.New("the key has been revoked")

/*
 * AuthenticationLifetime is how long the sign-in row a key mints under is kept alive, extended at
 * every mint.
 *
 * It is not the token's lifetime, which is minutes. The row stands for "this key is in use", so
 * that a client minting every quarter of an hour appears in the account's activity as one entry
 * rather than as ninety-six a day -- with the list capped at fifty, the second shape would push
 * every browser sign-in off the end within a day, which is the opposite of what the page is for.
 *
 * A generous window is not a widening: what a mint is allowed to do is decided by the key's
 * revocation and expiry, both checked at every mint, and the token it produces is short regardless.
 */
const AuthenticationLifetime = 30 * 24 * time.Hour

/*
 * AssertionRetention is how long a spent assertion's identifier is kept, counted from when it
 * arrived.
 *
 * From the server's clock rather than from the "exp" the assertion carried, which is the only way
 * the record is certain to outlive the assertion: a client's "exp" decides whether an assertion is
 * still presentable, and an assertion accepted at the near edge of Leeway carries one that has
 * already passed. Stored under that, the row would be swept by the very statement below that tidies
 * up after it, and the assertion could be presented again for as long as it remained acceptable.
 *
 * The "exp" of an assertion arriving now may sit as far out as Lifetime and Leeway together, and the
 * assertion stays acceptable for a further Leeway past it -- hence Leeway twice.
 *
 * Derived from the window rather than written down, so that lengthening how long an assertion may
 * be presented for cannot quietly leave it remembered for less.
 */
const AssertionRetention = assertion.Lifetime + 2*assertion.Leeway

// gosec reads the name and takes anything called a key for a credential. What is selected here is
// the opposite: the columns of a key row that are not the key material.
//
//nolint:gosec // G101: a SELECT over public columns, not a credential.
const apiKeySelectBase = `
	SELECT id, name, algorithm, created_at, expires_at, last_used_at, revoked_at
	FROM api_key`

type Cruder struct {
	Database *sql.DB
}

// Key is a registered key as the mint path needs it: enough to verify a signature and to decide
// whether the key may still be used at all.
type Key struct {
	Id        string
	Name      string
	Algorithm string
	PublicKey []byte
	AccountId string

	ExpiresAt *time.Time
	RevokedAt *time.Time
}

// Revoked says the key has been taken out of use, whatever else is true of it.
func (k *Key) Revoked() bool {
	return k != nil && k.RevokedAt != nil
}

// Expired says the key has passed the date it was registered with, if it was given one.
func (k *Key) Expired(now time.Time) bool {
	return k != nil && k.ExpiresAt != nil && !now.Before(*k.ExpiresAt)
}

func apiKeyFromRow(row interface{ Scan(...any) error }) (*apiKeyTypes.ApiKey, error) {
	var key apiKeyTypes.ApiKey
	err := row.Scan(
		&key.Id,
		&key.Name,
		&key.Algorithm,
		&key.CreatedAt,
		&key.ExpiresAt,
		&key.LastUsedAt,
		&key.RevokedAt,
	)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("row scan: %w", err))
	}

	return &key, nil
}

// Create registers a key to an account.
//
// The thumbprint is the primary key, so registering a key that is already registered -- to this
// account or to any other, revoked or not -- is a unique violation rather than a second row.
func (c *Cruder) Create(
	ctx context.Context,
	accountId string,
	key *public_key.Key,
	name string,
	expiresAt *time.Time,
) (*apiKeyTypes.ApiKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if c.Database == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql database"))
	}

	if accountId == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("account id"))
	}

	if key == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("key"))
	}

	if name == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("name"))
	}

	row := c.Database.QueryRowContext(
		ctx,
		`INSERT INTO api_key (id, account, name, algorithm, public_key, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, name, algorithm, created_at, expires_at, last_used_at, revoked_at;`,
		key.Id,
		accountId,
		name,
		key.Algorithm,
		key.Der,
		expiresAt,
	)
	if row == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql row"))
	}

	created, err := apiKeyFromRow(row)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: the key is already registered", altshiftErrors.ErrValidationError),
			)
		}
		return nil, altshiftErrors.New(fmt.Errorf("api key from row: %w", err), key.Id)
	}

	return created, nil
}

func isUniqueViolation(err error) bool {
	sqlState, ok := postgres.SqlState(err)
	return ok && sqlState == postgres.SqlStateUniqueViolation
}

// ReadBulkForAccount lists an account's keys, newest first, revoked ones included: a key that was
// revoked is part of what the account should see of its own history.
func (c *Cruder) ReadBulkForAccount(ctx context.Context, accountId string) ([]*apiKeyTypes.ApiKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if c.Database == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql database"))
	}

	if accountId == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("account id"))
	}

	rows, err := c.Database.QueryContext(
		ctx,
		apiKeySelectBase+` WHERE account = $1 ORDER BY created_at DESC;`,
		accountId,
	)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql query context: %w", err), accountId)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.WarnContext(
				altshiftContext.WithError(
					ctx,
					altshiftErrors.NewWithTrace(fmt.Errorf("rows close: %w", err), rows),
				),
				"An error occurred when closing the rows.",
			)
		}
	}()

	var keys []*apiKeyTypes.ApiKey
	for rows.Next() {
		key, err := apiKeyFromRow(rows)
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("api key from row: %w", err), rows)
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql rows err: %w", err))
	}

	return keys, nil
}

/*
 * RevokeForAccount takes a key out of use and ends what it minted, in one transaction.
 *
 * Both halves, because either alone leaves the account half revoked: the key with its sign-ins
 * still live would let the tokens already minted go on being renewed, and the sign-ins ended with
 * the key still registered would let the next mint make new ones.
 *
 * A key that is not this account's, one that does not exist, and one already revoked are all
 * sql.ErrNoRows, so the caller cannot learn from here that somebody else's key id is real.
 */
func (c *Cruder) RevokeForAccount(ctx context.Context, accountId string, keyId string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context err: %w", err)
	}

	if c.Database == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("sql database"))
	}

	if accountId == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("account id"))
	}

	if keyId == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("key id"))
	}

	transaction, err := c.Database.BeginTx(ctx, nil)
	if err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("sql begin tx: %w", err))
	}
	defer func() {
		if err := transaction.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.WarnContext(
				altshiftContext.WithError(
					ctx,
					altshiftErrors.NewWithTrace(fmt.Errorf("tx rollback: %w", err)),
				),
				"An error occurred when rolling back the transaction.",
			)
		}
	}()

	row := transaction.QueryRowContext(
		ctx,
		`UPDATE api_key SET revoked_at = now()
		 WHERE id = $1 AND account = $2 AND revoked_at IS NULL
		 RETURNING id;`,
		keyId,
		accountId,
	)
	if row == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("sql row"))
	}

	var revokedId string
	if err := row.Scan(&revokedId); err != nil {
		return err
	}

	if _, err := transaction.ExecContext(
		ctx,
		`UPDATE authentication SET ended = true, ended_at = now()
		 WHERE NOT ended AND id IN (
		     SELECT authentication FROM api_key_authentication WHERE api_key = $1
		 );`,
		keyId,
	); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("sql exec context (end authentications): %w", err))
	}

	if err := transaction.Commit(); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("tx commit: %w", err))
	}

	return nil
}

// SelectForMint reads a key by its own id, which is all a mint request names.
//
// Nothing is decided here: a revoked or expired key comes back as it is, and the endpoint answers
// for it. What the caller must not do is read the account before verifying the signature.
func (c *Cruder) SelectForMint(ctx context.Context, keyId string) (*Key, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if c.Database == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql database"))
	}

	if keyId == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("key id"))
	}

	row := c.Database.QueryRowContext(
		ctx,
		`SELECT id, name, algorithm, public_key, account, expires_at, revoked_at
		 FROM api_key WHERE id = $1;`,
		keyId,
	)
	if row == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql row"))
	}

	var key Key
	err := row.Scan(
		&key.Id,
		&key.Name,
		&key.Algorithm,
		&key.PublicKey,
		&key.AccountId,
		&key.ExpiresAt,
		&key.RevokedAt,
	)
	if err != nil {
		// sql.ErrNoRows passes up as it stands: an assertion naming a key nobody registered is
		// answered the same way as one whose signature does not check out.
		return nil, err
	}

	return &key, nil
}

/*
 * RecordMint remembers the assertion, keeps the key's sign-in alive, and returns that sign-in with
 * the account it belongs to, ready for a token to be minted from.
 *
 * One transaction, and the order matters. The key's row is locked first and its revocation read
 * again: the caller read the key before verifying the assertion, and a revoke committed since must
 * not be followed by a sign-in made for the key it revoked, while one arriving after waits for this
 * transaction and ends the sign-in it leaves. The assertion is stored next, so that a replay fails
 * before anything else is touched; the sign-in is then reused where there is a live one for this
 * key, and made where there is not, which is what keeps one key to one entry in the account's
 * activity however often it mints.
 *
 * How long the assertion is remembered for is counted here, by the database's own clock, and both
 * statements below read it within the one transaction -- so the row that was just written cannot be
 * swept by the sweep that follows it, whatever a client's clock or a client's "exp" had to say.
 */
func (c *Cruder) RecordMint(
	ctx context.Context,
	key *Key,
	jti string,
	metadata *authenticationPkg.ClientMetadata,
) (*authenticationPkg.Authentication, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context err: %w", err)
	}

	if c.Database == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql database"))
	}

	if key == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("key"))
	}

	if jti == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("jti"))
	}

	transaction, err := c.Database.BeginTx(ctx, nil)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql begin tx: %w", err))
	}
	defer func() {
		if err := transaction.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.WarnContext(
				altshiftContext.WithError(
					ctx,
					altshiftErrors.NewWithTrace(fmt.Errorf("tx rollback: %w", err)),
				),
				"An error occurred when rolling back the transaction.",
			)
		}
	}()

	// FOR UPDATE rather than FOR SHARE: the transaction updates the row further down, and two mints
	// of one key each holding a share lock would deadlock upgrading it.
	lockRow := transaction.QueryRowContext(ctx, `SELECT revoked_at FROM api_key WHERE id = $1 FOR UPDATE;`, key.Id)
	if lockRow == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql row"))
	}

	var revokedAt *time.Time
	if err := lockRow.Scan(&revokedAt); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql row scan (lock key): %w", err), key.Id)
	}
	if revokedAt != nil {
		return nil, ErrKeyRevoked
	}

	if _, err := transaction.ExecContext(
		ctx,
		`INSERT INTO api_key_assertion (api_key, jti, expires_at) VALUES ($1, $2, now() + $3::interval);`,
		key.Id,
		jti,
		fmt.Sprintf("%d seconds", int64(AssertionRetention.Seconds())),
	); err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("%w: %w", ErrAssertionAlreadyUsed, err)
		}
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql exec context (insert assertion): %w", err))
	}

	// The spent ones this key left behind. As with challenges, the next use tidies up after the
	// last rather than a job doing the rounds.
	if _, err := transaction.ExecContext(
		ctx,
		`DELETE FROM api_key_assertion WHERE api_key = $1 AND expires_at <= now();`,
		key.Id,
	); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql exec context (delete expired assertions): %w", err))
	}

	expiresAt := time.Now().Add(AuthenticationLifetime)

	row := transaction.QueryRowContext(
		ctx,
		`UPDATE authentication SET expires_at = $2
		 WHERE NOT ended AND expires_at > now() AND id IN (
		     SELECT authentication FROM api_key_authentication WHERE api_key = $1
		 )
		 RETURNING id, created_at;`,
		key.Id,
		expiresAt,
	)
	if row == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql row"))
	}

	var authenticationId string
	var createdAt *time.Time

	switch err := row.Scan(&authenticationId, &createdAt); {
	case err == nil:
	case errors.Is(err, sql.ErrNoRows):
		authenticationId, createdAt, err = insertAuthenticationForKey(ctx, transaction, key, expiresAt, metadata)
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("insert authentication for key: %w", err), key.Id)
		}
	default:
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql row scan (authentication): %w", err))
	}

	if _, err := transaction.ExecContext(
		ctx,
		`UPDATE api_key SET last_used_at = now() WHERE id = $1;`,
		key.Id,
	); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql exec context (last used at): %w", err))
	}

	account, err := selectAccount(ctx, transaction, key.AccountId)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("select account: %w", err), key.AccountId)
	}

	if err := transaction.Commit(); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("tx commit: %w", err))
	}

	return &authenticationPkg.Authentication{
		Id:        authenticationId,
		Account:   account,
		CreatedAt: createdAt,
		ExpiresAt: &expiresAt,
	}, nil
}

func insertAuthenticationForKey(
	ctx context.Context,
	transaction *sql.Tx,
	key *Key,
	expiresAt time.Time,
	metadata *authenticationPkg.ClientMetadata,
) (string, *time.Time, error) {
	now := time.Now()

	// The columns are nullable and ip_address is an inet, which refuses the empty string: what is
	// not known is stored as NULL rather than failing the insert, as InsertAuthentication does.
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

	row := transaction.QueryRowContext(
		ctx,
		`INSERT INTO authentication
		     (account, created_at, expires_at, ip_address, ip_address_country, ip_address_city, user_agent)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING id, created_at;`,
		key.AccountId,
		now,
		expiresAt,
		ipAddressArg,
		ipAddressCountryArg,
		ipAddressCityArg,
		userAgentArg,
	)
	if row == nil {
		return "", nil, altshiftErrors.NewWithTrace(nil_error.New("sql row"))
	}

	var authenticationId string
	var createdAt *time.Time
	if err := row.Scan(&authenticationId, &createdAt); err != nil {
		return "", nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql row scan: %w", err))
	}

	if _, err := transaction.ExecContext(
		ctx,
		`INSERT INTO api_key_authentication (authentication, api_key) VALUES ($1, $2);`,
		authenticationId,
		key.Id,
	); err != nil {
		return "", nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql exec context (link): %w", err))
	}

	return authenticationId, createdAt, nil
}

// The account a token is minted for, with what the claims need: the address it is addressed to, the
// roles it carries and the organisation it belongs to.
func selectAccount(ctx context.Context, transaction *sql.Tx, accountId string) (*accountPkg.Account, error) {
	row := transaction.QueryRowContext(
		ctx,
		`SELECT a.id, a.email_address, a.locked, c.id, c.name, COALESCE(a.roles, '{}'::text[])
		 FROM account a LEFT JOIN customer c ON c.id = a.customer
		 WHERE a.id = $1;`,
		accountId,
	)
	if row == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql row"))
	}

	var account accountPkg.Account
	var customerId sql.NullString
	var customerName sql.NullString
	var roles []string

	err := row.Scan(
		&account.Id,
		&account.EmailAddress,
		&account.Locked,
		&customerId,
		&customerName,
		postgres.TextArrayScanner{Target: &roles},
	)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql row scan: %w", err))
	}

	account.Roles = roles
	if customerId.Valid {
		account.Customer = &customerPkg.Customer{Id: customerId.String, Name: customerName.String}
	}

	return &account, nil
}
