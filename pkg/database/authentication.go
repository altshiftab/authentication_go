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
	authenticationInsertQuery                  = `INSERT INTO authentication (account, created_at, expires_at, id_token_hash, ip_address, ip_address_country, ip_address_city, user_agent) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id;`
	authenticationSelectRefreshQuery           = `SELECT au.ended, au.expires_at, au.created_at, au.dbsc_public_key, a.id, a.email_address, a.locked, c.id, c.name, COALESCE(a.roles, '{}'::text[]) AS roles FROM authentication au JOIN account a ON a.id = au.account LEFT JOIN customer c ON c.id = a.customer WHERE au.id = $1;`
	authenticationUpdateWithDbscPublicKeyQuery = `UPDATE authentication SET dbsc_public_key = $1 WHERE id = $2;`
	authenticationUpdateWithEndedQuery         = `UPDATE authentication SET ended = true, ended_at = now() WHERE id = $1;`
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
	var accountId string
	var emailAddress string
	var locked bool
	var customerId sql.NullString
	var customerName sql.NullString
	var roles []string
	if err := row.Scan(
		&ended, &expiresAt, &createdAt, &dbscPublicKey,
		&accountId, &emailAddress, &locked, &customerId, &customerName,
		postgres.TextArrayScanner{Target: &roles},
	); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql row scan: %w", err))
	}

	account := &accountPkg.Account{Id: accountId, EmailAddress: emailAddress, Locked: locked, Roles: roles}
	if customerId.Valid {
		account.Customer = &customer.Customer{Id: customerId.String, Name: customerName.String}
	}

	return &authenticationPkg.Authentication{
		Id: id, Ended: ended,
		CreatedAt:     &createdAt,
		ExpiresAt:     &expiresAt,
		DbscPublicKey: dbscPublicKey,
		Account:       account,
	}, nil
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

const (
	oauthFlowInsertQuery = `INSERT INTO oauth_flow (state, code_verifier, redirect_url, expires_at) VALUES ($1, $2, $3, $4) RETURNING id;`
	oauthFlowDeleteQuery = `DELETE FROM oauth_flow WHERE id = $1 RETURNING state, code_verifier, expires_at, redirect_url;`
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

	expiresAt := time.Now().Add(expirationDuration)
	row := database.QueryRowContext(ctx, oauthFlowInsertQuery, state, codeVerifier, redirectUrl, expiresAt)
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

const (
	dbscChallengeInsertQuery = `INSERT INTO dbsc_challenge (challenge, authentication, expires_at) VALUES ($1, $2, $3);`
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

	expiresAt := time.Now().Add(expirationDuration)
	if _, err := db.ExecContext(ctx, dbscChallengeInsertQuery, []byte(challenge), authenticationId, expiresAt); err != nil {
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
