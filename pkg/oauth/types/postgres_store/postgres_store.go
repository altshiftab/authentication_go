// Package postgres_store keeps what the OAuth authorization server hands out in the tables of
// database/types/oauth_authorization, alongside the service's accounts.
package postgres_store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/altshiftab/authentication_go/pkg/oauth"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
)

const (
	deleteExpiredRequestsQuery = `DELETE FROM oauth_authorization_request WHERE expires_at < now();`
	insertRequestQuery         = `INSERT INTO oauth_authorization_request (account, client_id, client_name, redirect_uri, state, code_challenge, resource, scope, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id;`
	popRequestQuery            = `DELETE FROM oauth_authorization_request WHERE id = $1 RETURNING account, client_id, client_name, redirect_uri, state, code_challenge, resource, scope, expires_at;`

	deleteExpiredCodesQuery = `DELETE FROM oauth_authorization_code WHERE expires_at < now();`
	insertCodeQuery         = `INSERT INTO oauth_authorization_code (code_hash, account, client_id, redirect_uri, code_challenge, resource, scope, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8);`
	popCodeQuery            = `DELETE FROM oauth_authorization_code WHERE code_hash = $1 RETURNING account, client_id, redirect_uri, code_challenge, resource, scope, expires_at;`

	insertGrantQuery        = `INSERT INTO oauth_grant (account, client_id, resource, scope, key_thumbprint, created_at) VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6) RETURNING id;`
	insertRefreshTokenQuery = `INSERT INTO oauth_refresh_token (token_hash, oauth_grant, expires_at) VALUES ($1, $2, $3);`                                                                                                                                                                         //nolint:gosec // G101: a query naming its token column, not a credential.
	selectRefreshTokenQuery = `SELECT rt.used_at, rt.expires_at, g.id, g.account, g.client_id, g.resource, g.scope, COALESCE(g.key_thumbprint, ''), g.created_at, g.revoked FROM oauth_refresh_token rt JOIN oauth_grant g ON g.id = rt.oauth_grant WHERE rt.token_hash = $1 FOR UPDATE OF rt, g;` //nolint:gosec // G101: a query naming its token column, not a credential.
	spendRefreshTokenQuery  = `UPDATE oauth_refresh_token SET used_at = $1 WHERE token_hash = $2;`                                                                                                                                                                                                 //nolint:gosec // G101: a query naming its token column, not a credential.
	revokeGrantQuery        = `UPDATE oauth_grant SET revoked = true WHERE id = $1;`

	revokeGrantOfRefreshTokenQuery = `UPDATE oauth_grant SET revoked = true WHERE id = (SELECT oauth_grant FROM oauth_refresh_token WHERE token_hash = $1);` //nolint:gosec // G101: a query naming its token column, not a credential.

	selectAccountLockedQuery = `SELECT locked FROM account WHERE id = $1;`
)

type Store struct {
	db *sql.DB
}

var _ oauth.Store = (*Store)(nil)

func New(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql db"))
	}
	return &Store{db: db}, nil
}

func (s *Store) InsertAuthorizationRequest(ctx context.Context, request *oauth.AuthorizationRequest) (string, error) {
	if request == nil {
		return "", altshiftErrors.NewWithTrace(nil_error.New("authorization request"))
	}
	if request.AccountId == "" {
		return "", altshiftErrors.NewWithTrace(empty_error.New("account id"))
	}

	// Requests no one answered are cleared on the way: there is nothing else to clear them.
	if _, err := s.db.ExecContext(ctx, deleteExpiredRequestsQuery); err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("sql exec (delete expired requests): %w", err))
	}

	var id string
	err := s.db.QueryRowContext(
		ctx, insertRequestQuery,
		request.AccountId, request.ClientId, request.ClientName, request.RedirectUri, request.State,
		request.CodeChallenge, request.Resource, request.Scope, request.ExpiresAt,
	).Scan(&id)
	if err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("sql query row (insert request): %w", err))
	}

	return id, nil
}

func (s *Store) PopAuthorizationRequest(ctx context.Context, id string) (*oauth.AuthorizationRequest, error) {
	if id == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("id"))
	}
	// The id comes from the request answering it, and an id the column cannot hold is one never
	// handed out, not a fault of the database's.
	if !isUuid(id) {
		return nil, oauth.ErrNotFound
	}

	request := &oauth.AuthorizationRequest{Id: id}
	err := s.db.QueryRowContext(ctx, popRequestQuery, id).Scan(
		&request.AccountId, &request.ClientId, &request.ClientName, &request.RedirectUri, &request.State,
		&request.CodeChallenge, &request.Resource, &request.Scope, &request.ExpiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, oauth.ErrNotFound
	}
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql query row (pop request): %w", err))
	}

	return request, nil
}

func (s *Store) InsertAuthorizationCode(ctx context.Context, codeHash []byte, code *oauth.AuthorizationCode) error {
	if len(codeHash) == 0 {
		return altshiftErrors.NewWithTrace(empty_error.New("code hash"))
	}
	if code == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("authorization code"))
	}

	if _, err := s.db.ExecContext(ctx, deleteExpiredCodesQuery); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("sql exec (delete expired codes): %w", err))
	}

	if _, err := s.db.ExecContext(
		ctx, insertCodeQuery,
		codeHash, code.AccountId, code.ClientId, code.RedirectUri, code.CodeChallenge, code.Resource, code.Scope, code.ExpiresAt,
	); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("sql exec (insert code): %w", err))
	}

	return nil
}

func (s *Store) PopAuthorizationCode(ctx context.Context, codeHash []byte) (*oauth.AuthorizationCode, error) {
	if len(codeHash) == 0 {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("code hash"))
	}

	code := &oauth.AuthorizationCode{}
	err := s.db.QueryRowContext(ctx, popCodeQuery, codeHash).Scan(
		&code.AccountId, &code.ClientId, &code.RedirectUri, &code.CodeChallenge, &code.Resource, &code.Scope, &code.ExpiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, oauth.ErrNotFound
	}
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql query row (pop code): %w", err))
	}

	return code, nil
}

func (s *Store) InsertGrant(ctx context.Context, grant *oauth.Grant, refreshTokenHash []byte, refreshTokenExpiresAt time.Time) (string, error) {
	if grant == nil {
		return "", altshiftErrors.NewWithTrace(nil_error.New("grant"))
	}
	if len(refreshTokenHash) == 0 {
		return "", altshiftErrors.NewWithTrace(empty_error.New("refresh token hash"))
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("sql begin tx: %w", err))
	}
	defer func() { _ = tx.Rollback() }()

	var id string
	if err := tx.QueryRowContext(
		ctx, insertGrantQuery,
		grant.AccountId, grant.ClientId, grant.Resource, grant.Scope, grant.KeyThumbprint, grant.CreatedAt,
	).Scan(&id); err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("sql query row (insert grant): %w", err))
	}

	if _, err := tx.ExecContext(ctx, insertRefreshTokenQuery, refreshTokenHash, id, refreshTokenExpiresAt); err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("sql exec (insert refresh token): %w", err))
	}

	if err := tx.Commit(); err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("sql commit: %w", err))
	}

	return id, nil
}

func (s *Store) RotateRefreshToken(
	ctx context.Context,
	refreshTokenHash []byte,
	newRefreshTokenHash []byte,
	newExpiresAt time.Time,
	now time.Time,
	check oauth.GrantCheck,
) (*oauth.Grant, error) {
	if len(refreshTokenHash) == 0 || len(newRefreshTokenHash) == 0 {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("refresh token hash"))
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql begin tx: %w", err))
	}
	defer func() { _ = tx.Rollback() }()

	var (
		usedAt    sql.NullTime
		expiresAt time.Time
		revoked   bool
		grant     oauth.Grant
	)
	err = tx.QueryRowContext(ctx, selectRefreshTokenQuery, refreshTokenHash).Scan(
		&usedAt, &expiresAt, &grant.Id, &grant.AccountId, &grant.ClientId, &grant.Resource, &grant.Scope,
		&grant.KeyThumbprint, &grant.CreatedAt, &revoked,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, oauth.ErrNotFound
	}
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql query row (select refresh token): %w", err))
	}

	// Spent before: one of the two presenting it is not the client, and which cannot be told, so
	// the grant goes for both.
	if usedAt.Valid {
		if _, err := tx.ExecContext(ctx, revokeGrantQuery, grant.Id); err != nil {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql exec (revoke grant): %w", err))
		}
		if err := tx.Commit(); err != nil {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql commit: %w", err))
		}
		return nil, oauth.ErrRefreshTokenReused
	}

	if revoked || !now.Before(expiresAt) {
		return nil, oauth.ErrNotFound
	}

	// Asked while the rows are locked, and before anything is written: a refusal rolls back and
	// leaves the token unspent. The check asks about the account on a connection of its own.
	if check != nil {
		checked := grant
		if err := check(&checked); err != nil {
			return nil, err
		}
	}

	if _, err := tx.ExecContext(ctx, spendRefreshTokenQuery, now, refreshTokenHash); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql exec (spend refresh token): %w", err))
	}
	if _, err := tx.ExecContext(ctx, insertRefreshTokenQuery, newRefreshTokenHash, grant.Id, newExpiresAt); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql exec (insert refresh token): %w", err))
	}

	if err := tx.Commit(); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql commit: %w", err))
	}

	return &grant, nil
}

func (s *Store) RevokeRefreshToken(ctx context.Context, refreshTokenHash []byte) error {
	if len(refreshTokenHash) == 0 {
		return altshiftErrors.NewWithTrace(empty_error.New("refresh token hash"))
	}

	if _, err := s.db.ExecContext(ctx, revokeGrantOfRefreshTokenQuery, refreshTokenHash); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("sql exec (revoke grant of refresh token): %w", err))
	}

	return nil
}

func (s *Store) AccountActive(ctx context.Context, accountId string) (bool, error) {
	if accountId == "" {
		return false, altshiftErrors.NewWithTrace(empty_error.New("account id"))
	}

	var locked bool
	err := s.db.QueryRowContext(ctx, selectAccountLockedQuery, accountId).Scan(&locked)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, altshiftErrors.NewWithTrace(fmt.Errorf("sql query row (select account): %w", err))
	}

	return !locked, nil
}

// isUuid says whether s is a UUID in the form Postgres writes one: 32 hexadecimal digits in groups of
// 8, 4, 4, 4 and 12, joined by hyphens.
func isUuid(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
				return false
			}
		}
	}
	return true
}
