package postgres_store

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	apiKeyTesting "github.com/altshiftab/authentication_go/pkg/api_key/testing"
	"github.com/altshiftab/authentication_go/pkg/oauth"
	oauthTesting "github.com/altshiftab/authentication_go/pkg/oauth/testing"
	altshiftSqlTesting "github.com/altshiftab/utils_go/pkg/database/sql/testing"
)

func TestMain(m *testing.M) {
	os.Exit(apiKeyTesting.Main(m, "postgres_store"))
}

// newEmailAddress is an address no other run in the package's database has taken.
func newEmailAddress() string {
	return strings.ToLower(rand.Text()) + "@example.test"
}

// A rotation that waited for its rows sees an account locked while it waited, as it reads the account
// in a statement of its own once it has them; read in the locking statement, the account would be as
// it was before the wait.
func TestStore_RotateSeesAccountLockedDuringWait(t *testing.T) {
	t.Parallel()

	db := apiKeyTesting.Db(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	account, err := apiKeyTesting.InsertAccount(ctx, db, newEmailAddress(), "")
	if err != nil {
		t.Fatalf("insert account: %v", err)
	}
	store, err := New(db)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	now := time.Now().Truncate(time.Second)
	token := oauth.HashSecret(rand.Text())
	grantId, err := store.InsertGrant(ctx, &oauth.Grant{
		AccountId: account.Id, ClientId: "a-client", Resource: "https://resource.example/mcp", Scope: "vocab", CreatedAt: now,
	}, token, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("insert grant: %v", err)
	}

	// Another transaction holds the grant's row, as one presenting the same token at once would.
	holder, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = holder.Rollback() }()
	var holderPid int
	if err := holder.QueryRowContext(ctx, `SELECT pg_backend_pid();`).Scan(&holderPid); err != nil {
		t.Fatalf("holder pid: %v", err)
	}
	if _, err := holder.ExecContext(ctx, `SELECT 1 FROM oauth_grant WHERE id = $1 FOR UPDATE;`, grantId); err != nil {
		t.Fatalf("hold grant: %v", err)
	}

	rotated := make(chan error, 1)
	go func() {
		_, err := store.RotateRefreshToken(ctx, token, oauth.HashSecret(rand.Text()), now.Add(time.Hour), now, nil)
		rotated <- err
	}()

	// The account is locked only once the rotation waits for the holder.
	for blocked := 0; blocked == 0; {
		if err := db.QueryRowContext(
			ctx,
			`SELECT count(*) FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid));`,
			holderPid,
		).Scan(&blocked); err != nil {
			t.Fatalf("count blocked: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := db.ExecContext(ctx, `UPDATE account SET locked = true WHERE id = $1;`, account.Id); err != nil {
		t.Fatalf("lock account: %v", err)
	}
	if err := holder.Rollback(); err != nil {
		t.Fatalf("rollback holder: %v", err)
	}

	if err := <-rotated; !errors.Is(err, oauth.ErrAccountInactive) {
		t.Errorf("rotate: %v, want ErrAccountInactive", err)
	}
}

// The store against Postgres, where TEST_DATABASE_URL names a server, through what the endpoints
// rely on.
//
//nolint:tparallel // The contract's group is serial so that it has run when StoreContract returns; its cases are parallel.
func TestStore_Contract(t *testing.T) {
	t.Parallel()

	db := apiKeyTesting.Db(t)
	active, err := apiKeyTesting.InsertAccount(t.Context(), db, newEmailAddress(), "")
	if err != nil {
		t.Fatalf("insert account: %v", err)
	}
	locked, err := apiKeyTesting.InsertAccount(t.Context(), db, newEmailAddress(), "")
	if err != nil {
		t.Fatalf("insert account: %v", err)
	}
	if _, err := db.ExecContext(t.Context(), `UPDATE account SET locked = true WHERE id = $1;`, locked.Id); err != nil {
		t.Fatalf("lock account: %v", err)
	}

	store, err := New(db)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	oauthTesting.StoreContract(t, store, active.Id, locked.Id)
}

// What the store refuses before it asks the database anything.
func TestStore_Refusals(t *testing.T) {
	t.Parallel()

	if _, err := New(nil); err == nil {
		t.Error("a store without a database")
	}

	store, err := New(altshiftSqlTesting.NewDb())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx := t.Context()

	testCases := []struct {
		name string
		call func() error
	}{
		{name: "no request", call: func() error { _, err := store.InsertAuthorizationRequest(ctx, nil); return err }},
		{name: "a request of no account", call: func() error {
			_, err := store.InsertAuthorizationRequest(ctx, &oauth.AuthorizationRequest{})
			return err
		}},
		{name: "no request id", call: func() error { _, err := store.PopAuthorizationRequest(ctx, ""); return err }},
		{name: "no code hash", call: func() error { return store.InsertAuthorizationCode(ctx, nil, &oauth.AuthorizationCode{}) }},
		{name: "no code", call: func() error { return store.InsertAuthorizationCode(ctx, []byte("h"), nil) }},
		{name: "no code hash to pop", call: func() error { _, err := store.PopAuthorizationCode(ctx, nil); return err }},
		{name: "no grant", call: func() error { _, err := store.InsertGrant(ctx, nil, []byte("h"), time.Now()); return err }},
		{name: "no refresh token hash", call: func() error { _, err := store.InsertGrant(ctx, &oauth.Grant{}, nil, time.Now()); return err }},
		{name: "no refresh token to rotate", call: func() error {
			_, err := store.RotateRefreshToken(ctx, nil, []byte("n"), time.Now(), time.Now(), nil)
			return err
		}},
		{name: "no refresh token to revoke", call: func() error { return store.RevokeRefreshToken(ctx, nil) }},
		{name: "no account", call: func() error { _, err := store.AccountActive(ctx, ""); return err }},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if err := testCase.call(); err == nil {
				t.Errorf("%s: no error", testCase.name)
			}
		})
	}
}

func TestIsUuid(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		id   string
		want bool
	}{
		{name: "as Postgres writes one", id: "0b0e7c4c-8f0b-4c5e-9d3a-2f6a1c9e7b10", want: true},
		{name: "in capitals", id: "0B0E7C4C-8F0B-4C5E-9D3A-2F6A1C9E7B10", want: true},
		{name: "not one at all", id: "never-made"},
		{name: "without hyphens", id: "0b0e7c4c8f0b4c5e9d3a2f6a1c9e7b10"},
		{name: "a hyphen out of place", id: "0b0e7c4c8-f0b-4c5e-9d3a-2f6a1c9e7b10"},
		{name: "a letter beyond f", id: "0b0e7c4c-8f0b-4c5e-9d3a-2f6a1c9e7b1g"},
		{name: "in braces", id: "{0b0e7c4c-8f0b-4c5e-9d3a-2f6a1c9e7b}"},
		{name: "empty", id: ""},
	}
	for _, testCase := range testCases {
		if got := isUuid(testCase.id); got != testCase.want {
			t.Errorf("%s: got %t, want %t", testCase.name, got, testCase.want)
		}
	}
}
