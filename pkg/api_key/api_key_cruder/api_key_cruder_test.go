package api_key_cruder

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/altshiftab/authentication_go/pkg/api_key/assertion"
	"github.com/altshiftab/authentication_go/pkg/api_key/public_key"
	apiKeyTesting "github.com/altshiftab/authentication_go/pkg/api_key/testing"
	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	altshiftTestingCmp "github.com/altshiftab/utils_go/pkg/testing/cmp"
)

const testRole = "user"

func TestMain(m *testing.M) {
	os.Exit(apiKeyTesting.Main(m, "api_key_cruder"))
}

func createAccount(t *testing.T, db *sql.DB, emailAddress string) string {
	t.Helper()

	account, err := apiKeyTesting.InsertAccount(t.Context(), db, emailAddress, "", testRole)
	if err != nil {
		t.Fatalf("insert account: %v", err)
	}

	return account.Id
}

func newPublicKey(t *testing.T) *public_key.Key {
	t.Helper()

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}

	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal pkix public key: %v", err)
	}

	key, err := public_key.Parse(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}

	return key
}

func createKey(t *testing.T, db *sql.DB, accountId string, name string) *Key {
	t.Helper()

	cruder := &Cruder{Database: db}
	key := newPublicKey(t)

	if _, err := cruder.Create(t.Context(), accountId, key, name, nil); err != nil {
		t.Fatalf("create: %v", err)
	}

	selected, err := cruder.SelectForMint(t.Context(), key.Id)
	if err != nil {
		t.Fatalf("select for mint: %v", err)
	}

	return selected
}

// Whether a key may still mint is decided from these two alone, at every mint.
func TestKey(t *testing.T) {
	t.Parallel()

	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	testCases := []struct {
		name        string
		key         *Key
		wantRevoked bool
		wantExpired bool
	}{
		{name: "no key", key: nil},
		{name: "a key with neither", key: &Key{}},
		{name: "a revoked key", key: &Key{RevokedAt: &past}, wantRevoked: true},
		{name: "a key that has expired", key: &Key{ExpiresAt: &past}, wantExpired: true},
		{name: "a key that expires now", key: &Key{ExpiresAt: &now}, wantExpired: true},
		{name: "a key that expires later", key: &Key{ExpiresAt: &future}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := testCase.key.Revoked(); got != testCase.wantRevoked {
				t.Errorf("revoked: got %t, want %t", got, testCase.wantRevoked)
			}
			if got := testCase.key.Expired(now); got != testCase.wantExpired {
				t.Errorf("expired: got %t, want %t", got, testCase.wantExpired)
			}
		})
	}
}

// What is refused before the database is asked anything: no database, and a request that names
// nothing -- an empty account id above all, which a query would otherwise take as matching nobody
// rather than as a mistake.
func TestRefusals(t *testing.T) {
	t.Parallel()

	key := newPublicKey(t)
	db := &sql.DB{}

	testCases := []struct {
		name    string
		call    func(*Cruder) error
		wantErr error
	}{
		{
			name: "create without a database",
			call: func(c *Cruder) error {
				_, err := (&Cruder{}).Create(t.Context(), "an-account", key, "a key", nil)
				return err
			},
			wantErr: nil_error.New("sql database"),
		},
		{
			name:    "create for no account",
			call:    func(c *Cruder) error { _, err := c.Create(t.Context(), "", key, "a key", nil); return err },
			wantErr: empty_error.New("account id"),
		},
		{
			name:    "create without a key",
			call:    func(c *Cruder) error { _, err := c.Create(t.Context(), "an-account", nil, "a key", nil); return err },
			wantErr: nil_error.New("key"),
		},
		{
			name:    "create without a name",
			call:    func(c *Cruder) error { _, err := c.Create(t.Context(), "an-account", key, "", nil); return err },
			wantErr: empty_error.New("name"),
		},
		{
			name:    "list for no account",
			call:    func(c *Cruder) error { _, err := c.ReadBulkForAccount(t.Context(), ""); return err },
			wantErr: empty_error.New("account id"),
		},
		{
			name:    "revoke for no account",
			call:    func(c *Cruder) error { return c.RevokeForAccount(t.Context(), "", "a-key") },
			wantErr: empty_error.New("account id"),
		},
		{
			name:    "revoke no key",
			call:    func(c *Cruder) error { return c.RevokeForAccount(t.Context(), "an-account", "") },
			wantErr: empty_error.New("key id"),
		},
		{
			name:    "select no key",
			call:    func(c *Cruder) error { _, err := c.SelectForMint(t.Context(), ""); return err },
			wantErr: empty_error.New("key id"),
		},
		{
			name:    "record a mint of no key",
			call:    func(c *Cruder) error { _, err := c.RecordMint(t.Context(), nil, "a-jti", nil); return err },
			wantErr: nil_error.New("key"),
		},
		{
			name:    "record a mint of no assertion",
			call:    func(c *Cruder) error { _, err := c.RecordMint(t.Context(), &Key{}, "", nil); return err },
			wantErr: empty_error.New("jti"),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			altshiftTestingCmp.CompareErr(t, testCase.call(&Cruder{Database: db}), testCase.wantErr)
		})
	}
}

/*
 * Registration. What is worth asking of it is what happens the second time a key is offered: the
 * thumbprint is the primary key, so one key is one row whoever brings it, and a key that was
 * revoked can never be registered again -- which is the behaviour a compromised key needs.
 */
func TestCreate(t *testing.T) {
	t.Parallel()

	db := apiKeyTesting.Db(t)
	cruder := &Cruder{Database: db}
	accountId := createAccount(t, db, "api-key-create@example.com")
	otherAccountId := createAccount(t, db, "api-key-create-other@example.com")

	key := newPublicKey(t)
	expiresAt := time.Now().Add(24 * time.Hour).Truncate(time.Second)

	created, err := cruder.Create(t.Context(), accountId, key, "a build runner", &expiresAt)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Id != key.Id {
		t.Errorf("id: got %q, want the thumbprint %q", created.Id, key.Id)
	}
	if created.Name != "a build runner" {
		t.Errorf("name: got %q", created.Name)
	}
	if created.Algorithm != public_key.AlgorithmEddsa {
		t.Errorf("algorithm: got %q", created.Algorithm)
	}
	if created.CreatedAt == nil {
		t.Error("The key came back without a creation time.")
	}
	if created.ExpiresAt == nil || !created.ExpiresAt.Equal(expiresAt) {
		t.Errorf("expires at: got %v, want %v", created.ExpiresAt, expiresAt)
	}
	if created.RevokedAt != nil || created.LastUsedAt != nil {
		t.Error("A new key is revoked or used.")
	}

	// What is stored is the key that was registered, read back as the mint path reads it.
	selected, err := cruder.SelectForMint(t.Context(), key.Id)
	if err != nil {
		t.Fatalf("select for mint: %v", err)
	}
	if selected.AccountId != accountId || selected.Name != "a build runner" || !slices.Equal(selected.PublicKey, key.Der) {
		t.Errorf("got %+v, want the key as it was registered", selected)
	}

	_, err = cruder.Create(t.Context(), accountId, key, "the same key again", nil)
	if !errors.Is(err, altshiftErrors.ErrValidationError) {
		t.Errorf("got %v, want a validation error for the same key twice", err)
	}

	// And by somebody else, which is the case that matters: one key belongs to one account.
	if _, err := cruder.Create(t.Context(), otherAccountId, key, "somebody else's", nil); err == nil {
		t.Error("One key was registered to two accounts.")
	}
}

// The account asking is the account answered for, which is the whole of this cruder's authorization.
func TestReadBulkForAccount(t *testing.T) {
	t.Parallel()

	db := apiKeyTesting.Db(t)
	cruder := &Cruder{Database: db}
	accountId := createAccount(t, db, "api-key-list@example.com")
	otherAccountId := createAccount(t, db, "api-key-list-other@example.com")

	first := createKey(t, db, accountId, "first")
	second := createKey(t, db, accountId, "second")
	othersKey := createKey(t, db, otherAccountId, "somebody else's")

	keys, err := cruder.ReadBulkForAccount(t.Context(), accountId)
	if err != nil {
		t.Fatalf("read bulk for account: %v", err)
	}

	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}
	for _, key := range keys {
		if key.Id == othersKey.Id {
			t.Error("Another account's key was listed.")
		}
	}

	// Newest first, as the settings page lists them.
	if keys[0].Id != second.Id || keys[1].Id != first.Id {
		t.Errorf("got %q, %q; want %q, %q (newest first)", keys[0].Id, keys[1].Id, second.Id, first.Id)
	}

	// An account with none has none, rather than an error.
	emptyAccountId := createAccount(t, db, "api-key-list-empty@example.com")
	keys, err = cruder.ReadBulkForAccount(t.Context(), emptyAccountId)
	if err != nil {
		t.Fatalf("read bulk for account: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("got %d keys for an account that registered none", len(keys))
	}
}

/*
 * Minting, which is the part with the most to get wrong.
 *
 * Three properties: an assertion cannot be presented twice, a key that mints repeatedly keeps one
 * sign-in rather than accumulating them, and the account the token will be minted for comes back
 * whole -- without it, the claims would be built from nothing.
 */
func TestRecordMint(t *testing.T) {
	t.Parallel()

	db := apiKeyTesting.Db(t)
	cruder := &Cruder{Database: db}
	accountId := createAccount(t, db, "api-key-mint@example.com")
	key := createKey(t, db, accountId, "a build runner")

	metadata := &authenticationPkg.ClientMetadata{IpAddress: "81.2.3.4", UserAgent: "curl/8.9.1"}

	authentication, err := cruder.RecordMint(t.Context(), key, "assertion-1", metadata)
	if err != nil {
		t.Fatalf("record mint: %v", err)
	}
	if authentication == nil || authentication.Id == "" {
		t.Fatal("No sign-in came back.")
	}
	if authentication.Account == nil {
		t.Fatal("The sign-in came back without its account.")
	}
	if authentication.Account.Id != accountId {
		t.Errorf("account: got %q, want %q", authentication.Account.Id, accountId)
	}
	if authentication.Account.EmailAddress != "api-key-mint@example.com" {
		t.Errorf("email address: got %q", authentication.Account.EmailAddress)
	}
	if !slices.Equal(authentication.Account.Roles, []string{testRole}) {
		t.Errorf("roles: got %v, want [%s], which is what a token would carry", authentication.Account.Roles, testRole)
	}
	if authentication.ExpiresAt == nil || authentication.CreatedAt == nil {
		t.Error("The sign-in came back without its times.")
	}

	// The same assertion again is a replay, whatever else is true of it.
	_, err = cruder.RecordMint(t.Context(), key, "assertion-1", metadata)
	if !errors.Is(err, ErrAssertionAlreadyUsed) {
		t.Errorf("got %v, want ErrAssertionAlreadyUsed", err)
	}

	// A different one mints again, and lands in the sign-in the first one made: one key, one entry
	// in the account's activity, however often it mints.
	second, err := cruder.RecordMint(t.Context(), key, "assertion-2", metadata)
	if err != nil {
		t.Fatalf("record mint: %v", err)
	}
	if second.Id != authentication.Id {
		t.Errorf("the second mint made a second sign-in: %q against %q", second.Id, authentication.Id)
	}

	rows, err := db.QueryContext(
		t.Context(),
		`SELECT host(ip_address), user_agent FROM authentication WHERE account = $1;`,
		accountId,
	)
	if err != nil {
		t.Fatalf("select authentications: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var authentications [][2]string
	for rows.Next() {
		var ipAddress, userAgent string
		if err := rows.Scan(&ipAddress, &userAgent); err != nil {
			t.Fatalf("rows scan: %v", err)
		}
		authentications = append(authentications, [2]string{ipAddress, userAgent})
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows err: %v", err)
	}

	if len(authentications) != 1 {
		t.Fatalf("got %d sign-ins for two mints, want 1", len(authentications))
	}

	// What the activity page shows of it came from the request that minted.
	if authentications[0] != [2]string{"81.2.3.4", "curl/8.9.1"} {
		t.Errorf("got %q; want the metadata the mint carried", authentications[0])
	}

	var lastUsedAt sql.NullTime
	if err := db.QueryRowContext(t.Context(), `SELECT last_used_at FROM api_key WHERE id = $1;`, key.Id).
		Scan(&lastUsedAt); err != nil {
		t.Fatalf("select last used at: %v", err)
	}
	if !lastUsedAt.Valid {
		t.Error("The key minted and was not marked as used.")
	}
}

/*
 * The account comes back with what the claims are built from, its customer among them: the join is
 * a left one, so an account belonging to no customer is minted for as well as one that belongs to
 * one, and only the second carries a tenant.
 */
func TestRecordMintAccount(t *testing.T) {
	t.Parallel()

	db := apiKeyTesting.Db(t)

	customerId, err := apiKeyTesting.InsertCustomer(t.Context(), db, "Mint Customer")
	if err != nil {
		t.Fatalf("insert customer: %v", err)
	}

	testCases := []struct {
		name         string
		emailAddress string
		customerId   string
		roles        []string
	}{
		{name: "with a customer", emailAddress: "api-key-tenant@example.com", customerId: customerId, roles: []string{"admin", testRole}},
		{name: "with no customer and no roles", emailAddress: "api-key-no-tenant@example.com"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			account, err := apiKeyTesting.InsertAccount(t.Context(), db, testCase.emailAddress, testCase.customerId, testCase.roles...)
			if err != nil {
				t.Fatalf("insert account: %v", err)
			}
			key := createKey(t, db, account.Id, "a key")

			authentication, err := (&Cruder{Database: db}).RecordMint(t.Context(), key, "assertion-1", nil)
			if err != nil {
				t.Fatalf("record mint: %v", err)
			}

			minted := authentication.Account
			if minted == nil {
				t.Fatal("The sign-in came back without its account.")
			}
			if !slices.Equal(minted.Roles, account.Roles) {
				t.Errorf("roles: got %v, want %v", minted.Roles, account.Roles)
			}

			if testCase.customerId == "" {
				if minted.Customer != nil {
					t.Errorf("customer: got %+v, want none", minted.Customer)
				}
				return
			}
			if minted.Customer == nil || minted.Customer.Id != testCase.customerId || minted.Customer.Name != "Mint Customer" {
				t.Errorf("customer: got %+v, want %q", minted.Customer, testCase.customerId)
			}
		})
	}
}

/*
 * What stops a replay is the row, so the row has to outlast every moment the assertion could be
 * presented in.
 *
 * It is dated from the database's clock, within the transaction that also sweeps the spent ones --
 * which is what keeps the sweep from taking the row the same transaction has just written. Dated
 * from the "exp" a client wrote instead, an assertion accepted at the near edge of the leeway
 * carries one that has already passed: the row would be swept on arrival, and the assertion could
 * be presented again for as long as it stayed acceptable.
 */
func TestRecordMintRemembersTheAssertionForAsLongAsItCanBePresented(t *testing.T) {
	t.Parallel()

	db := apiKeyTesting.Db(t)
	cruder := &Cruder{Database: db}
	accountId := createAccount(t, db, "api-key-retention@example.com")
	key := createKey(t, db, accountId, "a key that mints")

	if _, err := cruder.RecordMint(t.Context(), key, "assertion-1", nil); err != nil {
		t.Fatalf("record mint: %v", err)
	}

	// Scanning it at all is half the assertion: swept, there is no row to read.
	var expiresAt time.Time
	if err := db.QueryRowContext(
		t.Context(),
		`SELECT expires_at FROM api_key_assertion WHERE api_key = $1 AND jti = $2;`,
		key.Id,
		"assertion-1",
	).Scan(&expiresAt); err != nil {
		t.Fatalf("the spent assertion was not remembered: %v", err)
	}

	// How long an assertion arriving now could still be presented for: its "exp" may sit a lifetime
	// and a leeway out, and it is accepted for a leeway past that.
	presentableFor := assertion.Lifetime + 2*assertion.Leeway

	// The database's clock and this one are not the same clock, and neither is stopped between the
	// insert and the read. A few seconds keeps the test about retention rather than about that.
	const tolerance = 5 * time.Second

	if remaining := time.Until(expiresAt); remaining < presentableFor-tolerance {
		t.Errorf(
			"the assertion is remembered for %s, less than the %s it can be presented for",
			remaining,
			presentableFor,
		)
	}
}

/*
 * Revocation, which is where API access ends: the key stops minting and what it minted stops being
 * renewable. Either half alone leaves the account half revoked, so both are asserted, and the key
 * of another account is refused with the same answer as one that does not exist.
 */
func TestRevokeForAccount(t *testing.T) {
	t.Parallel()

	db := apiKeyTesting.Db(t)
	cruder := &Cruder{Database: db}
	accountId := createAccount(t, db, "api-key-revoke@example.com")
	otherAccountId := createAccount(t, db, "api-key-revoke-other@example.com")

	key := createKey(t, db, accountId, "a key to revoke")
	othersKey := createKey(t, db, otherAccountId, "somebody else's")

	authentication, err := cruder.RecordMint(t.Context(), key, "assertion-1", nil)
	if err != nil {
		t.Fatalf("record mint: %v", err)
	}

	othersAuthentication, err := cruder.RecordMint(t.Context(), othersKey, "assertion-1", nil)
	if err != nil {
		t.Fatalf("record mint: %v", err)
	}

	// Another account's key: the same answer as a key that never existed, so nothing is learned.
	if err := cruder.RevokeForAccount(t.Context(), accountId, othersKey.Id); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("got %v, want sql.ErrNoRows", err)
	}
	if endedAuthentication(t, db, othersAuthentication.Id) {
		t.Error("Another account's sign-in was ended.")
	}

	if err := cruder.RevokeForAccount(t.Context(), accountId, key.Id); err != nil {
		t.Fatalf("revoke for account: %v", err)
	}

	selected, err := cruder.SelectForMint(t.Context(), key.Id)
	if err != nil {
		t.Fatalf("select for mint: %v", err)
	}
	if !selected.Revoked() {
		t.Error("The key is not revoked.")
	}

	if !endedAuthentication(t, db, authentication.Id) {
		t.Error("The key's sign-in was left running after the key was revoked.")
	}

	// Revoking it again finds nothing to revoke, which reads the same as a key that is not there.
	if err := cruder.RevokeForAccount(t.Context(), accountId, key.Id); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("got %v, want sql.ErrNoRows", err)
	}

	if err := cruder.RevokeForAccount(t.Context(), accountId, "not-a-key"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("got %v, want sql.ErrNoRows", err)
	}

	// And a revoked key, once revoked, can never be registered again, by anyone.
	revokedKey, err := public_key.FromDer(selected.PublicKey)
	if err != nil {
		t.Fatalf("public key from der: %v", err)
	}
	if _, err := cruder.Create(t.Context(), accountId, revokedKey, "the revoked key again", nil); err == nil {
		t.Error("A revoked key was registered again.")
	}
}

/*
 * A revoke landing between the mint's read of the key and its record: the key the endpoint holds
 * still says it is live, and the record must not make a sign-in for it all the same.
 */
func TestRecordMintAfterARevokeItDidNotSee(t *testing.T) {
	t.Parallel()

	db := apiKeyTesting.Db(t)
	cruder := &Cruder{Database: db}
	accountId := createAccount(t, db, "api-key-revoke-race@example.com")
	key := createKey(t, db, accountId, "revoked under the mint")

	if err := cruder.RevokeForAccount(t.Context(), accountId, key.Id); err != nil {
		t.Fatalf("revoke for account: %v", err)
	}
	if key.Revoked() {
		t.Fatal("The key read before the revoke says it is revoked.")
	}

	if _, err := cruder.RecordMint(t.Context(), key, "assertion-1", nil); !errors.Is(err, ErrKeyRevoked) {
		t.Errorf("got %v, want ErrKeyRevoked", err)
	}

	var signIns int
	if err := db.QueryRowContext(
		t.Context(),
		`SELECT count(*) FROM api_key_authentication WHERE api_key = $1;`,
		key.Id,
	).Scan(&signIns); err != nil {
		t.Fatalf("count sign-ins: %v", err)
	}
	if signIns != 0 {
		t.Errorf("A revoked key was given %d sign-in(s).", signIns)
	}
}

func endedAuthentication(t *testing.T, db *sql.DB, authenticationId string) bool {
	t.Helper()

	var ended bool
	err := db.QueryRowContext(
		t.Context(),
		`SELECT ended FROM authentication WHERE id = $1;`,
		authenticationId,
	).Scan(&ended)
	if err != nil {
		t.Fatalf("select authentication: %v", err)
	}

	return ended
}

// A key that nobody registered reads as a key that is not there, which is what an assertion naming
// a made-up subject gets.
func TestSelectForMintMissing(t *testing.T) {
	t.Parallel()

	cruder := &Cruder{Database: apiKeyTesting.Db(t)}

	if _, err := cruder.SelectForMint(t.Context(), "not-a-registered-key"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("got %v, want sql.ErrNoRows", err)
	}
}

/*
 * A sign-in a key minted under that has since run out is not taken up again: the next mint makes a
 * new one. The window is long, but it is a window, and a key that comes back after it must not
 * revive a sign-in the account's activity has shown as over.
 */
func TestRecordMintAfterTheSignInExpired(t *testing.T) {
	t.Parallel()

	db := apiKeyTesting.Db(t)
	cruder := &Cruder{Database: db}
	accountId := createAccount(t, db, "api-key-expired-sign-in@example.com")
	key := createKey(t, db, accountId, "a key that comes back")

	first, err := cruder.RecordMint(t.Context(), key, "assertion-1", nil)
	if err != nil {
		t.Fatalf("record mint: %v", err)
	}

	if _, err := db.ExecContext(
		t.Context(),
		`UPDATE authentication SET expires_at = now() - interval '1 second' WHERE id = $1;`,
		first.Id,
	); err != nil {
		t.Fatalf("expire the sign-in: %v", err)
	}

	second, err := cruder.RecordMint(t.Context(), key, "assertion-2", nil)
	if err != nil {
		t.Fatalf("record mint: %v", err)
	}
	if second.Id == first.Id {
		t.Error("A sign-in that had run out was taken up again.")
	}
}
