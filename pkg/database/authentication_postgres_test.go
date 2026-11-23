package database_test

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	apiKeyTesting "github.com/altshiftab/authentication_go/pkg/api_key/testing"
	"github.com/altshiftab/authentication_go/pkg/database"
	databaseErrors "github.com/altshiftab/authentication_go/pkg/database/errors"
)

// The tests here are of the queries themselves, so they run against Postgres, where TEST_DATABASE_URL
// names a server, and are skipped where it does not.
func TestMain(m *testing.M) {
	os.Exit(apiKeyTesting.Main(m, "database"))
}

// newAuthentication is a running sign-in of an account of its own, by its id.
func newAuthentication(t *testing.T, db *sql.DB) string {
	t.Helper()

	account, err := apiKeyTesting.InsertAccount(t.Context(), db, strings.ToLower(rand.Text())+"@example.test", "")
	if err != nil {
		t.Fatalf("insert account: %v", err)
	}

	session, err := account.ActiveSession(t.Context(), db)
	if err != nil {
		t.Fatalf("active session: %v", err)
	}

	return session.AuthenticationId
}

// selectDbscPublicKey is the key registered for the authentication, nil where there is none.
func selectDbscPublicKey(t *testing.T, db *sql.DB, authenticationId string) []byte {
	t.Helper()

	var key []byte
	if err := db.QueryRowContext(
		t.Context(),
		`SELECT dbsc_public_key FROM authentication WHERE id = $1;`,
		authenticationId,
	).Scan(&key); err != nil {
		t.Fatalf("select dbsc public key: %v", err)
	}

	return key
}

// A session's device key is registered once. Whoever holds a copy of the cookie can ask to register
// one, so a second key, or the same one again, is refused and the first stays.
func TestUpdateAuthenticationWithDbscPublicKey_RegistersOnce(t *testing.T) {
	t.Parallel()

	db := apiKeyTesting.Db(t)

	firstKey := []byte("first key")
	secondKey := []byte("second key")

	testCases := []struct {
		name          string
		registeredKey []byte
		key           []byte
		noSuchSession bool
		wantErr       error
		wantKey       []byte
	}{
		{name: "the first key is registered", key: firstKey, wantKey: firstKey},
		{
			name:          "another key does not replace it",
			registeredKey: firstKey,
			key:           secondKey,
			wantErr:       databaseErrors.ErrDbscPublicKeyRegistered,
			wantKey:       firstKey,
		},
		{
			name:          "nor does the same key again",
			registeredKey: firstKey,
			key:           firstKey,
			wantErr:       databaseErrors.ErrDbscPublicKeyRegistered,
			wantKey:       firstKey,
		},
		{name: "an authentication that is not there", key: firstKey, noSuchSession: true, wantErr: sql.ErrNoRows},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			authenticationId := newAuthentication(t, db)
			if testCase.noSuchSession {
				authenticationId = apiKeyTesting.UnrecordedAuthenticationId
			}

			if testCase.registeredKey != nil {
				if err := database.UpdateAuthenticationWithDbscPublicKey(t.Context(), authenticationId, testCase.registeredKey, db); err != nil {
					t.Fatalf("%s: registering the first key: %v", testCase.name, err)
				}
			}

			err := database.UpdateAuthenticationWithDbscPublicKey(t.Context(), authenticationId, testCase.key, db)
			if testCase.wantErr == nil && err != nil {
				t.Fatalf("%s: unexpected error: %v", testCase.name, err)
			}
			if testCase.wantErr != nil && !errors.Is(err, testCase.wantErr) {
				t.Fatalf("%s: error %v, want %v", testCase.name, err, testCase.wantErr)
			}

			if testCase.noSuchSession {
				return
			}
			if key := selectDbscPublicKey(t, db, authenticationId); !bytes.Equal(key, testCase.wantKey) {
				t.Errorf("%s: registered key %q, want %q", testCase.name, key, testCase.wantKey)
			}
		})
	}
}

// What a refresh records is what the next one reads: the expiry a device bound session's idle bound
// is measured from, absent until the first refresh.
func TestSelectRefreshAuthentication_SessionExpiresAt(t *testing.T) {
	t.Parallel()

	db := apiKeyTesting.Db(t)

	testCases := []struct {
		name     string
		recorded *time.Time
	}{
		{name: "never refreshed"},
		{name: "refreshed", recorded: new(time.Now().Add(15 * time.Minute).Truncate(time.Microsecond))},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			authenticationId := newAuthentication(t, db)

			if testCase.recorded != nil {
				if err := database.UpdateAuthenticationWithSessionExpiresAt(t.Context(), authenticationId, *testCase.recorded, db); err != nil {
					t.Fatalf("%s: update authentication with session expires at: %v", testCase.name, err)
				}
			}

			authentication, err := database.SelectRefreshAuthentication(t.Context(), authenticationId, db)
			if err != nil {
				t.Fatalf("%s: select refresh authentication: %v", testCase.name, err)
			}

			got := authentication.SessionExpiresAt
			switch {
			case testCase.recorded == nil && got != nil:
				t.Errorf("%s: session expires at %s, want none", testCase.name, got)
			case testCase.recorded != nil && (got == nil || !got.Equal(*testCase.recorded)):
				t.Errorf("%s: session expires at %v, want %s", testCase.name, got, testCase.recorded)
			}
		})
	}

	t.Run("an authentication that is not there", func(t *testing.T) {
		t.Parallel()

		err := database.UpdateAuthenticationWithSessionExpiresAt(t.Context(), apiKeyTesting.UnrecordedAuthenticationId, time.Now(), db)
		if !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("error %v, want %v", err, sql.ErrNoRows)
		}
	})
}

// Every flow begun removes the flows that expired more than a while ago, which nothing else would: a
// flow is begun by anyone who asks, and is otherwise removed only by the callback that completes it.
// One that expired within the last 30 days is kept, for a callback arriving late to restart its
// sign-in from, and for the database dumps to hold.
func TestInsertOauthFlow_PurgesExpiredFlows(t *testing.T) {
	t.Parallel()

	db := apiKeyTesting.Db(t)

	testCases := []struct {
		name      string
		expiresIn time.Duration
		wantKept  bool
	}{
		{name: "a live flow is kept", expiresIn: 5 * time.Minute, wantKept: true},
		{name: "a flow expired a moment ago is kept", expiresIn: -10 * time.Minute, wantKept: true},
		{name: "a flow expired days ago is kept", expiresIn: -72 * time.Hour, wantKept: true},
		{name: "a flow expired a month ago is removed", expiresIn: -31 * 24 * time.Hour},
		{name: "a flow expired months ago is removed", expiresIn: -90 * 24 * time.Hour},
	}

	states := make([]string, len(testCases))
	for index, testCase := range testCases {
		states[index] = rand.Text()
		if _, err := db.ExecContext(
			t.Context(),
			`INSERT INTO oauth_flow (state, code_verifier, redirect_url, expires_at) VALUES ($1, $2, $3, $4);`,
			states[index], rand.Text(), "https://example.test/", time.Now().Add(testCase.expiresIn),
		); err != nil {
			t.Fatalf("%s: insert oauth flow: %v", testCase.name, err)
		}
	}

	flow, err := database.InsertOauthFlow(t.Context(), rand.Text(), rand.Text(), "https://example.test/", 8*time.Minute, db)
	if err != nil {
		t.Fatalf("insert oauth flow: %v", err)
	}
	if flow == nil || flow.Id == "" {
		t.Fatalf("insert oauth flow: no flow made: %+v", flow)
	}

	for index, testCase := range testCases {
		var kept bool
		if err := db.QueryRowContext(
			t.Context(),
			`SELECT EXISTS (SELECT 1 FROM oauth_flow WHERE state = $1);`,
			states[index],
		).Scan(&kept); err != nil {
			t.Fatalf("%s: select oauth flow: %v", testCase.name, err)
		}
		if kept != testCase.wantKept {
			t.Errorf("%s: kept %t, want %t", testCase.name, kept, testCase.wantKept)
		}
	}
}

// Every challenge issued removes the challenges that have expired, which no proof can redeem and
// which nothing else would remove: a challenge is otherwise removed only by the proof redeeming it.
func TestInsertDbscChallenge_PurgesExpiredChallenges(t *testing.T) {
	t.Parallel()

	db := apiKeyTesting.Db(t)
	authenticationId := newAuthentication(t, db)

	testCases := []struct {
		name      string
		expiresIn time.Duration
		wantKept  bool
	}{
		{name: "a live challenge is kept", expiresIn: 5 * time.Minute, wantKept: true},
		{name: "a challenge expired a moment ago is removed", expiresIn: -time.Second},
		{name: "a challenge expired days ago is removed", expiresIn: -72 * time.Hour},
	}

	challenges := make([]string, len(testCases))
	for index, testCase := range testCases {
		challenges[index] = rand.Text()
		if _, err := db.ExecContext(
			t.Context(),
			`INSERT INTO dbsc_challenge (challenge, authentication, expires_at) VALUES ($1, $2, $3);`,
			[]byte(challenges[index]), authenticationId, time.Now().Add(testCase.expiresIn),
		); err != nil {
			t.Fatalf("%s: insert dbsc challenge: %v", testCase.name, err)
		}
	}

	if err := database.InsertDbscChallenge(t.Context(), rand.Text(), authenticationId, time.Hour, db); err != nil {
		t.Fatalf("insert dbsc challenge: %v", err)
	}

	for index, testCase := range testCases {
		var kept bool
		if err := db.QueryRowContext(
			t.Context(),
			`SELECT EXISTS (SELECT 1 FROM dbsc_challenge WHERE challenge = $1);`,
			[]byte(challenges[index]),
		).Scan(&kept); err != nil {
			t.Fatalf("%s: select dbsc challenge: %v", testCase.name, err)
		}
		if kept != testCase.wantKept {
			t.Errorf("%s: kept %t, want %t", testCase.name, kept, testCase.wantKept)
		}
	}
}

// What the store deletes by is indexed, so that neither a removal nor a purge reads the table whole.
func TestSchema_IndexesWhatIsDeletedBy(t *testing.T) {
	t.Parallel()

	db := apiKeyTesting.Db(t)

	testCases := []struct {
		name   string
		table  string
		column string
	}{
		{name: "an expired flow is removed by its state", table: "oauth_flow", column: "state"},
		{name: "expired flows are purged by their expiry", table: "oauth_flow", column: "expires_at"},
		{name: "a challenge is redeemed by its value", table: "dbsc_challenge", column: "challenge"},
		{name: "expired challenges are purged by their expiry", table: "dbsc_challenge", column: "expires_at"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var indexed bool
			if err := db.QueryRowContext(
				t.Context(),
				`SELECT EXISTS (
					SELECT 1 FROM pg_index i
					JOIN pg_class c ON c.oid = i.indrelid
					JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = i.indkey[0]
					WHERE c.relname = $1 AND a.attname = $2
				);`,
				testCase.table, testCase.column,
			).Scan(&indexed); err != nil {
				t.Fatalf("%s: select index: %v", testCase.name, err)
			}
			if !indexed {
				t.Errorf("%s: no index leads with %s.%s", testCase.name, testCase.table, testCase.column)
			}
		})
	}
}
