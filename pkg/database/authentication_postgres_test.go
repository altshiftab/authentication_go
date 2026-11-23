package database_test

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"

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
