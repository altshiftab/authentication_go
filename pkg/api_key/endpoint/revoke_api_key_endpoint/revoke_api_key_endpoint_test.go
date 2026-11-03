package revoke_api_key_endpoint

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/altshiftab/authentication_go/pkg/api_key/api_key_cruder"
	"github.com/altshiftab/authentication_go/pkg/api_key/public_key"
	apiKeyTesting "github.com/altshiftab/authentication_go/pkg/api_key/testing"
	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser"
	altshiftSqlTesting "github.com/altshiftab/utils_go/pkg/database/sql/testing"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
	muxTesting "github.com/altshiftab/utils_go/pkg/http/mux/testing"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	altshiftTestingCmp "github.com/altshiftab/utils_go/pkg/testing/cmp"
)

const testRole = "user"

func TestMain(m *testing.M) {
	os.Exit(apiKeyTesting.Main(m, "revoke_api_key_endpoint"))
}

func TestInitialize(t *testing.T) {
	t.Parallel()

	emptyDb := altshiftSqlTesting.NewDb()

	testCases := []struct {
		name       string
		authorizer *authorizer_request_parser.Parser
		db         *sql.DB
		wantErr    error
	}{
		{name: "valid arguments", authorizer: apiKeyTesting.Authorizer, db: emptyDb},
		{name: "nil authorizer", db: emptyDb, wantErr: nil_error.New("authorizer")},
		{name: "nil database", authorizer: apiKeyTesting.Authorizer, wantErr: nil_error.New("sql database")},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint := New()
			err := testEndpoint.Initialize(testCase.authorizer, testCase.db)
			altshiftTestingCmp.CompareErr(t, err, testCase.wantErr)
		})
	}
}

func newAccount(t *testing.T, db *sql.DB, emailAddress string) *apiKeyTesting.Account {
	t.Helper()

	account, err := apiKeyTesting.InsertAccount(t.Context(), db, emailAddress, "", testRole)
	if err != nil {
		t.Fatalf("insert account: %v", err)
	}

	return account
}

func createKey(t *testing.T, db *sql.DB, accountId string, name string) string {
	t.Helper()

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}

	key, err := public_key.FromPublicKey(publicKey)
	if err != nil {
		t.Fatalf("public key from public key: %v", err)
	}

	if _, err := (&api_key_cruder.Cruder{Database: db}).Create(t.Context(), accountId, key, name, nil); err != nil {
		t.Fatalf("create api key: %v", err)
	}

	return key.Id
}

func revoked(t *testing.T, db *sql.DB, keyId string) bool {
	t.Helper()

	key, err := (&api_key_cruder.Cruder{Database: db}).SelectForMint(t.Context(), keyId)
	if err != nil {
		t.Fatalf("select for mint: %v", err)
	}

	return key.Revoked()
}

func revokePath(path string, keyId string) string {
	return path + "?" + url.Values{"id": {keyId}}.Encode()
}

/*
 * Revocation is the account's own, and the refusals are all one answer: a key belonging to somebody
 * else, a key that does not exist and a key already revoked are indistinguishable from outside, so
 * nothing here tells a caller that another account's key id is real.
 */
//
//nolint:tparallel,paralleltest // Subtests share one database and must not run in parallel.
func TestEndpoint(t *testing.T) {
	t.Parallel()

	db := apiKeyTesting.Db(t)

	account := newAccount(t, db, "revoke-api-key@example.com")
	otherAccount := newAccount(t, db, "revoke-api-key-other@example.com")

	keyId := createKey(t, db, account.Id, "a key to revoke")
	othersKeyId := createKey(t, db, otherAccount.Id, "somebody else's")

	testEndpoint := New()
	if err := testEndpoint.Initialize(apiKeyTesting.Authorizer, db); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint.Endpoint.Endpoint)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	session, err := account.ActiveSession(t.Context(), db)
	if err != nil {
		t.Fatalf("active session: %v", err)
	}
	sessionCookie, err := session.Cookie()
	if err != nil {
		t.Fatalf("cookie: %v", err)
	}

	notFound := &problem_detail.Detail{Detail: "No key of yours was found with the provided id."}

	t.Run("another account's key", func(t *testing.T) {
		muxTesting.TestArgs(t, &muxTesting.Args{
			Path:                  revokePath(testEndpoint.Path, othersKeyId),
			Method:                testEndpoint.Method,
			Headers:               [][2]string{{"Cookie", sessionCookie}},
			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedProblemDetail: notFound,
		}, httpServer.URL)

		if revoked(t, db, othersKeyId) {
			t.Error("Another account's key was revoked.")
		}
	})

	t.Run("a key that does not exist", func(t *testing.T) {
		muxTesting.TestArgs(t, &muxTesting.Args{
			Path:                  revokePath(testEndpoint.Path, "not-a-key"),
			Method:                testEndpoint.Method,
			Headers:               [][2]string{{"Cookie", sessionCookie}},
			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedProblemDetail: notFound,
		}, httpServer.URL)
	})

	t.Run("the account's own key", func(t *testing.T) {
		muxTesting.TestArgs(t, &muxTesting.Args{
			Path:               revokePath(testEndpoint.Path, keyId),
			Method:             testEndpoint.Method,
			Headers:            [][2]string{{"Cookie", sessionCookie}},
			ExpectedStatusCode: http.StatusNoContent,
		}, httpServer.URL)

		if !revoked(t, db, keyId) {
			t.Error("The key was answered for but not revoked.")
		}
	})

	t.Run("the same key again", func(t *testing.T) {
		muxTesting.TestArgs(t, &muxTesting.Args{
			Path:                  revokePath(testEndpoint.Path, keyId),
			Method:                testEndpoint.Method,
			Headers:               [][2]string{{"Cookie", sessionCookie}},
			ExpectedStatusCode:    http.StatusNotFound,
			ExpectedProblemDetail: notFound,
		}, httpServer.URL)
	})

	t.Run("no session", func(t *testing.T) {
		anotherKeyId := createKey(t, db, account.Id, "a key nobody may revoke")

		muxTesting.TestArgs(t, &muxTesting.Args{
			Path:               revokePath(testEndpoint.Path, anotherKeyId),
			Method:             testEndpoint.Method,
			ExpectedStatusCode: http.StatusUnauthorized,
			ExpectedProblemDetail: &problem_detail.Detail{
				Detail:    "Missing cookie with token.",
				Extension: map[string]any{"cookie": "session"},
			},
		}, httpServer.URL)

		if revoked(t, db, anotherKeyId) {
			t.Error("A key was revoked for a request carrying no session.")
		}
	})

	// A token whose sign-in is not in the database is refused, whatever its signature says: revoking
	// is checked against the sign-in standing behind the session, not against the token alone.
	t.Run("a session with no sign-in behind it", func(t *testing.T) {
		anotherKeyId := createKey(t, db, account.Id, "a key a stale session may not revoke")

		unrecordedCookie, err := account.Session().Cookie()
		if err != nil {
			t.Fatalf("cookie: %v", err)
		}

		muxTesting.TestArgs(t, &muxTesting.Args{
			Path:               revokePath(testEndpoint.Path, anotherKeyId),
			Method:             testEndpoint.Method,
			Headers:            [][2]string{{"Cookie", unrecordedCookie}},
			ExpectedStatusCode: http.StatusUnauthorized,
			// An absent row reads as an ended one: deleting an account deletes its sign-ins.
			ExpectedProblemDetail: &problem_detail.Detail{Detail: "The session's authentication has ended."},
		}, httpServer.URL)

		if revoked(t, db, anotherKeyId) {
			t.Error("A key was revoked for a session with no sign-in behind it.")
		}
	})
}
