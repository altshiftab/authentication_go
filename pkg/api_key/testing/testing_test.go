package testing

import (
	"context"
	"database/sql"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/altshiftab/authentication_go/pkg/session/types/authentication_method"
	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	altshiftTestingCmp "github.com/altshiftab/utils_go/pkg/testing/cmp"
)

func TestMain(m *testing.M) {
	os.Exit(Main(m, "api_key_testing"))
}

// The schema is the library's tables, every one a test of the API key packages reaches, with the
// extensions they need.
func TestSchema(t *testing.T) {
	t.Parallel()

	schema, err := Schema()
	if err != nil {
		t.Fatalf("schema: %v", err)
	}

	testCases := []struct {
		name string
		want string
	}{
		{name: "pgcrypto", want: "CREATE EXTENSION IF NOT EXISTS pgcrypto;"},
		{name: "citext", want: "CREATE EXTENSION IF NOT EXISTS citext;"},
		{name: "customer", want: "CREATE TABLE customer ("},
		{name: "account", want: "CREATE TABLE account ("},
		{name: "authentication", want: "CREATE TABLE authentication ("},
		{name: "api_key", want: "CREATE TABLE api_key ("},
		{name: "api_key_assertion", want: "CREATE TABLE api_key_assertion ("},
		{name: "api_key_authentication", want: "CREATE TABLE api_key_authentication ("},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if count := strings.Count(schema, testCase.want); count != 1 {
				t.Errorf("%q appears %d times in the schema, want once", testCase.want, count)
			}
		})
	}
}

/*
 * A session made here is taken by the authorizer it is meant for and by no other: a browser's by
 * Authorizer from a cookie, a minted token's by ApiKeyAuthorizer as a bearer token. The tests of the
 * endpoints rest on that, so it is asserted here rather than taken on trust.
 */
func TestSession(t *testing.T) {
	t.Parallel()

	apiKeyAuthorizer, err := ApiKeyAuthorizer()
	if err != nil {
		t.Fatalf("api key authorizer: %v", err)
	}

	account := &Account{Id: "11111111-1111-1111-1111-111111111111", EmailAddress: "session@example.com", Roles: []string{"user"}}

	browser := account.Session()
	minted := account.Session()
	minted.AuthenticationMethods = []string{authentication_method.ApiKey}

	testCases := []struct {
		name       string
		session    *Session
		authorizer *authorizer_request_parser.Parser
		asCookie   bool
		accepted   bool
	}{
		{name: "a browser's, by the browser authorizer", session: browser, authorizer: Authorizer, asCookie: true, accepted: true},
		{name: "a browser's, by the api key authorizer", session: browser, authorizer: apiKeyAuthorizer},
		{name: "a minted one, by the api key authorizer", session: minted, authorizer: apiKeyAuthorizer, accepted: true},
		{name: "a minted one, by the browser authorizer", session: minted, authorizer: Authorizer, asCookie: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}

			if testCase.asCookie {
				cookie, err := testCase.session.Cookie()
				if err != nil {
					t.Fatalf("cookie: %v", err)
				}
				request.Header.Set("Cookie", cookie)
			} else {
				token, err := testCase.session.Token()
				if err != nil {
					t.Fatalf("token: %v", err)
				}
				request.Header.Set("Authorization", "Bearer "+token)
			}

			sessionToken, responseError := testCase.authorizer.Parse(request)
			if !testCase.accepted {
				if responseError == nil {
					t.Fatal("The session was accepted.")
				}
				return
			}

			if responseError != nil {
				t.Fatalf("parse: %+v", responseError)
			}
			if sessionToken.SubjectId != account.Id || sessionToken.SubjectEmailAddress != account.EmailAddress {
				t.Errorf("subject: got %q, %q", sessionToken.SubjectId, sessionToken.SubjectEmailAddress)
			}
			if sessionToken.AuthenticationId != UnrecordedAuthenticationId {
				t.Errorf("authentication id: got %q", sessionToken.AuthenticationId)
			}
			if strings.Join(sessionToken.Roles, ",") != "user" {
				t.Errorf("roles: got %v", sessionToken.Roles)
			}
		})
	}
}

func TestSessionManager(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		db      *sql.DB
		wantErr bool
	}{
		{name: "a database", db: &sql.DB{}},
		{name: "none", wantErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			manager, err := SessionManager(testCase.db)
			if (err != nil) != testCase.wantErr {
				t.Fatalf("got error %v, want an error: %t", err, testCase.wantErr)
			}
			if err == nil && (manager.Issuer != Issuer || manager.CookieDomain != Audience) {
				t.Errorf("got issuer %q and audience %q", manager.Issuer, manager.CookieDomain)
			}
		})
	}
}

func TestNewDatabaseRefuses(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		databaseUrl string
		dbName      string
		wantErr     error
	}{
		{name: "no url", dbName: "a_database", wantErr: empty_error.New("database url")},
		{name: "no name", databaseUrl: "postgres://postgres@localhost/postgres", wantErr: empty_error.New("name")},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewDatabase(t.Context(), testCase.databaseUrl, testCase.dbName)
			altshiftTestingCmp.CompareErr(t, err, testCase.wantErr)
		})
	}
}

func TestInsertRefuses(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	if _, err := InsertCustomer(ctx, nil, "a customer"); err == nil {
		t.Error("A customer was inserted into no database.")
	}
	if _, err := InsertAccount(ctx, nil, "a@example.com", ""); err == nil {
		t.Error("An account was inserted into no database.")
	}
	if _, err := (&Account{}).ActiveSession(ctx, nil); err == nil {
		t.Error("A sign-in was inserted into no database.")
	}

	_, err := InsertAccount(ctx, &sql.DB{}, "", "")
	altshiftTestingCmp.CompareErr(t, err, empty_error.New("email address"))

	_, err = InsertCustomer(ctx, &sql.DB{}, "")
	altshiftTestingCmp.CompareErr(t, err, empty_error.New("name"))

	_, err = InsertCustomer(ctx, nil, "a customer")
	altshiftTestingCmp.CompareErr(t, err, nil_error.New("sql db"))
}

// What the tests insert is what the tables then hold, with the customer joined where there is one.
func TestInsertAccount(t *testing.T) {
	t.Parallel()

	db := Db(t)
	ctx := t.Context()

	customerId, err := InsertCustomer(ctx, db, "Example")
	if err != nil {
		t.Fatalf("insert customer: %v", err)
	}

	testCases := []struct {
		name         string
		emailAddress string
		customerId   string
		roles        []string
	}{
		{name: "with a customer and roles", emailAddress: "customer@example.com", customerId: customerId, roles: []string{"admin", "user"}},
		{name: "with neither", emailAddress: "alone@example.com"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			account, err := InsertAccount(ctx, db, testCase.emailAddress, testCase.customerId, testCase.roles...)
			if err != nil {
				t.Fatalf("insert account: %v", err)
			}

			var emailAddress string
			var customer sql.NullString
			var roles string
			if err := db.QueryRowContext(
				ctx,
				`SELECT email_address, customer, array_to_string(roles, ',') FROM account WHERE id = $1;`,
				account.Id,
			).Scan(&emailAddress, &customer, &roles); err != nil {
				t.Fatalf("select account: %v", err)
			}

			if emailAddress != testCase.emailAddress {
				t.Errorf("email address: got %q", emailAddress)
			}
			if customer.String != testCase.customerId {
				t.Errorf("customer: got %q, want %q", customer.String, testCase.customerId)
			}
			if roles != strings.Join(testCase.roles, ",") {
				t.Errorf("roles: got %q, want %v", roles, testCase.roles)
			}

			session, err := account.ActiveSession(ctx, db)
			if err != nil {
				t.Fatalf("active session: %v", err)
			}

			var ended bool
			if err := db.QueryRowContext(
				ctx,
				`SELECT ended FROM authentication WHERE id = $1 AND account = $2 AND expires_at > now();`,
				session.AuthenticationId,
				account.Id,
			).Scan(&ended); err != nil {
				t.Fatalf("the active session's sign-in is not in the database: %v", err)
			}
			if ended {
				t.Error("The active session's sign-in has ended.")
			}
		})
	}
}

// An address is one account's, as the schema has it, whatever case it is written in.
func TestInsertAccountTwice(t *testing.T) {
	t.Parallel()

	db := Db(t)
	ctx := t.Context()

	if _, err := InsertAccount(ctx, db, "twice@example.com", ""); err != nil {
		t.Fatalf("insert account: %v", err)
	}
	if _, err := InsertAccount(ctx, db, "Twice@Example.com", ""); err == nil {
		t.Error("Two accounts were made with one address.")
	}
}

// A database of its own is made with the schema in it, and is gone once it is closed.
func TestNewDatabase(t *testing.T) {
	t.Parallel()

	db := Db(t)
	ctx := t.Context()

	database, err := NewDatabase(ctx, os.Getenv(DatabaseUrlVariable), "api_key_testing_new_database")
	if err != nil {
		t.Fatalf("new database: %v", err)
	}

	var tables int
	if err := database.QueryRowContext(
		ctx,
		`SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';`,
	).Scan(&tables); err != nil {
		t.Fatalf("count tables: %v", err)
	}
	if tables != 6 {
		t.Errorf("got %d tables, want 6", tables)
	}

	if err := database.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	var exists bool
	if err := db.QueryRowContext(
		context.Background(),
		`SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1);`,
		database.name,
	).Scan(&exists); err != nil {
		t.Fatalf("select database: %v", err)
	}
	if exists {
		t.Errorf("The database %s is still there after it was closed.", database.name)
	}
}
