// Package testing is what the API key packages' tests share: a database of a test package's own, on
// the server TEST_DATABASE_URL names, with the library's tables in it; accounts in it; and session
// tokens for them, signed by a key the tests hold, as a browser or a minted token would carry them.
//
// It is the one package of the library that reaches a database through a driver, and nothing but
// tests imports it, so a service importing the library is not made to build pgx unless it already
// does.
package testing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/altshiftab/authentication_go/pkg/database/types/account"
	"github.com/altshiftab/authentication_go/pkg/database/types/api_key"
	"github.com/altshiftab/authentication_go/pkg/database/types/api_key_assertion"
	"github.com/altshiftab/authentication_go/pkg/database/types/api_key_authentication"
	"github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	"github.com/altshiftab/authentication_go/pkg/database/types/customer"
	"github.com/altshiftab/authentication_go/pkg/session/types/authentication_method"
	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser"
	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser/authorizer_request_parser_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_manager"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
	altshiftContext "github.com/altshiftab/utils_go/pkg/context"
	altshiftCryptoEddsa "github.com/altshiftab/utils_go/pkg/crypto/eddsa"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/token_cookie_extractor/token_cookie_extractor_config"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/token_header_extractor"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claim_strings"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claims/registered_claims"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claims/session_claims"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/numeric_date"
	"github.com/altshiftab/utils_go/pkg/type_export/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// DatabaseUrlVariable names the server the tests run against, as a postgres:// URL of a role that may
// create databases. Without it, the tests that need a database skip.
const DatabaseUrlVariable = "TEST_DATABASE_URL"

const (
	// Issuer is what the sessions here are issued by, and what Authorizer expects.
	Issuer = "https://login.example.test"
	// Audience is what the sessions here are for: the cookie domain of the session manager.
	Audience = "example.test"
)

var (
	// SessionMethod signs the sessions made here and verifies them in the authorizers.
	SessionMethod *altshiftCryptoEddsa.Method

	// Authorizer is an authorizer as an endpoint for a signed-in person has one: the session in a
	// cookie, and the browser's ways of signing in and no other.
	Authorizer *authorizer_request_parser.Parser
)

// extensions are what the tables need beyond PostgreSQL itself: gen_random_bytes for a customer's id,
// and citext for an email address.
var extensions = []string{"pgcrypto", "citext"}

// Schema is the SQL the library's tables generate: an account with its customer, its sign-ins, and
// the keys it registers with what they mint.
func Schema() (string, error) {
	tables, err := postgres.Convert(
		customer.Customer{},
		account.Account{},
		authentication.Authentication{},
		api_key.ApiKey{},
		api_key_assertion.ApiKeyAssertion{},
		api_key_authentication.ApiKeyAuthentication{},
	)
	if err != nil {
		return "", fmt.Errorf("postgres convert: %w", err)
	}

	var builder strings.Builder
	for _, extension := range extensions {
		builder.WriteString("CREATE EXTENSION IF NOT EXISTS " + extension + ";\n")
	}
	builder.WriteString("\n")
	builder.WriteString(tables)

	return builder.String(), nil
}

// Database is a database made for one test package, dropped again when it is closed.
type Database struct {
	*sql.DB

	name  string
	admin *sql.DB
}

/*
 * NewDatabase makes a database of its own on the server databaseUrl reaches and applies Schema to it.
 *
 * It is named after name with a random suffix, so that two runs side by side -- the packages of one
 * `go test ./...`, or two of those -- never share one. The connection databaseUrl makes is kept for
 * dropping it again.
 */
func NewDatabase(ctx context.Context, databaseUrl string, name string) (*Database, error) {
	if databaseUrl == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("database url"))
	}

	if name == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("name"))
	}

	// Before anything is made that would have to be dropped again.
	schema, err := Schema()
	if err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}

	// The error says why the URL could not be read and not what it was: it holds a password.
	adminConfig, err := pgx.ParseConfig(databaseUrl)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: pgx parse config", altshiftErrors.ErrParseError))
	}
	if adminConfig == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("pgx config"))
	}

	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("rand read: %w", err))
	}
	databaseName := strings.ToLower(name) + "_" + hex.EncodeToString(suffix)

	admin := stdlib.OpenDB(*adminConfig)
	if admin == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql db (admin)"))
	}

	database := &Database{name: databaseName, admin: admin}

	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+pgx.Identifier{databaseName}.Sanitize()); err != nil {
		_ = admin.Close()
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql db exec context (create database): %w", err), databaseName)
	}

	testConfig := adminConfig.Copy()
	testConfig.Database = databaseName
	database.DB = stdlib.OpenDB(*testConfig)
	if database.DB == nil {
		wrappedErr := altshiftErrors.NewWithTrace(nil_error.New("sql db (test)"))
		if dropErr := database.drop(ctx); dropErr != nil {
			return nil, fmt.Errorf("%w (and drop: %w)", wrappedErr, dropErr)
		}
		return nil, wrappedErr
	}

	if _, err := database.ExecContext(ctx, schema); err != nil {
		wrappedErr := altshiftErrors.NewWithTrace(fmt.Errorf("sql db exec context (schema): %w", err), databaseName)
		if dropErr := database.drop(ctx); dropErr != nil {
			return nil, fmt.Errorf("%w (and drop: %w)", wrappedErr, dropErr)
		}
		return nil, wrappedErr
	}

	return database, nil
}

// Close closes the database's connections and drops it. It is not given a context: it is what a test
// package does once its tests are done, by when theirs have ended.
func (database *Database) Close() error {
	return database.drop(context.Background())
}

func (database *Database) drop(ctx context.Context) error {
	if database.DB != nil {
		if err := database.DB.Close(); err != nil {
			return altshiftErrors.NewWithTrace(fmt.Errorf("sql db close: %w", err))
		}
	}

	if database.admin == nil {
		return nil
	}
	defer func() { _ = database.admin.Close() }()

	if _, err := database.admin.ExecContext(
		ctx,
		"DROP DATABASE IF EXISTS "+pgx.Identifier{database.name}.Sanitize()+" WITH (FORCE)",
	); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("sql db exec context (drop database): %w", err), database.name)
	}

	return nil
}

// packageDatabase is the database Main made for the running test package, if it made one.
var packageDatabase *Database

/*
 * Main is a test package's TestMain, as os.Exit(Main(m, "package_name")).
 *
 * Where DatabaseUrlVariable names a server, the package's tests run with a database of their own,
 * which Db hands out; where it does not, they run without one, and Db skips the tests that would
 * have used it. The tests that need no database run either way.
 */
func Main(m *testing.M, name string) int {
	if m == nil {
		return 1
	}

	databaseUrl := os.Getenv(DatabaseUrlVariable)
	if databaseUrl == "" {
		return m.Run()
	}

	database, err := NewDatabase(context.Background(), databaseUrl, name)
	if err != nil {
		slog.ErrorContext(
			altshiftContext.WithError(context.Background(), err),
			"An error occurred when making the test database.",
		)
		return 1
	}

	packageDatabase = database
	code := m.Run()

	if err := database.Close(); err != nil {
		slog.WarnContext(
			altshiftContext.WithError(context.Background(), err),
			"An error occurred when dropping the test database.",
		)
	}

	return code
}

// Db is the database Main made for the test package, and skips the test when it made none.
func Db(t testing.TB) *sql.DB {
	t.Helper()

	if packageDatabase == nil || packageDatabase.DB == nil {
		t.Skipf("%s is not set", DatabaseUrlVariable)
	}

	return packageDatabase.DB
}

// Account is an account as the tests make one.
type Account struct {
	Id           string
	EmailAddress string
	CustomerId   string
	Roles        []string
}

// InsertCustomer makes a customer, which an account belongs to when it is given one.
func InsertCustomer(ctx context.Context, db *sql.DB, name string) (string, error) {
	if db == nil {
		return "", altshiftErrors.NewWithTrace(nil_error.New("sql db"))
	}

	if name == "" {
		return "", altshiftErrors.NewWithTrace(empty_error.New("name"))
	}

	var customerId string
	if err := db.QueryRowContext(
		ctx,
		`INSERT INTO customer (name) VALUES ($1) RETURNING id;`,
		name,
	).Scan(&customerId); err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("sql row scan (insert customer): %w", err), name)
	}

	return customerId, nil
}

// InsertAccount makes an account with the roles, belonging to the customer where one is named.
func InsertAccount(
	ctx context.Context,
	db *sql.DB,
	emailAddress string,
	customerId string,
	roles ...string,
) (*Account, error) {
	if db == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql db"))
	}

	if emailAddress == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("email address"))
	}

	// The column takes no NULL, which is what a nil slice is sent as.
	if roles == nil {
		roles = []string{}
	}

	var customerArg any
	if customerId != "" {
		customerArg = customerId
	}

	var accountId string
	if err := db.QueryRowContext(
		ctx,
		`INSERT INTO account (email_address, customer, roles) VALUES ($1, $2, $3) RETURNING id;`,
		emailAddress,
		customerArg,
		roles,
	).Scan(&accountId); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql row scan (insert account): %w", err), emailAddress)
	}

	return &Account{Id: accountId, EmailAddress: emailAddress, CustomerId: customerId, Roles: roles}, nil
}

// UnrecordedAuthenticationId is the sign-in a session names when nothing about it is in the database:
// enough for an endpoint that judges the token alone, and refused by one that looks the sign-in up.
const UnrecordedAuthenticationId = "00000000-0000-0000-0000-000000000000"

// Session is a session token's subject and the sign-in it names.
type Session struct {
	AccountId        string
	EmailAddress     string
	AuthenticationId string
	Roles            []string

	// AuthenticationMethods is the token's "amr"; a browser's sign-in where it is left empty.
	AuthenticationMethods []string
}

// Session is a session for the account, naming a sign-in that is not in the database.
func (account *Account) Session() *Session {
	return &Session{
		AccountId:        account.Id,
		EmailAddress:     account.EmailAddress,
		AuthenticationId: UnrecordedAuthenticationId,
		Roles:            account.Roles,
	}
}

// ActiveSession is a session for the account whose sign-in is in the database and running, which is
// what an endpoint that checks a session against the database finds standing behind it.
func (account *Account) ActiveSession(ctx context.Context, db *sql.DB) (*Session, error) {
	if db == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("sql db"))
	}

	now := time.Now()

	var authenticationId string
	if err := db.QueryRowContext(
		ctx,
		`INSERT INTO authentication (account, created_at, expires_at) VALUES ($1, $2, $3) RETURNING id;`,
		account.Id,
		now,
		now.Add(time.Hour),
	).Scan(&authenticationId); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("sql row scan (insert authentication): %w", err), account.Id)
	}

	session := account.Session()
	session.AuthenticationId = authenticationId

	return session, nil
}

// Token is the session as a signed session token, good for an hour.
func (session *Session) Token() (string, error) {
	if SessionMethod == nil {
		return "", altshiftErrors.NewWithTrace(nil_error.New("session method"))
	}

	authenticationMethods := session.AuthenticationMethods
	if len(authenticationMethods) == 0 {
		authenticationMethods = []string{authentication_method.Sso}
	}

	now := time.Now()

	sessionToken, err := session_token.Parse(
		&session_claims.Claims{
			Claims: registered_claims.Claims{
				Issuer:    Issuer,
				Subject:   session.AccountId + ":" + session.EmailAddress,
				Audience:  claim_strings.ClaimStrings{Audience},
				ExpiresAt: numeric_date.New(now.Add(time.Hour)),
				NotBefore: numeric_date.New(now),
				IssuedAt:  numeric_date.New(now),
				Id:        session.AuthenticationId + ":" + rand.Text(),
			},
			AuthenticationMethods: authenticationMethods,
			AuthenticatedAt:       numeric_date.New(now),
			Roles:                 session.Roles,
		},
	)
	if err != nil {
		return "", fmt.Errorf("session token parse: %w", err)
	}
	if sessionToken == nil {
		return "", altshiftErrors.NewWithTrace(nil_error.New("session token"))
	}

	sessionTokenString, err := sessionToken.Encode(SessionMethod)
	if err != nil {
		return "", altshiftErrors.New(fmt.Errorf("session token encode: %w", err), sessionToken)
	}

	return sessionTokenString, nil
}

// Cookie is the session as the value of a Cookie header, which is how a browser presents it.
func (session *Session) Cookie() (string, error) {
	sessionTokenString, err := session.Token()
	if err != nil {
		return "", fmt.Errorf("token: %w", err)
	}

	return token_cookie_extractor_config.DefaultName + "=" + sessionTokenString, nil
}

// SessionManager mints sessions signed by SessionMethod, issued by Issuer for Audience.
func SessionManager(db *sql.DB) (*session_manager.Manager, error) {
	manager, err := session_manager.New(SessionMethod, db, Issuer, Audience)
	if err != nil {
		return nil, fmt.Errorf("session manager new: %w", err)
	}

	return manager, nil
}

// ApiKeyAuthorizer is an authorizer as an endpoint for API clients has one: the token as a bearer
// token, minted against a key and in no other way.
func ApiKeyAuthorizer() (*authorizer_request_parser.Parser, error) {
	authorizer, err := authorizer_request_parser.New(
		SessionMethod,
		Issuer,
		Audience,
		authorizer_request_parser_config.WithTokenExtractor(token_header_extractor.New()),
		authorizer_request_parser_config.WithAuthenticationMethods(authentication_method.ApiKey),
	)
	if err != nil {
		return nil, fmt.Errorf("authorizer request parser new: %w", err)
	}

	return authorizer, nil
}

func init() {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(fmt.Errorf("ed25519 generate key: %w", err))
	}
	SessionMethod = &altshiftCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey}

	Authorizer, err = authorizer_request_parser.New(SessionMethod, Issuer, Audience)
	if err != nil {
		panic(fmt.Errorf("authorizer request parser new: %w", err))
	}
}
