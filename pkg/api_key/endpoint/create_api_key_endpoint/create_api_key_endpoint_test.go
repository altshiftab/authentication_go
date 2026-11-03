package create_api_key_endpoint

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json/v2"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/altshiftab/authentication_go/pkg/api_key/api_key_cruder"
	"github.com/altshiftab/authentication_go/pkg/api_key/public_key"
	apiKeyTesting "github.com/altshiftab/authentication_go/pkg/api_key/testing"
	apiKeyTypes "github.com/altshiftab/authentication_go/pkg/api_key/types"
	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser"
	altshiftSqlTesting "github.com/altshiftab/utils_go/pkg/database/sql/testing"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
	altshiftTestingCmp "github.com/altshiftab/utils_go/pkg/testing/cmp"
)

const testRole = "user"

func TestMain(m *testing.M) {
	os.Exit(apiKeyTesting.Main(m, "create_api_key_endpoint"))
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

func encodePublicKey(t *testing.T, publicKey any) string {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal pkix public key: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func newEddsaPublicKey(t *testing.T) string {
	t.Helper()

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}

	return encodePublicKey(t, publicKey)
}

func newAccount(t *testing.T, db *sql.DB, emailAddress string) *apiKeyTesting.Account {
	t.Helper()

	account, err := apiKeyTesting.InsertAccount(t.Context(), db, emailAddress, "", testRole)
	if err != nil {
		t.Fatalf("insert account: %v", err)
	}

	return account
}

func activeSessionCookie(t *testing.T, db *sql.DB, account *apiKeyTesting.Account) (string, string) {
	t.Helper()

	session, err := account.ActiveSession(t.Context(), db)
	if err != nil {
		t.Fatalf("active session: %v", err)
	}

	cookie, err := session.Cookie()
	if err != nil {
		t.Fatalf("cookie: %v", err)
	}

	return cookie, session.AuthenticationId
}

/*
 * Registering a key is a paste and a name: no proof of possession is asked for, as none is asked
 * for an SSH key anywhere else either. What the endpoint does insist on is that the paste is a
 * public key of a kind this service will verify signatures from, that a key is registered once, and
 * that the session registering it is one still standing in the database.
 */
//
//nolint:tparallel,paralleltest // Subtests share one database and must not run in parallel.
func TestEndpoint(t *testing.T) {
	t.Parallel()

	db := apiKeyTesting.Db(t)

	account := newAccount(t, db, "create-api-key@example.com")
	otherAccount := newAccount(t, db, "create-api-key-other@example.com")

	testEndpoint := New()
	if err := testEndpoint.Initialize(apiKeyTesting.Authorizer, db); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint.Endpoint.Endpoint)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	sessionCookie, _ := activeSessionCookie(t, db, account)

	endedSessionCookie, endedAuthenticationId := activeSessionCookie(t, db, account)
	if _, err := db.ExecContext(
		t.Context(),
		`UPDATE authentication SET ended = true, ended_at = now() WHERE id = $1;`,
		endedAuthenticationId,
	); err != nil {
		t.Fatalf("end authentication: %v", err)
	}

	// The request is made here rather than through the mux testing helper, which asserts rather
	// than answers: what these cases need is the status and the body to read.
	register := func(t *testing.T, cookie string, body *apiKeyTypes.CreateApiKey) (int, []byte) {
		t.Helper()

		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("json marshal: %v", err)
		}

		request, err := http.NewRequestWithContext(
			t.Context(),
			http.MethodPost,
			httpServer.URL+testEndpoint.Path,
			bytes.NewReader(data),
		)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		request.Header.Set("Content-Type", "application/json")
		if cookie != "" {
			request.Header.Set("Cookie", cookie)
		}

		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatalf("do request: %v", err)
		}
		if response == nil {
			t.Fatal("The response is nil.")
		}
		defer func() {
			if err := response.Body.Close(); err != nil {
				t.Errorf("close body: %v", err)
			}
		}()

		responseBody, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}

		return response.StatusCode, responseBody
	}

	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa generate key: %v", err)
	}

	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa generate key: %v", err)
	}

	registeredKey := newEddsaPublicKey(t)

	t.Run("a key is registered to the account that asked", func(t *testing.T) {
		statusCode, body := register(t, sessionCookie, &apiKeyTypes.CreateApiKey{
			Name:      "a build runner",
			PublicKey: registeredKey,
		})

		if statusCode != http.StatusCreated {
			t.Fatalf("got status %d (%s), want %d", statusCode, body, http.StatusCreated)
		}

		var key apiKeyTypes.ApiKey
		if err := json.Unmarshal(body, &key); err != nil {
			t.Fatalf("decode key: %v", err)
		}

		if key.Name != "a build runner" || key.Algorithm != public_key.AlgorithmEddsa {
			t.Errorf("got %+v", key)
		}
		// The id is the key's thumbprint, which is what the client will put in its assertions.
		parsed, err := public_key.Parse(registeredKey)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if key.Id != parsed.Id {
			t.Errorf("id: got %q, want the thumbprint %q", key.Id, parsed.Id)
		}

		// And it belongs to the account whose session registered it, not to any other.
		cruder := &api_key_cruder.Cruder{Database: db}
		keys, err := cruder.ReadBulkForAccount(t.Context(), account.Id)
		if err != nil {
			t.Fatalf("read bulk for account: %v", err)
		}
		if len(keys) != 1 || keys[0].Id != parsed.Id {
			t.Errorf("the account's keys are %+v, want the one registered", keys)
		}

		othersKeys, err := cruder.ReadBulkForAccount(t.Context(), otherAccount.Id)
		if err != nil {
			t.Fatalf("read bulk for account: %v", err)
		}
		if len(othersKeys) != 0 {
			t.Errorf("the key landed on another account: %+v", othersKeys)
		}
	})

	t.Run("a P-256 key is registered as ES256", func(t *testing.T) {
		p256PrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa generate key: %v", err)
		}

		statusCode, body := register(t, sessionCookie, &apiKeyTypes.CreateApiKey{
			Name:      "a key in a key manager",
			PublicKey: encodePublicKey(t, &p256PrivateKey.PublicKey),
		})
		if statusCode != http.StatusCreated {
			t.Fatalf("got status %d (%s), want %d", statusCode, body, http.StatusCreated)
		}

		var key apiKeyTypes.ApiKey
		if err := json.Unmarshal(body, &key); err != nil {
			t.Fatalf("decode key: %v", err)
		}
		if key.Algorithm != public_key.AlgorithmEs256 {
			t.Errorf("algorithm: got %q, want %q", key.Algorithm, public_key.AlgorithmEs256)
		}
	})

	t.Run("the same key cannot be registered twice", func(t *testing.T) {
		statusCode, body := register(t, sessionCookie, &apiKeyTypes.CreateApiKey{
			Name:      "the same key again",
			PublicKey: registeredKey,
		})

		if statusCode != http.StatusConflict {
			t.Errorf("got status %d (%s), want %d", statusCode, body, http.StatusConflict)
		}
	})

	t.Run("what is refused", func(t *testing.T) {
		testCases := []struct {
			name           string
			cookie         string
			body           *apiKeyTypes.CreateApiKey
			wantStatusCode int
		}{
			{
				name:           "no session",
				body:           &apiKeyTypes.CreateApiKey{Name: "a key", PublicKey: newEddsaPublicKey(t)},
				wantStatusCode: http.StatusUnauthorized,
			},
			{
				// The token is good, and the sign-in behind it is over: a credential registered in
				// the window before the token expires would outlast the sign-in that made it.
				name:           "a session whose sign-in has ended",
				cookie:         endedSessionCookie,
				body:           &apiKeyTypes.CreateApiKey{Name: "a key", PublicKey: newEddsaPublicKey(t)},
				wantStatusCode: http.StatusUnauthorized,
			},
			{
				// Refused by the body's own schema, before the handler sees it: the fields are
				// required, and a required string is not an empty one.
				name:           "no name",
				cookie:         sessionCookie,
				body:           &apiKeyTypes.CreateApiKey{PublicKey: newEddsaPublicKey(t)},
				wantStatusCode: http.StatusUnprocessableEntity,
			},
			{
				// The schema bounds nothing at the top, so this is the handler's own check.
				name:           "a name of absurd length",
				cookie:         sessionCookie,
				body:           &apiKeyTypes.CreateApiKey{Name: string(make([]byte, 200)), PublicKey: newEddsaPublicKey(t)},
				wantStatusCode: http.StatusBadRequest,
			},
			// The key kinds this service will not verify signatures from. Each parses; each is
			// turned away rather than stored and found useless at the first mint.
			{
				name:           "an RSA key",
				cookie:         sessionCookie,
				body:           &apiKeyTypes.CreateApiKey{Name: "rsa", PublicKey: encodePublicKey(t, &rsaPrivateKey.PublicKey)},
				wantStatusCode: http.StatusBadRequest,
			},
			{
				name:           "a P-384 key",
				cookie:         sessionCookie,
				body:           &apiKeyTypes.CreateApiKey{Name: "p384", PublicKey: encodePublicKey(t, &ecdsaPrivateKey.PublicKey)},
				wantStatusCode: http.StatusBadRequest,
			},
			{
				name:           "something that is not a key",
				cookie:         sessionCookie,
				body:           &apiKeyTypes.CreateApiKey{Name: "nonsense", PublicKey: "ssh-ed25519 AAAA someone@example.com"},
				wantStatusCode: http.StatusBadRequest,
			},
			{
				name:           "no key at all",
				cookie:         sessionCookie,
				body:           &apiKeyTypes.CreateApiKey{Name: "nothing"},
				wantStatusCode: http.StatusUnprocessableEntity,
			},
		}

		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				statusCode, body := register(t, testCase.cookie, testCase.body)
				if statusCode != testCase.wantStatusCode {
					t.Errorf("got status %d (%s), want %d", statusCode, body, testCase.wantStatusCode)
				}
			})
		}
	})
}
