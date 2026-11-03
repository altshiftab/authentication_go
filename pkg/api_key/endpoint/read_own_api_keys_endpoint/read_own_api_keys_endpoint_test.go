package read_own_api_keys_endpoint

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/altshiftab/authentication_go/pkg/api_key/api_key_cruder"
	"github.com/altshiftab/authentication_go/pkg/api_key/public_key"
	apiKeyTesting "github.com/altshiftab/authentication_go/pkg/api_key/testing"
	apiKeyTypes "github.com/altshiftab/authentication_go/pkg/api_key/types"
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
	os.Exit(apiKeyTesting.Main(m, "read_own_api_keys_endpoint"))
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

// read is a GET of the endpoint with the cookie, answering with the status and the body.
func read(t *testing.T, url string, cookie string) (int, []byte) {
	t.Helper()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Cookie", cookie)

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

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	return response.StatusCode, body
}

// The account's own keys and nobody else's, and nothing of the key material in what comes back.
func TestEndpoint(t *testing.T) {
	t.Parallel()

	db := apiKeyTesting.Db(t)

	account := newAccount(t, db, "read-api-keys@example.com")
	otherAccount := newAccount(t, db, "read-api-keys-other@example.com")
	emptyAccount := newAccount(t, db, "read-api-keys-empty@example.com")

	keyId := createKey(t, db, account.Id, "a build runner")
	othersKeyId := createKey(t, db, otherAccount.Id, "somebody else's")

	testEndpoint := New()
	if err := testEndpoint.Initialize(apiKeyTesting.Authorizer, db); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint.Endpoint.Endpoint)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	sessionCookie, err := account.Session().Cookie()
	if err != nil {
		t.Fatalf("cookie: %v", err)
	}

	statusCode, body := read(t, httpServer.URL+testEndpoint.Path, sessionCookie)
	if statusCode != http.StatusOK {
		t.Fatalf("got status %d (%s)", statusCode, body)
	}

	var keys []*apiKeyTypes.ApiKey
	if err := json.Unmarshal(body, &keys); err != nil {
		t.Fatalf("decode keys: %v", err)
	}

	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	if keys[0].Id != keyId {
		t.Errorf("id: got %q, want %q", keys[0].Id, keyId)
	}
	if keys[0].Id == othersKeyId {
		t.Error("Another account's key was listed.")
	}
	if keys[0].Name != "a build runner" {
		t.Errorf("name: got %q", keys[0].Name)
	}

	// The key material never leaves the service. Nothing in the answer carries it, which the
	// response type makes so; this is the reading of the bytes that says so.
	for _, unwanted := range []string{"public_key", "BEGIN PUBLIC KEY"} {
		if strings.Contains(string(body), unwanted) {
			t.Errorf("the listing carries key material (%q): %s", unwanted, body)
		}
	}

	// An account with no keys is answered with an empty list rather than null, so that a page can
	// render it without a guard.
	emptyCookie, err := emptyAccount.Session().Cookie()
	if err != nil {
		t.Fatalf("cookie: %v", err)
	}
	statusCode, body = read(t, httpServer.URL+testEndpoint.Path, emptyCookie)
	if statusCode != http.StatusOK || strings.TrimSpace(string(body)) != "[]" {
		t.Errorf("got status %d and %s, want 200 and []", statusCode, body)
	}
}

func TestEndpointWithoutSession(t *testing.T) {
	t.Parallel()

	testEndpoint := New()
	if err := testEndpoint.Initialize(apiKeyTesting.Authorizer, altshiftSqlTesting.NewDb()); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint.Endpoint.Endpoint)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	muxTesting.TestArgs(t, &muxTesting.Args{
		Path:               testEndpoint.Path,
		Method:             testEndpoint.Method,
		ExpectedStatusCode: http.StatusUnauthorized,
		ExpectedProblemDetail: &problem_detail.Detail{
			Detail:    "Missing cookie with token.",
			Extension: map[string]any{"cookie": "session"},
		},
	}, httpServer.URL)
}
