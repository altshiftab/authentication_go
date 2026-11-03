package mint_token_endpoint

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/altshiftab/authentication_go/pkg/api_key/api_key_cruder"
	"github.com/altshiftab/authentication_go/pkg/api_key/assertion"
	"github.com/altshiftab/authentication_go/pkg/api_key/client"
	"github.com/altshiftab/authentication_go/pkg/api_key/public_key"
	apiKeyTesting "github.com/altshiftab/authentication_go/pkg/api_key/testing"
	apiKeyTypes "github.com/altshiftab/authentication_go/pkg/api_key/types"
	"github.com/altshiftab/authentication_go/pkg/session/types/authentication_method"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_manager"
	altshiftCryptoEddsa "github.com/altshiftab/utils_go/pkg/crypto/eddsa"
	altshiftSqlTesting "github.com/altshiftab/utils_go/pkg/database/sql/testing"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
	altshiftJwtToken "github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/token"
	altshiftTestingCmp "github.com/altshiftab/utils_go/pkg/testing/cmp"
)

const testAudience = "https://login.example.test"

func TestMain(m *testing.M) {
	os.Exit(apiKeyTesting.Main(m, "mint_token_endpoint"))
}

func TestInitialize(t *testing.T) {
	t.Parallel()

	emptyDb := altshiftSqlTesting.NewDb()

	manager, err := apiKeyTesting.SessionManager(emptyDb)
	if err != nil {
		t.Fatalf("session manager: %v", err)
	}

	testCases := []struct {
		name     string
		manager  *session_manager.Manager
		db       *sql.DB
		audience string
		wantErr  error
	}{
		{name: "valid arguments", manager: manager, db: emptyDb, audience: testAudience},
		{name: "nil session manager", db: emptyDb, audience: testAudience, wantErr: nil_error.New("session manager")},
		{name: "nil database", manager: manager, audience: testAudience, wantErr: nil_error.New("sql database")},
		{name: "no audience", manager: manager, db: emptyDb, wantErr: empty_error.New("audience")},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint := New()
			err := testEndpoint.Initialize(testCase.manager, testCase.db, testCase.audience)
			altshiftTestingCmp.CompareErr(t, err, testCase.wantErr)

			if err == nil && testEndpoint.TokenLifetime != DefaultTokenLifetime {
				t.Errorf("token lifetime: got %s, want the default %s", testEndpoint.TokenLifetime, DefaultTokenLifetime)
			}
		})
	}
}

// The path is the one the client posts to, so that neither moves without the other.
func TestDefaultPath(t *testing.T) {
	t.Parallel()

	if DefaultPath != client.TokenPath {
		t.Errorf("the endpoint is at %q and the client posts to %q", DefaultPath, client.TokenPath)
	}
	if New().Path != DefaultPath {
		t.Errorf("the endpoint is at %q, want %q", New().Path, DefaultPath)
	}
}

func newSessionManager(t *testing.T, db *sql.DB) *session_manager.Manager {
	t.Helper()

	manager, err := apiKeyTesting.SessionManager(db)
	if err != nil {
		t.Fatalf("session manager: %v", err)
	}

	return manager
}

// assertingClient is a client whose assertions are written out claim by claim, so that a case can
// leave one out or get one wrong, which pkg/api_key/client never does.
type assertingClient struct {
	key    *public_key.Key
	signer *altshiftCryptoEddsa.Method
}

func newAssertingClient(t *testing.T) *assertingClient {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}

	key, err := public_key.FromPublicKey(publicKey)
	if err != nil {
		t.Fatalf("public key from public key: %v", err)
	}

	return &assertingClient{key: key, signer: &altshiftCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey}}
}

// assert is an assertion as a client's own tooling would make it, with the changes made to it.
func (c *assertingClient) assert(t *testing.T, jti string, changes map[string]any) string {
	t.Helper()

	payload := map[string]any{
		"iss": c.key.Id,
		"sub": c.key.Id,
		"aud": testAudience,
		"exp": float64(time.Now().Add(time.Minute).Unix()),
		"iat": float64(time.Now().Unix()),
		"jti": jti,
	}
	for name, value := range changes {
		// A nil takes the claim out rather than setting it to null, which is how a case says the
		// client did not send one at all.
		if value == nil {
			delete(payload, name)
			continue
		}
		payload[name] = value
	}

	tokenString, err := (&altshiftJwtToken.Token{
		Header:  map[string]any{"alg": "EdDSA", "typ": assertion.Type},
		Payload: payload,
	}).Encode(c.signer)
	if err != nil {
		t.Fatalf("token encode: %v", err)
	}

	return tokenString
}

func newAccount(t *testing.T, db *sql.DB, emailAddress string, roles ...string) *apiKeyTesting.Account {
	t.Helper()

	account, err := apiKeyTesting.InsertAccount(t.Context(), db, emailAddress, "", roles...)
	if err != nil {
		t.Fatalf("insert account: %v", err)
	}

	return account
}

func registerKey(t *testing.T, db *sql.DB, accountId string, key *public_key.Key, name string, expiresAt *time.Time) {
	t.Helper()

	if _, err := (&api_key_cruder.Cruder{Database: db}).Create(t.Context(), accountId, key, name, expiresAt); err != nil {
		t.Fatalf("create api key: %v", err)
	}
}

// minted is what a mint request answered with. The response itself does not leave mint: its body is
// read and closed there, so no caller can forget to.
type minted struct {
	StatusCode   int
	CacheControl string
	Body         []byte
}

func mint(t *testing.T, serverUrl string, path string, assertionString string) *minted {
	t.Helper()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, serverUrl+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if assertionString != "" {
		request.Header.Set("Authorization", "Bearer "+assertionString)
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

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	return &minted{
		StatusCode:   response.StatusCode,
		CacheControl: response.Header.Get("Cache-Control"),
		Body:         body,
	}
}

func bearerRequest(t *testing.T, token string) *http.Request {
	t.Helper()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)

	return request
}

/*
 * The whole of API access, end to end: a client that holds a registered key gets a token, and the
 * token is one the services will take -- but only where they have said they take this kind.
 *
 * The authorizer cases are the point of the scheme. A minted token presented to an authorizer built
 * for browser sessions is refused, and a browser's session token presented to an authorizer built
 * for API keys is refused, though both are valid tokens signed by the same key for the same account.
 * Nothing but the "amr" claim separates them. The subtests share one database and one registered
 * key, so they run in sequence.
 */
//
//nolint:tparallel,paralleltest // Subtests share one database and must not run in parallel.
func TestEndpoint(t *testing.T) {
	t.Parallel()

	db := apiKeyTesting.Db(t)

	account := newAccount(t, db, "mint@example.com", "admin", "user")
	c := newAssertingClient(t)
	registerKey(t, db, account.Id, c.key, "a build runner", nil)

	testEndpoint := New()
	if err := testEndpoint.Initialize(newSessionManager(t, db), db, testAudience); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint.Endpoint.Endpoint)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	apiKeyAuthorizer, err := apiKeyTesting.ApiKeyAuthorizer()
	if err != nil {
		t.Fatalf("api key authorizer: %v", err)
	}

	var mintedToken string

	t.Run("a client that can sign for a registered key gets a token", func(t *testing.T) {
		result := mint(t, httpServer.URL, testEndpoint.Path, c.assert(t, "assertion-1", nil))

		if result.StatusCode != http.StatusOK {
			t.Fatalf("got status %d (%s), want %d", result.StatusCode, result.Body, http.StatusOK)
		}

		var token apiKeyTypes.Token
		if err := json.Unmarshal(result.Body, &token); err != nil {
			t.Fatalf("decode token: %v", err)
		}

		if token.TokenType != "Bearer" {
			t.Errorf("token type: got %q", token.TokenType)
		}
		if token.AccessToken == "" {
			t.Fatal("No access token came back.")
		}
		// Minutes, not hours: the lifetime is the window a revoked key's last token still works in.
		if token.ExpiresIn <= 0 || token.ExpiresIn > int(DefaultTokenLifetime.Seconds()) {
			t.Errorf("expires in: got %d seconds", token.ExpiresIn)
		}

		// Nothing in between may keep it.
		if result.CacheControl != "no-store" {
			t.Errorf("cache control: got %q, want no-store", result.CacheControl)
		}

		mintedToken = token.AccessToken
	})

	/*
	 * The floor: a subject, an expiry and an identifier, and none of "iss", "aud" or "iat". Each is
	 * covered on its own in the assertion package; this is the three of them absent at once, over the
	 * whole path, because that is the assertion a client written against the bare minimum makes.
	 */
	t.Run("a client sending only the required claims gets a token", func(t *testing.T) {
		minimal := c.assert(t, "assertion-minimal", map[string]any{"iss": nil, "aud": nil, "iat": nil})

		result := mint(t, httpServer.URL, testEndpoint.Path, minimal)
		if result.StatusCode != http.StatusOK {
			t.Fatalf("got status %d (%s), want %d", result.StatusCode, result.Body, http.StatusOK)
		}

		var token apiKeyTypes.Token
		if err := json.Unmarshal(result.Body, &token); err != nil {
			t.Fatalf("decode token: %v", err)
		}
		if token.AccessToken == "" {
			t.Fatal("No access token came back.")
		}
	})

	t.Run("the token is refused by an authorizer built for browser sessions", func(t *testing.T) {
		if mintedToken == "" {
			t.Skip("nothing was minted")
		}

		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		request.Header.Set("Cookie", "session="+mintedToken)

		if _, responseError := apiKeyTesting.Authorizer.Parse(request); responseError == nil {
			t.Error("A token minted against a key was accepted as a browser session.")
		}
	})

	t.Run("and accepted by one built for API keys, carrying the account's roles", func(t *testing.T) {
		if mintedToken == "" {
			t.Skip("nothing was minted")
		}

		sessionToken, responseError := apiKeyAuthorizer.Parse(bearerRequest(t, mintedToken))
		if responseError != nil {
			t.Fatalf("parse: %+v", responseError)
		}
		if sessionToken.SubjectId != account.Id || sessionToken.SubjectEmailAddress != account.EmailAddress {
			t.Errorf("subject: got %q, %q; want the account", sessionToken.SubjectId, sessionToken.SubjectEmailAddress)
		}
		if !slices.Equal(sessionToken.Roles, account.Roles) {
			t.Errorf("roles: got %v, want the account's %v", sessionToken.Roles, account.Roles)
		}
		if amr := sessionToken.Claims.AuthenticationMethods; !slices.Equal(amr, []string{authentication_method.ApiKey}) {
			t.Errorf("amr: got %v, want [%s]", amr, authentication_method.ApiKey)
		}

		// And the other direction: the browser's own credential is refused here.
		browserToken, err := account.Session().Token()
		if err != nil {
			t.Fatalf("session token: %v", err)
		}
		if _, responseError := apiKeyAuthorizer.Parse(bearerRequest(t, browserToken)); responseError == nil {
			t.Error("A browser's session token was accepted as an API key's.")
		}
	})

	t.Run("the same assertion cannot be presented twice", func(t *testing.T) {
		assertionString := c.assert(t, "assertion-replayed", nil)

		if first := mint(t, httpServer.URL, testEndpoint.Path, assertionString); first.StatusCode != http.StatusOK {
			t.Fatalf("got status %d (%s) for the first presentation", first.StatusCode, first.Body)
		}

		replayed := mint(t, httpServer.URL, testEndpoint.Path, assertionString)
		if replayed.StatusCode != http.StatusBadRequest {
			t.Errorf("got status %d (%s), want %d for a replay", replayed.StatusCode, replayed.Body, http.StatusBadRequest)
		}
	})

	t.Run("a revoked key mints nothing", func(t *testing.T) {
		revokedClient := newAssertingClient(t)
		registerKey(t, db, account.Id, revokedClient.key, "a key to revoke", nil)

		cruder := &api_key_cruder.Cruder{Database: db}
		if err := cruder.RevokeForAccount(t.Context(), account.Id, revokedClient.key.Id); err != nil {
			t.Fatalf("revoke for account: %v", err)
		}

		result := mint(t, httpServer.URL, testEndpoint.Path, revokedClient.assert(t, "assertion-1", nil))
		if result.StatusCode != http.StatusForbidden {
			t.Errorf("got status %d (%s), want %d", result.StatusCode, result.Body, http.StatusForbidden)
		}
	})

	t.Run("an expired key mints nothing", func(t *testing.T) {
		expiredClient := newAssertingClient(t)
		expiredAt := time.Now().Add(-time.Hour)
		registerKey(t, db, account.Id, expiredClient.key, "a key that has expired", &expiredAt)

		result := mint(t, httpServer.URL, testEndpoint.Path, expiredClient.assert(t, "assertion-1", nil))
		if result.StatusCode != http.StatusForbidden {
			t.Errorf("got status %d (%s), want %d", result.StatusCode, result.Body, http.StatusForbidden)
		}
	})

	// Everything that fails before the signature checks out is one answer: which of them it was
	// would say whose keys exist.
	t.Run("what is refused, and how", func(t *testing.T) {
		unregistered := newAssertingClient(t)

		testCases := []struct {
			name            string
			assertionString string
			wantStatusCode  int
		}{
			{
				name:            "an assertion for a key nobody registered",
				assertionString: unregistered.assert(t, "assertion-1", nil),
				wantStatusCode:  http.StatusUnauthorized,
			},
			{
				// Signed by a key that is not the one it names.
				name:            "an assertion signed by another key",
				assertionString: unregistered.assert(t, "assertion-2", map[string]any{"iss": c.key.Id, "sub": c.key.Id}),
				wantStatusCode:  http.StatusUnauthorized,
			},
			{
				name:            "an assertion made for another service",
				assertionString: c.assert(t, "assertion-3", map[string]any{"aud": "https://login.other.test"}),
				wantStatusCode:  http.StatusUnauthorized,
			},
			{
				name:            "an assertion that has expired",
				assertionString: c.assert(t, "assertion-4", map[string]any{"exp": float64(time.Now().Add(-time.Hour).Unix())}),
				wantStatusCode:  http.StatusUnauthorized,
			},
			{
				name:            "no assertion at all",
				assertionString: "",
				wantStatusCode:  http.StatusBadRequest,
			},
			{
				name:            "something that is not a token",
				assertionString: "not-a-token",
				wantStatusCode:  http.StatusUnauthorized,
			},
		}

		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				result := mint(t, httpServer.URL, testEndpoint.Path, testCase.assertionString)
				if result.StatusCode != testCase.wantStatusCode {
					t.Errorf("got status %d (%s), want %d", result.StatusCode, result.Body, testCase.wantStatusCode)
				}
			})
		}
	})
}

/*
 * The holder's side against the service's, with nothing written by hand between them: what
 * pkg/api_key/client signs is what this endpoint verifies, for both kinds of key a holder may have --
 * Ed25519 in a file, P-256 wherever a key manager keeps it -- and what it answers with is what the
 * client reads. The service is named by its origin, as the client names it in a Source.
 */
func TestClient(t *testing.T) {
	t.Parallel()

	db := apiKeyTesting.Db(t)
	account := newAccount(t, db, "client@example.com", "user")

	mux := &muxPkg.Mux{}
	// Unstarted, so that the address the endpoint is told it is at is known before it is served.
	httpServer := httptest.NewUnstartedServer(mux)
	service := &url.URL{Scheme: "http", Host: httpServer.Listener.Addr().String()}

	testEndpoint := New()
	if err := testEndpoint.Initialize(newSessionManager(t, db), db, service.String()); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	mux.Add(testEndpoint.Endpoint.Endpoint)

	httpServer.Start()
	// A cleanup rather than a defer: the subtests run in parallel, after this function has returned.
	t.Cleanup(httpServer.Close)

	apiKeyAuthorizer, err := apiKeyTesting.ApiKeyAuthorizer()
	if err != nil {
		t.Fatalf("api key authorizer: %v", err)
	}

	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa generate key: %v", err)
	}
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}

	testCases := []struct {
		name          string
		signer        crypto.Signer
		wantAlgorithm string
	}{
		{name: "p-256", signer: p256Key, wantAlgorithm: public_key.AlgorithmEs256},
		{name: "ed25519", signer: ed25519Key, wantAlgorithm: public_key.AlgorithmEddsa},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			key, err := public_key.FromPublicKey(testCase.signer.Public())
			if err != nil {
				t.Fatalf("public key from public key: %v", err)
			}
			if key.Algorithm != testCase.wantAlgorithm {
				t.Fatalf("algorithm: got %q, want %q", key.Algorithm, testCase.wantAlgorithm)
			}
			registerKey(t, db, account.Id, key, "a "+testCase.name+" key", nil)

			now := time.Now()
			assertionString, err := client.Assert(testCase.signer, service.String(), now)
			if err != nil {
				t.Fatalf("assert: %v", err)
			}

			token, err := client.Mint(t.Context(), httpServer.Client(), service, assertionString, now)
			if err != nil {
				t.Fatalf("mint: %v", err)
			}
			if token.AccessToken == "" {
				t.Fatal("No access token came back.")
			}
			if lifetime := token.ExpiresAt.Sub(now); lifetime <= 0 || lifetime > DefaultTokenLifetime {
				t.Errorf("the token is good for %s, want at most %s", lifetime, DefaultTokenLifetime)
			}

			sessionToken, responseError := apiKeyAuthorizer.Parse(bearerRequest(t, token.AccessToken))
			if responseError != nil {
				t.Fatalf("parse: %+v", responseError)
			}
			if sessionToken.SubjectId != account.Id {
				t.Errorf("subject: got %q, want the account %q", sessionToken.SubjectId, account.Id)
			}
			if !slices.Equal(sessionToken.Roles, account.Roles) {
				t.Errorf("roles: got %v, want %v", sessionToken.Roles, account.Roles)
			}

			// The client's own assertion presented again is a replay, refused as one.
			if _, err := client.Mint(t.Context(), httpServer.Client(), service, assertionString, now); !errors.Is(err, client.ErrRefused) {
				t.Errorf("got %v for a replayed assertion, want ErrRefused", err)
			}

			// And a Source, which makes a new assertion for every token it mints and keeps the token.
			source := &client.Source{Signer: testCase.signer, Service: service, HttpClient: httpServer.Client()}
			first, err := source.Token(t.Context())
			if err != nil {
				t.Fatalf("source token: %v", err)
			}
			second, err := source.Token(t.Context())
			if err != nil {
				t.Fatalf("source token: %v", err)
			}
			if first == "" || first != second {
				t.Error("The source did not keep the token it minted.")
			}
		})
	}
}
