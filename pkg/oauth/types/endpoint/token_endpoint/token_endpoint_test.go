package token_endpoint

import (
	"crypto/ed25519"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/altshiftab/authentication_go/pkg/oauth"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/memory_store"
	"github.com/altshiftab/authentication_go/pkg/pkce"
	altshiftCryptoEddsa "github.com/altshiftab/utils_go/pkg/crypto/eddsa"
)

const (
	resource  = "https://vocab.example.test/mcp"
	accountId = "an-account"
	clientId  = "a-client"
	verifier  = "a-code-verifier-of-at-least-forty-three-characters-xyz"
)

func newEndpoint(t *testing.T, store oauth.Store, now *time.Time) *Endpoint {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}
	endpoint := New()
	endpoint.now = func() time.Time { return *now }
	if err := endpoint.Initialize("https://login.example.test", &altshiftCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey}, "oauth-1", store,
		[]*oauth.Resource{{Url: resource, Scopes: []string{"vocab"}}}); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	return endpoint
}

func post(t *testing.T, endpoint *Endpoint, form url.Values) (int, map[string]any) {
	t.Helper()

	response, responseError := endpoint.Handler(httptest.NewRequestWithContext(t.Context(), http.MethodPost, DefaultPath, nil), []byte(form.Encode()))
	if responseError != nil || response == nil {
		t.Fatalf("handler: %+v", responseError)
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body, &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	status := response.StatusCode
	if status == 0 {
		status = http.StatusOK
	}
	return status, body
}

// Time is what the flow test cannot set: a code past its minute, and a grant past its lifetime
// however recently its refresh token was renewed.
func TestEndpoint_Lifetimes(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	store := memory_store.New(accountId)
	endpoint := newEndpoint(t, store, &now)

	insertCode := func(code string, expiresAt time.Time) {
		if err := store.InsertAuthorizationCode(t.Context(), oauth.HashSecret(code), &oauth.AuthorizationCode{
			AccountId: accountId, ClientId: clientId, RedirectUri: "https://client.example.test/cb",
			CodeChallenge: pkce.ChallengeS256(verifier), Resource: resource, Scope: "vocab", ExpiresAt: expiresAt,
		}); err != nil {
			t.Fatalf("insert code: %v", err)
		}
	}
	redeem := func(code string) (int, map[string]any) {
		return post(t, endpoint, url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientId},
			"redirect_uri": {"https://client.example.test/cb"}, "code_verifier": {verifier},
		})
	}

	insertCode("expired", now.Add(-time.Second))
	if status, body := redeem("expired"); status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("an expired code: %d %v", status, body)
	}

	insertCode("good", now.Add(time.Minute))
	status, body := redeem("good")
	if status != http.StatusOK {
		t.Fatalf("redeem: %d %v", status, body)
	}
	refreshToken, _ := body["refresh_token"].(string)

	// Renewed every day, the grant still ends at its lifetime from when it was given.
	for day := 1; ; day++ {
		now = now.Add(24 * time.Hour)
		status, body := post(t, endpoint, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {clientId}})
		if time.Duration(day)*24*time.Hour < DefaultGrantLifetime {
			if status != http.StatusOK {
				t.Fatalf("day %d: %d %v", day, status, body)
			}
			refreshToken, _ = body["refresh_token"].(string)
			continue
		}
		if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
			t.Errorf("day %d, past the grant's lifetime: %d %v", day, status, body)
		}
		break
	}
}

func TestEndpoint_Masks(t *testing.T) {
	t.Parallel()

	now := time.Now()
	endpoint := newEndpoint(t, memory_store.New(), &now)

	bodyFields, err := endpoint.MaskedBodyFields()
	if err != nil || bodyFields == nil || len(bodyFields.Request) != 1 || len(bodyFields.Response) != 1 {
		t.Fatalf("masked body fields %+v, %v", bodyFields, err)
	}
	if !slices.Contains(bodyFields.Request[0].Fields, "code_verifier") || !slices.Contains(bodyFields.Request[0].Fields, "refresh_token") ||
		bodyFields.Request[0].Url.Path != DefaultPath {
		t.Errorf("request fields %+v", bodyFields.Request[0])
	}
	if !slices.Contains(bodyFields.Response[0].Fields, "access_token") || !slices.Contains(bodyFields.Response[0].Fields, "refresh_token") {
		t.Errorf("response fields %+v", bodyFields.Response[0])
	}
}

func TestEndpoint_Initialize(t *testing.T) {
	t.Parallel()

	signer := &altshiftCryptoEddsa.Method{}
	resources := []*oauth.Resource{{Url: resource}}
	if err := New().Initialize("", signer, "k", memory_store.New(), resources); err == nil {
		t.Error("initialized without an issuer")
	}
	if err := New().Initialize("https://i", nil, "k", memory_store.New(), resources); err == nil {
		t.Error("initialized without a signer")
	}
	if err := New().Initialize("https://i", signer, "k", nil, resources); err == nil {
		t.Error("initialized without a store")
	}
	if err := New().Initialize("https://i", signer, "k", memory_store.New(), nil); err == nil {
		t.Error("initialized without resources")
	}
}
