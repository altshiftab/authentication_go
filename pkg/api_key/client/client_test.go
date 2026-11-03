package client

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/altshiftab/authentication_go/pkg/api_key/assertion"
	"github.com/altshiftab/authentication_go/pkg/api_key/public_key"
)

const audience = "https://login.example.test"

func signers(t *testing.T) map[string]crypto.Signer {
	t.Helper()
	_, eddsaKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]crypto.Signer{"ed25519": eddsaKey, "p-256": ecdsaKey}
}

// What a client signs is what the service verifies: the two halves of the scheme agree, for both
// kinds of key, and an assertion for another service or from long ago is refused.
func TestAssert(t *testing.T) {
	t.Parallel()

	now := time.Now()
	for name, signer := range signers(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			key, err := public_key.FromPublicKey(signer.Public())
			if err != nil {
				t.Fatalf("from public key: %v", err)
			}
			signed, err := Assert(signer, audience, now)
			if err != nil {
				t.Fatalf("assert: %v", err)
			}
			if subject, err := assertion.Subject(signed); err != nil || subject != key.Id {
				t.Errorf("subject %q, %v; want %q", subject, err, key.Id)
			}

			testCases := []struct {
				name     string
				audience string
				at       time.Time
				valid    bool
			}{
				{name: "the service it was made for", audience: audience, at: now, valid: true},
				{name: "another service", audience: "https://login.other.test", at: now},
				{name: "after it has run out", audience: audience, at: now.Add(AssertionLifetime + 2*assertion.Leeway)},
			}
			for _, testCase := range testCases {
				verified, err := assertion.Verify(signed, key, testCase.audience, testCase.at)
				if (err == nil) != testCase.valid {
					t.Errorf("%s: %+v, %v", testCase.name, verified, err)
				}
				if testCase.valid && (verified.KeyId != key.Id || verified.Jti == "") {
					t.Errorf("%s: verified %+v", testCase.name, verified)
				}
			}

			again, err := Assert(signer, audience, now)
			if err != nil {
				t.Fatalf("assert again: %v", err)
			}
			first, _ := assertion.Verify(signed, key, audience, now)
			second, _ := assertion.Verify(again, key, audience, now)
			if first == nil || second == nil || first.Jti == second.Jti {
				t.Error("two assertions share an identifier")
			}
		})
	}
}

func TestAssertRefuses(t *testing.T) {
	t.Parallel()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	testCases := []struct {
		name     string
		signer   crypto.Signer
		audience string
	}{
		{name: "no signer", audience: audience},
		{name: "no audience", signer: signers(t)["p-256"]},
		{name: "an RSA key", signer: rsaKey, audience: audience},
		{name: "a P-384 key", signer: p384Key, audience: audience},
	}
	for _, testCase := range testCases {
		if signed, err := Assert(testCase.signer, testCase.audience, time.Now()); err == nil {
			t.Errorf("%s: signed %q", testCase.name, signed)
		}
	}
}

// tokenService answers the token endpoint as the service does, counting the requests it answers.
func tokenService(t *testing.T, status int, body string) (*url.URL, *atomic.Int32) {
	t.Helper()
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != TokenPath ||
			!strings.HasPrefix(request.Header.Get("Authorization"), "Bearer ey") {
			http.Error(writer, "unexpected request", http.StatusTeapot)
			return
		}
		count.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		_, _ = writer.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	service, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return service, &count
}

func TestMint(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	signed, err := Assert(signers(t)["p-256"], audience, now)
	if err != nil {
		t.Fatal(err)
	}
	testCases := []struct {
		name    string
		status  int
		body    string
		refused bool
	}{
		{name: "a token", status: http.StatusOK, body: `{"access_token":"a.b.c","token_type":"Bearer","expires_in":900}`},
		{name: "a refusal", status: http.StatusUnauthorized, body: `{"detail":"The assertion is not valid."}`, refused: true},
		{name: "an answer of no token", status: http.StatusOK, body: `{"token_type":"Bearer"}`, refused: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			service, _ := tokenService(t, testCase.status, testCase.body)
			token, err := Mint(t.Context(), nil, service, signed, now)
			if testCase.refused {
				if !errors.Is(err, ErrRefused) {
					t.Errorf("%+v, %v", token, err)
				}
				return
			}
			if err != nil || token.AccessToken != "a.b.c" || !token.ExpiresAt.Equal(now.Add(15*time.Minute)) {
				t.Errorf("%+v, %v", token, err)
			}
		})
	}
}

// A token is kept until it is within the margin of its end, and minted again then.
func TestSource(t *testing.T) {
	t.Parallel()

	service, count := tokenService(t, http.StatusOK, `{"access_token":"a.b.c","expires_in":900}`)
	at := time.Now()
	source := &Source{Signer: signers(t)["ed25519"], Service: service, Now: func() time.Time { return at }}

	for _, step := range []struct {
		name  string
		after time.Duration
		mints int32
	}{
		{name: "the first", after: 0, mints: 1},
		{name: "soon after, the same", after: time.Minute, mints: 1},
		{name: "within the margin of its end, a new one", after: 14 * time.Minute, mints: 2},
	} {
		at = at.Add(step.after)
		if token, err := source.Token(t.Context()); err != nil || token != "a.b.c" || count.Load() != step.mints {
			t.Errorf("%s: %q, %v, %d mints", step.name, token, err, count.Load())
		}
	}
}
