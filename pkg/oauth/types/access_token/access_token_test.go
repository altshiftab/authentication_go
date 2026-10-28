package access_token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	altshiftCryptoEddsa "github.com/altshiftab/utils_go/pkg/crypto/eddsa"
)

func token() *Token {
	now := time.Unix(1_800_000_000, 0)
	return &Token{
		Issuer: "https://login.example.test", Subject: "an-account", Audience: "https://vocab.example.test/mcp",
		ClientId: "a-client", Scopes: []string{"vocab", "vocab:write"}, Id: "a-token-id",
		IssuedAt: now, ExpiresAt: now.Add(15 * time.Minute),
	}
}

func decode(t *testing.T, segment string) map[string]any {
	t.Helper()
	data, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return decoded
}

func TestMint(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}
	signer := &altshiftCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey}

	encoded, err := Mint(token(), signer, "oauth-1")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	parts := strings.Split(encoded, ".")
	if len(parts) != 3 {
		t.Fatalf("not a jws: %s", encoded)
	}

	header, payload := decode(t, parts[0]), decode(t, parts[1])
	if header["typ"] != Type || header["kid"] != "oauth-1" || header["alg"] != "EdDSA" {
		t.Errorf("header %v", header)
	}
	// What a session token has and a service accepting sessions requires, none of it.
	for _, claim := range []string{"amr", "roles", "email", "azp"} {
		if _, ok := payload[claim]; ok {
			t.Errorf("the token carries %s: %v", claim, payload)
		}
	}
	if payload["scope"] != "vocab vocab:write" || payload["sub"] != "an-account" || payload["aud"] != "https://vocab.example.test/mcp" {
		t.Errorf("payload %v", payload)
	}

	read, err := FromPayload(payload)
	if err != nil {
		t.Fatalf("from payload: %v", err)
	}
	if read.Subject != "an-account" || read.ClientId != "a-client" || len(read.Scopes) != 2 || !read.HasScope("vocab:write") ||
		!read.ExpiresAt.Equal(token().ExpiresAt) || read.KeyThumbprint != "" {
		t.Errorf("read back %+v", read)
	}

	testCases := []struct {
		name   string
		mutate func(*Token)
	}{
		{name: "no subject", mutate: func(token *Token) { token.Subject = "" }},
		{name: "no audience", mutate: func(token *Token) { token.Audience = "" }},
		{name: "no issuer", mutate: func(token *Token) { token.Issuer = "" }},
		{name: "no expiry", mutate: func(token *Token) { token.ExpiresAt = time.Time{} }},
	}
	for _, testCase := range testCases {
		incomplete := token()
		testCase.mutate(incomplete)
		if _, err := Mint(incomplete, signer, "oauth-1"); err == nil {
			t.Errorf("%s: minted", testCase.name)
		}
	}
	if _, err := Mint(token(), nil, "oauth-1"); err == nil {
		t.Error("minted without a signer")
	}
}

func TestFromPayload(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		payload map[string]any
		wantErr bool
		want    func(*Token) bool
	}{
		{
			name:    "bound to a key",
			payload: map[string]any{"sub": "a", "aud": "r", "cnf": map[string]any{"jkt": "thumb"}},
			want:    func(token *Token) bool { return token.KeyThumbprint == "thumb" },
		},
		{
			name:    "one audience in a list",
			payload: map[string]any{"sub": "a", "aud": []any{"r"}},
			want:    func(token *Token) bool { return token.Audience == "r" },
		},
		{name: "several audiences", payload: map[string]any{"sub": "a", "aud": []any{"r", "s"}}, wantErr: true},
		{name: "no subject", payload: map[string]any{"aud": "r"}, wantErr: true},
		{name: "nothing", payload: nil, wantErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			read, err := FromPayload(testCase.payload)
			if testCase.wantErr {
				if err == nil {
					t.Errorf("%s: read %+v", testCase.name, read)
				}
				return
			}
			if err != nil || !testCase.want(read) {
				t.Errorf("%s: %+v, %v", testCase.name, read, err)
			}
		})
	}
}
