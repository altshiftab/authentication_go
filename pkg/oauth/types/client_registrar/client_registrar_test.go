package client_registrar

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func newRegistrar(t *testing.T, allowLoopback bool) *Registrar {
	t.Helper()
	registrar, err := New(bytes.Repeat([]byte{7}, 32), allowLoopback, GeminiRedirectRules()...)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return registrar
}

const geminiRedirect = "https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-1234567890-vocab"

func TestRegistrar_Register(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		allowLoopback bool
		metadata      *Metadata
		wantErr       error
	}{
		{name: "Gemini CLI", allowLoopback: true, metadata: &Metadata{
			ClientName: "Gemini CLI", RedirectUris: []string{"http://localhost:53682/oauth/callback"},
			TokenEndpointAuthMethod: "none", GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"},
		}},
		{name: "the Gemini app", metadata: &Metadata{ClientName: "Gemini", RedirectUris: []string{geminiRedirect}}},
		{name: "the Gemini app's sandbox", metadata: &Metadata{RedirectUris: []string{
			"https://oauth-redirect-sandbox.googleusercontent.com/r/user_bound_custom-mcp-1-x",
		}}},
		{name: "loopback, not allowed", metadata: &Metadata{RedirectUris: []string{"http://127.0.0.1:1/cb"}}, wantErr: ErrInvalidRedirectUri},
		{name: "a site", allowLoopback: true, metadata: &Metadata{RedirectUris: []string{"https://evil.example/callback"}}, wantErr: ErrInvalidRedirectUri},
		// googleusercontent.com serves what users upload: only the redirect hosts, whole.
		{name: "another googleusercontent host", metadata: &Metadata{RedirectUris: []string{
			"https://evil.googleusercontent.com/r/user_bound_custom-mcp-1-x",
		}}, wantErr: ErrInvalidRedirectUri},
		{name: "another path on the redirect host", metadata: &Metadata{RedirectUris: []string{
			"https://oauth-redirect.googleusercontent.com/r/other",
		}}, wantErr: ErrInvalidRedirectUri},
		{name: "a further segment", metadata: &Metadata{RedirectUris: []string{geminiRedirect + "/more"}}, wantErr: ErrInvalidRedirectUri},
		{name: "a dotted segment", metadata: &Metadata{RedirectUris: []string{
			"https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-/../../x",
		}}, wantErr: ErrInvalidRedirectUri},
		{name: "an escaped slash", metadata: &Metadata{RedirectUris: []string{geminiRedirect + "%2F..%2Fx"}}, wantErr: ErrInvalidRedirectUri},
		{name: "a query", metadata: &Metadata{RedirectUris: []string{geminiRedirect + "?next=x"}}, wantErr: ErrInvalidRedirectUri},
		{name: "a port", metadata: &Metadata{RedirectUris: []string{
			"https://oauth-redirect.googleusercontent.com:8443/r/user_bound_custom-mcp-1-x",
		}}, wantErr: ErrInvalidRedirectUri},
		{name: "http", metadata: &Metadata{RedirectUris: []string{
			"http://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-1-x",
		}}, wantErr: ErrInvalidRedirectUri},
		{name: "one good, one not", metadata: &Metadata{RedirectUris: []string{geminiRedirect, "https://evil.example/cb"}}, wantErr: ErrInvalidRedirectUri},
		{name: "no redirect uris", metadata: &Metadata{ClientName: "x"}, wantErr: ErrInvalidRedirectUri},
		{name: "a confidential client", metadata: &Metadata{RedirectUris: []string{geminiRedirect}, TokenEndpointAuthMethod: "client_secret_basic"}, wantErr: ErrInvalidMetadata},
		{name: "another grant", metadata: &Metadata{RedirectUris: []string{geminiRedirect}, GrantTypes: []string{"client_credentials"}}, wantErr: ErrInvalidMetadata},
		{name: "the implicit flow", metadata: &Metadata{RedirectUris: []string{geminiRedirect}, ResponseTypes: []string{"token"}}, wantErr: ErrInvalidMetadata},
		{name: "a name too long", metadata: &Metadata{RedirectUris: []string{geminiRedirect}, ClientName: strings.Repeat("x", 101)}, wantErr: ErrInvalidMetadata},
		{name: "nothing", metadata: nil, wantErr: ErrInvalidMetadata},
		{name: "a redirect uri too long", allowLoopback: true, metadata: &Metadata{RedirectUris: []string{
			"http://localhost/" + strings.Repeat("x", 600),
		}}, wantErr: ErrInvalidRedirectUri},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			registrar := newRegistrar(t, testCase.allowLoopback)
			registered, issuedAt, err := registrar.Register(testCase.metadata)
			if testCase.wantErr != nil {
				if !errors.Is(err, testCase.wantErr) {
					t.Errorf("%s: %+v, %v, want %v", testCase.name, registered, err, testCase.wantErr)
				}
				return
			}
			if err != nil || registered == nil || issuedAt == 0 || !registered.SelfRegistered || !strings.HasPrefix(registered.Id, IdPrefix) {
				t.Fatalf("%s: %+v, %v", testCase.name, registered, err)
			}

			// The id is all there is: read back, it is the client registered.
			resolved, err := registrar.Resolve(registered.Id)
			if err != nil || resolved == nil || resolved.Name != registered.Name || len(resolved.RedirectUris) != len(testCase.metadata.RedirectUris) ||
				!resolved.SelfRegistered || !resolved.AllowsRedirectUri(testCase.metadata.RedirectUris[0]) {
				t.Errorf("%s: resolved %+v, %v", testCase.name, resolved, err)
			}
		})
	}
}

func TestRegistrar_Resolve(t *testing.T) {
	t.Parallel()

	registrar := newRegistrar(t, true)
	registered, _, err := registrar.Register(&Metadata{ClientName: "Gemini CLI", RedirectUris: []string{"http://localhost:7777/oauth/callback"}})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	payload, signature, _ := strings.Cut(strings.TrimPrefix(registered.Id, IdPrefix), ".")

	other, err := New(bytes.Repeat([]byte{8}, 32), true)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	forged, _, err := other.Register(&Metadata{ClientName: "Gemini CLI", RedirectUris: []string{"https://evil.example/cb"}})
	if err == nil {
		t.Fatalf("registered a site: %+v", forged)
	}

	testCases := []struct {
		name     string
		clientId string
	}{
		{name: "the signature of another key", clientId: func() string {
			id, _, _ := other.Register(&Metadata{RedirectUris: []string{"http://localhost/cb"}})
			return id.Id
		}()},
		{name: "a changed payload", clientId: IdPrefix + payload + "x." + signature},
		{name: "no signature", clientId: IdPrefix + payload},
		{name: "a signature that is not base64", clientId: IdPrefix + payload + ".!!"},
		{name: "not one of its ids", clientId: "https://claude.ai/oauth/mcp-oauth-client-metadata"},
		{name: "nothing", clientId: ""},
	}
	for _, testCase := range testCases {
		if resolved, err := registrar.Resolve(testCase.clientId); !errors.Is(err, ErrUnknownClient) {
			t.Errorf("%s: %+v, %v, want ErrUnknownClient", testCase.name, resolved, err)
		}
	}

	if !registrar.Allows(registered.Id) || registrar.Allows("https://claude.ai/x") {
		t.Error("allows")
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	if _, err := New(make([]byte, 16), true); !errors.Is(err, ErrKeyTooShort) {
		t.Errorf("a short key: %v", err)
	}
	if _, err := New(make([]byte, 32), true, &RedirectRule{Host: "x.example", PathPrefix: "no-slash"}); err == nil {
		t.Error("a rule whose prefix is no path")
	}
	if _, err := New(make([]byte, 32), true, &RedirectRule{PathPrefix: "/x"}); err == nil {
		t.Error("a rule of no host")
	}
	if _, err := New(make([]byte, 32), false, nil); err != nil {
		t.Errorf("a nil rule: %v", err)
	}
}

// The rules in force are the ones a client is held to, whatever they were when it registered: a
// loopback address registered while the registrar allowed them is refused once it no longer does.
func TestRegistrar_Resolve_RulesInForce(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{7}, 32)
	before, err := New(key, true, GeminiRedirectRules()...)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	loopback, _, err := before.Register(&Metadata{RedirectUris: []string{"http://localhost/cb"}})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	both, _, err := before.Register(&Metadata{RedirectUris: []string{"http://localhost/cb", geminiRedirect}})
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	after, err := New(key, false, GeminiRedirectRules()...)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if resolved, err := after.Resolve(loopback.Id); !errors.Is(err, ErrUnknownClient) {
		t.Errorf("a loopback client once loopback is refused: %+v, %v", resolved, err)
	}
	resolved, err := after.Resolve(both.Id)
	if err != nil || len(resolved.RedirectUris) != 1 || resolved.RedirectUris[0] != geminiRedirect || resolved.AllowsRedirectUri("http://localhost/cb") {
		t.Errorf("a client with an address still allowed: %+v, %v", resolved, err)
	}
}
