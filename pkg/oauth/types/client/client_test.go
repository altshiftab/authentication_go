package client

import (
	"net/url"
	"testing"
)

func TestClient_AllowsRedirectUri(t *testing.T) {
	t.Parallel()

	c := &Client{
		Id: "https://claude.ai/oauth/mcp",
		RedirectUris: []string{
			"https://claude.ai/api/mcp/auth_callback",
			"http://localhost/callback",
			"se.vvvp.vocab:/oauth2redirect",
		},
	}

	testCases := []struct {
		name string
		uri  string
		want bool
	}{
		{name: "registered exactly", uri: "https://claude.ai/api/mcp/auth_callback", want: true},
		{name: "another path", uri: "https://claude.ai/api/mcp/other", want: false},
		{name: "a query added", uri: "https://claude.ai/api/mcp/auth_callback?x=1", want: false},
		{name: "another host", uri: "https://claude.ai.example.com/api/mcp/auth_callback", want: false},
		{name: "http instead of https", uri: "http://claude.ai/api/mcp/auth_callback", want: false},
		{name: "a loopback port", uri: "http://localhost:53682/callback", want: true},
		{name: "a loopback address on another path", uri: "http://localhost:53682/other", want: false},
		{name: "loopback over https is no loopback", uri: "https://localhost:53682/callback", want: false},
		{name: "another loopback name", uri: "http://127.0.0.1:53682/callback", want: false},
		{name: "a port on a registered https uri", uri: "https://claude.ai:8443/api/mcp/auth_callback", want: false},
		{name: "a loopback uri with a fragment", uri: "http://localhost:53682/callback#x", want: false},
		{name: "an app's own link", uri: "se.vvvp.vocab:/oauth2redirect", want: true},
		{name: "an app's own link, another path", uri: "se.vvvp.vocab:/other", want: false},
		{name: "another app's link", uri: "se.evil.vocab:/oauth2redirect", want: false},
		{name: "nothing", uri: "", want: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := c.AllowsRedirectUri(testCase.uri); got != testCase.want {
				t.Errorf("%s: got %t, want %t", testCase.name, got, testCase.want)
			}
		})
	}
}

func TestIsLoopback(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		uri  string
		want bool
	}{
		{name: "localhost", uri: "http://localhost:53682/callback", want: true},
		{name: "the IPv4 loopback", uri: "http://127.0.0.1/callback", want: true},
		// No Content-Security-Policy can name it, so the consent page could not send the user on.
		{name: "the IPv6 loopback", uri: "http://[::1]:53682/callback"},
		{name: "over https", uri: "https://localhost/callback"},
		{name: "with a user", uri: "http://user@localhost/callback"},
		{name: "another host", uri: "http://example.com/callback"},
	}
	for _, testCase := range testCases {
		parsed, err := url.Parse(testCase.uri)
		if err != nil {
			t.Fatalf("%s: parse: %v", testCase.name, err)
		}
		if got := IsLoopback(parsed); got != testCase.want {
			t.Errorf("%s: got %t, want %t", testCase.name, got, testCase.want)
		}
	}
	if IsLoopback(nil) {
		t.Error("nil is a loopback")
	}
}
