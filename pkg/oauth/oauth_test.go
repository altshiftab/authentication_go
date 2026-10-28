package oauth

import (
	"net/url"
	"strings"
	"testing"
)

func TestFindResource(t *testing.T) {
	t.Parallel()

	vocab := &Resource{Url: "https://vocab.example.test/mcp", Scopes: []string{"vocab"}}
	feeds := &Resource{Url: "https://feeds.example.test/mcp", Scopes: []string{"feeds"}}

	testCases := []struct {
		name      string
		resources []*Resource
		url       string
		want      *Resource
	}{
		{name: "named", resources: []*Resource{vocab, feeds}, url: feeds.Url, want: feeds},
		{name: "not served", resources: []*Resource{vocab}, url: feeds.Url},
		{name: "none named, one served", resources: []*Resource{vocab}, want: vocab},
		// Which of several would be a guess at what the user is asked to consent to.
		{name: "none named, several served", resources: []*Resource{vocab, feeds}},
		{name: "a prefix of one served", resources: []*Resource{vocab}, url: "https://vocab.example.test/"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := FindResource(testCase.resources, testCase.url); got != testCase.want {
				t.Errorf("%s: got %+v, want %+v", testCase.name, got, testCase.want)
			}
		})
	}
}

func TestResource_AllowsScopes(t *testing.T) {
	t.Parallel()

	resource := &Resource{Scopes: []string{"vocab", "vocab:write"}}
	testCases := []struct {
		name   string
		scopes []string
		want   bool
	}{
		{name: "one it has", scopes: []string{"vocab"}, want: true},
		{name: "all it has", scopes: []string{"vocab", "vocab:write"}, want: true},
		{name: "one it lacks", scopes: []string{"vocab", "admin"}},
		{name: "none", want: true},
	}
	for _, testCase := range testCases {
		if got := resource.AllowsScopes(testCase.scopes); got != testCase.want {
			t.Errorf("%s: got %t, want %t", testCase.name, got, testCase.want)
		}
	}
}

func TestAuthorizationResponseUrl(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		redirectUri string
		parameters  map[string]string
		want        url.Values
	}{
		{
			name:        "parameters and the issuer",
			redirectUri: "https://client.example.test/callback",
			parameters:  map[string]string{"code": "c", "state": "s"},
			want:        url.Values{"code": {"c"}, "state": {"s"}, "iss": {"https://issuer.example.test"}},
		},
		{
			name:        "beside the redirect uri's own query",
			redirectUri: "https://client.example.test/callback?tenant=1",
			parameters:  map[string]string{"error": "access_denied", "state": ""},
			want:        url.Values{"tenant": {"1"}, "error": {"access_denied"}, "iss": {"https://issuer.example.test"}},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := AuthorizationResponseUrl(testCase.redirectUri, "https://issuer.example.test", testCase.parameters)
			if err != nil {
				t.Fatalf("%s: %v", testCase.name, err)
			}
			parsed, err := url.Parse(got)
			if err != nil {
				t.Fatalf("%s: parse: %v", testCase.name, err)
			}
			if query := parsed.Query(); query.Encode() != testCase.want.Encode() {
				t.Errorf("%s: query %v, want %v", testCase.name, query, testCase.want)
			}
		})
	}
}

func TestSecrets(t *testing.T) {
	t.Parallel()

	first, err := NewSecret()
	if err != nil {
		t.Fatalf("new secret: %v", err)
	}
	second, err := NewSecret()
	if err != nil {
		t.Fatalf("new secret: %v", err)
	}
	if len(first) != 43 || first == second {
		t.Errorf("secrets %q and %q", first, second)
	}
	if hash := HashSecret(first); len(hash) != 32 || string(hash) == first {
		t.Errorf("hash %x", hash)
	}
	again := strings.Clone(first)
	if string(HashSecret(first)) != string(HashSecret(again)) {
		t.Error("a secret hashes differently each time")
	}
}
