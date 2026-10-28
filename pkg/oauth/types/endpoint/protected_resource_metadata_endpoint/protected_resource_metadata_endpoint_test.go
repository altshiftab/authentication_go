package protected_resource_metadata_endpoint

import (
	"encoding/json/v2"
	"net/http/httptest"
	"testing"

	"github.com/altshiftab/authentication_go/pkg/oauth"
)

func TestPathAndUrl(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		resource string
		wantPath string
		wantUrl  string
	}{
		{name: "a resource with a path", resource: "https://vocab.example.test/mcp", wantPath: "/.well-known/oauth-protected-resource/mcp", wantUrl: "https://vocab.example.test/.well-known/oauth-protected-resource/mcp"},
		{name: "a resource at the root", resource: "https://vocab.example.test", wantPath: "/.well-known/oauth-protected-resource", wantUrl: "https://vocab.example.test/.well-known/oauth-protected-resource"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			path, err := Path(testCase.resource)
			if err != nil || path != testCase.wantPath {
				t.Errorf("%s: path %q, %v, want %q", testCase.name, path, err, testCase.wantPath)
			}
			u, err := Url(testCase.resource)
			if err != nil || u != testCase.wantUrl {
				t.Errorf("%s: url %q, %v, want %q", testCase.name, u, err, testCase.wantUrl)
			}
		})
	}
}

func TestEndpoint(t *testing.T) {
	t.Parallel()

	resource := &oauth.Resource{Url: "https://vocab.example.test/mcp", Name: "Vocab", Scopes: []string{"vocab"}}
	endpoint, err := New(resource.Url)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if endpoint.Path != "/.well-known/oauth-protected-resource/mcp" {
		t.Errorf("path %q", endpoint.Path)
	}
	if err := endpoint.Initialize(resource, "https://login.example.test"); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	response, responseError := endpoint.Handler(httptest.NewRequestWithContext(t.Context(), "GET", endpoint.Path, nil), nil)
	if responseError != nil || response == nil {
		t.Fatalf("handler: %+v", responseError)
	}
	var metadata Metadata
	if err := json.Unmarshal(response.Body, &metadata); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if metadata.Resource != resource.Url || len(metadata.AuthorizationServers) != 1 || metadata.AuthorizationServers[0] != "https://login.example.test" {
		t.Errorf("metadata %+v", metadata)
	}

	if err := endpoint.Initialize(nil, "https://login.example.test"); err == nil {
		t.Error("initialized without a resource")
	}
	if err := endpoint.Initialize(resource, ""); err == nil {
		t.Error("initialized without an issuer")
	}
}
