package authorization_server_metadata_endpoint

import (
	"encoding/json/v2"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestEndpoint(t *testing.T) {
	t.Parallel()

	endpoint := New()
	if err := endpoint.Initialize("https://login.example.test", "/oauth/authorize", "/oauth/token", "/oauth/revoke", "/oauth/register", []string{"vocab"}); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	response, responseError := endpoint.Handler(httptest.NewRequestWithContext(t.Context(), "GET", DefaultPath, nil), nil)
	if responseError != nil || response == nil {
		t.Fatalf("handler: %+v", responseError)
	}
	var metadata Metadata
	if err := json.Unmarshal(response.Body, &metadata); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if metadata.Issuer != "https://login.example.test" || metadata.AuthorizationEndpoint != "https://login.example.test/oauth/authorize" ||
		metadata.TokenEndpoint != "https://login.example.test/oauth/token" || metadata.RevocationEndpoint != "https://login.example.test/oauth/revoke" ||
		metadata.RegistrationEndpoint != "https://login.example.test/oauth/register" {
		t.Errorf("metadata %+v", metadata)
	}
	// What has Claude register by its metadata document, and use PKCE.
	if !metadata.ClientIdMetadataDocumentSupported || !slices.Equal(metadata.TokenEndpointAuthMethodsSupported, []string{"none"}) ||
		!slices.Equal(metadata.CodeChallengeMethodsSupported, []string{"S256"}) || !metadata.AuthorizationResponseIssParameterSupported ||
		!slices.Equal(metadata.RevocationEndpointAuthMethodsSupported, []string{"none"}) {
		t.Errorf("metadata %+v", metadata)
	}

	for _, args := range [][4]string{{"", "/a", "/t", "/r"}, {"https://i", "", "/t", "/r"}, {"https://i", "/a", "", "/r"}, {"https://i", "/a", "/t", ""}} {
		if err := New().Initialize(args[0], args[1], args[2], args[3], "", nil); err == nil {
			t.Errorf("initialized with %v", args)
		}
	}

	// Without registration, none is named.
	without := New()
	if err := without.Initialize("https://i", "/a", "/t", "/r", "", nil); err != nil {
		t.Fatalf("initialize without registration: %v", err)
	}
	response, responseError = without.Handler(httptest.NewRequestWithContext(t.Context(), "GET", DefaultPath, nil), nil)
	if responseError != nil || response == nil || strings.Contains(string(response.Body), "registration_endpoint") {
		t.Errorf("metadata without registration: %+v %+v", response, responseError)
	}
}
