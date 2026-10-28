// Package authorization_server_metadata_endpoint serves the authorization server's metadata (RFC
// 8414), which is how a client learns where to send the user and where to redeem a code, and what
// the server supports -- among it that a client may register by its metadata document, which is
// what has Claude use one rather than register dynamically.
package authorization_server_metadata_endpoint

import (
	"encoding/json/v2"
	"fmt"
	"net/http"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	muxResponse "github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	altshiftReflect "github.com/altshiftab/utils_go/pkg/reflect"
)

// DefaultPath is where RFC 8414 has a client look for an issuer without a path.
const DefaultPath = "/.well-known/oauth-authorization-server"

type Metadata struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	RegistrationEndpoint                       string   `json:"registration_endpoint,omitzero"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported     []string `json:"revocation_endpoint_auth_methods_supported"`
	ScopesSupported                            []string `json:"scopes_supported,omitzero"`
	ClientIdMetadataDocumentSupported          bool     `json:"client_id_metadata_document_supported"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
}

type Endpoint struct {
	*initialization_endpoint.Endpoint
}

// Initialize has the endpoint describe the issuer, its authorization, token, revocation and -- if
// registrationPath is not empty -- registration endpoints by their paths under it, and the scopes
// its resources have.
func (e *Endpoint) Initialize(
	issuer string,
	authorizationPath string,
	tokenPath string,
	revocationPath string,
	registrationPath string,
	scopes []string,
) error {
	for name, value := range map[string]string{
		"issuer": issuer, "authorization path": authorizationPath, "token path": tokenPath, "revocation path": revocationPath,
	} {
		if value == "" {
			return altshiftErrors.NewWithTrace(empty_error.New(name))
		}
	}

	metadata := &Metadata{
		Issuer:                                     issuer,
		AuthorizationEndpoint:                      issuer + authorizationPath,
		TokenEndpoint:                              issuer + tokenPath,
		RevocationEndpoint:                         issuer + revocationPath,
		ResponseTypesSupported:                     []string{"code"},
		GrantTypesSupported:                        []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported:              []string{"S256"},
		TokenEndpointAuthMethodsSupported:          []string{"none"},
		RevocationEndpointAuthMethodsSupported:     []string{"none"},
		ScopesSupported:                            scopes,
		ClientIdMetadataDocumentSupported:          true,
		AuthorizationResponseIssParameterSupported: true,
	}
	if registrationPath != "" {
		metadata.RegistrationEndpoint = issuer + registrationPath
	}
	body, err := json.Marshal(metadata)
	if err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("json marshal (metadata): %w", err))
	}

	e.Handler = func(_ *http.Request, _ []byte) (*muxResponse.Response, *response_error.ResponseError) {
		return &muxResponse.Response{
			Body: body,
			Headers: []*muxResponse.HeaderEntry{
				{Name: "Content-Type", Value: "application/json"},
				{Name: "Cache-Control", Value: "public, max-age=3600", Overwrite: true},
			},
		}, nil
	}

	e.Initialized = true

	return nil
}

func New() *Endpoint {
	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:      DefaultPath,
				Method:    http.MethodGet,
				UrlParser: adapter.New(query_extractor.Empty),
				Public:    true,
				Hint: &endpoint.Hint{
					OutputType:        altshiftReflect.TypeOf[Metadata](),
					OutputContentType: "application/json",
				},
			},
		},
	}
}
