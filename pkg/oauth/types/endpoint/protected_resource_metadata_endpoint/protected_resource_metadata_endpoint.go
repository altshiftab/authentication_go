// Package protected_resource_metadata_endpoint serves a resource's metadata (RFC 9728), which is
// how a client that was refused by the resource learns which authorization server to ask, and for
// what scope.
package protected_resource_metadata_endpoint

import (
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/altshiftab/authentication_go/pkg/oauth"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	muxResponse "github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	altshiftReflect "github.com/altshiftab/utils_go/pkg/reflect"
)

// wellKnownPrefix is the path RFC 9728 section 3.1 puts before a resource's own path.
const wellKnownPrefix = "/.well-known/oauth-protected-resource"

type Metadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported,omitzero"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceName           string   `json:"resource_name,omitzero"`
}

// Path is where a resource's metadata is served, on the resource's host.
func Path(resourceUrl string) (string, error) {
	u, err := url.Parse(resourceUrl)
	if err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("url parse (resource): %w", err), resourceUrl)
	}
	return wellKnownPrefix + strings.TrimSuffix(u.Path, "/"), nil
}

// Url is the absolute URL of a resource's metadata, as a refusal names it.
func Url(resourceUrl string) (string, error) {
	u, err := url.Parse(resourceUrl)
	if err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("url parse (resource): %w", err), resourceUrl)
	}
	path, err := Path(resourceUrl)
	if err != nil {
		return "", err
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: path}).String(), nil
}

type Endpoint struct {
	*initialization_endpoint.Endpoint
}

// Initialize has the endpoint describe the resource, naming the issuer as its authorization server.
func (e *Endpoint) Initialize(resource *oauth.Resource, issuer string) error {
	if resource == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("resource"))
	}
	if resource.Url == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("resource url"))
	}
	if issuer == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("issuer"))
	}

	body, err := json.Marshal(&Metadata{
		Resource:               resource.Url,
		AuthorizationServers:   []string{issuer},
		ScopesSupported:        resource.Scopes,
		BearerMethodsSupported: []string{"header"},
		ResourceName:           resource.Name,
	})
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

// New is the endpoint for the resource at resourceUrl, served at the path RFC 9728 gives it.
func New(resourceUrl string) (*Endpoint, error) {
	path, err := Path(resourceUrl)
	if err != nil {
		return nil, err
	}

	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:      path,
				Method:    http.MethodGet,
				UrlParser: adapter.New(query_extractor.Empty),
				Public:    true,
				Hint: &endpoint.Hint{
					OutputType:        altshiftReflect.TypeOf[Metadata](),
					OutputContentType: "application/json",
				},
			},
		},
	}, nil
}
