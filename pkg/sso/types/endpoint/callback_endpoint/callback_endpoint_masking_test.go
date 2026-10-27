package callback_endpoint

import (
	"net/url"
	"slices"
	"testing"

	testing2 "github.com/altshiftab/authentication_go/pkg/sso/testing"
	"github.com/altshiftab/utils_go/pkg/http/types/http_context_extractor/http_context_extractor_config"
)

func TestEndpoint_Masks(t *testing.T) {
	t.Parallel()

	const path = "/api/login/test/callback"

	baseConfig := oauthConfig
	if baseConfig == nil {
		t.Fatal("no oauth config")
	}

	configuredTokenUrl, err := url.Parse(baseConfig.Endpoint.TokenURL)
	if err != nil {
		t.Fatalf("url parse: %v", err)
	}
	if configuredTokenUrl == nil {
		t.Fatal("no token url")
	}

	testCases := []struct {
		name       string
		initialize bool
		tokenUrl   string
		wantDomain string
		wantPath   string
		wantErr    bool
	}{
		{
			name:       "initialized",
			initialize: true,
			tokenUrl:   baseConfig.Endpoint.TokenURL,
			wantDomain: configuredTokenUrl.Hostname(),
			wantPath:   configuredTokenUrl.Path,
		},
		{
			// The token URL is learnt at Initialize, so asking before it is an error.
			name:    "not initialized",
			wantErr: true,
		},
		{name: "a token URL that does not parse", initialize: true, tokenUrl: "://no-scheme", wantErr: true},
		{name: "a token URL with no host", initialize: true, tokenUrl: "/token", wantErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			endpoint, err := New[*testing2.ProviderClaims](path)
			if err != nil {
				t.Fatalf("%s: new: %v", testCase.name, err)
			}

			if testCase.initialize {
				config := *baseConfig
				config.Endpoint.TokenURL = testCase.tokenUrl
				err := endpoint.Initialize(testOrigin, &config, idTokenAuthenticator, sessionManager)
				if testCase.wantErr {
					if err == nil {
						t.Errorf("%s: initialized", testCase.name)
					}
					return
				}
				if err != nil {
					t.Fatalf("%s: initialize: %v", testCase.name, err)
				}
			}

			urlParams := endpoint.MaskedUrlParams()
			if len(urlParams) != 1 || urlParams[0].Path != path || urlParams[0].Query != "code&state&session_state" {
				t.Errorf("%s: masked url params %+v", testCase.name, urlParams)
			}

			bodyFields, err := endpoint.MaskedBodyFields()
			if !testCase.initialize {
				if err == nil {
					t.Errorf("%s: masked body fields %+v, want an error", testCase.name, bodyFields)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: masked body fields: %v", testCase.name, err)
			}
			if bodyFields == nil {
				t.Fatalf("%s: no masked body fields", testCase.name)
			}

			// The token endpoint's request's and response's credentials, field by field.
			for name, testFields := range map[string]struct {
				entries  []*http_context_extractor_config.MaskedBodyFields
				wantSome string
			}{
				"request":  {entries: bodyFields.Request, wantSome: "client_secret"},
				"response": {entries: bodyFields.Response, wantSome: "id_token"},
			} {
				entries := testFields.entries
				if len(entries) != 1 || entries[0].Url == nil ||
					entries[0].Url.Domain != testCase.wantDomain || entries[0].Url.Path != testCase.wantPath {
					t.Errorf("%s: masked %s body fields %+v, want %s%s", testCase.name, name, entries, testCase.wantDomain, testCase.wantPath)
					continue
				}
				if entries[0].AllValues || !slices.Contains(entries[0].Fields, testFields.wantSome) {
					t.Errorf("%s: masked %s body fields %v, want %s among them", testCase.name, name, entries[0].Fields, testFields.wantSome)
				}
			}
		})
	}
}
