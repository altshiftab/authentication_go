package callback_endpoint

import (
	"net/url"
	"testing"

	testing2 "github.com/altshiftab/authentication_go/pkg/sso/testing"
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

			bodyUrls, err := endpoint.MaskedBodyUrls()
			if !testCase.initialize {
				if err == nil {
					t.Errorf("%s: masked body urls %+v, want an error", testCase.name, bodyUrls)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: masked body urls: %v", testCase.name, err)
			}
			if len(bodyUrls) != 1 || bodyUrls[0].Domain != testCase.wantDomain || bodyUrls[0].Path != testCase.wantPath {
				t.Errorf("%s: masked body urls %+v, want %s%s", testCase.name, bodyUrls, testCase.wantDomain, testCase.wantPath)
			}
		})
	}
}
