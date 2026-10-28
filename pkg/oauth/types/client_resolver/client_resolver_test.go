package client_resolver

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/altshiftab/authentication_go/pkg/oauth/types/cimd_fetcher"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/client"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/client_registrar"
)

type documentTransport struct{ body string }

func (d *documentTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(d.body)),
		Request:    request,
	}, nil
}

func TestResolver_Resolve(t *testing.T) {
	t.Parallel()

	const documentId = "https://claude.ai/oauth/mcp-client-metadata"
	fetcher, err := cimd_fetcher.New([]string{"claude.ai"}, &http.Client{Transport: &documentTransport{
		body: `{"client_id":"` + documentId + `","client_name":"Claude","redirect_uris":["https://claude.ai/api/mcp/auth_callback"]}`,
	}})
	if err != nil {
		t.Fatalf("cimd fetcher new: %v", err)
	}

	registered := &client.Client{Id: "vocab-android", Name: "Vocab", RedirectUris: []string{"se.vvvp.vocab:/oauth"}}

	registrar, err := client_registrar.New(bytes.Repeat([]byte{7}, 32), true)
	if err != nil {
		t.Fatalf("client registrar new: %v", err)
	}
	selfRegistered, _, err := registrar.Register(&client_registrar.Metadata{ClientName: "Gemini CLI", RedirectUris: []string{"http://localhost:7777/oauth/callback"}})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	otherRegistrar, err := client_registrar.New(bytes.Repeat([]byte{8}, 32), true)
	if err != nil {
		t.Fatalf("client registrar new: %v", err)
	}

	testCases := []struct {
		name     string
		resolver *Resolver
		clientId string
		wantName string
		wantErr  error
	}{
		{name: "a registered client", resolver: New(fetcher, registrar, registered), clientId: "vocab-android", wantName: "Vocab"},
		{name: "a client with a document", resolver: New(fetcher, registrar, registered), clientId: documentId, wantName: "Claude"},
		{name: "an unknown client", resolver: New(fetcher, registrar, registered), clientId: "someone", wantErr: ErrUnknownClient},
		{name: "a document on a host not allowed", resolver: New(fetcher, registrar), clientId: "https://evil.example/client", wantErr: ErrUnknownClient},
		{name: "a document with no fetcher", resolver: New(nil, nil), clientId: documentId, wantErr: ErrUnknownClient},
		{name: "a client that registered", resolver: New(fetcher, registrar), clientId: selfRegistered.Id, wantName: "Gemini CLI"},
		{name: "a client registered under another key", resolver: New(fetcher, otherRegistrar), clientId: selfRegistered.Id, wantErr: client_registrar.ErrUnknownClient},
		{name: "a registered id with no registrar", resolver: New(fetcher, nil), clientId: selfRegistered.Id, wantErr: ErrUnknownClient},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			resolved, err := testCase.resolver.Resolve(t.Context(), testCase.clientId)
			if testCase.wantErr != nil {
				if !errors.Is(err, testCase.wantErr) {
					t.Errorf("%s: got %+v, %v, want %v", testCase.name, resolved, err, testCase.wantErr)
				}
				return
			}
			if err != nil || resolved == nil || resolved.Name != testCase.wantName {
				t.Errorf("%s: got %+v, %v", testCase.name, resolved, err)
			}
		})
	}
}
