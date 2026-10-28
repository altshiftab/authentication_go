package cimd_fetcher

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const clientId = "https://claude.ai/oauth/mcp-client-metadata"

// stubTransport answers every request with the response it is given, and counts what reaches it.
type stubTransport struct {
	status      int
	header      http.Header
	body        string
	requests    atomic.Int32
	lastRequest *http.Request
}

func (s *stubTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	s.requests.Add(1)
	s.lastRequest = request
	header := s.header
	if header == nil {
		header = http.Header{"Content-Type": {"application/json"}}
	}
	return &http.Response{
		StatusCode: s.status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(s.body)),
		Request:    request,
	}, nil
}

func newFetcher(t *testing.T, transport *stubTransport) *Fetcher {
	t.Helper()

	fetcher, err := New([]string{"claude.ai"}, &http.Client{Transport: transport})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if fetcher == nil {
		t.Fatal("no fetcher")
	}
	return fetcher
}

const validDocument = `{"client_id":"` + clientId + `","client_name":"Claude","redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"token_endpoint_auth_method":"none","logo_uri":"https://claude.ai/logo.png"}`

func TestFetcher_Fetch(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		clientId string
		status   int
		header   http.Header
		body     string
		wantName string
		wantErr  error
		// wantNoRequest is a client id refused without being fetched.
		wantNoRequest bool
	}{
		{name: "a document", clientId: clientId, status: http.StatusOK, body: validDocument, wantName: "Claude"},
		{
			name:     "a document with no name is called by its id",
			clientId: clientId,
			status:   http.StatusOK,
			body:     `{"client_id":"` + clientId + `","redirect_uris":["http://localhost/callback"]}`,
			wantName: clientId,
		},
		{name: "a host not allowed", clientId: "https://evil.example/client", wantErr: ErrNotAllowed, wantNoRequest: true},
		{name: "an allowed host's look-alike", clientId: "https://claude.ai.evil.example/client", wantErr: ErrNotAllowed, wantNoRequest: true},
		{name: "http", clientId: "http://claude.ai/oauth/mcp-client-metadata", wantErr: ErrNotAllowed, wantNoRequest: true},
		{name: "a port", clientId: "https://claude.ai:8443/oauth/mcp-client-metadata", wantErr: ErrNotAllowed, wantNoRequest: true},
		{name: "a user", clientId: "https://u@claude.ai/oauth/mcp-client-metadata", wantErr: ErrNotAllowed, wantNoRequest: true},
		{name: "a query", clientId: clientId + "?x=1", wantErr: ErrNotAllowed, wantNoRequest: true},
		{name: "no path", clientId: "https://claude.ai/", wantErr: ErrNotAllowed, wantNoRequest: true},
		{name: "not found", clientId: clientId, status: http.StatusNotFound, wantErr: ErrInvalidDocument},
		{
			// Not followed: the document must be where its id says.
			name:     "a redirect",
			clientId: clientId,
			status:   http.StatusFound,
			header:   http.Header{"Location": {"https://evil.example/doc"}, "Content-Type": {"application/json"}},
			body:     validDocument,
			wantErr:  ErrInvalidDocument,
		},
		{
			name:     "not json",
			clientId: clientId,
			status:   http.StatusOK,
			header:   http.Header{"Content-Type": {"text/html"}},
			body:     validDocument,
			wantErr:  ErrInvalidDocument,
		},
		{name: "too large", clientId: clientId, status: http.StatusOK, body: `{"client_name":"` + strings.Repeat("x", DefaultMaxBytes) + `"}`, wantErr: ErrInvalidDocument},
		{name: "malformed", clientId: clientId, status: http.StatusOK, body: `{"client_id":`, wantErr: ErrInvalidDocument},
		{
			name:     "another client's id",
			clientId: clientId,
			status:   http.StatusOK,
			body:     `{"client_id":"https://claude.ai/other","redirect_uris":["https://claude.ai/api/mcp/auth_callback"]}`,
			wantErr:  ErrInvalidDocument,
		},
		{
			name:     "a confidential client",
			clientId: clientId,
			status:   http.StatusOK,
			body:     `{"client_id":"` + clientId + `","redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"token_endpoint_auth_method":"client_secret_basic"}`,
			wantErr:  ErrInvalidDocument,
		},
		{name: "no redirect uris", clientId: clientId, status: http.StatusOK, body: `{"client_id":"` + clientId + `"}`, wantErr: ErrInvalidDocument},
		{
			name:     "a plain http redirect uri",
			clientId: clientId,
			status:   http.StatusOK,
			body:     `{"client_id":"` + clientId + `","redirect_uris":["http://evil.example/callback"]}`,
			wantErr:  ErrInvalidDocument,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			transport := &stubTransport{status: testCase.status, header: testCase.header, body: testCase.body}
			fetched, err := newFetcher(t, transport).Fetch(t.Context(), testCase.clientId)

			if testCase.wantNoRequest && transport.requests.Load() != 0 {
				t.Errorf("%s: fetched", testCase.name)
			}
			if testCase.wantErr != nil {
				if !errors.Is(err, testCase.wantErr) {
					t.Errorf("%s: got %v, %v, want %v", testCase.name, fetched, err, testCase.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: fetch: %v", testCase.name, err)
			}
			if fetched == nil || fetched.Id != testCase.clientId || fetched.Name != testCase.wantName || len(fetched.RedirectUris) != 1 {
				t.Errorf("%s: got %+v", testCase.name, fetched)
			}
		})
	}
}

func TestFetcher_Fetch_Cache(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		cacheControl string
		elapsed      time.Duration
		wantRequests int32
	}{
		{name: "kept for its max-age", cacheControl: "max-age=600", elapsed: 5 * time.Minute, wantRequests: 1},
		{name: "fetched again after it", cacheControl: "max-age=600", elapsed: 11 * time.Minute, wantRequests: 2},
		{name: "not kept past the maximum", cacheControl: "max-age=86400", elapsed: MaxTtl + time.Minute, wantRequests: 2},
		{name: "not kept at all for no-store", cacheControl: "no-store", elapsed: time.Second, wantRequests: 2},
		{name: "kept for the default without a word", elapsed: DefaultTtl - time.Second, wantRequests: 1},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			header := http.Header{"Content-Type": {"application/json"}}
			if testCase.cacheControl != "" {
				header.Set("Cache-Control", testCase.cacheControl)
			}
			transport := &stubTransport{status: http.StatusOK, header: header, body: validDocument}
			fetcher := newFetcher(t, transport)

			now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
			fetcher.now = func() time.Time { return now }
			if _, err := fetcher.Fetch(t.Context(), clientId); err != nil {
				t.Fatalf("%s: fetch: %v", testCase.name, err)
			}
			now = now.Add(testCase.elapsed)
			if _, err := fetcher.Fetch(t.Context(), clientId); err != nil {
				t.Fatalf("%s: fetch again: %v", testCase.name, err)
			}

			if got := transport.requests.Load(); got != testCase.wantRequests {
				t.Errorf("%s: %d requests, want %d", testCase.name, got, testCase.wantRequests)
			}
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	if _, err := New(nil, nil); err == nil {
		t.Error("a fetcher with no allowed hosts")
	}
	if _, err := New([]string{""}, nil); err == nil {
		t.Error("a fetcher with an empty allowed host")
	}
}
