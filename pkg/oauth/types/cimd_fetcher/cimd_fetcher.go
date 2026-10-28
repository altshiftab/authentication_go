// Package cimd_fetcher reads a client's metadata document (Client ID Metadata Documents, as the MCP
// authorization specification has clients register): a client's id is the HTTPS URL of a JSON
// document saying what the client is called and where it may be sent back to, which the
// authorization server fetches when the client first asks for authorization.
//
// The id is chosen by whoever starts an authorization, so the fetch is one a stranger can aim. Only
// hosts on the fetcher's allow-list are fetched from -- the clients the service means to have, which
// also keeps the fetch off anything internal -- over HTTPS, without following redirects, within a
// time and a size.
package cimd_fetcher

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/altshiftab/authentication_go/pkg/oauth/types/client"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
)

const (
	// DefaultMaxBytes is the largest document read; a client's is a few hundred bytes.
	DefaultMaxBytes = 16 * 1024
	// DefaultTimeout bounds the fetch, which a user's authorization waits on.
	DefaultTimeout = 5 * time.Second
	// DefaultTtl is how long a document is kept that says nothing of its own caching, and MaxTtl
	// the longest one is kept whatever it says, so that a client's change reaches the server.
	DefaultTtl = 5 * time.Minute
	MaxTtl     = time.Hour
)

var (
	// ErrNotAllowed is a client id that is no HTTPS URL on an allowed host.
	ErrNotAllowed = errors.New("client id not allowed")
	// ErrInvalidDocument is a document that could not be fetched, or says something a client's may
	// not.
	ErrInvalidDocument = errors.New("invalid client metadata document")
)

// document is a client metadata document, of the members the server reads (RFC 7591 section 2).
type document struct {
	ClientId                string   `json:"client_id"`
	ClientName              string   `json:"client_name,omitzero"`
	RedirectUris            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitzero"`
}

type entry struct {
	client    *client.Client
	expiresAt time.Time
}

type Fetcher struct {
	allowedHosts map[string]struct{}
	httpClient   *http.Client
	maxBytes     int64
	now          func() time.Time

	mutex sync.Mutex
	cache map[string]*entry
}

// New is a fetcher of documents on the allowed hosts. httpClient is the one fetched with -- nil for
// one of DefaultTimeout -- and is made not to follow redirects either way: a document must be where
// its id says.
func New(allowedHosts []string, httpClient *http.Client) (*Fetcher, error) {
	if len(allowedHosts) == 0 {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("allowed hosts"))
	}

	hosts := make(map[string]struct{}, len(allowedHosts))
	for _, host := range allowedHosts {
		if host == "" {
			return nil, altshiftErrors.NewWithTrace(empty_error.New("allowed host"))
		}
		hosts[strings.ToLower(host)] = struct{}{}
	}

	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultTimeout}
	}
	noRedirects := *httpClient
	noRedirects.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	return &Fetcher{
		allowedHosts: hosts,
		httpClient:   &noRedirects,
		maxBytes:     DefaultMaxBytes,
		now:          time.Now,
		cache:        make(map[string]*entry),
	}, nil
}

// Allows says whether the client id is one the fetcher would fetch: an HTTPS URL, with a path, on
// an allowed host, naming no port, user or fragment.
func (f *Fetcher) Allows(clientId string) bool {
	u, err := url.Parse(clientId)
	if err != nil {
		return false
	}
	if u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Fragment != "" || u.RawQuery != "" {
		return false
	}
	if u.Path == "" || u.Path == "/" {
		return false
	}
	_, ok := f.allowedHosts[strings.ToLower(u.Hostname())]
	return ok
}

// Fetch is the client the id's document describes.
func (f *Fetcher) Fetch(ctx context.Context, clientId string) (*client.Client, error) {
	if !f.Allows(clientId) {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, ErrNotAllowed), clientId)
	}

	now := f.now()
	f.mutex.Lock()
	cached, ok := f.cache[clientId]
	f.mutex.Unlock()
	if ok && now.Before(cached.expiresAt) {
		return cached.client, nil
	}

	fetched, ttl, err := f.fetch(ctx, clientId)
	if err != nil {
		return nil, err
	}

	if ttl > 0 {
		f.mutex.Lock()
		f.cache[clientId] = &entry{client: fetched, expiresAt: now.Add(ttl)}
		f.mutex.Unlock()
	}

	return fetched, nil
}

func (f *Fetcher) fetch(ctx context.Context, clientId string) (*client.Client, time.Duration, error) {
	invalid := func(reason string) error {
		return altshiftErrors.NewWithTrace(fmt.Errorf("%w: %w: %s", altshiftErrors.ErrValidationError, ErrInvalidDocument, reason), clientId)
	}
	invalidBy := func(reason string, err error) error {
		return altshiftErrors.NewWithTrace(fmt.Errorf("%w: %w: %s: %w", altshiftErrors.ErrValidationError, ErrInvalidDocument, reason, err), clientId)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, clientId, nil)
	if err != nil {
		return nil, 0, altshiftErrors.NewWithTrace(fmt.Errorf("http new request with context: %w", err), clientId)
	}
	request.Header.Set("Accept", "application/json")

	response, err := f.httpClient.Do(request)
	if err != nil {
		return nil, 0, invalidBy("fetch", err)
	}
	if response == nil {
		return nil, 0, invalid("no response")
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, 0, invalid(fmt.Sprintf("status %d", response.StatusCode))
	}
	if mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		return nil, 0, invalid(fmt.Sprintf("content type %q", response.Header.Get("Content-Type")))
	}

	data, err := io.ReadAll(io.LimitReader(response.Body, f.maxBytes+1))
	if err != nil {
		return nil, 0, invalidBy("read", err)
	}
	if int64(len(data)) > f.maxBytes {
		return nil, 0, invalid(fmt.Sprintf("larger than %d bytes", f.maxBytes))
	}

	var parsed document
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, 0, invalidBy("json unmarshal", err)
	}
	if parsed.ClientId != clientId {
		return nil, 0, invalid("the document names another client id")
	}
	// The server issues tokens to public clients only, which prove nothing at the token endpoint
	// but the PKCE verifier.
	if method := parsed.TokenEndpointAuthMethod; method != "" && method != "none" {
		return nil, 0, invalid(fmt.Sprintf("token endpoint auth method %q", method))
	}
	if len(parsed.RedirectUris) == 0 {
		return nil, 0, invalid("no redirect uris")
	}
	for _, redirectUri := range parsed.RedirectUris {
		u, err := url.Parse(redirectUri)
		if err != nil || !u.IsAbs() || u.Fragment != "" || (u.Scheme != "https" && !client.IsLoopback(u)) {
			return nil, 0, invalid(fmt.Sprintf("redirect uri %q", redirectUri))
		}
	}

	name := parsed.ClientName
	if name == "" {
		name = clientId
	}

	return &client.Client{Id: clientId, Name: name, RedirectUris: parsed.RedirectUris}, cacheTtl(response.Header.Get("Cache-Control")), nil
}

// cacheTtl is how long a document may be kept, as its Cache-Control says: nothing for no-store or
// no-cache, its max-age up to MaxTtl, and DefaultTtl where it says neither.
func cacheTtl(cacheControl string) time.Duration {
	ttl := DefaultTtl
	for directive := range strings.SplitSeq(cacheControl, ",") {
		name, value, _ := strings.Cut(strings.TrimSpace(strings.ToLower(directive)), "=")
		switch name {
		case "no-store", "no-cache":
			return 0
		case "max-age":
			if seconds, err := strconv.Atoi(strings.Trim(value, `"`)); err == nil && seconds >= 0 {
				ttl = time.Duration(seconds) * time.Second
			}
		}
	}
	return min(ttl, MaxTtl)
}
