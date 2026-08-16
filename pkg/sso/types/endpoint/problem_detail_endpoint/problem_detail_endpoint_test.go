package problem_detail_endpoint

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	muxPkg "github.com/Motmedel/utils_go/pkg/http/mux"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/problem_detail_endpoint/problem_detail_endpoint_config"
)

const (
	defaultPath   = "/problems/test"
	testType      = "/sso/problems/test"
	testTitle     = "Test problem"
	testDetail    = "A test problem occurred."
	testStatus    = http.StatusForbidden
	testCacheCtrl = "public, max-age=3600"
)

func newTestEndpoint(t *testing.T, options ...problem_detail_endpoint_config.Option) *httptest.Server {
	t.Helper()

	base := []problem_detail_endpoint_config.Option{
		problem_detail_endpoint_config.WithPath(defaultPath),
		problem_detail_endpoint_config.WithType(testType),
		problem_detail_endpoint_config.WithTitle(testTitle),
		problem_detail_endpoint_config.WithDetail(testDetail),
		problem_detail_endpoint_config.WithStatus(testStatus),
	}

	testEndpoint, err := New(append(base, options...)...)
	if err != nil {
		t.Fatalf("new endpoint: %v", err)
	}

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func get(t *testing.T, serverURL, accept string) *http.Response {
	t.Helper()

	request, err := http.NewRequest(http.MethodGet, serverURL+defaultPath, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if accept != "" {
		request.Header.Set("Accept", accept)
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("client do: %v", err)
	}
	return response
}

func TestNewValidation(t *testing.T) {
	t.Parallel()

	// No path (Path == "") must be rejected.
	if _, err := New(problem_detail_endpoint_config.WithStatus(testStatus)); err == nil {
		t.Error("expected an error for a missing path")
	}
	// Missing status (Status == 0) must be rejected.
	if _, err := New(problem_detail_endpoint_config.WithPath(defaultPath)); err == nil {
		t.Error("expected an error for a missing status")
	}
}

func TestContentNegotiation(t *testing.T) {
	t.Parallel()

	server := newTestEndpoint(t)

	t.Run("json default", func(t *testing.T) {
		t.Parallel()
		response := get(t, server.URL, "application/problem+json")
		defer func() { _ = response.Body.Close() }()

		if got := response.Header.Get("Content-Type"); got != "application/problem+json" {
			t.Errorf("Content-Type = %q, want %q", got, "application/problem+json")
		}
		if response.StatusCode != testStatus {
			t.Errorf("status = %d, want %d", response.StatusCode, testStatus)
		}

		body, _ := io.ReadAll(response.Body)
		var detail problem_detail.Detail
		if err := json.Unmarshal(body, &detail); err != nil {
			t.Fatalf("unmarshal problem detail: %v (body: %s)", err, body)
		}
		if detail.Type != testType {
			t.Errorf("type = %q, want %q", detail.Type, testType)
		}
		if detail.Title != testTitle {
			t.Errorf("title = %q, want %q", detail.Title, testTitle)
		}
		if detail.Detail != testDetail {
			t.Errorf("detail = %q, want %q", detail.Detail, testDetail)
		}
		if detail.Status != testStatus {
			t.Errorf("status field = %d, want %d", detail.Status, testStatus)
		}
	})

	t.Run("xml when negotiated", func(t *testing.T) {
		t.Parallel()
		response := get(t, server.URL, "application/problem+xml")
		defer func() { _ = response.Body.Close() }()

		if got := response.Header.Get("Content-Type"); got != "application/problem+xml" {
			t.Errorf("Content-Type = %q, want %q", got, "application/problem+xml")
		}

		body, _ := io.ReadAll(response.Body)
		// The Detail type customizes MarshalXML (RFC 7807 namespace) but provides
		// no UnmarshalXML, so assert on the serialized document directly.
		bodyString := string(body)
		if !strings.HasPrefix(bodyString, "<?xml") {
			t.Errorf("body does not start with an XML declaration: %s", bodyString)
		}
		for _, want := range []string{"<problem", testType, testTitle, testDetail} {
			if !strings.Contains(bodyString, want) {
				t.Errorf("xml body missing %q: %s", want, bodyString)
			}
		}
	})

	t.Run("text/plain when negotiated", func(t *testing.T) {
		t.Parallel()
		response := get(t, server.URL, "text/plain")
		defer func() { _ = response.Body.Close() }()

		if got := response.Header.Get("Content-Type"); got != "text/plain" {
			t.Errorf("Content-Type = %q, want %q", got, "text/plain")
		}
	})
}

func TestCacheHeaders(t *testing.T) {
	t.Parallel()

	server := newTestEndpoint(t)
	response := get(t, server.URL, "application/problem+json")
	defer func() { _ = response.Body.Close() }()

	if got := response.Header.Get("Cache-Control"); got != testCacheCtrl {
		t.Errorf("Cache-Control = %q, want %q", got, testCacheCtrl)
	}

	// The representation varies by Accept, so a Vary: Accept header must be set
	// for caches to store the representations separately.
	vary := response.Header.Values("Vary")
	if !containsToken(vary, "Accept") {
		t.Errorf("Vary = %v, want it to contain %q", vary, "Accept")
	}
}

func TestCustomCacheControl(t *testing.T) {
	t.Parallel()

	server := newTestEndpoint(t, problem_detail_endpoint_config.WithCacheControl("no-store"))
	response := get(t, server.URL, "application/problem+json")
	defer func() { _ = response.Body.Close() }()

	if got := response.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store")
	}
}

func containsToken(headerValues []string, token string) bool {
	for _, value := range headerValues {
		for _, part := range strings.Split(value, ",") {
			if strings.TrimSpace(part) == token {
				return true
			}
		}
	}
	return false
}
