package problem_detail_endpoint

import (
	"io"
	"strings"
	"testing"

	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/problem_detail_endpoint/problem_detail_endpoint_config"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
)

const testBackUrl = "/login?redirect=%2Fapp"

// By default (no explicit converter) the endpoint serves HTML to browsers, with
// a back link when a back URL is configured, and problem+json to API clients.
func TestHtmlIsDefault(t *testing.T) {
	t.Parallel()

	server := newTestEndpoint(t, problem_detail_endpoint_config.WithBackUrl(testBackUrl))

	t.Run("browser gets html with a back link", func(t *testing.T) {
		t.Parallel()
		response := get(t, server.URL, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		defer func() { _ = response.Body.Close() }()

		if got := response.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
			t.Errorf("Content-Type = %q, want %q", got, "text/html; charset=utf-8")
		}

		body, _ := io.ReadAll(response.Body)
		bodyString := string(body)
		for _, want := range []string{
			"<h1>" + testTitle + "</h1>",
			testDetail,
			`href="` + testBackUrl + `"`,
			DefaultBackLabel,
		} {
			if !strings.Contains(bodyString, want) {
				t.Errorf("html body missing %q:\n%s", want, bodyString)
			}
		}
	})

	t.Run("api client still gets problem+json", func(t *testing.T) {
		t.Parallel()
		response := get(t, server.URL, "application/problem+json")
		defer func() { _ = response.Body.Close() }()

		if got := response.Header.Get("Content-Type"); got != "application/problem+json" {
			t.Errorf("Content-Type = %q, want %q", got, "application/problem+json")
		}
		body, _ := io.ReadAll(response.Body)
		if strings.Contains(string(body), "<html") {
			t.Errorf("problem+json response unexpectedly contains HTML: %s", body)
		}
	})

	t.Run("wildcard accept gets problem+json", func(t *testing.T) {
		t.Parallel()
		response := get(t, server.URL, "*/*")
		defer func() { _ = response.Body.Close() }()

		if got := response.Header.Get("Content-Type"); got != "application/problem+json" {
			t.Errorf("Content-Type = %q, want %q", got, "application/problem+json")
		}
	})
}

func TestHtmlDefaultBackUrlIsRoot(t *testing.T) {
	t.Parallel()

	// With no options, the back link defaults to "/".
	server := newTestEndpoint(t)

	response := get(t, server.URL, "text/html")
	defer func() { _ = response.Body.Close() }()

	if got := response.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", got, "text/html; charset=utf-8")
	}
	body, _ := io.ReadAll(response.Body)
	bodyString := string(body)
	if !strings.Contains(bodyString, "<h1>"+testTitle+"</h1>") {
		t.Errorf("expected the problem title in the html body:\n%s", bodyString)
	}
	if !strings.Contains(bodyString, `href="`+problem_detail_endpoint_config.DefaultBackUrl+`"`) {
		t.Errorf("expected a back link to %q:\n%s", problem_detail_endpoint_config.DefaultBackUrl, bodyString)
	}
}

func TestHtmlBackUrlCleared(t *testing.T) {
	t.Parallel()

	// An explicit empty back URL omits the link.
	server := newTestEndpoint(t, problem_detail_endpoint_config.WithBackUrl(""))

	response := get(t, server.URL, "text/html")
	defer func() { _ = response.Body.Close() }()

	body, _ := io.ReadAll(response.Body)
	bodyString := string(body)
	if !strings.Contains(bodyString, "<h1>"+testTitle+"</h1>") {
		t.Errorf("expected the problem title in the html body:\n%s", bodyString)
	}
	if strings.Contains(bodyString, "<a href") {
		t.Errorf("expected no back link when back URL is explicitly empty:\n%s", bodyString)
	}
}

func TestPlainConverterOptOut(t *testing.T) {
	t.Parallel()

	// Opting out of HTML: even a browser gets problem+json.
	server := newTestEndpoint(
		t,
		problem_detail_endpoint_config.WithProblemDetailConverter(response_error.DefaultProblemDetailConverter),
	)

	response := get(t, server.URL, "text/html")
	defer func() { _ = response.Body.Close() }()

	if got := response.Header.Get("Content-Type"); got != "application/problem+json" {
		t.Errorf("Content-Type = %q, want %q (opted out of HTML)", got, "application/problem+json")
	}
}
