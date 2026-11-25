package landing_endpoint

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/altshiftab/authentication_go/pkg/log_options/log_options_testing"
	magicLinkTesting "github.com/altshiftab/authentication_go/pkg/magic_link/testing"
	"github.com/altshiftab/authentication_go/pkg/magic_link/types/endpoint/landing_endpoint/landing_endpoint_config"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
)

var errTestSpentChecker = errors.New("database unavailable")

// spentCheckWarning is what the landing logs when it cannot tell whether a link was spent.
const spentCheckWarning = "An error occurred when checking whether a magic link was spent."

/*
 * A landing that cannot tell whether its link was spent offers the form, and says why in the log:
 * the error as an error object, which Elasticsearch takes where `error` is one, not as a string it
 * refuses.
 */
//nolint:paralleltest // Swaps the global slog default; running it in parallel would race.
func TestEndpoint_SpentCheckFailureIsLoggedAsAnError(t *testing.T) {
	testEndpoint := New(landing_endpoint_config.WithUnusablePageBuilder(unusablePageBuilder))
	testEndpoint.SpentChecker = makeSpentChecker(false, errTestSpentChecker)
	if err := testEndpoint.Initialize(signer); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint.Endpoint.Endpoint)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	token := mintToken(t, defaultPayload(magicLinkTesting.ValidEmail, "ok"))

	var statusCode int
	lines, err := log_options_testing.Capture(func() {
		requestUrl := httpServer.URL + testEndpoint.Path + "?" + url.Values{"token": {token}}.Encode()
		request, err := http.NewRequestWithContext(t.Context(), testEndpoint.Method, requestUrl, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}

		response, err := httpServer.Client().Do(request)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		_ = response.Body.Close()
		statusCode = response.StatusCode
	})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}

	if statusCode != http.StatusOK {
		t.Fatalf("status code %d, expected %d", statusCode, http.StatusOK)
	}

	var warnings []map[string]any
	for _, line := range lines {
		if line["msg"] == spentCheckWarning {
			warnings = append(warnings, line)
		}
	}
	if len(warnings) != 1 {
		t.Fatalf("%d lines logged the warning, want one: %v", len(warnings), lines)
	}
	errorObject, ok := warnings[0]["error"].(map[string]any)
	if !ok {
		t.Fatalf("error: got %#v, want an object", warnings[0]["error"])
	}
	if message, _ := errorObject["message"].(string); message == "" {
		t.Errorf("error.message: got %#v, want the error's message", errorObject["message"])
	}
}
