package callback_endpoint

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	muxTesting "github.com/altshiftab/utils_go/pkg/http/mux/testing"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/altshiftab/authentication_go/pkg/database/types/oauth_flow"
	"github.com/altshiftab/authentication_go/pkg/sso/errors/oauth_error"
	testing2 "github.com/altshiftab/authentication_go/pkg/sso/testing"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
	"github.com/altshiftab/utils_go/pkg/http/types/http_context_extractor"
	altshiftLog "github.com/altshiftab/utils_go/pkg/log"
	altshiftContextLogger "github.com/altshiftab/utils_go/pkg/log/context_logger"
)

// TestProviderErrorLogging drives the OAuth provider-error path (the user
// declined consent) and asserts both the HTTP behavior and the ECS fields of the
// structured log line it emits.
//
// It is intentionally NOT parallel: it swaps the global slog default to capture
// output. Non-parallel tests run to completion before the package's parallel
// tests resume, so this does not race with TestEndpoint's parallel subtests.
func TestProviderErrorLogging(t *testing.T) {
	const errorDescription = "User declined to consent to access the app."

	var logBuffer bytes.Buffer
	httpContextExtractor := http_context_extractor.New()
	logger := altshiftContextLogger.New(
		slog.NewJSONHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelInfo}),
		&altshiftLog.ErrorContextExtractor{
			ContextExtractors: []altshiftLog.ContextExtractor{httpContextExtractor},
		},
		httpContextExtractor,
	)
	previousLogger := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(previousLogger)

	testEndpoint, err := New[*testing2.ProviderClaims](defaultPath)
	if err != nil {
		t.Fatalf("new endpoint: %v", err)
	}
	if err := testEndpoint.Initialize(testOrigin, oauthConfig, idTokenAuthenticator, sessionManager); err != nil {
		t.Fatalf("test endpoint initialize: %v", err)
	}
	testEndpoint.popOauthFlow = func(ctx context.Context, id string, database *sql.DB) (*oauth_flow.Flow, error) {
		expiresAt := time.Now().Add(time.Hour)
		return &oauth_flow.Flow{
			Id:          testing2.OauthFlowId,
			RedirectUrl: testing2.RedirectUrl,
			State:       testing2.State,
			ExpiresAt:   &expiresAt,
		}, nil
	}

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint.Endpoint.Endpoint)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	requestUrl := httpServer.URL + defaultPath +
		"?state=" + testing2.State +
		"&error=access_denied&error_subcode=cancel" +
		"&error_description=" + url.QueryEscape(errorDescription)

	request, err := http.NewRequest(http.MethodGet, requestUrl, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.AddCookie(&http.Cookie{Name: testEndpoint.CallbackCookieName, Value: testing2.OauthFlowId})

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("client do: %v", err)
	}
	defer func() { _ = response.Body.Close() }()

	// Behavior: redirect to the cancelled problem page, with the callback cookie
	// cleared.
	wantLocation := testOrigin + categoryProblemPaths[oauth_error.CategoryCancelled]
	if response.StatusCode != http.StatusSeeOther {
		t.Errorf("status code = %d, want %d", response.StatusCode, http.StatusSeeOther)
	}
	if location := response.Header.Get("Location"); location != wantLocation {
		t.Errorf("Location = %q, want %q", location, wantLocation)
	}

	var callbackCookie *http.Cookie
	for _, cookie := range response.Cookies() {
		if cookie.Name == testEndpoint.CallbackCookieName {
			callbackCookie = cookie
		}
	}
	if callbackCookie == nil {
		t.Fatalf("expected a %q Set-Cookie in the response", testEndpoint.CallbackCookieName)
	}
	if callbackCookie.MaxAge >= 0 {
		t.Errorf("callback cookie MaxAge = %d, want < 0 (cleared)", callbackCookie.MaxAge)
	}

	// ECS log assertions.
	logEntry := findLogEntry(t, &logBuffer, "An OAuth error occurred.")

	if level, _ := logEntry["level"].(string); level != "WARN" {
		t.Errorf("level = %q, want %q", level, "WARN")
	}

	event := childObject(t, logEntry, "event")
	if got := event["action"]; got != "log_oauth_error" {
		t.Errorf("event.action = %v, want %q", got, "log_oauth_error")
	}
	if got := event["reason"]; got != "An OAuth error occurred." {
		t.Errorf("event.reason = %v, want %q", got, "An OAuth error occurred.")
	}

	// The error.* group is produced from the oauth_error.Error placed in the
	// logging context by the error context extractor: GetCode() surfaces as
	// error.code, and Error() as error.message.
	errorObject := childObject(t, logEntry, "error")
	if got := errorObject["code"]; got != "access_denied" {
		t.Errorf("error.code = %v, want %q", got, "access_denied")
	}
	if message, _ := errorObject["message"].(string); !strings.Contains(message, "access_denied") ||
		!strings.Contains(message, errorDescription) {
		t.Errorf("error.message = %q, want it to contain %q and %q", message, "access_denied", errorDescription)
	}

	// Bridging the mux HTTP context onto the logging context should let the
	// http_context_extractor populate the ECS http/url groups.
	if _, ok := logEntry["http"]; !ok {
		t.Errorf("expected an `http` group in the log entry; got keys %v", keysOf(logEntry))
	}
	if _, ok := logEntry["url"]; !ok {
		t.Errorf("expected a `url` group in the log entry; got keys %v", keysOf(logEntry))
	}
}

func findLogEntry(t *testing.T, buffer *bytes.Buffer, message string) map[string]any {
	t.Helper()

	scanner := bufio.NewScanner(bytes.NewReader(buffer.Bytes()))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		var entry map[string]any
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatalf("unmarshal log line %q: %v", line, err)
		}

		if entry["msg"] == message {
			return entry
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan log buffer: %v", err)
	}

	t.Fatalf("no log entry with msg %q found in:\n%s", message, buffer.String())
	return nil
}

func childObject(t *testing.T, parent map[string]any, key string) map[string]any {
	t.Helper()

	child, ok := parent[key].(map[string]any)
	if !ok {
		t.Fatalf("expected %q to be an object, got %T (%v)", key, parent[key], parent[key])
	}
	return child
}

func keysOf(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}

// TestSignInLoggingIdentifiesUser covers the sign-in log naming the account it concerns. Without it
// the authentication methods can be counted but not attributed, and one user signing in repeatedly
// is indistinguishable from many users signing in once.
func TestSignInLoggingIdentifiesUser(t *testing.T) {
	var logBuffer bytes.Buffer
	httpContextExtractor := http_context_extractor.New()
	logger := altshiftContextLogger.New(
		slog.NewJSONHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelInfo}),
		&altshiftLog.ErrorContextExtractor{
			ContextExtractors: []altshiftLog.ContextExtractor{httpContextExtractor},
		},
		httpContextExtractor,
	)
	previousLogger := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(previousLogger)

	testEndpoint, err := New[*testing2.ProviderClaims](defaultPath)
	if err != nil {
		t.Fatalf("new endpoint: %v", err)
	}
	if err := testEndpoint.Initialize(testOrigin, oauthConfig, idTokenAuthenticator, sessionManager); err != nil {
		t.Fatalf("test endpoint initialize: %v", err)
	}
	testEndpoint.popOauthFlow = func(_ context.Context, _ string, _ *sql.DB) (*oauth_flow.Flow, error) {
		expiresAt := time.Now().Add(time.Hour)
		return &oauth_flow.Flow{
			Id:          testing2.OauthFlowId,
			RedirectUrl: testing2.RedirectUrl,
			State:       testing2.State,
			ExpiresAt:   &expiresAt,
		}, nil
	}

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint.Endpoint.Endpoint)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	callbackCookie := http.Cookie{Name: testEndpoint.CallbackCookieName, Value: testing2.OauthFlowId}
	muxTesting.TestArgs(
		t,
		&muxTesting.Args{
			Path:               testEndpoint.Path + "?state=" + testing2.State + "&code=" + testing2.OauthStrongAuthenticationCode,
			Method:             testEndpoint.Method,
			Headers:            [][2]string{{"Cookie", callbackCookie.String()}},
			ExpectedStatusCode: http.StatusSeeOther,
		},
		httpServer.URL,
	)

	entry := findLogEntry(t, &logBuffer, "An identity provider authenticated a user.")

	user, _ := entry["user"].(map[string]any)
	if user == nil {
		t.Fatalf("no user in log entry: %v", entry)
	}
	if emailAddress, _ := user["email"].(string); emailAddress != testing2.EmailAddress {
		t.Errorf("user email: got %v, expected %s", user["email"], testing2.EmailAddress)
	}
	if id, _ := user["id"].(string); id != testing2.Subject {
		t.Errorf("user id: got %v, expected %s", user["id"], testing2.Subject)
	}

	if strongAuthentication, _ := entry["strong_authentication"].(bool); !strongAuthentication {
		t.Errorf("expected the sign-in to be recorded as strongly authenticated: %v", entry)
	}
}
