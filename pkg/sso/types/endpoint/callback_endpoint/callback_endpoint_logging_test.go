package callback_endpoint

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"github.com/altshiftab/authentication_go/pkg/log_masking"
	logMaskingTesting "github.com/altshiftab/authentication_go/pkg/log_masking/testing"
	"github.com/altshiftab/authentication_go/pkg/log_options"
	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/callback_endpoint/callback_endpoint_config"
	muxTesting "github.com/altshiftab/utils_go/pkg/http/mux/testing"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
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
	"github.com/altshiftab/utils_go/pkg/log/pii_hasher"
)

// TestProviderErrorLogging drives the OAuth provider-error path (the user
// declined consent) and asserts both the HTTP behavior and the ECS fields of the
// structured log line it emits.
//
// It is intentionally NOT parallel: it swaps the global slog default to capture
// output. Non-parallel tests run to completion before the package's parallel
// tests resume, so this does not race with TestEndpoint's parallel subtests.
func TestProviderErrorLogging(t *testing.T) { //nolint:paralleltest // Swaps the global slog default; see above.
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

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, requestUrl, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.AddCookie(&http.Cookie{Name: testEndpoint.CallbackCookieName, Value: testing2.OauthFlowId}) //nolint:gosec // G124: a request cookie; its attributes are never sent.

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("client do: %v", err)
	}
	if response == nil {
		t.Fatal("nil response")
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

	// What the identity provider said goes to the service's own log: the error with its
	// description and code, and the request it came on, bridged from the mux's HTTP context. It
	// carries no event, so that it is not taken for the record.
	logEntry := findLogEntry(t, &logBuffer, "An OAuth error occurred.")
	if level, _ := logEntry["level"].(string); level != "WARN" {
		t.Errorf("level = %q, want %q", level, "WARN")
	}
	if _, ok := logEntry["event"]; ok {
		t.Errorf("the line of what the provider said carries an event: %v", logEntry["event"])
	}
	errorObject := childObject(t, logEntry, "error")
	if got := errorObject["code"]; got != "access_denied" {
		t.Errorf("error.code = %v, want %q", got, "access_denied")
	}
	if message, _ := errorObject["message"].(string); !strings.Contains(message, "access_denied") ||
		!strings.Contains(message, errorDescription) {
		t.Errorf("error.message = %q, want it to contain %q and %q", message, "access_denied", errorDescription)
	}
	for _, group := range []string{"http", "url"} {
		if _, ok := logEntry[group]; !ok {
			t.Errorf("expected a %q group in the log entry; got keys %v", group, keysOf(logEntry))
		}
	}

	// The record: a failed authentication by the identity provider, as the success is the same
	// action with the outcome success, so that one query over the action answers both. It carries
	// the error's codes alone: not the description, the provider's free text, nor the request, which
	// the success's record does not carry either.
	record := findLogEntry(t, &logBuffer, "An identity provider did not authenticate a user.")
	if level, _ := record["level"].(string); level != "WARN" {
		t.Errorf("level = %q, want %q", level, "WARN")
	}
	event := childObject(t, record, "event")
	if got := event["action"]; got != "identity_provider_authentication" {
		t.Errorf("event.action = %v, want %q", got, "identity_provider_authentication")
	}
	if got := event["outcome"]; got != "failure" {
		t.Errorf("event.outcome = %v, want %q", got, "failure")
	}
	if got := event["reason"]; got != "An OAuth error occurred." {
		t.Errorf("event.reason = %v, want %q", got, "An OAuth error occurred.")
	}
	wantError := map[string]any{"message": "oauth error: access_denied (cancel)"}
	if got := record["error"]; !reflect.DeepEqual(got, wantError) {
		t.Errorf("the record's error is %v, want %v", got, wantError)
	}
	for _, group := range []string{"url", "client", "user_agent"} {
		if _, ok := record[group]; ok {
			t.Errorf("the record carries the request's %q: %v", group, record[group])
		}
	}
	recordBytes, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("json marshal (record): %v", err)
	}
	if strings.Contains(string(recordBytes), "declined") {
		t.Errorf("the record holds the provider's description: %s", recordBytes)
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
//
//nolint:paralleltest // Swaps the global slog default; running it in parallel would race.
func TestSignInLoggingIdentifiesUser(t *testing.T) {
	hasher, err := pii_hasher.New(bytes.Repeat([]byte{7}, pii_hasher.MinimumKeyLength))
	if err != nil {
		t.Fatalf("pii hasher new: %v", err)
	}

	// The address is named by its keyed hash, and not at all without a hasher; in neither case is it
	// written out.
	testCases := []struct {
		name     string
		hasher   *pii_hasher.Hasher
		wantHash string
	}{
		{name: "with a hasher", hasher: hasher, wantHash: hasher.HashEmailAddress(testing2.EmailAddress)},
		{name: "without a hasher"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			testSignInLoggingIdentifiesUser(t, testCase.name, testCase.hasher, testCase.wantHash)
		})
	}
}

func testSignInLoggingIdentifiesUser(t *testing.T, name string, hasher *pii_hasher.Hasher, wantHash string) {
	t.Helper()

	var logBuffer bytes.Buffer
	httpContextExtractor := http_context_extractor.New()
	logger := altshiftContextLogger.New(
		slog.NewJSONHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}),
		&altshiftLog.ErrorContextExtractor{
			ContextExtractors: []altshiftLog.ContextExtractor{httpContextExtractor},
		},
		httpContextExtractor,
	)
	previousLogger := slog.Default()
	slog.SetDefault(logger)
	defer slog.SetDefault(previousLogger)

	testEndpoint, err := New[*testing2.ProviderClaims](
		defaultPath,
		callback_endpoint_config.WithLog(log_options.WithEmailAddressHasher(hasher)),
	)
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

	// Masked as a service masks it, and through New, for the request log the mux writes
	// once a response is served: that is where a request's headers and body are written.
	if err := log_masking.Apply(httpContextExtractor, testEndpoint); err != nil {
		t.Fatalf("log masking apply: %v", err)
	}
	mux := muxPkg.New(testEndpoint.Endpoint.Endpoint)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	callbackCookie := http.Cookie{Name: testEndpoint.CallbackCookieName, Value: testing2.OauthFlowId} //nolint:gosec // G124: a request cookie; its attributes are never sent.
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

	if found := logMaskingTesting.FindAddress(logBuffer.String(), testing2.EmailAddress); len(found) != 0 {
		t.Errorf("%s: the address is in the log %q: %s", name, found, logBuffer.String())
	}

	entry := findLogEntry(t, &logBuffer, "An identity provider authenticated a user.")

	// Whether the tenant verified the address's domain, as the token said: logged, not required.
	if got := entry["email_domain_owner_verified"]; got != "true" {
		t.Errorf("%s: email_domain_owner_verified = %v, want %q", name, got, "true")
	}

	// The provider's authentication, which the endpoint's own checks can still refuse after it.
	wantEvent := map[string]any{
		"category": []any{"authentication"},
		"type":     []any{"start"},
		"action":   "identity_provider_authentication",
		"outcome":  "success",
	}
	if event, _ := entry["event"].(map[string]any); !reflect.DeepEqual(event, wantEvent) {
		t.Errorf("%s: event %v, want %v", name, event, wantEvent)
	}

	user, _ := entry["user"].(map[string]any)
	if user == nil {
		t.Fatalf("no user in log entry: %v", entry)
	}
	if hash, _ := user["hash"].(string); hash != wantHash {
		t.Errorf("%s: user hash: got %v, expected %q", name, user["hash"], wantHash)
	}
	if id, _ := user["id"].(string); id != testing2.Subject {
		t.Errorf("user id: got %v, expected %s", user["id"], testing2.Subject)
	}

	// Nested as ECS organization.id: a top-level string clashes with the organization object mapping.
	organization, _ := entry["organization"].(map[string]any)
	if organization == nil {
		t.Errorf("expected an organization object; got %v", entry["organization"])
	} else if _, ok := organization["id"].(string); !ok {
		t.Errorf("expected a string organization id; got %v", organization["id"])
	}
	if strongAuthentication, _ := entry["strong_authentication"].(bool); !strongAuthentication {
		t.Errorf("expected the sign-in to be recorded as strongly authenticated: %v", entry)
	}
}

// A refused sign-in is still on record: the identity provider's line is written first, with what it
// said and what was required of it, and the refusal follows it. Checking before the line would leave
// the refusal unrecorded -- for an address the provider did not verify, as for an email domain the
// account's organization has not verified.
//
//nolint:paralleltest // Swaps the global slog default.
func TestRefusedSignInIsOnRecord(t *testing.T) {
	const addressDetail = "The email address that is tied to the id token is unverified or invalid."
	const domainDetail = "The organization the account belongs to has not verified the domain of its email address."

	testCases := []struct {
		name       string
		code       string
		options    []callback_endpoint_config.Option
		detail     string
		wantFields map[string]any
	}{
		{
			name:       "an email domain the organization has not verified",
			code:       testing2.OauthUnverifiedEmailDomainCode,
			options:    []callback_endpoint_config.Option{callback_endpoint_config.WithRequireEmailDomainOwnerVerified(true)},
			detail:     domainDetail,
			wantFields: map[string]any{"email_domain_owner_verified": "false", "email_domain_owner_verified_required": true, "email_address_verified": true},
		},
		{
			// Microsoft's and Google's claims refuse an address that is missing as they refuse one
			// that is unverified, with ErrForbiddenUser, so this is the path both take.
			name:       "an address the provider did not verify",
			code:       testing2.OauthUnverifiedEmailAddressCode,
			detail:     addressDetail,
			wantFields: map[string]any{"email_address_verified": false},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			entry := refusedSignInEntry(t, testCase.code, testCase.detail, testCase.options...)
			for field, want := range testCase.wantFields {
				if got := entry[field]; got != want {
					t.Errorf("%s = %v, want %v", field, got, want)
				}
			}
			// The account is named by its id whatever the address.
			if user, _ := entry["user"].(map[string]any); user["id"] != testing2.Subject {
				t.Errorf("user = %v, want the id %q", entry["user"], testing2.Subject)
			}
		})
	}
}

// refusedSignInEntry drives a sign-in with code that the endpoint refuses with detail, and returns
// the identity provider's line it wrote before refusing.
func refusedSignInEntry(t *testing.T, code string, detail string, options ...callback_endpoint_config.Option) map[string]any {
	t.Helper()

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

	testEndpoint, err := New[*testing2.ProviderClaims](defaultPath, options...)
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

	mux := muxPkg.New(testEndpoint.Endpoint.Endpoint)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	callbackCookie := http.Cookie{Name: testEndpoint.CallbackCookieName, Value: testing2.OauthFlowId} //nolint:gosec // G124: a request cookie; its attributes are never sent.
	muxTesting.TestArgs(
		t,
		&muxTesting.Args{
			Path:                  testEndpoint.Path + "?state=" + testing2.State + "&code=" + code,
			Method:                testEndpoint.Method,
			Headers:               [][2]string{{"Cookie", callbackCookie.String()}},
			ExpectedStatusCode:    http.StatusForbidden,
			ExpectedProblemDetail: &problem_detail.Detail{Detail: detail},
		},
		httpServer.URL,
	)

	return findLogEntry(t, &logBuffer, "An identity provider authenticated a user.")
}
