package validate_endpoint

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	magicLinkTesting "github.com/altshiftab/authentication_go/pkg/magic_link/testing"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
	muxTesting "github.com/altshiftab/utils_go/pkg/http/mux/testing"
	"github.com/altshiftab/utils_go/pkg/http/types/http_context_extractor"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	altshiftLog "github.com/altshiftab/utils_go/pkg/log"
	altshiftContextLogger "github.com/altshiftab/utils_go/pkg/log/context_logger"
)

const signInMessage = "A magic link authenticated a user."

// TestSignInLogging covers the sign-in this endpoint records. This is the request that authenticates
// the user and mints the session, and it named nobody: the account first appeared on the redirect
// that follows, on the strength of the cookie this request set, so a magic link sign-in could only
// be attributed by inference from the request after it.
//
// The message is deliberately not the identity provider's. No provider authenticated anyone here,
// and a magic link proves only possession of a mailbox -- no second factor, no organization, no
// authentication context -- so the two are kept queryable apart rather than pooled under a line that
// would overstate what a magic link establishes.
//
// It is intentionally NOT parallel: it swaps the global slog default to capture output. Non-parallel
// tests run to completion before the package's parallel tests resume, so this does not race with
// TestEndpoint's parallel subtests.
//
//nolint:paralleltest // Swaps the global slog default; running it in parallel would race.
func TestSignInLogging(t *testing.T) {
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

	testEndpoint := New()
	if err := testEndpoint.Initialize(signer, sessionManager, redirectUrl); err != nil {
		t.Fatalf("test endpoint initialize: %v", err)
	}

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint.Endpoint.Endpoint)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	token := mintToken(t, defaultPayload(magicLinkTesting.ValidEmail, "logging-nonce"))

	muxTesting.TestArgs(
		t,
		&muxTesting.Args{
			Path:                   testEndpoint.Path + "?token=" + token,
			Method:                 testEndpoint.Method,
			ExpectedStatusCode:     http.StatusSeeOther,
			ExpectedHeadersPresent: []string{"Set-Cookie"},
		},
		httpServer.URL,
	)

	// The link is spent: a second submission, as a double-clicked button sends, is refused and must not
	// be recorded as a second sign-in.
	muxTesting.TestArgs(
		t,
		&muxTesting.Args{
			Path:               testEndpoint.Path + "?token=" + token,
			Method:             testEndpoint.Method,
			ExpectedStatusCode: http.StatusConflict,
			ExpectedProblemDetail: &problem_detail.Detail{
				Detail: "This sign-in link has already been used.",
			},
		},
		httpServer.URL,
	)

	if count := countLogEntries(t, &logBuffer, signInMessage); count != 1 {
		t.Errorf("got %d %q log entries, want 1", count, signInMessage)
	}

	entry := findLogEntry(t, &logBuffer, signInMessage)

	user, _ := entry["user"].(map[string]any)
	if user == nil {
		t.Fatalf("no user in log entry: %v", entry)
	}
	if emailAddress, _ := user["email"].(string); emailAddress != magicLinkTesting.ValidEmail {
		t.Errorf("user.email = %v, want %s", user["email"], magicLinkTesting.ValidEmail)
	}

	// A magic link states nothing about how the user authenticated, so the line must not carry the
	// fields an SSO sign-in does. Reporting strong_authentication:false here would read as a weak
	// sign-in assessed and found wanting, rather than a method with nothing to assess.
	for _, key := range []string{
		"strong_authentication",
		"authentication_method_references",
		"authentication_context_class",
		"organization",
	} {
		if value, ok := entry[key]; ok {
			t.Errorf("expected no %s on a magic link sign-in; got %v", key, value)
		}
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

func countLogEntries(t *testing.T, buffer *bytes.Buffer, message string) int {
	t.Helper()

	var count int
	for line := range bytes.Lines(buffer.Bytes()) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		var entry map[string]any
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatalf("unmarshal log line %q: %v", line, err)
		}

		if entry["msg"] == message {
			count++
		}
	}

	return count
}
