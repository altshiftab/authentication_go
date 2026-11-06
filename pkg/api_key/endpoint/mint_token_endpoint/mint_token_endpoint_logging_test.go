package mint_token_endpoint

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"

	apiKeyTesting "github.com/altshiftab/authentication_go/pkg/api_key/testing"
	logMaskingTesting "github.com/altshiftab/authentication_go/pkg/log_masking/testing"
	"github.com/altshiftab/authentication_go/pkg/log_options"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
	"github.com/altshiftab/utils_go/pkg/http/types/http_context_extractor"
	altshiftLog "github.com/altshiftab/utils_go/pkg/log"
	altshiftContextLogger "github.com/altshiftab/utils_go/pkg/log/context_logger"
)

const mintMessage = "An API key minted a token."

// TestMintLogging covers what the mint's line and the request log say about the account that minted:
// its id always, and its address only when the service asks for it -- by default the address is in
// neither.
//
//nolint:paralleltest // Swaps the global slog default; running it in parallel would race.
func TestMintLogging(t *testing.T) {
	const emailAddress = "logging-mint@example.com"

	db := apiKeyTesting.Db(t)
	account := newAccount(t, db, emailAddress, "admin")

	testCases := []struct {
		name      string
		options   []log_options.Option
		wantEmail bool
	}{
		{name: "by default the account is named by its id alone"},
		{
			name:      "the address when the service asks for it",
			options:   []log_options.Option{log_options.WithLogEmailAddress(true)},
			wantEmail: true,
		},
	}

	for i, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			c := newAssertingClient(t)
			registerKey(t, db, account.Id, c.key, "a logging runner", nil)

			var logBuffer bytes.Buffer
			httpContextExtractor := http_context_extractor.New()
			previousLogger := slog.Default()
			slog.SetDefault(altshiftContextLogger.New(
				slog.NewJSONHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}),
				&altshiftLog.ErrorContextExtractor{ContextExtractors: []altshiftLog.ContextExtractor{httpContextExtractor}},
				httpContextExtractor,
			))
			defer slog.SetDefault(previousLogger)

			testEndpoint := New(testCase.options...)
			if err := testEndpoint.Initialize(newSessionManager(t, db), db, testAudience); err != nil {
				t.Fatalf("initialize: %v", err)
			}

			mux := &muxPkg.Mux{}
			mux.Add(testEndpoint.Endpoint.Endpoint)
			httpServer := httptest.NewServer(mux)
			defer httpServer.Close()

			result := mint(t, httpServer.URL, testEndpoint.Path, c.assert(t, "logging-assertion-"+strconv.Itoa(i), nil))
			if result.StatusCode != http.StatusOK {
				t.Fatalf("got status %d (%s), want %d", result.StatusCode, result.Body, http.StatusOK)
			}

			found := logMaskingTesting.FindAddress(logBuffer.String(), emailAddress)
			if !testCase.wantEmail && len(found) != 0 {
				t.Errorf("the address is in the log %q: %s", found, logBuffer.String())
			}

			entry := findMintEntry(t, &logBuffer)

			wantEvent := map[string]any{
				"category": []any{"authentication"},
				"type":     []any{"start"},
				"action":   "mint_token",
				"outcome":  "success",
			}
			if event, _ := entry["event"].(map[string]any); !reflect.DeepEqual(event, wantEvent) {
				t.Errorf("event %v, want %v", event, wantEvent)
			}

			user, _ := entry["user"].(map[string]any)
			if id, _ := user["id"].(string); id != account.Id {
				t.Errorf("user.id = %v, want %s", user["id"], account.Id)
			}
			if email, _ := user["email"].(string); testCase.wantEmail != (email == emailAddress) {
				t.Errorf("user.email = %q, want the address: %t", email, testCase.wantEmail)
			}
		})
	}
}

func findMintEntry(t *testing.T, buffer *bytes.Buffer) map[string]any {
	t.Helper()

	scanner := bufio.NewScanner(bytes.NewReader(buffer.Bytes()))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		var entry map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("unmarshal log line %q: %v", scanner.Bytes(), err)
		}
		if entry["msg"] == mintMessage {
			return entry
		}
	}

	t.Fatalf("no log entry with msg %q found in:\n%s", mintMessage, buffer.String())
	return nil
}
