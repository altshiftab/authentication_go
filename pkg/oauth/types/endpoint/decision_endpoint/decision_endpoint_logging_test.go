package decision_endpoint

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/altshiftab/authentication_go/pkg/log_options"
	"github.com/altshiftab/authentication_go/pkg/log_options/log_options_testing"
	"github.com/altshiftab/authentication_go/pkg/oauth"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/memory_store"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
)

/*
 * What a decision says in the log: one line, allowing or denying, naming the user by id and the
 * client by its id, with the service's own event attributes. A refusal is the client's failure to
 * be authorized, so it is logged as one, and the same query finds it beside every other refusal.
 */
//nolint:paralleltest // Swaps the global slog default; running it in parallel would race.
func TestAuditEvents(t *testing.T) {
	const (
		accountId = "an-account"
		clientId  = "se.vvvp.vocab"
	)

	// The session as the endpoint sees it: the account is signed in.
	authorizer := request_parser.New(func(*http.Request) (*session_token.Token, *response_error.ResponseError) {
		return &session_token.Token{SubjectId: accountId}, nil
	})

	testCases := []struct {
		name        string
		decision    string
		wantMessage string
		wantOutcome string
		// wantParameter is what the client is sent back with.
		wantParameter string
	}{
		{
			name:          "allowing the client",
			decision:      "allow",
			wantMessage:   "An OAuth client was authorized.",
			wantOutcome:   log_options.OutcomeSuccess,
			wantParameter: "code",
		},
		{
			name:          "denying the client",
			decision:      "deny",
			wantMessage:   "An OAuth client was refused authorization.",
			wantOutcome:   log_options.OutcomeFailure,
			wantParameter: "error",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			store := memory_store.New()
			requestId, err := store.InsertAuthorizationRequest(t.Context(), &oauth.AuthorizationRequest{
				AccountId:     accountId,
				ClientId:      clientId,
				RedirectUri:   "se.vvvp.vocab:/oauth2redirect",
				State:         "a-state",
				CodeChallenge: "a-challenge",
				Resource:      "https://api.example.com",
				Scope:         "vocab",
				ExpiresAt:     time.Now().Add(time.Minute),
			})
			if err != nil {
				t.Fatalf("%s: store insert authorization request: %v", testCase.name, err)
			}

			endpoint := New(log_options.WithEventAttrs(slog.String("dataset", "service.audit")))
			if err := endpoint.Initialize(authorizer, "https://issuer.example.com", store); err != nil {
				t.Fatalf("%s: initialize: %v", testCase.name, err)
			}
			server := httptest.NewServer(muxPkg.New(endpoint.Endpoint.Endpoint))
			defer server.Close()

			var status int
			var location string
			lines, err := log_options_testing.Capture(func() {
				status, location = post(t, server.URL+DefaultPath, url.Values{"request_id": {requestId}, "decision": {testCase.decision}})
			})
			if err != nil {
				t.Fatalf("%s: capture: %v", testCase.name, err)
			}

			if status != http.StatusSeeOther {
				t.Fatalf("%s: got status %d, want %d", testCase.name, status, http.StatusSeeOther)
			}
			if parsed, err := url.Parse(location); err != nil || !parsed.Query().Has(testCase.wantParameter) {
				t.Errorf("%s: the client is sent back to %q, without %q", testCase.name, location, testCase.wantParameter)
			}

			wantEvent := map[string]any{
				"category": []any{"authentication"},
				"type":     []any{"start"},
				"action":   "oauth_authorization_decision",
				"outcome":  testCase.wantOutcome,
				"dataset":  "service.audit",
			}
			if events := log_options_testing.Events(lines, "oauth_authorization_decision"); len(events) != 1 || !reflect.DeepEqual(events[0], wantEvent) {
				t.Fatalf("%s: got events %v, want one %v", testCase.name, events, wantEvent)
			}

			line := decisionLine(lines)
			if message, _ := line["msg"].(string); message != testCase.wantMessage {
				t.Errorf("%s: got message %q, want %q", testCase.name, message, testCase.wantMessage)
			}
			if user, _ := line["user"].(map[string]any); user["id"] != accountId {
				t.Errorf("%s: got user %v, want id %q", testCase.name, line["user"], accountId)
			}
			if client, _ := line["oauth"].(map[string]any); client["client_id"] != clientId || client["scope"] != "vocab" {
				t.Errorf("%s: got oauth %v, want client %q and scope vocab", testCase.name, line["oauth"], clientId)
			}
		})
	}
}

// post sends the consent page's answer and returns the response's status and where it sends the
// user, its redirect not followed.
func post(t *testing.T, target string, form url.Values) (int, string) {
	t.Helper()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if response == nil {
		t.Fatal("no response")
	}
	defer response.Body.Close()

	return response.StatusCode, response.Header.Get("Location")
}

// decisionLine is the line that carries the decision's event.
func decisionLine(lines []map[string]any) map[string]any {
	for _, line := range lines {
		if event, _ := line["event"].(map[string]any); event["action"] == "oauth_authorization_decision" {
			return line
		}
	}

	return nil
}
