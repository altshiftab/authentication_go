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
				status, location = post(t, server.URL+DefaultPath, url.Values{"request_id": {requestId}, "decision": {testCase.decision}}.Encode())
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

/*
 * What a refused answer says in the log: one line, a failure with the reason, naming the user who
 * answered, and, when the request is known, its client and the account it was made for if that is
 * someone else. An answer for another account's request is the one worth looking into.
 */
//nolint:paralleltest // Swaps the global slog default; running it in parallel would race.
func TestRefusalAuditEvents(t *testing.T) {
	const (
		accountId = "an-account"
		otherId   = "another-account"
		clientId  = "se.vvvp.vocab"
	)

	authorizer := request_parser.New(func(*http.Request) (*session_token.Token, *response_error.ResponseError) {
		return &session_token.Token{SubjectId: accountId}, nil
	})

	testCases := []struct {
		name string
		// requestAccount is the account the stored request was made for; none is stored when empty.
		requestAccount string
		expired        bool
		// body is the answer sent, given the stored request's id.
		body       func(requestId string) string
		wantStatus int
		wantReason string
		// wantClient is whether the line names the request's client, the request being known.
		wantClient bool
		wantTarget string
	}{
		{
			name:           "an answer for another account's request",
			requestAccount: otherId,
			body:           func(id string) string { return url.Values{"request_id": {id}, "decision": {"allow"}}.Encode() },
			wantStatus:     http.StatusForbidden,
			wantReason:     "request for another account",
			wantClient:     true,
			wantTarget:     otherId,
		},
		{
			name:           "an expired request",
			requestAccount: accountId,
			expired:        true,
			body:           func(id string) string { return url.Values{"request_id": {id}, "decision": {"allow"}}.Encode() },
			wantStatus:     http.StatusBadRequest,
			wantReason:     "expired request",
			wantClient:     true,
		},
		{
			name:           "an answer neither to allow nor to deny",
			requestAccount: accountId,
			body:           func(id string) string { return url.Values{"request_id": {id}, "decision": {"maybe"}}.Encode() },
			wantStatus:     http.StatusBadRequest,
			wantReason:     "unknown decision",
			wantClient:     true,
		},
		{
			name: "a request answered already, or never made",
			body: func(string) string {
				return url.Values{"request_id": {"no-such-request"}, "decision": {"allow"}}.Encode()
			},
			wantStatus: http.StatusBadRequest,
			wantReason: "unknown request",
		},
		{
			name:       "an answer naming no request",
			body:       func(string) string { return url.Values{"decision": {"allow"}}.Encode() },
			wantStatus: http.StatusBadRequest,
			wantReason: "no request id",
		},
		{
			name:       "an answer that cannot be read",
			body:       func(string) string { return "request_id=%zz" },
			wantStatus: http.StatusBadRequest,
			wantReason: "unreadable answer",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			store := memory_store.New()
			var requestId string
			if testCase.requestAccount != "" {
				expiresAt := time.Now().Add(time.Minute)
				if testCase.expired {
					expiresAt = time.Now().Add(-time.Minute)
				}
				var err error
				requestId, err = store.InsertAuthorizationRequest(t.Context(), &oauth.AuthorizationRequest{
					AccountId:     testCase.requestAccount,
					ClientId:      clientId,
					RedirectUri:   "se.vvvp.vocab:/oauth2redirect",
					State:         "a-state",
					CodeChallenge: "a-challenge",
					Resource:      "https://api.example.com",
					Scope:         "vocab",
					ExpiresAt:     expiresAt,
				})
				if err != nil {
					t.Fatalf("%s: store insert authorization request: %v", testCase.name, err)
				}
			}

			endpoint := New(log_options.WithEventAttrs(slog.String("dataset", "service.audit")))
			if err := endpoint.Initialize(authorizer, "https://issuer.example.com", store); err != nil {
				t.Fatalf("%s: initialize: %v", testCase.name, err)
			}
			server := httptest.NewServer(muxPkg.New(endpoint.Endpoint.Endpoint))
			defer server.Close()

			var status int
			lines, err := log_options_testing.Capture(func() {
				status, _ = post(t, server.URL+DefaultPath, testCase.body(requestId))
			})
			if err != nil {
				t.Fatalf("%s: capture: %v", testCase.name, err)
			}
			if status != testCase.wantStatus {
				t.Errorf("%s: got status %d, want %d", testCase.name, status, testCase.wantStatus)
			}

			wantEvent := map[string]any{
				"category": []any{"authentication"},
				"type":     []any{"start"},
				"action":   "oauth_authorization_decision",
				"outcome":  log_options.OutcomeFailure,
				"dataset":  "service.audit",
			}
			if events := log_options_testing.Events(lines, "oauth_authorization_decision"); len(events) != 1 || !reflect.DeepEqual(events[0], wantEvent) {
				t.Fatalf("%s: got events %v, want one %v", testCase.name, events, wantEvent)
			}

			line := decisionLine(lines)
			client, _ := line["oauth"].(map[string]any)
			if client["error"] != testCase.wantReason {
				t.Errorf("%s: got reason %v, want %q", testCase.name, client["error"], testCase.wantReason)
			}
			if _, named := client["client_id"]; named != testCase.wantClient || (named && client["client_id"] != clientId) {
				t.Errorf("%s: got oauth %v, want the client named: %t", testCase.name, client, testCase.wantClient)
			}

			user, _ := line["user"].(map[string]any)
			if user["id"] != accountId {
				t.Errorf("%s: got user %v, want id %q", testCase.name, user, accountId)
			}
			target, _ := user["target"].(map[string]any)
			if gotTarget, _ := target["id"].(string); gotTarget != testCase.wantTarget {
				t.Errorf("%s: got target %q, want %q", testCase.name, gotTarget, testCase.wantTarget)
			}
		})
	}
}

// post sends the consent page's answer and returns the response's status and where it sends the
// user, its redirect not followed.
func post(t *testing.T, target string, body string) (int, string) {
	t.Helper()

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(body))
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
