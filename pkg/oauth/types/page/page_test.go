package page

import (
	"strings"
	"testing"
)

func TestRenderConsent(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		redirectUri    string
		wantFormAction string
		wantWarning    bool
	}{
		{name: "a web client", redirectUri: "https://claude.ai/api/mcp/auth_callback", wantFormAction: "form-action 'self' https://claude.ai;"},
		{name: "an app on the user's machine", redirectUri: "http://localhost:53682/callback", wantFormAction: "form-action 'self' http://localhost:*;", wantWarning: true},
		// A scheme alone is a CSP scheme-source.
		{name: "an app on the user's phone", redirectUri: "se.vvvp.vocab:/oauth2redirect", wantFormAction: "form-action 'self' se.vvvp.vocab:;", wantWarning: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			body, headers, err := RenderConsent(&Consent{
				ClientName:   `Claude <script>alert(1)</script>`,
				ClientId:     "https://claude.ai/oauth/mcp",
				RedirectUri:  testCase.redirectUri,
				ResourceName: "Vocab",
				ResourceUrl:  "https://vocab.vvvp.se/mcp",
				Scope:        "vocab",
				RequestId:    "a-request",
				DecisionPath: "/oauth/authorize/decision",
			})
			if err != nil {
				t.Fatalf("%s: %v", testCase.name, err)
			}

			page := string(body)
			// The client names itself, so its name is text, never markup.
			if strings.Contains(page, "<script>") || !strings.Contains(page, "&lt;script&gt;") {
				t.Errorf("%s: the client's name is not escaped: %s", testCase.name, page)
			}
			if !strings.Contains(page, `name="request_id" value="a-request"`) || !strings.Contains(page, `action="/oauth/authorize/decision"`) {
				t.Errorf("%s: no form answering the request: %s", testCase.name, page)
			}
			if hasWarning := strings.Contains(page, "on this computer") || strings.Contains(page, "on this device"); hasWarning != testCase.wantWarning {
				t.Errorf("%s: warning %t, want %t", testCase.name, hasWarning, testCase.wantWarning)
			}

			values := map[string]string{}
			for _, h := range headers {
				values[h.Name] = h.Value
			}
			policy := values["Content-Security-Policy"]
			for _, want := range []string{"default-src 'none'", "frame-ancestors 'none'", testCase.wantFormAction} {
				if !strings.Contains(policy+";", want) {
					t.Errorf("%s: policy %q lacks %q", testCase.name, policy, want)
				}
			}
			if values["Cache-Control"] != "no-store" || values["X-Frame-Options"] != "DENY" {
				t.Errorf("%s: headers %v", testCase.name, values)
			}
		})
	}
}

func TestRenderMessage(t *testing.T) {
	t.Parallel()

	body, headers, err := RenderMessage("Refused", `<b>bold</b>`)
	if err != nil {
		t.Fatalf("render message: %v", err)
	}
	if strings.Contains(string(body), "<b>") {
		t.Errorf("the detail is not escaped: %s", body)
	}
	for _, h := range headers {
		if h.Name == "Content-Security-Policy" && !strings.Contains(h.Value, "form-action 'none'") {
			t.Errorf("policy %q", h.Value)
		}
	}
}
