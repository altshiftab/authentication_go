package session_instructions

import (
	"encoding/json/v2"
	"testing"
)

func TestEnded(t *testing.T) {
	t.Parallel()

	instructions := Ended()
	if instructions == nil {
		t.Fatalf("nil instructions")
	}
	if instructions.Continue == nil {
		t.Fatalf("nil continue")
	}
	if *instructions.Continue {
		t.Errorf("expected continue to be false")
	}
}

func TestInstructionsMarshalling(t *testing.T) {
	t.Parallel()

	sessionContinues := true

	testCases := []struct {
		name         string
		instructions *Instructions
		expected     string
	}{
		{
			// Ending a session carries nothing else: the other fields may be omitted.
			name:         "ended",
			instructions: Ended(),
			expected:     `{"continue":false}`,
		},
		{
			// The protocol requires include_site, so it is emitted even when false.
			name: "scope with include site false",
			instructions: &Instructions{
				SessionIdentifier: "session-id",
				RefreshURL:        "/refresh",
				Scope:             &Scope{Origin: "https://example.com", IncludeSite: false},
			},
			expected: `{"session_identifier":"session-id","refresh_url":"/refresh","scope":{"origin":"https://example.com","include_site":false}}`,
		},
		{
			name: "full instructions",
			instructions: &Instructions{
				SessionIdentifier: "session-id",
				RefreshURL:        "/refresh",
				Scope: &Scope{
					Origin:      "https://example.com",
					IncludeSite: true,
					ScopeSpecification: []*ScopeSpecification{
						{Type: "exclude", Domain: "example.com", Path: "/static"},
					},
				},
				Credentials:              []*Credential{{Type: "cookie", Name: "session", Attributes: "Path=/; Secure"}},
				AllowedRefreshInitiators: []string{"*.example.com"},
				Continue:                 &sessionContinues,
			},
			expected: `{"session_identifier":"session-id","refresh_url":"/refresh","scope":{"origin":"https://example.com","include_site":true,"scope_specification":[{"type":"exclude","domain":"example.com","path":"/static"}]},"credentials":[{"type":"cookie","name":"session","attributes":"Path=/; Secure"}],"allowed_refresh_initiators":["*.example.com"],"continue":true}`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			data, err := json.Marshal(testCase.instructions)
			if err != nil {
				t.Fatalf("json marshal: %v", err)
			}
			if string(data) != testCase.expected {
				t.Errorf("got %s, expected %s", data, testCase.expected)
			}
		})
	}
}
