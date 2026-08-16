package oauth_error

import (
	"testing"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
)

// Error must satisfy the error context extractor's CodeErrorI so that the OAuth
// error code is emitted as ECS `error.code`.
var _ motmedelErrors.CodeErrorI = (*Error)(nil)

func TestError(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		code        string
		subcode     string
		description string
		uri         string
		want        string
	}{
		{
			name: "code only",
			code: "access_denied",
			want: "oauth error: access_denied",
		},
		{
			name:    "code and subcode",
			code:    "access_denied",
			subcode: "cancel",
			want:    "oauth error: access_denied (cancel)",
		},
		{
			name:        "code and description",
			code:        "access_denied",
			description: "User declined to consent to access the app.",
			want:        "oauth error: access_denied: User declined to consent to access the app.",
		},
		{
			name:        "all fields",
			code:        "access_denied",
			subcode:     "cancel",
			description: "User declined to consent to access the app.",
			uri:         "https://example.com/error",
			want:        "oauth error: access_denied (cancel): User declined to consent to access the app.",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := New(testCase.code, testCase.subcode, testCase.description, testCase.uri)
			if got := err.Error(); got != testCase.want {
				t.Errorf("Error() = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestGetCode(t *testing.T) {
	t.Parallel()

	err := New("access_denied", "cancel", "User declined.", "https://example.com/error")
	if got := err.GetCode(); got != "access_denied" {
		t.Errorf("GetCode() = %q, want %q", got, "access_denied")
	}
}

func TestCategory(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		code        string
		subcode     string
		description string
		want        Category
	}{
		{name: "microsoft cancel", code: "access_denied", subcode: "cancel", want: CategoryCancelled},
		{name: "bare access_denied (google cancel)", code: "access_denied", want: CategoryCancelled},
		{name: "declined consent", code: "access_denied", description: "AADSTS65004: User declined to consent.", want: CategoryCancelled},
		{name: "not assigned to app", code: "access_denied", description: "AADSTS50105: not assigned.", want: CategoryAccessDenied},
		{name: "not in tenant", code: "access_denied", description: "AADSTS90072: account does not exist.", want: CategoryAccessDenied},
		{name: "google admin policy", code: "admin_policy_enforced", want: CategoryAccessDenied},
		{name: "google org internal", code: "org_internal", want: CategoryAccessDenied},
		{name: "consent required", code: "consent_required", want: CategoryAccessDenied},
		{name: "server error", code: "server_error", want: CategoryUnavailable},
		{name: "temporarily unavailable", code: "temporarily_unavailable", want: CategoryUnavailable},
		{name: "misconfig invalid_scope", code: "invalid_scope", want: CategoryFailed},
		{name: "unauthorized client", code: "unauthorized_client", want: CategoryFailed},
		{name: "unknown", code: "something_new", want: CategoryFailed},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := New(testCase.code, testCase.subcode, testCase.description, "")
			if got := err.Category(); got != testCase.want {
				t.Errorf("Category() = %d, want %d", got, testCase.want)
			}
		})
	}
}

func TestCategoryNil(t *testing.T) {
	t.Parallel()

	var err *Error
	if got := err.Category(); got != CategoryFailed {
		t.Errorf("nil Category() = %d, want %d (CategoryFailed)", got, CategoryFailed)
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	err := New("access_denied", "cancel", "User declined.", "https://example.com/error")
	if err.Code != "access_denied" {
		t.Errorf("Code = %q, want %q", err.Code, "access_denied")
	}
	if err.Subcode != "cancel" {
		t.Errorf("Subcode = %q, want %q", err.Subcode, "cancel")
	}
	if err.Description != "User declined." {
		t.Errorf("Description = %q, want %q", err.Description, "User declined.")
	}
	if err.Uri != "https://example.com/error" {
		t.Errorf("Uri = %q, want %q", err.Uri, "https://example.com/error")
	}
}
