package oauth_error

import (
	"errors"
	"fmt"
	"strings"
)

// Error represents an OAuth 2.0 authorization error response (RFC 6749 §4.1.2.1),
// which the provider returns via the redirect URI instead of an authorization
// code, e.g. when the user declines consent or cancels (error=access_denied).
type Error struct {
	// Code is the OAuth 2.0 `error` parameter, e.g. "access_denied".
	Code string
	// Subcode is a provider extension (Microsoft `error_subcode`, e.g. "cancel").
	Subcode string
	// Description is the human-readable `error_description` parameter.
	Description string
	// Uri is the `error_uri` parameter.
	Uri string
}

func (e *Error) Error() string {
	msg := e.codes()
	if e.Description != "" {
		msg += fmt.Sprintf(": %s", e.Description)
	}

	return msg
}

// Summary is the error as a record of the failed authentication carries it: its code and subcode,
// which the provider chooses from a set of its own, without the description, which is its free
// text and can name the account. It is a plain error, which a log writes as its message alone.
func (e *Error) Summary() error {
	if e == nil {
		return nil
	}

	//nolint:err113 // Plain, so that the log writes the message alone, with no type or cause.
	return errors.New(e.codes())
}

// codes is the error's code, and its subcode when it has one, as its message opens with them.
func (e *Error) codes() string {
	msg := fmt.Sprintf("oauth error: %s", e.Code)
	if e.Subcode != "" {
		msg += fmt.Sprintf(" (%s)", e.Subcode)
	}

	return msg
}

// GetCode satisfies github.com/altshiftab/utils_go/pkg/errors.CodeErrorI so the
// OAuth error code is emitted as ECS `error.code` by the error context extractor.
func (e *Error) GetCode() string {
	return e.Code
}

func New(code, subcode, description, uri string) *Error {
	return &Error{Code: code, Subcode: subcode, Description: description, Uri: uri}
}

// Category is a coarse, UX-oriented classification of an OAuth error, used to
// decide how to handle it (which problem page to show, whether a retry helps).
type Category int

const (
	// CategoryFailed is the default: an unexpected failure or one that indicates
	// application misconfiguration. Retrying is not expected to help.
	CategoryFailed Category = iota
	// CategoryCancelled is a user-initiated, recoverable outcome (declined consent
	// or pressed cancel/back). The user can simply try again.
	CategoryCancelled
	// CategoryAccessDenied is an authorization denial: the user authenticated but
	// is not permitted (tenant/role/admin policy). Retrying re-denies.
	CategoryAccessDenied
	// CategoryUnavailable is a transient provider failure; trying again later may
	// succeed.
	CategoryUnavailable
)

// accessDeniedDescriptionMarkers are substrings that, when present in an
// access_denied error_description, indicate a genuine authorization denial (the
// user authenticated but is not permitted) rather than a cancellation. These are
// best-effort Microsoft Entra codes; supply a custom classifier for
// provider-specific precision.
var accessDeniedDescriptionMarkers = []string{
	"AADSTS50105", // the signed-in user is not assigned to a role for the application
	"AADSTS90072", // the account does not exist in the tenant
	"AADSTS50020", // user account from an external identity provider does not exist in the tenant
	"AADSTS53003", // access blocked by a Conditional Access policy
}

// Category classifies the error for UX handling. The mapping is intentionally
// conservative: a bare access_denied is treated as a cancellation (the common,
// non-alarming case), and only escalated to a denial when an explicit policy
// signal is present. Unrecognized errors fall through to CategoryFailed so they
// are never silently treated as recoverable.
func (e *Error) Category() Category {
	if e == nil {
		return CategoryFailed
	}

	switch e.Code {
	case "access_denied":
		if e.Subcode == "cancel" {
			return CategoryCancelled
		}
		for _, marker := range accessDeniedDescriptionMarkers {
			if strings.Contains(e.Description, marker) {
				return CategoryAccessDenied
			}
		}
		return CategoryCancelled
	case "admin_policy_enforced", "org_internal", "consent_required":
		return CategoryAccessDenied
	case "server_error", "temporarily_unavailable":
		return CategoryUnavailable
	default:
		return CategoryFailed
	}
}
