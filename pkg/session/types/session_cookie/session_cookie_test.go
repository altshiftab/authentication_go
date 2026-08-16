package session_cookie

import (
	"net/http"
	"testing"
	"time"

	"github.com/altshiftab/authentication_go/pkg/session/types/session_cookie/session_cookie_config"
)

func TestNew(t *testing.T) {
	t.Parallel()

	expiresAt := time.Now().Add(time.Hour)

	testCases := []struct {
		name        string
		tokenString string
		cookieName  string
		domain      string
		options     []session_cookie_config.Option
		expectError bool
		check       func(t *testing.T, cookie *http.Cookie)
	}{
		{
			name:        "defaults",
			tokenString: "token",
			cookieName:  "session",
			domain:      "example.com",
			check: func(t *testing.T, cookie *http.Cookie) {
				if cookie.Value != "token" || cookie.Name != "session" || cookie.Domain != "example.com" {
					t.Errorf("cookie mismatch: %+v", cookie)
				}
				if cookie.Path != "/" || !cookie.Secure || !cookie.HttpOnly {
					t.Errorf("expected secure, http-only cookie on /: %+v", cookie)
				}
				if cookie.SameSite != session_cookie_config.DefaultSameSite {
					t.Errorf("same site: got %v", cookie.SameSite)
				}
				if !cookie.Expires.Equal(expiresAt) {
					t.Errorf("expires: got %v", cookie.Expires)
				}
			},
		},
		{
			name:        "with same site option",
			tokenString: "token",
			cookieName:  "session",
			domain:      "example.com",
			options:     []session_cookie_config.Option{session_cookie_config.WithSameSite(http.SameSiteStrictMode)},
			check: func(t *testing.T, cookie *http.Cookie) {
				if cookie.SameSite != http.SameSiteStrictMode {
					t.Errorf("same site: got %v", cookie.SameSite)
				}
			},
		},
		{name: "empty token", cookieName: "session", domain: "example.com", expectError: true},
		{name: "empty name", tokenString: "token", domain: "example.com", expectError: true},
		{name: "empty domain", tokenString: "token", cookieName: "session", expectError: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			cookie, err := New(testCase.tokenString, expiresAt, testCase.cookieName, testCase.domain, testCase.options...)
			if testCase.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("new: %v", err)
			}
			if cookie == nil {
				t.Fatalf("nil cookie")
			}

			testCase.check(t, cookie)
		})
	}
}

func TestAttributes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		domain   string
		options  []session_cookie_config.Option
		expected string
	}{
		{
			name:     "defaults",
			domain:   "example.com",
			expected: "Path=/; Domain=example.com; Secure; HttpOnly; SameSite=Lax",
		},
		{
			name:     "strict same site",
			domain:   "example.com",
			options:  []session_cookie_config.Option{session_cookie_config.WithSameSite(http.SameSiteStrictMode)},
			expected: "Path=/; Domain=example.com; Secure; HttpOnly; SameSite=Strict",
		},
		{
			name:     "none same site",
			domain:   "example.com",
			options:  []session_cookie_config.Option{session_cookie_config.WithSameSite(http.SameSiteNoneMode)},
			expected: "Path=/; Domain=example.com; Secure; HttpOnly; SameSite=None",
		},
		{
			name:     "default same site mode",
			domain:   "example.com",
			options:  []session_cookie_config.Option{session_cookie_config.WithSameSite(http.SameSiteDefaultMode)},
			expected: "Path=/; Domain=example.com; Secure; HttpOnly",
		},
		{
			name:     "empty domain",
			expected: "Path=/; Secure; HttpOnly; SameSite=Lax",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if attributes := Attributes(testCase.domain, testCase.options...); attributes != testCase.expected {
				t.Errorf("attributes: got %q, want %q", attributes, testCase.expected)
			}
		})
	}
}
