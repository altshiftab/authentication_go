package callback_endpoint_config

import (
	"context"
	"database/sql"
	"testing"

	"github.com/altshiftab/authentication_go/pkg/database/types/oauth_flow"
	"github.com/altshiftab/authentication_go/pkg/sso/errors/oauth_error"
)

func TestNew(t *testing.T) {
	t.Parallel()

	config := New()
	if config == nil {
		t.Fatalf("nil config")
	}

	if config.CallbackCookieName != DefaultCallbackCookieName {
		t.Errorf("callback cookie name: got %q", config.CallbackCookieName)
	}
	if config.PopOauthFlow == nil {
		t.Errorf("nil pop oauth flow")
	}
	if config.ClassifyOauthError == nil {
		t.Errorf("nil classify oauth error")
	}
}

func TestDefaultClassifyOauthError(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		err      *oauth_error.Error
		expected oauth_error.Category
	}{
		{
			name:     "cancelled",
			err:      oauth_error.New("access_denied", "cancel", "", ""),
			expected: oauth_error.CategoryCancelled,
		},
		{
			name:     "failed",
			err:      oauth_error.New("server_error_unknown", "", "", ""),
			expected: oauth_error.CategoryFailed,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if category := DefaultClassifyOauthError(testCase.err); category != testCase.expected {
				t.Errorf("category: got %v, want %v", category, testCase.expected)
			}
		})
	}
}

func TestOptions(t *testing.T) {
	t.Parallel()

	t.Run("with callback cookie name", func(t *testing.T) {
		t.Parallel()

		if config := New(WithCallbackCookieName("custom")); config.CallbackCookieName != "custom" {
			t.Errorf("callback cookie name: got %q", config.CallbackCookieName)
		}
	})

	t.Run("with pop oauth flow", func(t *testing.T) {
		t.Parallel()

		invoked := false
		config := New(WithPopOauthFlow(
			func(_ context.Context, _ string, _ *sql.DB) (*oauth_flow.Flow, error) {
				invoked = true
				return nil, nil
			},
		))

		if _, err := config.PopOauthFlow(t.Context(), "", nil); err != nil {
			t.Fatalf("pop oauth flow: %v", err)
		}
		if !invoked {
			t.Errorf("expected the configured function to be invoked")
		}
	})

	t.Run("with oauth error classifier", func(t *testing.T) {
		t.Parallel()

		config := New(WithOauthErrorClassifier(func(_ *oauth_error.Error) oauth_error.Category {
			return oauth_error.CategoryUnavailable
		}))

		if category := config.ClassifyOauthError(nil); category != oauth_error.CategoryUnavailable {
			t.Errorf("category: got %v", category)
		}
	})
}
