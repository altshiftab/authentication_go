package testing

import (
	"errors"
	"testing"

	ssoErrors "github.com/altshiftab/authentication_go/pkg/sso/errors"
)

func TestSetUp(t *testing.T) {
	t.Parallel()

	sessionManager, authenticatorWithKeyHandler, oauthConfig, signer := SetUp()
	if sessionManager == nil || authenticatorWithKeyHandler == nil || oauthConfig == nil || signer == nil {
		t.Fatalf("incomplete setup")
	}
	defer sessionManager.Db.Close()
}

func TestProviderClaimsVerifiedEmailAddress(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		claims      *ProviderClaims
		expected    string
		expectError bool
	}{
		{
			name:     "verified",
			claims:   &ProviderClaims{EmailAddress: EmailAddress, Verified: true},
			expected: EmailAddress,
		},
		{
			name:        "unverified",
			claims:      &ProviderClaims{EmailAddress: EmailAddress},
			expectError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			emailAddress, err := testCase.claims.VerifiedEmailAddress()
			if testCase.expectError {
				if !errors.Is(err, ssoErrors.ErrForbiddenUser) {
					t.Fatalf("expected forbidden user error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("verified email address: %v", err)
			}

			if emailAddress != testCase.expected {
				t.Errorf("email address: got %q, want %q", emailAddress, testCase.expected)
			}
		})
	}
}
