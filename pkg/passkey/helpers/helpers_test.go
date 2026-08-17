package helpers

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"testing"

	passkeyProviderErrors "github.com/altshiftab/authentication_go/pkg/passkey/errors"
	webauthnErrors "github.com/altshiftab/utils_go/pkg/webauthn/errors"
)

func TestGenerateChallenge(t *testing.T) {
	t.Parallel()

	challenge, err := GenerateChallenge()
	if err != nil {
		t.Fatalf("generate challenge: %v", err)
	}
	if len(challenge) != 64 {
		t.Errorf("challenge length: got %d, want 64", len(challenge))
	}

	otherChallenge, err := GenerateChallenge()
	if err != nil {
		t.Fatalf("generate challenge: %v", err)
	}
	if bytes.Equal(challenge, otherChallenge) {
		t.Errorf("expected distinct challenges")
	}
}

func TestMakeValidationResponseError(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{
			name:           "common bad request error",
			err:            fmt.Errorf("wrapped: %w", webauthnErrors.ErrChallengeMismatch),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "extra bad request error",
			err:            fmt.Errorf("wrapped: %w", webauthnErrors.ErrSignatureVerifyFailure),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "other error",
			err:            errors.ErrUnsupported,
			expectedStatus: http.StatusUnprocessableEntity,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			responseError := MakeValidationResponseError(
				testCase.err,
				[]error{webauthnErrors.ErrSignatureVerifyFailure},
			)
			if responseError == nil {
				t.Fatalf("nil response error")
			}

			problemDetail := responseError.ProblemDetail
			if problemDetail == nil {
				t.Fatalf("nil problem detail")
			}
			if problemDetail.Status != testCase.expectedStatus {
				t.Errorf("status: got %d, want %d", problemDetail.Status, testCase.expectedStatus)
			}

			if !errors.Is(responseError.ClientError, testCase.err) {
				t.Errorf("client error: got %v", responseError.ClientError)
			}
		})
	}
}

func TestMakeDatabaseChallengeResponseError(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		err            error
		expectedStatus int
		expectNil      bool
	}{
		{
			name:           "no challenge",
			err:            fmt.Errorf("wrapped: %w", passkeyProviderErrors.ErrNoChallenge),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "expired challenge",
			err:            fmt.Errorf("wrapped: %w", passkeyProviderErrors.ErrExpiredChallenge),
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:      "other error",
			err:       errors.ErrUnsupported,
			expectNil: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			responseError := MakeDatabaseChallengeResponseError(testCase.err)
			if testCase.expectNil {
				if responseError != nil {
					t.Fatalf("expected nil response error, got %+v", responseError)
				}
				return
			}
			if responseError == nil {
				t.Fatalf("nil response error")
			}

			problemDetail := responseError.ProblemDetail
			if problemDetail == nil {
				t.Fatalf("nil problem detail")
			}
			if problemDetail.Status != testCase.expectedStatus {
				t.Errorf("status: got %d, want %d", problemDetail.Status, testCase.expectedStatus)
			}
		})
	}
}
