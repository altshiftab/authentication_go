package dbsc_session_response_processor

import (
	"context"
	"database/sql"
	"encoding/base64"
	loginTesting "github.com/altshiftab/authentication_go/pkg/session/testing"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/altshiftab/authentication_go/pkg/database/types/dbsc_challenge"
	"github.com/altshiftab/authentication_go/pkg/session/types/dbsc_session_response_processor/dbsc_session_response_processor_config"
	altshiftSqlTesting "github.com/altshiftab/utils_go/pkg/database/sql/testing"
)

// A DBSC response JWT (typ dbsc+jwt) self-signed with the EC key embedded in its own key claim,
// shared with the dbsc_register_endpoint tests.
const (
	validAudience = "https://example.com/api/session/dbsc/register"
)

func makeKeylessToken(t *testing.T) string {
	t.Helper()

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"dbsc+jwt"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"aud":"` + validAudience + `","jti":"cv","iat":1}`))
	signature := base64.RawURLEncoding.EncodeToString([]byte("signature"))

	return strings.Join([]string{header, payload, signature}, ".")
}

func newProcessor(t *testing.T, popDbscChallenge func(ctx context.Context, challenge string, authenticationId string, db *sql.DB) (*dbsc_challenge.Challenge, error)) *Processor {
	t.Helper()

	processor, err := New(
		validAudience,
		altshiftSqlTesting.NewDb(),
		dbsc_session_response_processor_config.WithPopDbscChallenge(popDbscChallenge),
	)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if processor == nil {
		t.Fatalf("nil processor")
	}

	return processor
}

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("empty audience", func(t *testing.T) {
		t.Parallel()

		if _, err := New("", altshiftSqlTesting.NewDb()); err == nil {
			t.Errorf("expected error")
		}
	})

	t.Run("nil db", func(t *testing.T) {
		t.Parallel()

		if _, err := New(validAudience, nil); err == nil {
			t.Errorf("expected error")
		}
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		processor, err := New(validAudience, altshiftSqlTesting.NewDb())
		if err != nil {
			t.Fatalf("new: %v", err)
		}
		if processor == nil || processor.TokenValidator == nil || processor.Db == nil {
			t.Fatalf("incomplete processor: %+v", processor)
		}
	})
}

var validToken, _ = loginTesting.MakeDbscProof("cv")

// A browser speaking the current protocol sends no audience; the check still applies to a client
// that does send one.
var wrongAudienceToken, _ = loginTesting.MakeDbscProof("cv", map[string]any{"aud": "https://wrong.example.com"})

func TestProcess(t *testing.T) {
	t.Parallel()

	popChallenge := func(_ context.Context, challenge string, authenticationId string, _ *sql.DB) (*dbsc_challenge.Challenge, error) {
		if challenge != "cv" || authenticationId != "auth-id" {
			return nil, nil
		}
		return &dbsc_challenge.Challenge{
			Challenge: []byte(challenge),
			ExpiresAt: new(time.Now().Add(time.Hour)),
		}, nil
	}

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		derEncodedKeyMaterial, responseError := newProcessor(t, popChallenge).Process(
			t.Context(),
			&Input{TokenString: validToken, AuthenticationId: "auth-id"},
		)
		if responseError != nil {
			t.Fatalf("response error: %+v", responseError)
		}
		if len(derEncodedKeyMaterial) == 0 {
			t.Fatalf("empty der-encoded key material")
		}
	})

	t.Run("expired challenge", func(t *testing.T) {
		t.Parallel()

		_, responseError := newProcessor(
			t,
			func(_ context.Context, challenge string, _ string, _ *sql.DB) (*dbsc_challenge.Challenge, error) {
				return &dbsc_challenge.Challenge{
					Challenge: []byte(challenge),
					ExpiresAt: new(time.Now().Add(-time.Hour)),
				}, nil
			},
		).Process(t.Context(), &Input{TokenString: validToken, AuthenticationId: "auth-id"})
		if responseError == nil || responseError.ProblemDetail == nil ||
			responseError.ProblemDetail.Status != http.StatusBadRequest {
			t.Fatalf("expected bad request, got %+v", responseError)
		}
	})

	t.Run("missing challenge", func(t *testing.T) {
		t.Parallel()

		_, responseError := newProcessor(t, popChallenge).Process(
			t.Context(),
			&Input{TokenString: validToken, AuthenticationId: "other-auth-id"},
		)
		if responseError == nil || responseError.ProblemDetail == nil ||
			responseError.ProblemDetail.Status != http.StatusBadRequest {
			t.Fatalf("expected bad request, got %+v", responseError)
		}
	})

	t.Run("wrong audience", func(t *testing.T) {
		t.Parallel()

		processor, err := New(
			"https://other.example.com",
			altshiftSqlTesting.NewDb(),
			dbsc_session_response_processor_config.WithPopDbscChallenge(popChallenge),
		)
		if err != nil {
			t.Fatalf("new: %v", err)
		}

		_, responseError := processor.Process(
			t.Context(),
			&Input{TokenString: wrongAudienceToken, AuthenticationId: "auth-id"},
		)
		if responseError == nil || responseError.ClientError == nil {
			t.Fatalf("expected client error, got %+v", responseError)
		}
	})

	errorCases := []struct {
		name           string
		input          *Input
		expectedStatus int
	}{
		{name: "nil input"},
		{name: "empty token string", input: &Input{AuthenticationId: "auth-id"}},
		{name: "empty authentication id", input: &Input{TokenString: validToken}},
		{
			name:           "malformed token",
			input:          &Input{TokenString: "garbage", AuthenticationId: "auth-id"},
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, testCase := range errorCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, responseError := newProcessor(t, popChallenge).Process(t.Context(), testCase.input)
			if responseError == nil {
				t.Fatalf("expected response error")
			}
			if testCase.expectedStatus != 0 {
				if responseError.ProblemDetail == nil || responseError.ProblemDetail.Status != testCase.expectedStatus {
					t.Errorf("expected status %d, got %+v", testCase.expectedStatus, responseError)
				}
			}
		})
	}

	t.Run("token without key", func(t *testing.T) {
		t.Parallel()

		_, responseError := newProcessor(t, popChallenge).Process(
			t.Context(),
			&Input{TokenString: makeKeylessToken(t), AuthenticationId: "auth-id"},
		)
		if responseError == nil || responseError.ProblemDetail == nil ||
			responseError.ProblemDetail.Status != http.StatusBadRequest {
			t.Fatalf("expected bad request, got %+v", responseError)
		}
	})
}
