package id_token_endpoint

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ssoTesting "github.com/altshiftab/authentication_go/pkg/sso/testing"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
	muxTesting "github.com/altshiftab/utils_go/pkg/http/mux/testing"
	"github.com/altshiftab/utils_go/pkg/http/types/http_context_extractor"
	altshiftJwtToken "github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/token"
	altshiftLog "github.com/altshiftab/utils_go/pkg/log"
	altshiftContextLogger "github.com/altshiftab/utils_go/pkg/log/context_logger"
)

// TestSignInLogging covers the sign-in this endpoint records. Without it the account behind a
// sign-in through the front end cannot be named at all: this route mints a session without going
// through the authorization code flow, so nothing else in the request writes who signed in.
//
// The absence assertions are the point of the "silent provider" cases. This endpoint is used with
// providers that state nothing about how they authenticated the user — Google's id token has no
// "amr" claim, and no configuration adds one — so copying the authorization code flow's log block
// verbatim would stamp strong_authentication:false on every sign-in through it. That reads as a
// weak sign-in rather than as an unanswered question, which is the distinction
// provider_claims.AuthenticationContext exists to keep.
//
// It is intentionally NOT parallel: it swaps the global slog default to capture output. Non-parallel
// tests run to completion before the package's parallel tests resume, so this does not race with
// TestEndpoint's parallel subtests.
//
//nolint:paralleltest // Swaps the global slog default; running it in parallel would race.
func TestSignInLogging(t *testing.T) {
	testCases := []struct {
		name                     string
		methodReferences         []string
		organization             string
		wantMethodReferences     []any
		wantStrongAuthentication bool
		wantAuthenticationFields bool
	}{
		{
			name:                     "provider stated multi-factor",
			methodReferences:         []string{"pwd", "mfa"},
			organization:             ssoTesting.Organization,
			wantMethodReferences:     []any{"pwd", "mfa"},
			wantStrongAuthentication: true,
			wantAuthenticationFields: true,
		},
		{
			name:                     "provider stated a single factor",
			methodReferences:         []string{"pwd"},
			organization:             ssoTesting.Organization,
			wantMethodReferences:     []any{"pwd"},
			wantStrongAuthentication: false,
			wantAuthenticationFields: true,
		},
		{
			// The Google case: the token carries no "amr" at all.
			name:                     "provider said nothing",
			organization:             ssoTesting.Organization,
			wantAuthenticationFields: false,
		},
		{
			// A personal account belongs to no organization, which the empty identifier records.
			name:                     "provider said nothing, no organization",
			wantAuthenticationFields: false,
		},
	}

	//nolint:paralleltest // Each case swaps the global slog default; see the comment on the test.
	for index, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var logBuffer bytes.Buffer
			httpContextExtractor := http_context_extractor.New()
			logger := altshiftContextLogger.New(
				slog.NewJSONHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelInfo}),
				&altshiftLog.ErrorContextExtractor{
					ContextExtractors: []altshiftLog.ContextExtractor{httpContextExtractor},
				},
				httpContextExtractor,
			)
			previousLogger := slog.Default()
			slog.SetDefault(logger)
			defer slog.SetDefault(previousLogger)

			testEndpoint, err := New[*ssoTesting.ProviderClaims](defaultPath)
			if err != nil {
				t.Fatalf("new endpoint: %v", err)
			}
			if err := testEndpoint.Initialize(idTokenAuthenticator, sessionManager); err != nil {
				t.Fatalf("test endpoint initialize: %v", err)
			}

			mux := &muxPkg.Mux{}
			mux.Add(testEndpoint.Endpoint.Endpoint)
			httpServer := httptest.NewServer(mux)
			defer httpServer.Close()

			tokenPayload := map[string]any{
				"iss": "aux",
				"aud": "test-client",
				"iat": time.Now().Add(-1 * time.Minute).Unix(),
				"nbf": time.Now().Add(-1 * time.Minute).Unix(),
				// Distinct per case so that no two tokens hash alike; the session manager refuses a
				// reused id token.
				"exp":           time.Now().Add(time.Duration(10+index) * time.Minute).Unix(),
				"verified":      true,
				"email_address": ssoTesting.EmailAddress,
				"sub":           ssoTesting.Subject,
			}
			if len(testCase.methodReferences) != 0 {
				tokenPayload["amr"] = testCase.methodReferences
			}
			if testCase.organization != "" {
				tokenPayload["organization"] = testCase.organization
			}

			token := altshiftJwtToken.Token{
				Header:  map[string]any{"typ": "JWT", "kid": ssoTesting.KeyId},
				Payload: tokenPayload,
			}
			tokenString, err := token.Encode(idTokenMethod)
			if err != nil {
				t.Fatalf("token encode: %v", err)
			}

			muxTesting.TestArgs(
				t,
				&muxTesting.Args{
					Path:                   testEndpoint.Path,
					Method:                 testEndpoint.Method,
					Headers:                [][2]string{{"Authorization", fmt.Sprintf("Bearer %s", tokenString)}},
					ExpectedStatusCode:     http.StatusNoContent,
					ExpectedHeadersPresent: []string{"Set-Cookie"},
				},
				httpServer.URL,
			)

			entry := findSignInLogEntry(t, &logBuffer)

			user, _ := entry["user"].(map[string]any)
			if user == nil {
				t.Fatalf("%s: no user in log entry: %v", testCase.name, entry)
			}
			if emailAddress, _ := user["email"].(string); emailAddress != ssoTesting.EmailAddress {
				t.Errorf("%s: user.email = %v, want %s", testCase.name, user["email"], ssoTesting.EmailAddress)
			}
			if id, _ := user["id"].(string); id != ssoTesting.Subject {
				t.Errorf("%s: user.id = %v, want %s", testCase.name, user["id"], ssoTesting.Subject)
			}

			organization, ok := entry["organization"].(string)
			if !ok {
				t.Errorf("%s: expected an organization field; got keys %v", testCase.name, keysOf(entry))
			} else if organization != testCase.organization {
				t.Errorf("%s: organization = %q, want %q", testCase.name, organization, testCase.organization)
			}

			methodReferences, hasMethodReferences := entry["authentication_method_references"]
			strongAuthentication, hasStrongAuthentication := entry["strong_authentication"]

			if !testCase.wantAuthenticationFields {
				// A provider that said nothing must not be recorded as having said "no".
				if hasMethodReferences {
					t.Errorf(
						"%s: expected no authentication_method_references; got %v",
						testCase.name,
						methodReferences,
					)
				}
				if hasStrongAuthentication {
					t.Errorf(
						"%s: expected no strong_authentication; got %v",
						testCase.name,
						strongAuthentication,
					)
				}
				return
			}

			if !hasMethodReferences {
				t.Fatalf("%s: expected authentication_method_references; got keys %v", testCase.name, keysOf(entry))
			}
			gotMethodReferences, _ := methodReferences.([]any)
			if !slicesEqual(gotMethodReferences, testCase.wantMethodReferences) {
				t.Errorf(
					"%s: authentication_method_references = %v, want %v",
					testCase.name,
					gotMethodReferences,
					testCase.wantMethodReferences,
				)
			}

			if !hasStrongAuthentication {
				t.Fatalf("%s: expected strong_authentication; got keys %v", testCase.name, keysOf(entry))
			}
			if got, _ := strongAuthentication.(bool); got != testCase.wantStrongAuthentication {
				t.Errorf(
					"%s: strong_authentication = %v, want %v",
					testCase.name,
					got,
					testCase.wantStrongAuthentication,
				)
			}
		})
	}
}

const signInMessage = "An identity provider authenticated a user."

func findSignInLogEntry(t *testing.T, buffer *bytes.Buffer) map[string]any {
	t.Helper()

	scanner := bufio.NewScanner(bytes.NewReader(buffer.Bytes()))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		var entry map[string]any
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatalf("unmarshal log line %q: %v", line, err)
		}

		if entry["msg"] == signInMessage {
			return entry
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan log buffer: %v", err)
	}

	t.Fatalf("no log entry with msg %q found in:\n%s", signInMessage, buffer.String())
	return nil
}

func keysOf(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}

func slicesEqual(got []any, want []any) bool {
	if len(got) != len(want) {
		return false
	}
	for index, value := range got {
		if value != want[index] {
			return false
		}
	}
	return true
}
