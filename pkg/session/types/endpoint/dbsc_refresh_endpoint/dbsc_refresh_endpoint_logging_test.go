package dbsc_refresh_endpoint

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	accountPkg "github.com/altshiftab/authentication_go/pkg/database/types/account"
	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	"github.com/altshiftab/authentication_go/pkg/database/types/dbsc_challenge"
	"github.com/altshiftab/authentication_go/pkg/log_options/log_options_testing"
	"github.com/altshiftab/authentication_go/pkg/session"
	loginTesting "github.com/altshiftab/authentication_go/pkg/session/testing"
	"github.com/altshiftab/authentication_go/pkg/session/types/dbsc_session_response_processor"
	"github.com/altshiftab/authentication_go/pkg/session/types/dbsc_session_response_processor/dbsc_session_response_processor_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/endpoint/dbsc_refresh_endpoint/dbsc_refresh_endpoint_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/endpoint/dbsc_register_endpoint/dbsc_register_endpoint_config"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
)

var errTestInsertChallenge = errors.New("insert challenge failed")

// nextChallengeWarning is what a refresh logs when the challenge for the next one cannot be issued.
const nextChallengeWarning = "An error occurred when issuing the next DBSC challenge. The next refresh will need one."

/*
 * A refresh whose next challenge cannot be stored still succeeds, and says why in the log: the error
 * as an error object, which Elasticsearch takes where `error` is one, not as a string it refuses.
 */
//nolint:paralleltest // Swaps the global slog default; running it in parallel would race.
func TestEndpoint_NextChallengeFailureIsLoggedAsAnError(t *testing.T) {
	const testChallenge = "test-challenge"

	validToken, validTokenPublicKey := loginTesting.MakeDbscProof(testChallenge)

	testEndpoint := New(
		dbsc_refresh_endpoint_config.WithUpdateAuthenticationWithSessionExpiresAt(
			func(context.Context, string, time.Time, *sql.DB) error { return nil },
		),
	)
	processor, err := dbsc_session_response_processor.New(
		"https://example.com"+dbsc_register_endpoint_config.DefaultPath,
		db,
		dbsc_session_response_processor_config.WithPopDbscChallenge(
			func(ctx context.Context, challenge string, authenticationId string, db *sql.DB) (*dbsc_challenge.Challenge, error) {
				return &dbsc_challenge.Challenge{
					Authentication: &authenticationPkg.Authentication{Id: authenticationId},
					Challenge:      []byte(challenge),
					ExpiresAt:      new(time.Now().Add(time.Hour)),
				}, nil
			},
		),
	)
	if err != nil {
		t.Fatalf("dbsc session response processor new: %v", err)
	}
	if err := testEndpoint.Initialize(processor, sessionManager); err != nil {
		t.Fatalf("test endpoint initialize: %v", err)
	}

	now := time.Now()
	testEndpoint.selectRefreshAuthentication = func(ctx context.Context, id string, database *sql.DB) (*authenticationPkg.Authentication, error) {
		return &authenticationPkg.Authentication{
			Id: id,
			Account: &accountPkg.Account{
				Id:           "test-account-id",
				EmailAddress: "test@example.com",
				Roles:        []string{"test-role"},
			},
			DbscPublicKey: validTokenPublicKey,
			CreatedAt:     new(now.Add(-time.Hour)),
			ExpiresAt:     new(now.Add(time.Hour)),
		}, nil
	}
	testEndpoint.generateDbscChallenge = func() (string, error) { return testChallenge, nil }
	testEndpoint.insertDbscChallenge = func(context.Context, string, string, time.Duration, *sql.DB) error {
		return errTestInsertChallenge
	}

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint.Endpoint.Endpoint)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	var statusCode int
	lines, err := log_options_testing.Capture(func() {
		request, err := http.NewRequestWithContext(t.Context(), testEndpoint.Method, httpServer.URL+testEndpoint.Path, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		request.Header.Set(session.DbscSessionIdHeaderName, testAuthenticationId)
		request.Header.Set(session.DbscSessionResponseHeaderName, validToken)

		response, err := httpServer.Client().Do(request)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		_ = response.Body.Close()
		statusCode = response.StatusCode
	})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}

	if statusCode != http.StatusNoContent {
		t.Fatalf("status code %d, expected %d", statusCode, http.StatusNoContent)
	}

	var warnings []map[string]any
	for _, line := range lines {
		if line["msg"] == nextChallengeWarning {
			warnings = append(warnings, line)
		}
	}
	if len(warnings) != 1 {
		t.Fatalf("%d lines logged the warning, want one: %v", len(warnings), lines)
	}
	errorObject, ok := warnings[0]["error"].(map[string]any)
	if !ok {
		t.Fatalf("error: got %#v, want an object", warnings[0]["error"])
	}
	if message, _ := errorObject["message"].(string); message == "" {
		t.Errorf("error.message: got %#v, want the error's message", errorObject["message"])
	}
}
