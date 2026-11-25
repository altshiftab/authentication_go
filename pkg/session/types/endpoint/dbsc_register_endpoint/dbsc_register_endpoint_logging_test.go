package dbsc_register_endpoint

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authenticationPkg "github.com/altshiftab/authentication_go/pkg/database/types/authentication"
	"github.com/altshiftab/authentication_go/pkg/database/types/dbsc_challenge"
	"github.com/altshiftab/authentication_go/pkg/log_options/log_options_testing"
	"github.com/altshiftab/authentication_go/pkg/session"
	loginTesting "github.com/altshiftab/authentication_go/pkg/session/testing"
	"github.com/altshiftab/authentication_go/pkg/session/types/dbsc_session_response_processor"
	"github.com/altshiftab/authentication_go/pkg/session/types/dbsc_session_response_processor/dbsc_session_response_processor_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/endpoint/dbsc_register_endpoint/dbsc_register_endpoint_config"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
)

// recordingWarning is what a registration logs when the bound session's token expiry cannot be recorded.
const recordingWarning = "An error occurred when recording the bound session's token expiry. Its first refresh will not be held to the idle bound."

/*
 * A registration whose token expiry cannot be recorded keeps the binding, and says why in the log:
 * the error as an error object, which Elasticsearch takes where `error` is one, not as a string it
 * refuses.
 */
//nolint:paralleltest // Swaps the global slog default; running it in parallel would race.
func TestEndpoint_RecordingFailureIsLoggedAsAnError(t *testing.T) {
	validToken, _ := loginTesting.MakeDbscProof("cv")

	testEndpoint := New(
		dbsc_register_endpoint_config.WithUpdateAuthenticationWithDbscPublicKey(
			func(context.Context, string, []byte, *sql.DB) error { return nil },
		),
		dbsc_register_endpoint_config.WithUpdateAuthenticationWithSessionExpiresAt(
			func(context.Context, string, time.Time, *sql.DB) error { return sql.ErrConnDone },
		),
	)
	testEndpointProcessor, err := dbsc_session_response_processor.New(
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
	if err := testEndpoint.Initialize(defaultAuthorizationRequestParser, testEndpointProcessor, loginTesting.RegisteredDomain); err != nil {
		t.Fatalf("test endpoint initialize: %v", err)
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
		request.Header.Set("Cookie", defaultSessionCookieString)
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

	if statusCode != http.StatusOK {
		t.Fatalf("status code %d, expected %d", statusCode, http.StatusOK)
	}

	var warnings []map[string]any
	for _, line := range lines {
		if line["msg"] == recordingWarning {
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
