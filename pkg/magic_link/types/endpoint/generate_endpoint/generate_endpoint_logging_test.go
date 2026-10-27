package generate_endpoint

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/altshiftab/authentication_go/pkg/log_masking"
	logMaskingTesting "github.com/altshiftab/authentication_go/pkg/log_masking/testing"
	magicLinkTesting "github.com/altshiftab/authentication_go/pkg/magic_link/testing"
	"github.com/altshiftab/authentication_go/pkg/magic_link/types/endpoint/generate_endpoint/generate_endpoint_config"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
	muxTesting "github.com/altshiftab/utils_go/pkg/http/mux/testing"
	"github.com/altshiftab/utils_go/pkg/http/types/http_context_extractor"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	altshiftLog "github.com/altshiftab/utils_go/pkg/log"
	altshiftContextLogger "github.com/altshiftab/utils_go/pkg/log/context_logger"
	"github.com/altshiftab/utils_go/pkg/log/pii_hasher"
)

/*
 * What the log says of a link asked for: the address typed into the form is nowhere in it -- not in
 * the request's body, which the log writes with every request, nor in an error -- and a real address
 * is named by its keyed hash, whether it has an account or not. Something typed that is no address
 * at all is named by nothing, being as likely as not something else typed into the field.
 */
//nolint:paralleltest // Swaps the global slog default, as the other logging tests do.
func TestRequestLogging(t *testing.T) {
	hasher, err := pii_hasher.New(bytes.Repeat([]byte{7}, pii_hasher.MinimumKeyLength))
	if err != nil {
		t.Fatalf("pii hasher new: %v", err)
	}

	const notAnAddress = "correct horse battery staple"

	testCases := []struct {
		name  string
		typed string
		// body is the request's body, where it is not the typed value as the form sends it.
		body string
		// secrets are what must not reach the log, where they are not the typed value whole.
		secrets       []string
		accountExists bool
		wantStatus    int
		wantDetail    string
		wantHash      string
	}{
		{
			name:          "an address with an account",
			typed:         magicLinkTesting.ValidEmail,
			accountExists: true,
			wantStatus:    http.StatusNoContent,
			wantHash:      hasher.HashEmailAddress(magicLinkTesting.ValidEmail),
		},
		{
			name:       "an address with no account",
			typed:      "someone-else@example.com",
			wantStatus: http.StatusNoContent,
			wantHash:   hasher.HashEmailAddress("someone-else@example.com"),
		},
		{
			name:       "something that is no address",
			typed:      notAnAddress,
			wantStatus: http.StatusUnprocessableEntity,
			wantDetail: "The email address is invalid.",
		},
		{
			// net/mail's message quotes what follows the first address.
			name:       "two addresses",
			typed:      "jane@example.com, john@example.com",
			secrets:    []string{"jane@example.com", "john@example.com"},
			wantStatus: http.StatusUnprocessableEntity,
			wantDetail: "The email address is invalid.",
		},
		{
			// A body that does not parse into the form's fields is refused before the endpoint
			// sees it, by the body parser.
			name:       "the address in a list",
			typed:      "jane@example.com",
			body:       `{"email_address":["jane@example.com"]}`,
			wantStatus: http.StatusUnprocessableEntity,
			wantDetail: "Invalid body. The value is not appropriate for the JSON type.",
		},
		{
			name:       "an address in a member the form does not have",
			typed:      "jane@example.com",
			body:       `{"email_address":"ok@example.com","x":"jane@example.com"}`,
			wantStatus: http.StatusUnprocessableEntity,
			wantDetail: `Invalid body. Unknown member: "/x".`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			testEndpoint := New(
				generate_endpoint_config.WithAccountChecker(
					func(_ context.Context, _ string) (bool, error) { return testCase.accountExists, nil },
				),
			)
			testEndpoint.EmailAddressHasher = hasher
			if err := testEndpoint.Initialize(
				&magicLinkTesting.FakeMailSender{},
				magicLinkTesting.NewSigner(),
				magicLinkTesting.MustFromAddress(),
				magicLinkTesting.MustParseUrl(magicLinkTesting.LinkBaseUrl),
				magicLinkTesting.Domain,
			); err != nil {
				t.Fatalf("%s: initialize: %v", testCase.name, err)
			}

			httpContextExtractor := http_context_extractor.New()
			if err := log_masking.Apply(httpContextExtractor, testEndpoint); err != nil {
				t.Fatalf("%s: log masking apply: %v", testCase.name, err)
			}

			var logBuffer bytes.Buffer
			logger := altshiftContextLogger.New(
				slog.NewJSONHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}),
				&altshiftLog.ErrorContextExtractor{
					ContextExtractors: []altshiftLog.ContextExtractor{httpContextExtractor},
				},
				httpContextExtractor,
			)
			previousLogger := slog.Default()
			slog.SetDefault(logger)
			defer slog.SetDefault(previousLogger)

			// New, for the request log the mux writes once a response is served.
			mux := muxPkg.New(testEndpoint.Endpoint.Endpoint)
			httpServer := httptest.NewServer(mux)
			defer httpServer.Close()

			body := testCase.body
			if body == "" {
				body = `{"email_address":"` + testCase.typed + `"}`
			}
			args := &muxTesting.Args{
				Path:               testEndpoint.Path,
				Method:             testEndpoint.Method,
				Headers:            [][2]string{{"Content-Type", "application/json"}},
				Body:               []byte(body),
				ExpectedStatusCode: testCase.wantStatus,
			}
			if testCase.wantDetail != "" {
				args.ExpectedProblemDetail = &problem_detail.Detail{Detail: testCase.wantDetail}
			}
			muxTesting.TestArgs(t, args, httpServer.URL)

			written := logBuffer.String()
			if written == "" {
				t.Fatalf("%s: nothing was logged", testCase.name)
			}
			secrets := testCase.secrets
			if len(secrets) == 0 {
				secrets = []string{testCase.typed}
			}
			for _, secret := range secrets {
				if found := logMaskingTesting.FindAddress(written, secret); len(found) != 0 {
					t.Errorf("%s: %q is in the log %q: %s", testCase.name, secret, found, written)
				}
			}
			if testCase.wantHash != "" && !bytes.Contains(logBuffer.Bytes(), []byte(testCase.wantHash)) {
				t.Errorf("%s: the address's hash %s is not in the log: %s", testCase.name, testCase.wantHash, written)
			}
		})
	}
}
