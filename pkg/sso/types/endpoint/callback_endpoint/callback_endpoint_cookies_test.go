package callback_endpoint

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/altshiftab/authentication_go/pkg/database/types/oauth_flow"
	testing2 "github.com/altshiftab/authentication_go/pkg/sso/testing"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
	muxTesting "github.com/altshiftab/utils_go/pkg/http/mux/testing"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
)

// What a flow store keyed by a uuid returns for a value that is not one.
var errMalformedFlowId = errors.New("invalid input syntax for type uuid")

// What a store that is failing outright returns.
var errStoreFailure = errors.New("store failure")

// A front end that forwards a single cookie name -- Firebase Hosting forwards
// only `__session` -- leaves the callback cookie sharing a name with the session
// cookie, so the callback is reached with more than one cookie of that name and
// nothing to say which comes first.
func TestEndpointSeveralCallbackCookies(t *testing.T) {
	t.Parallel()

	// Another flow's id: well formed, but not the flow this callback is for.
	const otherFlowId = "6c2e9a41-0d3b-4f8a-b7e5-91a4c2d8f306"
	const anotherFlowId = "a93d5f12-7e64-4b0c-8d29-5f1e3b7c4a68"
	// A flow id the store fails on.
	const failingFlowId = "2b7f4e90-c1a8-4d35-9e6b-0a5c8f3d2e17"
	// A session token shares the cookie's name and is not a uuid.
	const sessionCookieValue = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl"

	successArgs := func() *muxTesting.Args {
		return &muxTesting.Args{
			ExpectedStatusCode:     http.StatusSeeOther,
			ExpectedHeaders:        [][2]string{{"Location", testing2.RedirectUrl}},
			ExpectedHeadersPresent: []string{"Set-Cookie"},
		}
	}

	noMatchArgs := func() *muxTesting.Args {
		return &muxTesting.Args{
			ExpectedStatusCode: http.StatusBadRequest,
			ExpectedProblemDetail: &problem_detail.Detail{
				Detail: "No OAuth flow matches the callback cookie value.",
			},
		}
	}

	testCases := []struct {
		name             string
		cookieValues     []string
		args             *muxTesting.Args
		expectedPopCount int
	}{
		{
			name:             "flow id first",
			cookieValues:     []string{testing2.OauthFlowId, otherFlowId},
			args:             successArgs(),
			expectedPopCount: 1,
		},
		{
			// The one the previous single-cookie read got wrong.
			name:             "flow id second",
			cookieValues:     []string{otherFlowId, testing2.OauthFlowId},
			args:             successArgs(),
			expectedPopCount: 2,
		},
		{
			name:             "empty value beside the flow id",
			cookieValues:     []string{"", testing2.OauthFlowId},
			args:             successArgs(),
			expectedPopCount: 1,
		},
		{
			// The state in the url matches a flow, so a fallback to looking the
			// flow up by state would turn this into a sign-in. It must not.
			name:             "no value matches a flow",
			cookieValues:     []string{otherFlowId, anotherFlowId},
			args:             noMatchArgs(),
			expectedPopCount: 2,
		},
		{
			// A signed-in browser sends its session token too; it is never put to the store.
			name:             "session token before the flow id",
			cookieValues:     []string{sessionCookieValue, testing2.OauthFlowId},
			args:             successArgs(),
			expectedPopCount: 1,
		},
		{
			// The parser takes forms the store does not; the flow id is put in canonical form.
			name:             "flow id in urn form",
			cookieValues:     []string{"urn:uuid:" + testing2.OauthFlowId},
			args:             successArgs(),
			expectedPopCount: 1,
		},
		{
			// A signed-in browser whose flow cookie is gone: the browser's fault, not the store's.
			name:             "session token alone",
			cookieValues:     []string{sessionCookieValue},
			args:             noMatchArgs(),
			expectedPopCount: 0,
		},
		{
			// A store that is failing outright is still a server error.
			name:         "store failure",
			cookieValues: []string{sessionCookieValue, failingFlowId},
			args: &muxTesting.Args{
				ExpectedStatusCode:    http.StatusInternalServerError,
				ExpectedProblemDetail: &problem_detail.Detail{},
			},
			expectedPopCount: 1,
		},
		{
			name: "more values than are tried",
			cookieValues: []string{
				otherFlowId,
				otherFlowId,
				otherFlowId,
				otherFlowId,
				otherFlowId,
				testing2.OauthFlowId,
			},
			args:             noMatchArgs(),
			expectedPopCount: maxCallbackCookieValues,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint, err := New[*testing2.ProviderClaims](defaultPath)
			if err != nil {
				t.Fatalf("new endpoint: %v", err)
			}

			if err := testEndpoint.Initialize(testOrigin, oauthConfig, idTokenAuthenticator, sessionManager); err != nil {
				t.Fatalf("test endpoint initialize: %v", err)
			}

			var popCount int
			testEndpoint.popOauthFlow = func(_ context.Context, id string, _ *sql.DB) (*oauth_flow.Flow, error) {
				popCount++

				switch id {
				case testing2.OauthFlowId:
				case failingFlowId:
					return nil, errStoreFailure
				default:
					// Stricter than Postgres, which takes some other forms but not all the parser does.
					if parsed, err := uuid.Parse(id); err != nil || parsed.String() != id {
						return nil, errMalformedFlowId
					}
					return nil, sql.ErrNoRows
				}

				expiresAt := time.Now().Add(time.Hour)

				return &oauth_flow.Flow{
					Id:          testing2.OauthFlowId,
					RedirectUrl: testing2.RedirectUrl,
					ExpiresAt:   &expiresAt,
					State:       testing2.State,
				}, nil
			}

			mux := &muxPkg.Mux{}
			mux.Add(testEndpoint.Endpoint.Endpoint)
			httpServer := httptest.NewServer(mux)
			defer httpServer.Close()

			var cookieParts []string
			for _, cookieValue := range testCase.cookieValues {
				cookieParts = append(cookieParts, testEndpoint.CallbackCookieName+"="+cookieValue)
			}

			testCase.args.Headers = append(
				testCase.args.Headers,
				[2]string{"Cookie", strings.Join(cookieParts, "; ")},
			)
			testCase.args.Path = testEndpoint.Path + "?state=" + testing2.State + "&code=" + testing2.OauthCode
			testCase.args.Method = testEndpoint.Method

			muxTesting.TestArgs(t, testCase.args, httpServer.URL)

			if popCount != testCase.expectedPopCount {
				t.Errorf("oauth flow pops: got %d, want %d", popCount, testCase.expectedPopCount)
			}
		})
	}
}
