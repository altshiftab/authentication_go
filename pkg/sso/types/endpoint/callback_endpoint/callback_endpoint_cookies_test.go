package callback_endpoint

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/altshiftab/authentication_go/pkg/database/types/oauth_flow"
	testing2 "github.com/altshiftab/authentication_go/pkg/sso/testing"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
	muxTesting "github.com/altshiftab/utils_go/pkg/http/mux/testing"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
)

// A front end that forwards a single cookie name -- Firebase Hosting forwards
// only `__session` -- leaves the callback cookie sharing a name with the session
// cookie, so the callback is reached with more than one cookie of that name and
// nothing to say which comes first.
func TestEndpointSeveralCallbackCookies(t *testing.T) {
	t.Parallel()

	const otherValue = "not-a-flow-id"

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
			cookieValues:     []string{testing2.OauthFlowId, otherValue},
			args:             successArgs(),
			expectedPopCount: 1,
		},
		{
			// The one the previous single-cookie read got wrong.
			name:             "flow id second",
			cookieValues:     []string{otherValue, testing2.OauthFlowId},
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
			cookieValues:     []string{otherValue, "another-" + otherValue},
			args:             noMatchArgs(),
			expectedPopCount: 2,
		},
		{
			name: "more values than are tried",
			cookieValues: []string{
				otherValue,
				otherValue,
				otherValue,
				otherValue,
				otherValue,
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

				if id != testing2.OauthFlowId {
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
