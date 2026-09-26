package landing_endpoint

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	magicLinkTesting "github.com/altshiftab/authentication_go/pkg/magic_link/testing"
	"github.com/altshiftab/authentication_go/pkg/magic_link/types/endpoint/landing_endpoint/landing_endpoint_config"
	altshiftCryptoEddsa "github.com/altshiftab/utils_go/pkg/crypto/eddsa"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
	muxTesting "github.com/altshiftab/utils_go/pkg/http/mux/testing"
	altshiftHttpTypes "github.com/altshiftab/utils_go/pkg/http/types"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	altshiftJwtToken "github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/token"
)

var signer *altshiftCryptoEddsa.Method

func TestMain(m *testing.M) {
	signer = magicLinkTesting.NewSigner()
	os.Exit(m.Run())
}

func mintToken(t *testing.T, payload map[string]any) string {
	t.Helper()
	token := &altshiftJwtToken.Token{Payload: payload}
	tokenString, err := token.Encode(signer)
	if err != nil {
		t.Fatalf("token encode: %v", err)
	}
	return tokenString
}

func defaultPayload(emailAddress, nonce string) map[string]any {
	now := time.Now()
	return map[string]any{
		"jti": nonce,
		"sub": emailAddress,
		"iat": now.Unix(),
		"exp": now.Add(15 * time.Minute).Unix(),
	}
}

func TestEndpoint(t *testing.T) {
	t.Parallel()

	expiredPayload := defaultPayload(magicLinkTesting.ValidEmail, "expired")
	expiredPayload["exp"] = time.Now().Add(-1 * time.Minute).Unix()

	testCases := []struct {
		name      string
		token     string
		skipQuery bool
		args      *muxTesting.Args
	}{
		{
			name:  "success renders form",
			token: mintToken(t, defaultPayload(magicLinkTesting.ValidEmail, "ok")),
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusOK,
				ExpectedHeaders:    [][2]string{{"Content-Type", "text/html; charset=utf-8"}},
				ExpectedBody:       []byte(muxTesting.ExpectedBodyNonEmpty),
			},
		},
		{
			name:      "missing token",
			skipQuery: true,
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "Bad query.",
					Extension: map[string]any{
						"errors": []any{"validation error: missing parameter: token"},
					},
				},
			},
		},
		{
			name:  "expired token",
			token: mintToken(t, expiredPayload),
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The token has expired.",
				},
			},
		},
		{
			name:  "invalid token",
			token: "not-a-jwt",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The token is invalid.",
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint := New()
			if err := testEndpoint.Initialize(signer); err != nil {
				t.Fatalf("initialize: %v", err)
			}

			mux := &muxPkg.Mux{}
			mux.Add(testEndpoint.Endpoint.Endpoint)
			httpServer := httptest.NewServer(mux)
			defer httpServer.Close()

			if testCase.skipQuery {
				testCase.args.Path = testEndpoint.Path
			} else {
				testCase.args.Path = testEndpoint.Path + "?" + url.Values{"token": {testCase.token}}.Encode()
			}
			testCase.args.Method = testEndpoint.Method

			muxTesting.TestArgs(t, testCase.args, httpServer.URL)
		})
	}
}

var unusablePage = []byte("unusable")

func unusablePageBuilder(string, *altshiftHttpTypes.AcceptLanguage) ([]byte, error) {
	return unusablePage, nil
}

func makeSpentChecker(spent bool, err error) SpentChecker {
	return func(context.Context, []byte) (bool, error) {
		return spent, err
	}
}

func TestEndpoint_UnusablePage(t *testing.T) {
	t.Parallel()

	expiredPayload := defaultPayload(magicLinkTesting.ValidEmail, "expired")
	expiredPayload["exp"] = time.Now().Add(-1 * time.Minute).Unix()
	validToken := mintToken(t, defaultPayload(magicLinkTesting.ValidEmail, "ok"))

	testCases := []struct {
		name                string
		token               string
		unusablePageBuilder landing_endpoint_config.PageBuilder
		spentChecker        SpentChecker
		args                *muxTesting.Args
	}{
		{
			name:                "expired token renders unusable page",
			token:               mintToken(t, expiredPayload),
			unusablePageBuilder: unusablePageBuilder,
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusGone,
				ExpectedHeaders:    [][2]string{{"Content-Type", "text/html; charset=utf-8"}},
				ExpectedBody:       unusablePage,
			},
		},
		{
			name:                "spent token renders unusable page",
			token:               validToken,
			unusablePageBuilder: unusablePageBuilder,
			spentChecker:        makeSpentChecker(true, nil),
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusGone,
				ExpectedBody:       unusablePage,
			},
		},
		{
			name:                "unspent token renders form",
			token:               validToken,
			unusablePageBuilder: unusablePageBuilder,
			spentChecker:        makeSpentChecker(false, nil),
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusOK,
				ExpectedBody:       []byte(muxTesting.ExpectedBodyNonEmpty),
			},
		},
		{
			name:                "spent checker error offers the form",
			token:               validToken,
			unusablePageBuilder: unusablePageBuilder,
			spentChecker:        makeSpentChecker(true, errors.New("database unavailable")), //nolint:err113 // A test's stand-in failure.
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusOK,
				ExpectedBody:       []byte(muxTesting.ExpectedBodyNonEmpty),
			},
		},
		{
			name:                "invalid token keeps problem detail",
			token:               "not-a-jwt",
			unusablePageBuilder: unusablePageBuilder,
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The token is invalid.",
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint := New(landing_endpoint_config.WithUnusablePageBuilder(testCase.unusablePageBuilder))
			testEndpoint.SpentChecker = testCase.spentChecker
			if err := testEndpoint.Initialize(signer); err != nil {
				t.Fatalf("initialize: %v", err)
			}

			mux := &muxPkg.Mux{}
			mux.Add(testEndpoint.Endpoint.Endpoint)
			httpServer := httptest.NewServer(mux)
			defer httpServer.Close()

			testCase.args.Path = testEndpoint.Path + "?" + url.Values{"token": {testCase.token}}.Encode()
			testCase.args.Method = testEndpoint.Method

			muxTesting.TestArgs(t, testCase.args, httpServer.URL)
		})
	}
}

func TestEndpoint_ContentSecurityPolicyHeader(t *testing.T) {
	t.Parallel()

	testEndpoint := New()
	if err := testEndpoint.Initialize(signer); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint.Endpoint.Endpoint)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	tokenString := mintToken(t, defaultPayload(magicLinkTesting.ValidEmail, "csp-header"))
	rawQuery := url.Values{"token": {tokenString}}.Encode()

	resp, err := http.Get(httpServer.URL + testEndpoint.Path + "?" + rawQuery)
	if err != nil {
		t.Fatalf("http get: %v", err)
	}
	defer resp.Body.Close()

	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("missing Content-Security-Policy header")
	}
	if !strings.Contains(csp, "'"+landing_endpoint_config.DefaultStyleSrcHash+"'") {
		t.Errorf("CSP missing style hash %q; got: %s", landing_endpoint_config.DefaultStyleSrcHash, csp)
	}
	if strings.Contains(csp, "form-action") {
		t.Errorf("CSP should not include form-action; got: %s", csp)
	}
}

func TestEndpoint_FormBodyContainsAction(t *testing.T) {
	t.Parallel()

	testEndpoint := New()
	if err := testEndpoint.Initialize(signer); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint.Endpoint.Endpoint)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	tokenString := mintToken(t, defaultPayload(magicLinkTesting.ValidEmail, "body-action"))
	rawQuery := url.Values{"token": {tokenString}}.Encode()

	resp, err := http.Get(httpServer.URL + testEndpoint.Path + "?" + rawQuery)
	if err != nil {
		t.Fatalf("http get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status code: got %d, want 200", resp.StatusCode)
	}

	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	wantAction := `action="` + testEndpoint.Path + "?" + rawQuery + `"`
	if !strings.Contains(body, wantAction) {
		t.Errorf("body missing form action %q; got:\n%s", wantAction, body)
	}
	if !strings.Contains(body, `method="POST"`) {
		t.Errorf("body missing POST form method; got:\n%s", body)
	}
}

// TestEndpoint_ReferrerPolicy covers the header against a mux with its default document headers,
// whose own Referrer-Policy would otherwise be what is answered with.
func TestEndpoint_ReferrerPolicy(t *testing.T) {
	t.Parallel()

	expiredPayload := defaultPayload(magicLinkTesting.ValidEmail, "expired")
	expiredPayload["exp"] = time.Now().Add(-1 * time.Minute).Unix()

	testCases := []struct {
		name       string
		token      string
		statusCode int
	}{
		{name: "form page", token: mintToken(t, defaultPayload(magicLinkTesting.ValidEmail, "ok")), statusCode: http.StatusOK},
		{name: "unusable page", token: mintToken(t, expiredPayload), statusCode: http.StatusGone},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint := New(landing_endpoint_config.WithUnusablePageBuilder(unusablePageBuilder))
			if err := testEndpoint.Initialize(signer); err != nil {
				t.Fatalf("initialize: %v", err)
			}

			httpServer := httptest.NewServer(muxPkg.New(testEndpoint.Endpoint.Endpoint))
			defer httpServer.Close()

			muxTesting.TestArgs(
				t,
				&muxTesting.Args{
					Method:             testEndpoint.Method,
					Path:               testEndpoint.Path + "?" + url.Values{"token": {testCase.token}}.Encode(),
					ExpectedStatusCode: testCase.statusCode,
					ExpectedHeaders:    [][2]string{{"Referrer-Policy", "strict-origin"}},
					ExpectedBody:       []byte(muxTesting.ExpectedBodyNonEmpty),
				},
				httpServer.URL,
			)
		})
	}
}

func TestEndpoint_Initialize_SpentCheckerRequiresUnusablePage(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name                string
		unusablePageBuilder landing_endpoint_config.PageBuilder
		wantErr             bool
	}{
		{name: "without unusable page", wantErr: true},
		{name: "with unusable page", unusablePageBuilder: unusablePageBuilder},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint := New(landing_endpoint_config.WithUnusablePageBuilder(testCase.unusablePageBuilder))
			testEndpoint.SpentChecker = makeSpentChecker(false, nil)

			if err := testEndpoint.Initialize(signer); (err != nil) != testCase.wantErr {
				t.Errorf("initialize error = %v, want error %v", err, testCase.wantErr)
			}
		})
	}
}
