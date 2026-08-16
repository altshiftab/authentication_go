package landing_endpoint

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	motmedelCryptoEddsa "github.com/Motmedel/utils_go/pkg/crypto/eddsa"
	muxPkg "github.com/Motmedel/utils_go/pkg/http/mux"
	muxTesting "github.com/Motmedel/utils_go/pkg/http/mux/testing"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	motmedelJwtToken "github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/token"
	magicLinkTesting "github.com/altshiftab/authentication_go/pkg/magic_link/testing"
	"github.com/altshiftab/authentication_go/pkg/magic_link/types/endpoint/landing_endpoint/landing_endpoint_config"
)

var signer *motmedelCryptoEddsa.Method

func TestMain(m *testing.M) {
	signer = magicLinkTesting.NewSigner()
	os.Exit(m.Run())
}

func mintToken(t *testing.T, payload map[string]any) string {
	t.Helper()
	token := &motmedelJwtToken.Token{Payload: payload}
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
