package validate_endpoint

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	motmedelCryptoEddsa "github.com/Motmedel/utils_go/pkg/crypto/eddsa"
	muxPkg "github.com/Motmedel/utils_go/pkg/http/mux"
	muxTesting "github.com/Motmedel/utils_go/pkg/http/mux/testing"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	motmedelJwtToken "github.com/Motmedel/utils_go/pkg/json/jose/jwt/types/token"
	magicLinkTesting "github.com/altshiftab/authentication_go/pkg/magic_link/testing"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_manager"
)

const defaultPath = "/api/login/magic/validate"

var (
	sessionManager *session_manager.Manager
	signer         *motmedelCryptoEddsa.Method
	redirectUrl    *url.URL
)

func TestMain(m *testing.M) {
	sessionManager, signer = magicLinkTesting.SetUp()
	redirectUrl = magicLinkTesting.MustParseUrl(magicLinkTesting.RedirectUrl)

	code := m.Run()
	_ = sessionManager.Db.Close()

	os.Exit(code)
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

	otherSigner := magicLinkTesting.NewSigner()

	expiredPayload := defaultPayload(magicLinkTesting.ValidEmail, "expired-nonce")
	expiredPayload["exp"] = time.Now().Add(-1 * time.Minute).Unix()

	missingSub := defaultPayload(magicLinkTesting.ValidEmail, "missing-sub-nonce")
	delete(missingSub, "sub")

	missingJti := defaultPayload(magicLinkTesting.ValidEmail, "missing-jti-nonce")
	delete(missingJti, "jti")

	missingExp := defaultPayload(magicLinkTesting.ValidEmail, "missing-exp-nonce")
	delete(missingExp, "exp")

	emptySub := defaultPayload("", "empty-sub-nonce")

	testCases := []struct {
		name      string
		args      *muxTesting.Args
		token     string
		skipQuery bool
	}{
		{
			name: "success",
			args: &muxTesting.Args{
				ExpectedStatusCode:     http.StatusSeeOther,
				ExpectedHeaders:        [][2]string{{"Location", magicLinkTesting.RedirectUrl}},
				ExpectedHeadersPresent: []string{"Set-Cookie", "Secure-Session-Registration"},
			},
			token: mintToken(t, defaultPayload(magicLinkTesting.ValidEmail, "success-nonce")),
		},
		{
			name: "missing token",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "Bad query.",
					Extension: map[string]any{
						"errors": []any{"validation error: missing parameter: token"},
					},
				},
			},
			skipQuery: true,
		},
		{
			name: "empty token",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The token is empty.",
				},
			},
			token: "",
		},
		{
			name: "malformed token",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The token is invalid.",
				},
			},
			token: "not-a-jwt",
		},
		{
			name: "wrong signature",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The token is invalid.",
				},
			},
			token: func() string {
				token := &motmedelJwtToken.Token{Payload: defaultPayload(magicLinkTesting.ValidEmail, "wrong-sig-nonce")}
				tokenString, err := token.Encode(otherSigner)
				if err != nil {
					t.Fatalf("token encode: %v", err)
				}
				return tokenString
			}(),
		},
		{
			name: "expired token",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The token has expired.",
				},
			},
			token: mintToken(t, expiredPayload),
		},
		{
			name: "missing exp",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The token exp claim is missing.",
				},
			},
			token: mintToken(t, missingExp),
		},
		{
			name: "missing sub",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The token sub claim is missing.",
				},
			},
			token: mintToken(t, missingSub),
		},
		{
			name: "empty sub",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The token sub claim is empty.",
				},
			},
			token: mintToken(t, emptySub),
		},
		{
			name: "missing jti",
			args: &muxTesting.Args{
				ExpectedStatusCode: http.StatusBadRequest,
				ExpectedProblemDetail: &problem_detail.Detail{
					Detail: "The token jti claim is missing.",
				},
			},
			token: mintToken(t, missingJti),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testEndpoint := New()
			if err := testEndpoint.Initialize(signer, sessionManager, redirectUrl); err != nil {
				t.Fatalf("initialize: %v", err)
			}

			mux := &muxPkg.Mux{}
			mux.Add(testEndpoint.Endpoint.Endpoint)
			httpServer := httptest.NewServer(mux)
			defer httpServer.Close()

			if testCase.skipQuery {
				testCase.args.Path = testEndpoint.Path
			} else {
				values := url.Values{"token": {testCase.token}}
				testCase.args.Path = testEndpoint.Path + "?" + values.Encode()
			}
			testCase.args.Method = testEndpoint.Method

			muxTesting.TestArgs(t, testCase.args, httpServer.URL)
		})
	}
}

func TestEndpoint_RedirectClaimOverridesDefault(t *testing.T) {
	t.Parallel()

	testEndpoint := New()
	if err := testEndpoint.Initialize(signer, sessionManager, redirectUrl); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint.Endpoint.Endpoint)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	const overrideUrl = "https://example.com/elsewhere"
	payload := defaultPayload(magicLinkTesting.ValidEmail, "redirect-nonce")
	payload["redirect"] = overrideUrl

	tokenString := mintToken(t, payload)
	path := testEndpoint.Path + "?" + url.Values{"token": {tokenString}}.Encode()

	muxTesting.TestArgs(
		t,
		&muxTesting.Args{
			Method:                 http.MethodPost,
			Path:                   path,
			ExpectedStatusCode:     http.StatusSeeOther,
			ExpectedHeaders:        [][2]string{{"Location", overrideUrl}},
			ExpectedHeadersPresent: []string{"Set-Cookie", "Secure-Session-Registration"},
		},
		httpServer.URL,
	)
}

func TestEndpoint_TokenReuse(t *testing.T) {
	t.Parallel()

	testEndpoint := New()
	if err := testEndpoint.Initialize(signer, sessionManager, redirectUrl); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	mux := &muxPkg.Mux{}
	mux.Add(testEndpoint.Endpoint.Endpoint)
	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	tokenString := mintToken(t, defaultPayload(magicLinkTesting.ValidEmail, "reuse-nonce"))
	path := testEndpoint.Path + "?" + url.Values{"token": {tokenString}}.Encode()

	muxTesting.TestArgs(
		t,
		&muxTesting.Args{
			Method:                 http.MethodPost,
			Path:                   path,
			ExpectedStatusCode:     http.StatusSeeOther,
			ExpectedHeaders:        [][2]string{{"Location", magicLinkTesting.RedirectUrl}},
			ExpectedHeadersPresent: []string{"Set-Cookie", "Secure-Session-Registration"},
		},
		httpServer.URL,
	)

	muxTesting.TestArgs(
		t,
		&muxTesting.Args{
			Method:             http.MethodPost,
			Path:               path,
			ExpectedStatusCode: http.StatusConflict,
			ExpectedProblemDetail: &problem_detail.Detail{
				Detail: "This sign-in link has already been used.",
			},
		},
		httpServer.URL,
	)
}

func TestEndpoint_Initialize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		nilVerifier   bool
		nilSession    bool
		nilRedirect   bool
		emptyRedirect bool
		wantErr       bool
	}{
		{name: "success"},
		{name: "nil verifier", nilVerifier: true, wantErr: true},
		{name: "nil session manager", nilSession: true, wantErr: true},
		{name: "nil redirect url", nilRedirect: true, wantErr: true},
		{name: "empty redirect url", emptyRedirect: true, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			endpoint := New()
			var verifierArg *motmedelCryptoEddsa.Method = signer
			if tt.nilVerifier {
				verifierArg = nil
			}
			var sessionArg = sessionManager
			if tt.nilSession {
				sessionArg = nil
			}
			var redirectArg = redirectUrl
			switch {
			case tt.nilRedirect:
				redirectArg = nil
			case tt.emptyRedirect:
				redirectArg = &url.URL{}
			}
			err := endpoint.Initialize(verifierArg, sessionArg, redirectArg)
			if (err != nil) != tt.wantErr {
				t.Errorf("Initialize() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}
