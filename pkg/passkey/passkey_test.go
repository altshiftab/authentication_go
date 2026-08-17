package passkey

import (
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/altshiftab/authentication_go/pkg/passkey/helpers/login/types"
	passkeyConfig "github.com/altshiftab/authentication_go/pkg/passkey/passkey_config"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
	muxResponse "github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/webauthn"
)

type stubUserHandler struct {
	registrationIssuances int
}

func (h *stubUserHandler) GetPublicKeyCredential(_ context.Context, _ []byte) (*types.SigningData, error) {
	return nil, nil
}

func (h *stubUserHandler) AddPublicKeyCredential(_ context.Context, _ string, _ *webauthn.AttestationPublicKeyCredential) error {
	return nil
}

func (h *stubUserHandler) UpdatePublicKeyCredential(_ context.Context, _ []byte, _ uint32) error {
	return nil
}

func (h *stubUserHandler) AddRegistrationIssuance(_ context.Context, _ string, _ []byte) error {
	h.registrationIssuances++
	return nil
}

func (h *stubUserHandler) DeleteRegistrationIssuance(_ context.Context, _ []byte) (string, error) {
	return "", nil
}

func (h *stubUserHandler) GenerateUserId(_ context.Context) string {
	return "test-user-id"
}

func (h *stubUserHandler) AddUser(_ context.Context, _ string, _ string) error {
	return nil
}

type stubSessionHandler struct {
	authenticationRequests int
}

func (h *stubSessionHandler) AddPublicKeyAuthenticationRequest(_ context.Context, _ []byte) error {
	h.authenticationRequests++
	return nil
}

func (h *stubSessionHandler) DeletePublicKeyAuthenticationRequest(_ context.Context, _ []byte) error {
	return nil
}

func (h *stubSessionHandler) HandleSuccessfulAuthentication(_ context.Context, _ string) ([]*muxResponse.HeaderEntry, error) {
	return nil, nil
}

func makeRelyingParty() *webauthn.RelyingParty {
	return &webauthn.RelyingParty{Id: "example.com", Name: "Example"}
}

func makeOriginUrl(t *testing.T) *url.URL {
	t.Helper()

	originUrl, err := url.Parse("https://example.com")
	if err != nil {
		t.Fatalf("url parse: %v", err)
	}

	return originUrl
}

func TestPatchMux(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		mux            *muxPkg.Mux
		sessionHandler SessionHandler
		userHandler    UserHandler
		originUrl      *url.URL
		relyingParty   *webauthn.RelyingParty
		options        []passkeyConfig.Option
		expectError    bool
	}{
		{
			name: "nil mux",
		},
		{
			name:           "nil origin url",
			mux:            &muxPkg.Mux{},
			sessionHandler: &stubSessionHandler{},
			userHandler:    &stubUserHandler{},
			relyingParty:   makeRelyingParty(),
			expectError:    true,
		},
		{
			name:         "nil session handler",
			mux:          &muxPkg.Mux{},
			userHandler:  &stubUserHandler{},
			originUrl:    &url.URL{Scheme: "https", Host: "example.com"},
			relyingParty: makeRelyingParty(),
			expectError:  true,
		},
		{
			name:           "nil user handler",
			mux:            &muxPkg.Mux{},
			sessionHandler: &stubSessionHandler{},
			originUrl:      &url.URL{Scheme: "https", Host: "example.com"},
			relyingParty:   makeRelyingParty(),
			expectError:    true,
		},
		{
			name:           "nil relaying party",
			mux:            &muxPkg.Mux{},
			sessionHandler: &stubSessionHandler{},
			userHandler:    &stubUserHandler{},
			originUrl:      &url.URL{Scheme: "https", Host: "example.com"},
			expectError:    true,
		},
		{
			name:           "success",
			mux:            &muxPkg.Mux{},
			sessionHandler: &stubSessionHandler{},
			userHandler:    &stubUserHandler{},
			originUrl:      &url.URL{Scheme: "https", Host: "example.com"},
			relyingParty:   makeRelyingParty(),
		},
		{
			name:           "direct attestation preference",
			mux:            &muxPkg.Mux{},
			sessionHandler: &stubSessionHandler{},
			userHandler:    &stubUserHandler{},
			originUrl:      &url.URL{Scheme: "https", Host: "example.com"},
			relyingParty:   makeRelyingParty(),
			options: []passkeyConfig.Option{
				passkeyConfig.WithAttestationConveyancePreference(passkeyConfig.AttestationConveyancePreferenceDirect),
			},
		},
		{
			name:           "unknown attestation preference",
			mux:            &muxPkg.Mux{},
			sessionHandler: &stubSessionHandler{},
			userHandler:    &stubUserHandler{},
			originUrl:      &url.URL{Scheme: "https", Host: "example.com"},
			relyingParty:   makeRelyingParty(),
			options: []passkeyConfig.Option{
				passkeyConfig.WithAttestationConveyancePreference("bogus"),
			},
			expectError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := PatchMux(
				testCase.mux,
				testCase.sessionHandler,
				testCase.userHandler,
				testCase.originUrl,
				testCase.relyingParty,
				[]int{-7},
				testCase.options...,
			)
			if testCase.expectError && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !testCase.expectError && err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
		})
	}
}

func newPatchedServer(t *testing.T) (*httptest.Server, *stubSessionHandler, *stubUserHandler) {
	t.Helper()

	mux := &muxPkg.Mux{}
	sessionHandler := &stubSessionHandler{}
	userHandler := &stubUserHandler{}

	err := PatchMux(mux, sessionHandler, userHandler, makeOriginUrl(t), makeRelyingParty(), []int{-7})
	if err != nil {
		t.Fatalf("patch mux: %v", err)
	}

	httpServer := httptest.NewServer(mux)
	t.Cleanup(httpServer.Close)

	return httpServer, sessionHandler, userHandler
}

func TestOptionsEndpoints(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		path string
	}{
		{name: "login options", path: "/api/login/passkey/options"},
		{name: "registration options", path: "/api/register/passkey/options"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			httpServer, sessionHandler, userHandler := newPatchedServer(t)

			request, err := http.NewRequestWithContext(
				t.Context(),
				http.MethodGet,
				httpServer.URL+testCase.path,
				nil,
			)
			if err != nil {
				t.Fatalf("http new request: %v", err)
			}

			response, err := httpServer.Client().Do(request)
			if err != nil {
				t.Fatalf("http get: %v", err)
			}
			defer func() {
				if err := response.Body.Close(); err != nil {
					t.Errorf("response body close: %v", err)
				}
			}()

			if response.StatusCode != http.StatusOK {
				t.Fatalf("status code: got %d, want %d", response.StatusCode, http.StatusOK)
			}

			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}

			var parsedBody map[string]any
			if err := json.Unmarshal(body, &parsedBody); err != nil {
				t.Fatalf("json unmarshal body: %v", err)
			}

			challenge, ok := parsedBody["challenge"].(string)
			if !ok || challenge == "" {
				t.Errorf("missing challenge in options body: %s", body)
			}

			if sessionHandler.authenticationRequests+userHandler.registrationIssuances != 1 {
				t.Errorf(
					"expected exactly one recorded challenge, got %d authentication requests and %d registration issuances",
					sessionHandler.authenticationRequests,
					userHandler.registrationIssuances,
				)
			}
		})
	}
}

func TestBodyEndpointsRejectBadBody(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		path string
		body string
	}{
		{name: "login empty object", path: "/api/login/passkey", body: "{}"},
		{name: "login malformed json", path: "/api/login/passkey", body: "not json"},
		{name: "registration empty object", path: "/api/register/passkey", body: "{}"},
		{name: "registration malformed json", path: "/api/register/passkey", body: "not json"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			httpServer, _, _ := newPatchedServer(t)

			request, err := http.NewRequestWithContext(
				t.Context(),
				http.MethodPost,
				httpServer.URL+testCase.path,
				strings.NewReader(testCase.body),
			)
			if err != nil {
				t.Fatalf("http new request: %v", err)
			}
			request.Header.Set("Content-Type", "application/json")

			response, err := httpServer.Client().Do(request)
			if err != nil {
				t.Fatalf("http post: %v", err)
			}
			defer func() {
				if err := response.Body.Close(); err != nil {
					t.Errorf("response body close: %v", err)
				}
			}()

			if response.StatusCode < 400 || response.StatusCode >= 500 {
				t.Errorf("status code: got %d, want a client error", response.StatusCode)
			}
		})
	}
}
