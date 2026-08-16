package passkey

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	muxPkg "github.com/Motmedel/utils_go/pkg/http/mux"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	"github.com/Motmedel/utils_go/pkg/webauthn"
	"github.com/altshiftab/authentication_go/pkg/passkey/helpers/login/types"
	passkeyConfig "github.com/altshiftab/authentication_go/pkg/passkey/passkey_config"
)

var errAttestationRequired = errors.New("attestation required")

// A real registration and authentication ceremony pair for rp id "alt-shift.se", shared with the
// utils_go webauthn transport tests. The registration's credential public key equals
// flowPublicKeyDerBase64, and the authentication's signature verifies against it.
const (
	flowRegistrationBodyJson = `{
	  "id": "AsDY91_hSwTVT8owaP_hfw",
	  "rawId": "AsDY91_hSwTVT8owaP_hfw",
	  "response": {
		"attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViU1a2ljx0QHe9thc1Bo3Gm2O8_GyFQPoxAhTSh0lRpifNdAAAAAOqbjWZNAR0hPOS2tIy1ddQAEALA2Pdf4UsE1U_KMGj_4X-lAQIDJiABIVggAZdqCklTaOiYUPmAfwoiOiCzV71PdToO0G7LS-JKWJMiWCC8RDpZjuMxm4dwDtBf1Ybd1jMrqzK4LSg-8P7tVB4R4Q",
		"clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWjdJTjdNZE9SNW8wZGtESG9tY214VUhoM2RyN3ZPM1NMMVhfTlVuRF9hOTQtQ1YtVHhWWGpRNExtcEJhNnB2SW1xaVdZRDVlS2FHNDhNa3NOYU9WcFEiLCJvcmlnaW4iOiJodHRwczovL2xvZ2luLmFsdC1zaGlmdC5zZSIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
		"transports": ["hybrid", "internal"]
	  },
	  "type": "public-key"
	}`

	flowLoginBodyJson = `{
	  "id": "AsDY91_hSwTVT8owaP_hfw",
	  "rawId": "AsDY91_hSwTVT8owaP_hfw",
	  "response": {
		"authenticatorData": "1a2ljx0QHe9thc1Bo3Gm2O8_GyFQPoxAhTSh0lRpifMdAAAAAA",
		"clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQVJQTU9oTTczYnVIUmxuNXFQb2lkTjV2SFdzSGwtbDVEdTJxNWlwZmlrRm5UYWRLZGJXYTZFdkNMUlBYaUR1dnotWXNibnV3Y1NpbGhSTG44NERFelEiLCJvcmlnaW4iOiJodHRwczovL2xvZ2luLmFsdC1zaGlmdC5zZSIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
		"signature": "MEQCIBCCQkxvytFK7GGjITF2san-K8nHPy3f2uTX3p9zqqtWAiAaEUiZTi0FmEfLvy6Su0k6rneI-mwXEK041d9qDsCTyA",
		"userHandle": "YjdiYmFhMTQtMmQzZS00ZTQyLWI1NjUtZmJhYTFkOWM1MmQ1"
	  },
	  "type": "public-key"
	}`

	flowPublicKeyDerBase64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAZdqCklTaOiYUPmAfwoiOiCzV71PdToO0G7LS-JKWJO8RDpZjuMxm4dwDtBf1Ybd1jMrqzK4LSg-8P7tVB4R4Q"

	// The attestation object embedded verbatim in flowRegistrationBodyJson.
	flowAttestationObjectBase64 = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViU1a2ljx0QHe9thc1Bo3Gm2O8_GyFQPoxAhTSh0lRpifNdAAAAAOqbjWZNAR0hPOS2tIy1ddQAEALA2Pdf4UsE1U_KMGj_4X-lAQIDJiABIVggAZdqCklTaOiYUPmAfwoiOiCzV71PdToO0G7LS-JKWJMiWCC8RDpZjuMxm4dwDtBf1Ybd1jMrqzK4LSg-8P7tVB4R4Q"

	flowUserId = "b7bbaa14-2d3e-4e42-b565-fbaa1d9c52d5"
)

type flowUserHandler struct {
	stubUserHandler

	signingData          *types.SigningData
	registrationUserId   string
	addedUserId          string
	addedCredential      *webauthn.AttestationPublicKeyCredential
	updatedCredentialIds [][]byte
}

func (h *flowUserHandler) GetPublicKeyCredential(_ context.Context, _ []byte) (*types.SigningData, error) {
	return h.signingData, nil
}

func (h *flowUserHandler) DeleteRegistrationIssuance(_ context.Context, _ []byte) (string, error) {
	return h.registrationUserId, nil
}

func (h *flowUserHandler) AddUser(_ context.Context, userId string, _ string) error {
	h.addedUserId = userId
	return nil
}

func (h *flowUserHandler) AddPublicKeyCredential(_ context.Context, _ string, credential *webauthn.AttestationPublicKeyCredential) error {
	h.addedCredential = credential
	return nil
}

func (h *flowUserHandler) UpdatePublicKeyCredential(_ context.Context, credentialId []byte, _ uint32) error {
	h.updatedCredentialIds = append(h.updatedCredentialIds, credentialId)
	return nil
}

type flowSessionHandler struct {
	stubSessionHandler

	authenticatedUserId string
}

func (h *flowSessionHandler) HandleSuccessfulAuthentication(_ context.Context, userId string) ([]*muxResponse.HeaderEntry, error) {
	h.authenticatedUserId = userId
	return []*muxResponse.HeaderEntry{{Name: "X-Test-Session", Value: "session-value"}}, nil
}

func postJson(t *testing.T, serverUrl string, path string, body string) (int, http.Header) {
	t.Helper()

	request, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		serverUrl+path,
		bytes.NewReader([]byte(body)),
	)
	if err != nil {
		t.Fatalf("http new request: %v", err)
	}
	request.Header.Set("Content-Type", contentTypeJson)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("http post: %v", err)
	}
	if response == nil {
		t.Fatalf("nil response")
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Errorf("response body close: %v", err)
		}
	}()

	return response.StatusCode, response.Header
}

func TestRegistrationAndLoginFlows(t *testing.T) {
	t.Parallel()

	publicKeyDer, err := base64.RawURLEncoding.DecodeString(flowPublicKeyDerBase64)
	if err != nil {
		t.Fatalf("base64 decode public key der: %v", err)
	}

	userHandler := &flowUserHandler{
		signingData: &types.SigningData{
			PublicKey:          publicKeyDer,
			SignatureCount:     0,
			PublicKeyAlgorithm: -7,
		},
		registrationUserId: "registered-user-id",
	}
	sessionHandler := &flowSessionHandler{}

	mux := &muxPkg.Mux{}
	err = PatchMux(
		mux,
		sessionHandler,
		userHandler,
		&url.URL{Scheme: "https", Host: "login.alt-shift.se"},
		&webauthn.RelyingParty{Id: "alt-shift.se", Name: "Alt-Shift"},
		[]int{-7},
	)
	if err != nil {
		t.Fatalf("patch mux: %v", err)
	}

	httpServer := httptest.NewServer(mux)
	t.Cleanup(httpServer.Close)

	// Registration.
	statusCode, _ := postJson(t, httpServer.URL, "/api/register/passkey", flowRegistrationBodyJson)
	if statusCode >= 300 {
		t.Fatalf("registration status code: got %d", statusCode)
	}

	if userHandler.addedUserId != "registered-user-id" {
		t.Errorf("added user id: got %q", userHandler.addedUserId)
	}

	credential := userHandler.addedCredential
	if credential == nil {
		t.Fatalf("nil added credential")
	}

	authenticatorData := credential.Response.GetAuthenticatorData()
	if authenticatorData == nil || authenticatorData.AttestedCredential == nil {
		t.Fatalf("missing attested credential")
	}
	if len(authenticatorData.AttestedCredential.RawPublicKey) == 0 {
		t.Errorf("missing attested credential public key")
	}

	// Login.
	statusCode, header := postJson(t, httpServer.URL, "/api/login/passkey", flowLoginBodyJson)
	if statusCode >= 300 {
		t.Fatalf("login status code: got %d", statusCode)
	}

	if header.Get("X-Test-Session") != "session-value" {
		t.Errorf("missing session header")
	}

	if sessionHandler.authenticatedUserId != flowUserId {
		t.Errorf("authenticated user id: got %q", sessionHandler.authenticatedUserId)
	}

	if len(userHandler.updatedCredentialIds) != 1 {
		t.Errorf("updated credential ids: got %d", len(userHandler.updatedCredentialIds))
	}

	// Login with a tampered signature must be rejected as client error.
	tamperedBody := strings.Replace(flowLoginBodyJson, `"signature": "MEQCIBCC`, `"signature": "MEQCIBCD`, 1)
	statusCode, _ = postJson(t, httpServer.URL, "/api/login/passkey", tamperedBody)
	if statusCode != http.StatusBadRequest {
		t.Errorf("tampered login status code: got %d, want %d", statusCode, http.StatusBadRequest)
	}
}

// TestRegistrationRejectsUnexpectedAttestation verifies that a registration whose attestation
// object carries a non-"none" statement format (unexpected for a "none"-requesting relying
// party) is rejected rather than trusted, exercising the attestation statement verification.
func TestRegistrationRejectsUnexpectedAttestation(t *testing.T) {
	t.Parallel()

	// The flow attestation object with its "none" format relabelled to the unsupported "tpm"
	// format, keeping the CBOR map structure valid.
	attestationObject := decodeFlowAttestationObject(t)
	tamperedAttestationObject := bytes.Replace(
		attestationObject,
		[]byte("\x63fmt\x64none"),
		[]byte("\x63fmt\x63tpm"),
		1,
	)
	if bytes.Equal(tamperedAttestationObject, attestationObject) {
		t.Fatalf("attestation object format not relabelled")
	}

	registrationBody := strings.Replace(
		flowRegistrationBodyJson,
		flowAttestationObjectBase64,
		base64.RawURLEncoding.EncodeToString(tamperedAttestationObject),
		1,
	)

	mux := &muxPkg.Mux{}
	err := PatchMux(
		mux,
		&flowSessionHandler{},
		&flowUserHandler{registrationUserId: "registered-user-id"},
		&url.URL{Scheme: "https", Host: "login.alt-shift.se"},
		&webauthn.RelyingParty{Id: "alt-shift.se", Name: "Alt-Shift"},
		[]int{-7},
	)
	if err != nil {
		t.Fatalf("patch mux: %v", err)
	}

	httpServer := httptest.NewServer(mux)
	t.Cleanup(httpServer.Close)

	statusCode, _ := postJson(t, httpServer.URL, "/api/register/passkey", registrationBody)
	if statusCode < 400 || statusCode >= 500 {
		t.Errorf("status code: got %d, want a client error", statusCode)
	}
}

func decodeFlowAttestationObject(t *testing.T) []byte {
	t.Helper()

	attestationObject, err := base64.RawURLEncoding.DecodeString(flowAttestationObjectBase64)
	if err != nil {
		t.Fatalf("base64 decode attestation object: %v", err)
	}

	return attestationObject
}

// TestRegistrationAttestationVerifier verifies that a configured AttestationVerifier is applied
// to the verified result and can reject the registration.
func TestRegistrationAttestationVerifier(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		verifier       func(result *webauthn.AttestationVerificationResult) error
		expectAccepted bool
	}{
		{
			name:           "accepting verifier",
			verifier:       func(_ *webauthn.AttestationVerificationResult) error { return nil },
			expectAccepted: true,
		},
		{
			name: "rejecting verifier",
			verifier: func(result *webauthn.AttestationVerificationResult) error {
				// The flow fixture is a "none" attestation; a policy requiring real attestation
				// rejects it.
				if result.Type == webauthn.AttestationTypeNone {
					return errAttestationRequired
				}
				return nil
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			mux := &muxPkg.Mux{}
			err := PatchMux(
				mux,
				&flowSessionHandler{},
				&flowUserHandler{registrationUserId: "registered-user-id"},
				&url.URL{Scheme: "https", Host: "login.alt-shift.se"},
				&webauthn.RelyingParty{Id: "alt-shift.se", Name: "Alt-Shift"},
				[]int{-7},
				passkeyConfig.WithAttestationVerifier(testCase.verifier),
			)
			if err != nil {
				t.Fatalf("patch mux: %v", err)
			}

			httpServer := httptest.NewServer(mux)
			t.Cleanup(httpServer.Close)

			statusCode, _ := postJson(t, httpServer.URL, "/api/register/passkey", flowRegistrationBodyJson)
			if testCase.expectAccepted {
				if statusCode >= 300 {
					t.Errorf("status code: got %d, want < 300", statusCode)
				}
				return
			}
			if statusCode != http.StatusForbidden {
				t.Errorf("status code: got %d, want %d", statusCode, http.StatusForbidden)
			}
		})
	}
}
