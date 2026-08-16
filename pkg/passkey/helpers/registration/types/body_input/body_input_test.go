package body_input

import (
	"encoding/json/v2"
	"net/http"
	"testing"

	webauthnTransport "github.com/Motmedel/utils_go/pkg/webauthn/transport"
)

const attestationCredentialJson = `{
	  "id": "AsDY91_hSwTVT8owaP_hfw",
	  "rawId": "AsDY91_hSwTVT8owaP_hfw",
	  "response": {
		"attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViU1a2ljx0QHe9thc1Bo3Gm2O8_GyFQPoxAhTSh0lRpifNdAAAAAOqbjWZNAR0hPOS2tIy1ddQAEALA2Pdf4UsE1U_KMGj_4X-lAQIDJiABIVggAZdqCklTaOiYUPmAfwoiOiCzV71PdToO0G7LS-JKWJMiWCC8RDpZjuMxm4dwDtBf1Ybd1jMrqzK4LSg-8P7tVB4R4Q",
		"clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWjdJTjdNZE9SNW8wZGtESG9tY214VUhoM2RyN3ZPM1NMMVhfTlVuRF9hOTQtQ1YtVHhWWGpRNExtcEJhNnB2SW1xaVdZRDVlS2FHNDhNa3NOYU9WcFEiLCJvcmlnaW4iOiJodHRwczovL2xvZ2luLmFsdC1zaGlmdC5zZSIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
		"transports": ["hybrid", "internal"]
	  },
	  "type": "public-key"
	}`

func TestPublicKeyCredentialProcessor(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		var transportCredential webauthnTransport.AttestationPublicKeyCredential
		if err := json.Unmarshal([]byte(attestationCredentialJson), &transportCredential); err != nil {
			t.Fatalf("json unmarshal: %v", err)
		}

		bodyInput, responseError := PublicKeyCredentialProcessor.Process(t.Context(), &transportCredential)
		if responseError != nil {
			t.Fatalf("response error: %+v", responseError)
		}
		if bodyInput == nil || bodyInput.Credential == nil {
			t.Fatalf("nil body input or credential")
		}

		if bodyInput.Credential.Response.AttestationObject == nil {
			t.Errorf("nil attestation object")
		}
	})

	t.Run("undecodable credential", func(t *testing.T) {
		t.Parallel()

		_, responseError := PublicKeyCredentialProcessor.Process(
			t.Context(),
			&webauthnTransport.AttestationPublicKeyCredential{},
		)
		if responseError == nil || responseError.ProblemDetail == nil ||
			responseError.ProblemDetail.Status != http.StatusUnprocessableEntity {
			t.Fatalf("expected unprocessable entity, got %+v", responseError)
		}
	})
}
