package body_input

import (
	"encoding/json/v2"
	"net/http"
	"testing"

	webauthnTransport "github.com/Motmedel/utils_go/pkg/webauthn/transport"
)

const assertionCredentialJson = `{
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

func TestPublicKeyCredentialProcessor(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		var transportCredential webauthnTransport.AssertionPublicKeyCredential
		if err := json.Unmarshal([]byte(assertionCredentialJson), &transportCredential); err != nil {
			t.Fatalf("json unmarshal: %v", err)
		}

		bodyInput, responseError := PublicKeyCredentialProcessor.Process(t.Context(), &transportCredential)
		if responseError != nil {
			t.Fatalf("response error: %+v", responseError)
		}
		if bodyInput == nil {
			t.Fatalf("nil body input")
		}

		if bodyInput.Credential == nil {
			t.Errorf("nil credential")
		}
		if len(bodyInput.CredentialId) == 0 || len(bodyInput.Challenge) == 0 {
			t.Errorf("missing credential id or challenge: %+v", bodyInput)
		}
		if bodyInput.UserId != "b7bbaa14-2d3e-4e42-b565-fbaa1d9c52d5" {
			t.Errorf("user id: got %q", bodyInput.UserId)
		}
		if len(bodyInput.RawClientDataJson) == 0 || len(bodyInput.RawAuthenticatorData) == 0 {
			t.Errorf("missing raw fields")
		}
	})

	t.Run("nil credential", func(t *testing.T) {
		t.Parallel()

		_, responseError := PublicKeyCredentialProcessor.Process(t.Context(), nil)
		if responseError == nil || responseError.ServerError == nil {
			t.Fatalf("expected server error, got %+v", responseError)
		}
	})

	t.Run("undecodable credential", func(t *testing.T) {
		t.Parallel()

		_, responseError := PublicKeyCredentialProcessor.Process(
			t.Context(),
			&webauthnTransport.AssertionPublicKeyCredential{},
		)
		if responseError == nil || responseError.ProblemDetail == nil ||
			responseError.ProblemDetail.Status != http.StatusUnprocessableEntity {
			t.Fatalf("expected unprocessable entity, got %+v", responseError)
		}
	})
}
