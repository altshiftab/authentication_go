package registration

import (
	"encoding/base64"
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/Motmedel/utils_go/pkg/webauthn"
	webauthnTransport "github.com/Motmedel/utils_go/pkg/webauthn/transport"
)

func TestMakeRegistrationOptionsBytes(t *testing.T) {
	t.Parallel()

	userId := webauthnTransport.Base64URL("test-user-id")
	user := &webauthnTransport.PublicKeyCredentialUserEntity{Id: &userId}
	relyingParty := &webauthn.RelyingParty{Id: "example.com", Name: "Example"}
	challenge := []byte("test-challenge")

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		optionsBytes, err := MakeRegistrationOptionsBytes(user, relyingParty, challenge, []int{-7, -257}, "")
		if err != nil {
			t.Fatalf("make registration options bytes: %v", err)
		}

		var options struct {
			RelyingParty struct {
				Id   string `json:"id"`
				Name string `json:"name"`
			} `json:"rp"`
			User struct {
				Id string `json:"id"`
			} `json:"user"`
			Challenge        string `json:"challenge"`
			PubKeyCredParams []struct {
				Type string `json:"type"`
				Alg  int    `json:"alg"`
			} `json:"pubKeyCredParams"`
			Attestation string `json:"attestation"`
		}
		if err := json.Unmarshal(optionsBytes, &options); err != nil {
			t.Fatalf("json unmarshal: %v", err)
		}

		if options.RelyingParty.Id != "example.com" || options.RelyingParty.Name != "Example" {
			t.Errorf("relying party: got %+v", options.RelyingParty)
		}
		if options.User.Id != base64.RawURLEncoding.EncodeToString([]byte("test-user-id")) {
			t.Errorf("user id: got %q", options.User.Id)
		}
		if options.Challenge != base64.RawURLEncoding.EncodeToString(challenge) {
			t.Errorf("challenge: got %q", options.Challenge)
		}
		if len(options.PubKeyCredParams) != 2 || options.PubKeyCredParams[0].Alg != -7 ||
			options.PubKeyCredParams[0].Type != "public-key" {
			t.Errorf("pub key cred params: got %+v", options.PubKeyCredParams)
		}
		if options.Attestation != "none" {
			t.Errorf("attestation: got %q", options.Attestation)
		}

		// The resident-key preference must force requireResidentKey for older clients.
		if !strings.Contains(string(optionsBytes), `"requireResidentKey":true`) {
			t.Errorf("missing forced requireResidentKey: %s", optionsBytes)
		}
	})

	t.Run("attestation conveyance preference", func(t *testing.T) {
		t.Parallel()

		optionsBytes, err := MakeRegistrationOptionsBytes(user, relyingParty, challenge, []int{-7}, "direct")
		if err != nil {
			t.Fatalf("make registration options bytes: %v", err)
		}

		var options struct {
			Attestation string `json:"attestation"`
		}
		if err := json.Unmarshal(optionsBytes, &options); err != nil {
			t.Fatalf("json unmarshal: %v", err)
		}

		if options.Attestation != "direct" {
			t.Errorf("attestation: got %q, want %q", options.Attestation, "direct")
		}
	})

	testCases := []struct {
		name                  string
		user                  *webauthnTransport.PublicKeyCredentialUserEntity
		relyingParty          *webauthn.RelyingParty
		challenge             []byte
		allowedCoseAlgorithms []int
	}{
		{name: "nil user", relyingParty: relyingParty, challenge: challenge, allowedCoseAlgorithms: []int{-7}},
		{name: "nil relying party", user: user, challenge: challenge, allowedCoseAlgorithms: []int{-7}},
		{name: "empty challenge", user: user, relyingParty: relyingParty, allowedCoseAlgorithms: []int{-7}},
		{name: "empty algorithms", user: user, relyingParty: relyingParty, challenge: challenge},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, err := MakeRegistrationOptionsBytes(
				testCase.user,
				testCase.relyingParty,
				testCase.challenge,
				testCase.allowedCoseAlgorithms,
				"",
			)
			if err == nil {
				t.Errorf("expected error")
			}
		})
	}
}
