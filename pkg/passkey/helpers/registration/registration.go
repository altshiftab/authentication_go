package registration

import (
	"encoding/json/v2"
	"fmt"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/webauthn"
	webauthnTransport "github.com/Motmedel/utils_go/pkg/webauthn/transport"
)

func MakeRegistrationOptionsBytes(
	user *webauthnTransport.PublicKeyCredentialUserEntity,
	relyingParty *webauthn.RelyingParty,
	challenge []byte,
	allowedCoseAlgorithms []int,
	attestationConveyancePreference string,
) ([]byte, error) {
	if user == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("user entity"))
	}

	if relyingParty == nil {
		return nil, motmedelErrors.NewWithTrace(nil_error.New("relying party"))
	}

	if len(challenge) == 0 {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("challenge"))
	}

	if len(allowedCoseAlgorithms) == 0 {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("allowed cose algorithms"))
	}

	var publickeyCredentialParams []*webauthn.PublicKeyCredentialParam
	for _, coseAlgorithm := range allowedCoseAlgorithms {
		publickeyCredentialParams = append(
			publickeyCredentialParams,
			&webauthn.PublicKeyCredentialParam{
				Type: "public-key",
				Alg:  coseAlgorithm,
			},
		)
	}

	if attestationConveyancePreference == "" {
		attestationConveyancePreference = "none"
	}

	transportChallenge := webauthnTransport.Base64URL(challenge)

	options := webauthnTransport.PublicKeyCredentialCreationOptions{
		RelyingParty:     relyingParty,
		User:             user,
		Challenge:        &transportChallenge,
		PubKeyCredParams: publickeyCredentialParams,
		AuthenticatorSelection: &webauthn.AuthenticatorSelection{
			AuthenticatorAttachment: "platform",
			ResidentKey:             "required",
			RequireResidentKey:      true,
		},
		Attestation: attestationConveyancePreference,
	}

	optionsBytes, err := json.Marshal(options)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("json marshal: %w", err), options)
	}

	return optionsBytes, nil
}
