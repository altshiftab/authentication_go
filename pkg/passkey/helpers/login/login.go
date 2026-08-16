package login

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json/v2"
	"fmt"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/utils"
	webauthnTransport "github.com/Motmedel/utils_go/pkg/webauthn/transport"
)

func MakeEcdsaPublicKey(data []byte) (*ecdsa.PublicKey, error) {
	publicKey, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("x509 parse pkix public key: %w", err))
	}

	ecdsaPublicKey, err := utils.Convert[*ecdsa.PublicKey](publicKey)
	if err != nil {
		return nil, motmedelErrors.New(fmt.Errorf("convert: %w", err), publicKey)
	}

	return ecdsaPublicKey, nil
}

func MakeOptionsBytes(challenge []byte, relyingPartyId string) ([]byte, error) {
	if len(challenge) == 0 {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("challenge"))
	}

	transportChallenge := webauthnTransport.Base64URL(challenge)

	// NOTE: Relying party id is optional.
	options := webauthnTransport.PublicKeyCredentialRequestOptions{
		Challenge: &transportChallenge,
		RpId:      relyingPartyId,
	}

	optionsBytes, err := json.Marshal(options)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("json marshal: %w", err), options)
	}

	return optionsBytes, nil
}
