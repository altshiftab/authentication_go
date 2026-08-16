package body_input

import (
	"context"
	"net/http"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	processorPkg "github.com/Motmedel/utils_go/pkg/http/mux/types/processor"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	"github.com/Motmedel/utils_go/pkg/webauthn"
	webauthnTransport "github.com/Motmedel/utils_go/pkg/webauthn/transport"
)

type BodyInput struct {
	Credential           *webauthn.AssertionPublicKeyCredential
	CredentialId         []byte
	Challenge            []byte
	UserId               string
	RawClientDataJson    []byte
	RawAuthenticatorData []byte
}

var PublicKeyCredentialProcessor = processorPkg.New(
	func(_ context.Context, transportCredential *webauthnTransport.AssertionPublicKeyCredential) (*BodyInput, *response_error.ResponseError) {
		if transportCredential == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(nil_error.New("public key credential")),
			}
		}
		credential, err := webauthnTransport.MakeAssertionPublicKeyCredential(transportCredential)
		if err != nil {
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusUnprocessableEntity,
					problem_detail_config.WithDetail("The public key credential could not be decoded."),
				),
				ClientError: err,
			}
		}
		if credential == nil {
			return nil, &response_error.ResponseError{
				ServerError: motmedelErrors.NewWithTrace(nil_error.New("public key credential")),
			}
		}

		response := credential.Response

		return &BodyInput{
			Credential:           credential,
			CredentialId:         credential.Id,
			Challenge:            response.ClientDataJson.Challenge,
			UserId:               string(response.UserHandle),
			RawClientDataJson:    transportCredential.Response.GetClientDataJson(),
			RawAuthenticatorData: transportCredential.Response.GetAuthenticatorData(),
		}, nil
	},
)
