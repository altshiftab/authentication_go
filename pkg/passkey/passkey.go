package passkey

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/Motmedel/utils_go/pkg/cose"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/Motmedel/utils_go/pkg/http/mux"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/body_loader"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/body_loader/body_setting"
	"github.com/Motmedel/utils_go/pkg/http/mux/types/body_parser"
	bodyParserAdapter "github.com/Motmedel/utils_go/pkg/http/mux/types/body_parser/adapter"
	jsonSchemaBodyParser "github.com/Motmedel/utils_go/pkg/http/mux/types/body_parser/json_schema_body_parser"
	endpointPkg "github.com/Motmedel/utils_go/pkg/http/mux/types/endpoint"
	muxResponse "github.com/Motmedel/utils_go/pkg/http/mux/types/response"
	muxResponseError "github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/Motmedel/utils_go/pkg/http/mux/utils"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	"github.com/Motmedel/utils_go/pkg/net/types/domain_parts"
	"github.com/Motmedel/utils_go/pkg/utils"
	"github.com/Motmedel/utils_go/pkg/webauthn"
	webauthnTransport "github.com/Motmedel/utils_go/pkg/webauthn/transport"
	passkeyProviderErrors "github.com/altshiftab/authentication_go/pkg/passkey/errors"
	passkeyHelpers "github.com/altshiftab/authentication_go/pkg/passkey/helpers"
	"github.com/altshiftab/authentication_go/pkg/passkey/helpers/login"
	"github.com/altshiftab/authentication_go/pkg/passkey/helpers/login/types"
	loginBodyInput "github.com/altshiftab/authentication_go/pkg/passkey/helpers/login/types/body_input"
	"github.com/altshiftab/authentication_go/pkg/passkey/helpers/registration"
	registrationBodyInput "github.com/altshiftab/authentication_go/pkg/passkey/helpers/registration/types/body_input"
	passkeyConfig "github.com/altshiftab/authentication_go/pkg/passkey/passkey_config"
)

const contentTypeJson = "application/json"

type UserHandler interface {
	GetPublicKeyCredential(ctx context.Context, credentialId []byte) (*types.SigningData, error)
	AddPublicKeyCredential(ctx context.Context, userId string, credential *webauthn.AttestationPublicKeyCredential) error
	UpdatePublicKeyCredential(ctx context.Context, credentialId []byte, signatureCount uint32) error
	AddRegistrationIssuance(ctx context.Context, userId string, challenge []byte) error
	DeleteRegistrationIssuance(ctx context.Context, challenge []byte) (string, error)
	// TODO: Maybe this should return an error as well?
	GenerateUserId(ctx context.Context) string
	AddUser(ctx context.Context, userId string, emailAddress string) error
}

type SessionHandler interface {
	AddPublicKeyAuthenticationRequest(ctx context.Context, challenge []byte) error
	DeletePublicKeyAuthenticationRequest(ctx context.Context, challenge []byte) error
	HandleSuccessfulAuthentication(ctx context.Context, userId string) ([]*muxResponse.HeaderEntry, error)
}

func PatchMux(
	mux *mux.Mux,
	sessionHandler SessionHandler,
	userHandler UserHandler,
	originUrl *url.URL,
	relyingParty *webauthn.RelyingParty,
	allowedCoseAlgorithms []int,
	options ...passkeyConfig.Option,
) error {
	if mux == nil {
		return nil
	}

	config := passkeyConfig.New(options...)

	switch config.AttestationConveyancePreference {
	case passkeyConfig.AttestationConveyancePreferenceNone,
		passkeyConfig.AttestationConveyancePreferenceIndirect,
		passkeyConfig.AttestationConveyancePreferenceDirect,
		passkeyConfig.AttestationConveyancePreferenceEnterprise:
	default:
		return motmedelErrors.NewWithTrace(
			fmt.Errorf(
				"%w: unsupported attestation conveyance preference %q",
				motmedelErrors.ErrValidationError,
				config.AttestationConveyancePreference,
			),
		)
	}

	if originUrl == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("origin url"))
	}

	originUrlString := originUrl.String()
	originUrlHostName := originUrl.Hostname()

	domainParts := domain_parts.New(originUrlHostName)
	if domainParts == nil {
		return motmedelErrors.New(nil_error.New("domain parts"))
	}

	if utils.IsNil(sessionHandler) {
		return motmedelErrors.NewWithTrace(nil_error.New("session handler"))
	}

	if utils.IsNil(userHandler) {
		return motmedelErrors.NewWithTrace(nil_error.New("user handler"))
	}

	if relyingParty == nil {
		return motmedelErrors.NewWithTrace(nil_error.New("relying party"))
	}

	relyingPartyId := relyingParty.Id
	if relyingPartyId == "" {
		return motmedelErrors.NewWithTrace(empty_error.New("relying party id"))
	}

	if relyingParty.Name == "" {
		return motmedelErrors.NewWithTrace(empty_error.New("relying party name"))
	}

	coseAlgorithms := make([]cose.Algorithm, 0, len(allowedCoseAlgorithms))
	for _, allowedCoseAlgorithm := range allowedCoseAlgorithms {
		coseAlgorithms = append(coseAlgorithms, cose.Algorithm(allowedCoseAlgorithm))
	}

	loginTransportCredentialBodyParser, err := jsonSchemaBodyParser.New[*webauthnTransport.AssertionPublicKeyCredential]()
	if err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("json schema body parser new (login public key credential): %w", err))
	}
	loginPublicKeyCredentialBodyParser := body_parser.NewWithProcessor(
		loginTransportCredentialBodyParser,
		loginBodyInput.PublicKeyCredentialProcessor,
	)

	registerTransportCredentialBodyParser, err := jsonSchemaBodyParser.New[*webauthnTransport.AttestationPublicKeyCredential]()
	if err != nil {
		return motmedelErrors.NewWithTrace(fmt.Errorf("json schema body parser new (register public key credential): %w", err))
	}
	registerPublicKeyCredentialBodyParser := body_parser.NewWithProcessor(
		registerTransportCredentialBodyParser,
		registrationBodyInput.PublicKeyCredentialProcessor,
	)

	mux.Add(
		&endpointPkg.Endpoint{
			Path:   "/api/login/passkey/options",
			Method: http.MethodGet,
			Handler: func(request *http.Request, _ []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
				ctx := request.Context()

				challenge, err := passkeyHelpers.GenerateChallenge()
				if err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("generate challenge: %w", err)),
					}
				}

				if err := sessionHandler.AddPublicKeyAuthenticationRequest(ctx, challenge); err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.NewWithTrace(
							fmt.Errorf("login add challenge to database: %w", err),
							challenge,
						),
					}
				}

				optionsBytes, err := login.MakeOptionsBytes(challenge, relyingPartyId)
				if err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.NewWithTrace(
							fmt.Errorf("login make options bytes: %w", err),
							challenge,
						),
					}
				}

				return &muxResponse.Response{
					Headers: []*muxResponse.HeaderEntry{{Name: "Content-Type", Value: contentTypeJson}},
					Body:    optionsBytes,
				}, nil
			},
		},
		&endpointPkg.Endpoint{
			Path:   "/api/login/passkey",
			Method: http.MethodPost,
			BodyLoader: &body_loader.Loader{
				Setting:     body_setting.Required,
				ContentType: contentTypeJson,
				MaxBytes:    2048,
				Parser:      bodyParserAdapter.New(loginPublicKeyCredentialBodyParser),
			},
			Handler: func(request *http.Request, requestBody []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
				ctx := request.Context()

				bodyInput, responseError := muxUtils.GetServerNonZeroParsedRequestBody[*loginBodyInput.BodyInput](ctx)
				if responseError != nil {
					return nil, responseError
				}

				credentialId := bodyInput.CredentialId
				if len(credentialId) == 0 {
					return nil, &muxResponseError.ResponseError{
						ClientError: motmedelErrors.NewWithTrace(empty_error.New("credential id")),
						ProblemDetail: problem_detail.New(
							http.StatusUnprocessableEntity,
							problem_detail_config.WithDetail("The credential id is empty."),
						),
					}
				}

				// NOTE: The user is identified solely based on the credential ID, no email address e.g.
				signingData, err := userHandler.GetPublicKeyCredential(ctx, credentialId)
				if err != nil {
					wrappedErr := fmt.Errorf("get database signing data: %w", err)

					if errors.Is(err, passkeyProviderErrors.ErrNoPublicKeyCredential) {
						return nil, &muxResponseError.ResponseError{
							ProblemDetail: problem_detail.New(
								http.StatusBadRequest,
								problem_detail_config.WithDetail(
									"No stored public key credential was found for the given credential id.",
								),
							),
							ClientError: wrappedErr,
						}
					} else {
						return nil, &muxResponseError.ResponseError{ServerError: wrappedErr}
					}
				}
				if signingData == nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.NewWithTrace(nil_error.New("signing data")),
					}
				}

				challenge := bodyInput.Challenge
				if err := sessionHandler.DeletePublicKeyAuthenticationRequest(ctx, challenge); err != nil {
					wrappedErr := motmedelErrors.New(
						fmt.Errorf("session handler delete public key authentication request: %w", err),
						sessionHandler, challenge,
					)

					if responseError := passkeyHelpers.MakeDatabaseChallengeResponseError(wrappedErr); responseError != nil {
						return nil, responseError
					} else {
						return nil, &muxResponseError.ResponseError{ServerError: wrappedErr}
					}
				}

				publicKeyData := signingData.PublicKey
				publicKey, err := x509.ParsePKIXPublicKey(publicKeyData)
				if err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.NewWithTrace(
							fmt.Errorf("x509 parse pkix public key: %w", err),
							publicKeyData,
						),
					}
				}

				verifier, err := webauthn.NewVerifier(cose.Algorithm(signingData.PublicKeyAlgorithm), publicKey)
				if err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.New(
							fmt.Errorf("webauthn new verifier: %w", err),
							signingData.PublicKeyAlgorithm, publicKey,
						),
					}
				}

				err = webauthn.ValidateAssertionPublicKeyCredential(
					bodyInput.Credential,
					bodyInput.RawClientDataJson,
					bodyInput.RawAuthenticatorData,
					challenge,
					originUrlString,
					relyingPartyId,
					signingData.SignatureCount,
					verifier,
				)
				if err != nil {
					wrappedErr := motmedelErrors.New(
						fmt.Errorf("validate assertion public key credential: %w", err),
						bodyInput.Credential,
						bodyInput.RawClientDataJson,
						bodyInput.RawAuthenticatorData,
						challenge,
						originUrlString,
						relyingPartyId,
						signingData.SignatureCount,
						verifier,
					)

					// Signature failures are wrapped as verification errors; both classes are
					// caused by client input.
					if motmedelErrors.IsAny(err, motmedelErrors.ErrValidationError, motmedelErrors.ErrVerificationError) {
						validationResponseError := passkeyHelpers.MakeValidationResponseError(
							wrappedErr,
							webauthn.AssertionBadRequestErrors,
						)
						if validationResponseError == nil {
							return nil, &muxResponseError.ResponseError{
								ServerError: motmedelErrors.NewWithTrace(nil_error.New("validation response error")),
							}
						}
						return nil, validationResponseError
					}

					return nil, &muxResponseError.ResponseError{ServerError: wrappedErr}
				}

				signatureCount := signingData.SignatureCount
				if err := userHandler.UpdatePublicKeyCredential(ctx, credentialId, signatureCount); err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.New(
							fmt.Errorf("update public key credential: %w", err),
							credentialId, signatureCount,
						),
					}
				}

				userId := bodyInput.UserId
				headerEntries, err := sessionHandler.HandleSuccessfulAuthentication(ctx, userId)
				if err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.New(
							fmt.Errorf("session handler handle successful authentication: %w", err),
							sessionHandler, userId,
						),
					}
				}

				return &muxResponse.Response{Headers: headerEntries}, nil
			},
		},
		&endpointPkg.Endpoint{
			Path:   "/api/register/passkey/options",
			Method: http.MethodGet,
			Handler: func(request *http.Request, _ []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
				ctx := request.Context()

				challenge, err := passkeyHelpers.GenerateChallenge()
				if err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.NewWithTrace(fmt.Errorf("generate challenge: %w", err)),
					}
				}

				userId := userHandler.GenerateUserId(ctx)
				transportUserId := webauthnTransport.Base64URL(userId)

				// NOTE: `Name` and `DisplayName` are set client side.
				optionsBytes, err := registration.MakeRegistrationOptionsBytes(
					&webauthnTransport.PublicKeyCredentialUserEntity{
						Id: &transportUserId,
					},
					relyingParty,
					challenge,
					allowedCoseAlgorithms,
					config.AttestationConveyancePreference,
				)
				if err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.NewWithTrace(
							fmt.Errorf("make registration options bytes: %w", err),
						),
					}
				}

				if err := userHandler.AddRegistrationIssuance(ctx, userId, challenge); err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.NewWithTrace(
							fmt.Errorf("user handler add token issuance: %w", err),
							userHandler, userId, challenge,
						),
					}
				}

				return &muxResponse.Response{
					Headers: []*muxResponse.HeaderEntry{{Name: "Content-Type", Value: contentTypeJson}},
					Body:    optionsBytes,
				}, nil
			},
		},
		&endpointPkg.Endpoint{
			Path:   "/api/register/passkey",
			Method: http.MethodPost,
			BodyLoader: &body_loader.Loader{
				Setting:     body_setting.Required,
				ContentType: contentTypeJson,
				Parser:      bodyParserAdapter.New(registerPublicKeyCredentialBodyParser),
				MaxBytes:    2048,
			},
			Handler: func(request *http.Request, requestBody []byte) (*muxResponse.Response, *muxResponseError.ResponseError) {
				ctx := request.Context()

				bodyInput, responseError := muxUtils.GetServerNonZeroParsedRequestBody[*registrationBodyInput.BodyInput](ctx)
				if responseError != nil {
					return nil, responseError
				}

				challenge := bodyInput.Credential.Response.ClientDataJson.Challenge
				userId, err := userHandler.DeleteRegistrationIssuance(ctx, challenge)
				if err != nil {
					wrappedErr := motmedelErrors.New(
						fmt.Errorf("user handler delete token issuance: %w", err),
						userHandler,
					)

					if responseError := passkeyHelpers.MakeDatabaseChallengeResponseError(wrappedErr); responseError != nil {
						return nil, responseError
					} else {
						return nil, &muxResponseError.ResponseError{ServerError: wrappedErr}
					}
				}

				err = webauthn.ValidateAttestationPublicKeyCredential(
					bodyInput.Credential,
					challenge,
					originUrlString,
					relyingPartyId,
					coseAlgorithms,
				)
				if err != nil {
					wrappedErr := motmedelErrors.New(
						fmt.Errorf("validate attestation public key credential: %w", err),
						bodyInput.Credential, challenge, originUrlString, relyingPartyId, coseAlgorithms,
					)

					if errors.Is(err, motmedelErrors.ErrValidationError) {
						validationResponseError := passkeyHelpers.MakeValidationResponseError(
							wrappedErr,
							webauthn.AttestationBadRequestErrors,
						)
						if validationResponseError == nil {
							return nil, &muxResponseError.ResponseError{
								ServerError: motmedelErrors.NewWithTrace(nil_error.New("validation response error")),
							}
						}
						return nil, validationResponseError
					}

					return nil, &muxResponseError.ResponseError{ServerError: wrappedErr}
				}

				// Verify the attestation statement (WebAuthn §7.1.19). With the default "none"
				// preference a conforming authenticator returns an empty "none" statement, and
				// verification confirms that and rejects any unexpected or malformed statement;
				// with a stronger preference it verifies the actual statement format. The
				// verified result is handed to the configured AttestationVerifier, if any, which
				// applies the relying party's trust policy.
				attestationResult, err := webauthn.VerifyAttestationStatement(
					bodyInput.Credential.Response.AttestationObject,
					bodyInput.RawClientDataJson,
				)
				if err != nil {
					wrappedErr := motmedelErrors.New(
						fmt.Errorf("verify attestation statement: %w", err),
						bodyInput.Credential, bodyInput.RawClientDataJson,
					)

					if motmedelErrors.IsAny(err, motmedelErrors.ErrValidationError, motmedelErrors.ErrVerificationError) {
						validationResponseError := passkeyHelpers.MakeValidationResponseError(
							wrappedErr,
							webauthn.AttestationBadRequestErrors,
						)
						if validationResponseError == nil {
							return nil, &muxResponseError.ResponseError{
								ServerError: motmedelErrors.NewWithTrace(nil_error.New("validation response error")),
							}
						}
						return nil, validationResponseError
					}

					return nil, &muxResponseError.ResponseError{ServerError: wrappedErr}
				}

				if attestationVerifier := config.AttestationVerifier; attestationVerifier != nil {
					if err := attestationVerifier(attestationResult); err != nil {
						return nil, &muxResponseError.ResponseError{
							ProblemDetail: problem_detail.New(
								http.StatusForbidden,
								problem_detail_config.WithDetail("The authenticator is not acceptable."),
							),
							ClientError: motmedelErrors.New(
								fmt.Errorf("attestation verifier: %w", err),
								attestationResult,
							),
						}
					}
				}

				if err := userHandler.AddUser(ctx, userId, ""); err != nil {
					wrappedErr := motmedelErrors.New(
						fmt.Errorf("user handler add user: %w", err),
						userHandler, userId,
					)

					if errors.Is(err, passkeyProviderErrors.ErrEmailAddressUserIdConflict) {
						return nil, &muxResponseError.ResponseError{
							ProblemDetail: problem_detail.New(
								http.StatusConflict,
								problem_detail_config.WithDetail(
									"The email address is already registered with a different user id.",
								),
							),
							ClientError: wrappedErr,
						}
					}

					return nil, &muxResponseError.ResponseError{ServerError: wrappedErr}
				}

				credential := bodyInput.Credential
				if err := userHandler.AddPublicKeyCredential(ctx, userId, credential); err != nil {
					return nil, &muxResponseError.ResponseError{
						ServerError: motmedelErrors.New(
							fmt.Errorf("user handler add public key credential: %w", err),
							userHandler, userId, credential,
						),
					}
				}

				return nil, nil
			},
		},
	)

	return nil
}
