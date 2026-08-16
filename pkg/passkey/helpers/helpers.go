package helpers

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"

	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	muxResponseError "github.com/Motmedel/utils_go/pkg/http/mux/types/response_error"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail"
	"github.com/Motmedel/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	"github.com/Motmedel/utils_go/pkg/webauthn"
	passkeyProviderErrors "github.com/altshiftab/authentication_go/pkg/passkey/errors"
)

func GenerateChallenge() ([]byte, error) {
	challenge := make([]byte, 64)
	if _, err := rand.Read(challenge); err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("rand read: %w", err))
	}

	return challenge, nil
}

func MakeValidationResponseError(err error, badRequestErrors []error) *muxResponseError.ResponseError {
	var statusCode int
	isBadRequestErr := motmedelErrors.IsAny(err, webauthn.CommonBadRequestErrors...) || motmedelErrors.IsAny(err, badRequestErrors...)
	if isBadRequestErr {
		statusCode = http.StatusBadRequest
	} else {
		statusCode = http.StatusUnprocessableEntity
	}

	return &muxResponseError.ResponseError{
		ProblemDetail: problem_detail.New(
			statusCode,
			problem_detail_config.WithDetail("The public key credential did not pass validation."),
		),
		ClientError: err,
	}
}

func MakeDatabaseChallengeResponseError(err error) *muxResponseError.ResponseError {
	if errors.Is(err, passkeyProviderErrors.ErrNoChallenge) {
		return &muxResponseError.ResponseError{
			ProblemDetail: problem_detail.New(
				http.StatusBadRequest,
				problem_detail_config.WithDetail("No challenge was found."),
			),
			ClientError: err,
		}
	} else if errors.Is(err, passkeyProviderErrors.ErrExpiredChallenge) {
		return &muxResponseError.ResponseError{
			ProblemDetail: problem_detail.New(
				http.StatusUnauthorized,
				problem_detail_config.WithDetail("The challenge has expired."),
			),
			ClientError: err,
		}
	} else {
		return nil
	}
}
