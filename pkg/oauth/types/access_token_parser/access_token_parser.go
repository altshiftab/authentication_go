// Package access_token_parser is how a resource accepts the authorization server's access tokens:
// a request parser that takes a bearer token only of the server's type, signed with its key, for
// this resource and with the scope the resource requires.
//
// A request without one is answered as RFC 9728 has a resource answer it, with a challenge naming
// where the resource's metadata is -- which is how a client finds the authorization server to ask.
package access_token_parser

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/altshiftab/authentication_go/pkg/oauth/types/access_token"
	altshiftCryptoInterfaces "github.com/altshiftab/utils_go/pkg/crypto/interfaces"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	"github.com/altshiftab/utils_go/pkg/interfaces/comparer"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/authenticator"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/authenticator/authenticator_config"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/validator/header_validator"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/validator/registered_claims_validator"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/validator/setting"
	"github.com/altshiftab/utils_go/pkg/utils"
)

type Parser struct {
	authenticator       *authenticator.Authenticator
	requiredScope       string
	resourceMetadataUrl string
}

// New is a parser of tokens the issuer signed with the verifier's key for the resource. A token
// must have been granted requiredScope; resourceMetadataUrl is where the resource's metadata is,
// which every refusal names.
func New(
	verifier altshiftCryptoInterfaces.NamedVerifier,
	issuer string,
	resource string,
	requiredScope string,
	resourceMetadataUrl string,
) (*Parser, error) {
	if verifier == nil || utils.IsNil(verifier) {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("verifier"))
	}
	for name, value := range map[string]string{
		"issuer": issuer, "resource": resource, "required scope": requiredScope, "resource metadata url": resourceMetadataUrl,
	} {
		if value == "" {
			return nil, altshiftErrors.NewWithTrace(empty_error.New(name))
		}
	}

	return &Parser{
		authenticator: authenticator.New(
			authenticator_config.WithSignatureVerifier(verifier),
			authenticator_config.WithHeaderValidator(&header_validator.Validator{
				Settings: map[string]setting.Setting{"typ": setting.Required, "alg": setting.Required},
				Expected: &header_validator.ExpectedFields{
					Typ: comparer.NewEqualComparer(access_token.Type),
					Alg: comparer.NewEqualComparer(verifier.GetName()),
				},
			}),
			// iat and nbf are not held to a clock: exp bounds the token, and a resource's clock a moment
			// behind the server's would refuse a token minted a moment ago.
			authenticator_config.WithClaimsValidator(&registered_claims_validator.Validator{
				Settings: map[string]setting.Setting{
					"iss": setting.Required,
					"aud": setting.Required,
					"exp": setting.Required,
					"sub": setting.Required,
					"iat": setting.Skip,
					"nbf": setting.Skip,
				},
				Expected: &registered_claims_validator.ExpectedClaims{
					IssuerComparer:   comparer.NewEqualComparer(issuer),
					AudienceComparer: comparer.NewEqualComparer(resource),
				},
			}),
		),
		requiredScope:       requiredScope,
		resourceMetadataUrl: resourceMetadataUrl,
	}, nil
}

// challenge is the WWW-Authenticate value a refusal is answered with (RFC 6750 section 3, RFC 9728
// section 5.1): with an error code where a token was presented, without one where none was.
func (p *Parser) challenge(errorCode string, description string) string {
	parameters := []string{fmt.Sprintf("resource_metadata=%q", p.resourceMetadataUrl), fmt.Sprintf("scope=%q", p.requiredScope)}
	if errorCode != "" {
		parameters = append([]string{fmt.Sprintf("error=%q", errorCode), fmt.Sprintf("error_description=%q", description)}, parameters...)
	}
	return "Bearer " + strings.Join(parameters, ", ")
}

func (p *Parser) refuse(status int, errorCode string, description string, err error) *response_error.ResponseError {
	return &response_error.ResponseError{
		ClientError: err,
		ProblemDetail: problem_detail.New(
			status,
			problem_detail_config.WithDetail(description),
		),
		Headers: []*response.HeaderEntry{{Name: "WWW-Authenticate", Value: p.challenge(errorCode, description)}},
	}
}

func (p *Parser) Parse(request *http.Request) (*access_token.Token, *response_error.ResponseError) {
	if request == nil {
		return nil, &response_error.ResponseError{ServerError: altshiftErrors.NewWithTrace(nil_error.New("request"))}
	}

	authorization := request.Header.Get("Authorization")
	if authorization == "" {
		return nil, p.refuse(http.StatusUnauthorized, "", "An access token is required.", nil)
	}

	scheme, tokenString, found := strings.Cut(authorization, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(tokenString) == "" {
		return nil, p.refuse(
			http.StatusUnauthorized, "invalid_request", "The access token must be sent as a bearer token.",
			altshiftErrors.NewWithTrace(fmt.Errorf("%w: authorization scheme", altshiftErrors.ErrParseError)),
		)
	}

	authenticated, err := p.authenticator.Authenticate(request.Context(), strings.TrimSpace(tokenString))
	if err != nil {
		return nil, p.refuse(
			http.StatusUnauthorized, "invalid_token", "The access token is invalid.",
			altshiftErrors.New(fmt.Errorf("%w: authenticator authenticate: %w", altshiftErrors.ErrVerificationError, err)),
		)
	}
	if authenticated == nil {
		return nil, &response_error.ResponseError{ServerError: altshiftErrors.NewWithTrace(nil_error.New("authenticated token"))}
	}

	token, err := access_token.FromPayload(authenticated.Payload)
	if err != nil {
		return nil, p.refuse(
			http.StatusUnauthorized, "invalid_token", "The access token is invalid.",
			altshiftErrors.New(fmt.Errorf("%w: access token from payload: %w", altshiftErrors.ErrValidationError, err)),
		)
	}

	// A token bound to a key is presented with a proof of it (RFC 9449), which this parser does not
	// take; as a bearer token it is refused, so that a copy of it is worth nothing.
	if token.KeyThumbprint != "" {
		return nil, p.refuse(
			http.StatusUnauthorized, "invalid_token", "The access token is bound to a key.",
			altshiftErrors.NewWithTrace(fmt.Errorf("%w: a bound token as a bearer token", altshiftErrors.ErrVerificationError)),
		)
	}

	if !token.HasScope(p.requiredScope) {
		return nil, p.refuse(
			http.StatusForbidden, "insufficient_scope", "The access token does not grant the scope required.",
			altshiftErrors.NewWithTrace(fmt.Errorf("%w: scope", altshiftErrors.ErrVerificationError)),
		)
	}

	return token, nil
}
