package authorizer_request_parser

import (
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser/authorizer_request_parser_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
	altshiftCryptoInterfaces "github.com/altshiftab/utils_go/pkg/crypto/interfaces"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/jwt_extractor"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	"github.com/altshiftab/utils_go/pkg/interfaces/comparer"
	jwtAuthenticator "github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/authenticator"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/authenticator/authenticator_config"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claims/session_claims"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/validator/registered_claims_validator"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/validator/session_claims_validator"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/validator/setting"
	"github.com/altshiftab/utils_go/pkg/utils"
)

type Parser struct {
	JwtExtractor *jwt_extractor.Parser[request_parser.RequestParser[string]]

	AllowedRoles    []string
	AllowedTenantId string
	SuperAdminRoles []string

	verifier altshiftCryptoInterfaces.NamedVerifier
}

func (p *Parser) Parse(request *http.Request) (*session_token.Token, *response_error.ResponseError) {
	authenticatedJwtToken, responseError := p.JwtExtractor.Parse(request)
	if responseError != nil {
		return nil, responseError
	}
	if authenticatedJwtToken == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("authenticated jwt token")),
		}
	}

	payload := authenticatedJwtToken.Payload
	sessionClaims, err := session_claims.New(payload)
	if err != nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.New(fmt.Errorf("session claims new: %w", err), payload),
		}
	}
	if sessionClaims == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("session claims")),
		}
	}

	sessionToken, err := session_token.Parse(sessionClaims)
	if err != nil {
		wrappedErr := altshiftErrors.New(fmt.Errorf("session token new from session claims: %w", err), sessionClaims)
		if errors.Is(err, altshiftErrors.ErrParseError) {
			return nil, &response_error.ResponseError{
				ClientError: wrappedErr,
				ProblemDetail: problem_detail.New(
					http.StatusUnauthorized,
					problem_detail_config.WithDetail("Invalid token."),
				),
			}
		}
		return nil, &response_error.ResponseError{ServerError: wrappedErr}
	}
	if sessionToken == nil {
		return nil, &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("session token")),
		}
	}

	if superAdminRoles := p.SuperAdminRoles; len(superAdminRoles) != 0 {
		for _, role := range sessionToken.Roles {
			if slices.Contains(superAdminRoles, role) {
				return sessionToken, nil
			}
		}
	}

	var allowed bool

	if allowedTenantId := p.AllowedTenantId; allowedTenantId != "" {
		if sessionToken.TenantId != allowedTenantId {
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusForbidden,
					problem_detail_config.WithDetail("The session token's tenant id does not match the allowed tenant id."),
				),
			}
		}
	}

	if allowedRoles := p.AllowedRoles; len(allowedRoles) != 0 {
		for _, role := range sessionToken.Roles {
			if slices.Contains(p.AllowedRoles, role) {
				allowed = true
				break
			}
		}
	} else {
		allowed = true
	}

	if !allowed {
		return nil, &response_error.ResponseError{
			ProblemDetail: problem_detail.New(
				http.StatusForbidden,
				problem_detail_config.WithDetail("None of the session token's roles match the allowed roles."),
			),
		}
	}

	return sessionToken, nil
}

func (p *Parser) Verifier() altshiftCryptoInterfaces.NamedVerifier {
	return p.verifier
}

func New(
	verifier altshiftCryptoInterfaces.NamedVerifier,
	issuer string,
	audience string,
	options ...authorizer_request_parser_config.Option,
) (*Parser, error) {
	if utils.IsNil(verifier) {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("verifier"))
	}

	if issuer == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("issuer"))
	}

	if audience == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("audience"))
	}

	config := authorizer_request_parser_config.New(options...)

	expSetting := setting.Required
	if config.SkipExp {
		expSetting = setting.Skip
	}

	jwtExtractor, err := jwt_extractor.New(
		config.TokenExtractor,
		jwtAuthenticator.New(
			authenticator_config.WithSignatureVerifier(verifier),
			authenticator_config.WithClaimsValidator(
				&session_claims_validator.Validator{
					RegisteredClaimsValidator: &registered_claims_validator.Validator{
						Settings: map[string]setting.Setting{
							"iss": setting.Required,
							"aud": setting.Required,
							"sub": setting.Required,
							"exp": expSetting,
						},
						Expected: &registered_claims_validator.ExpectedClaims{
							IssuerComparer:   comparer.NewEqualComparer(issuer),
							AudienceComparer: comparer.NewEqualComparer(audience),
						},
					},
					Settings: map[string]setting.Setting{
						"amr":   setting.Required,
						"azp":   setting.Optional,
						"roles": setting.Required,
					},
				},
			),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("jwt extractor new: %w", err)
	}

	return &Parser{
		JwtExtractor:    jwtExtractor,
		AllowedRoles:    config.AllowedRoles,
		AllowedTenantId: config.AllowedTenantId,
		SuperAdminRoles: config.SuperAdminRoles,
		verifier:        verifier,
	}, nil
}
