package authorizer_request_parser

import (
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/altshiftab/authentication_go/pkg/dpop"
	dpopErrors "github.com/altshiftab/authentication_go/pkg/dpop/errors"
	"github.com/altshiftab/authentication_go/pkg/dpop/types/proof_verifier"
	sessionErrors "github.com/altshiftab/authentication_go/pkg/session/errors"
	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser/authorizer_request_parser_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
	altshiftCryptoInterfaces "github.com/altshiftab/utils_go/pkg/crypto/interfaces"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/jwt_extractor"
	muxResponse "github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	"github.com/altshiftab/utils_go/pkg/interfaces/comparer"
	jwtAuthenticator "github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/authenticator"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/authenticator/authenticator_config"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/validator/registered_claims_validator"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/validator/session_claims_validator"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/validator/setting"
	"github.com/altshiftab/utils_go/pkg/utils"
)

type Parser struct {
	// JwtExtractor verifies the token's signature and claims, and nothing more: calling it directly
	// rather than through Parse skips the binding a DPoP-bound token is held to, and the roles.
	JwtExtractor *jwt_extractor.Parser[request_parser.RequestParser[string]]

	AllowedRoles    []string
	AllowedTenantId string
	SuperAdminRoles []string

	verifier          altshiftCryptoInterfaces.NamedVerifier
	proofVerifier     *proof_verifier.Verifier
	requireBoundToken bool
}

// SchemeReporter is implemented by a token extractor that reads an HTTP authentication scheme, so
// that the authorizer can tell a token presented as DPoP from one presented as Bearer or in a
// cookie. dpop/types/token_extractor is one; an extractor that is not reports no scheme, and a bound
// token reaching the authorizer through it is refused.
type SchemeReporter interface {
	Scheme(request *http.Request) string
}

// challenger is implemented by a token extractor that renders the WWW-Authenticate value a refusal
// answers with. A cookie has no challenge to give, and its extractor none to render.
type challenger interface {
	Challenge(errorCode string, errorDescription string) string
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
	sessionToken, err := session_token.ParsePayload(payload)
	if err != nil {
		wrappedErr := altshiftErrors.New(fmt.Errorf("session token parse payload: %w", err), payload)
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

	// Before the roles: a token held to a key it was not presented with is not authenticated, and
	// is answered 401 rather than told what it would have been allowed.
	if responseError := p.checkBinding(request, authenticatedJwtToken.Raw(), sessionToken); responseError != nil {
		return nil, responseError
	}

	if err := p.Admits(sessionToken.Roles, sessionToken.TenantId); err != nil {
		if errors.Is(err, sessionErrors.ErrTenantNotAllowed) {
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusForbidden,
					problem_detail_config.WithDetail("The session token's tenant id does not match the allowed tenant id."),
				),
			}
		}
		if errors.Is(err, sessionErrors.ErrRolesNotAllowed) {
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusForbidden,
					problem_detail_config.WithDetail("None of the session token's roles match the allowed roles."),
				),
			}
		}
		return nil, &response_error.ResponseError{ServerError: fmt.Errorf("admits: %w", err)}
	}

	return sessionToken, nil
}

// Admits reports whether a holder of roles, in the tenant tenantId, is one this parser lets
// through: a super admin role admits outright, and otherwise the tenant must be the allowed one
// and one of the roles an allowed one, where either is required at all. The refusals are
// errors.ErrTenantNotAllowed and errors.ErrRolesNotAllowed.
//
// Parse asks it of what a token claims. It is exported so that the same decision can be asked of
// what an account is now, which may no longer be what its token says.
func (p *Parser) Admits(roles []string, tenantId string) error {
	if superAdminRoles := p.SuperAdminRoles; len(superAdminRoles) != 0 {
		for _, role := range roles {
			if slices.Contains(superAdminRoles, role) {
				return nil
			}
		}
	}

	if allowedTenantId := p.AllowedTenantId; allowedTenantId != "" && tenantId != allowedTenantId {
		return sessionErrors.ErrTenantNotAllowed
	}

	if allowedRoles := p.AllowedRoles; len(allowedRoles) != 0 {
		for _, role := range roles {
			if slices.Contains(allowedRoles, role) {
				return nil
			}
		}
		return sessionErrors.ErrRolesNotAllowed
	}

	return nil
}

/*
 * checkBinding holds a token to the key it is bound to, if any (RFC 9449 §7).
 *
 * Two rules, and only the second is a setting:
 *
 *   - A bound token is accepted under the DPoP scheme, with a proof by its key made for this
 *     request, and in no other way. Presented as Bearer, or in a cookie, it is refused (§7.2): that
 *     is the whole of what makes the binding worth having, since an authorizer that took it as a
 *     bearer token would take a stolen copy too. This holds for every authorizer, whatever its
 *     extractor -- one that reports no scheme reports no DPoP either -- so no path through the
 *     library reads a bound token without its proof.
 *   - An unbound token under the DPoP scheme is refused (§7.1 asks for a token bound to the proof's
 *     key, which it cannot be). Outside that scheme it is accepted, unless the authorizer was built
 *     to require bound tokens.
 *
 * accessToken is the token as the client sent it, which the proof's "ath" is a hash of.
 */
func (p *Parser) checkBinding(
	request *http.Request,
	accessToken string,
	sessionToken *session_token.Token,
) *response_error.ResponseError {
	var scheme string
	if reporter, ok := p.tokenExtractor().(SchemeReporter); ok && !utils.IsNil(reporter) {
		scheme = reporter.Scheme(request)
	}

	keyThumbprint := sessionToken.KeyThumbprint

	if scheme != dpop.Scheme {
		if keyThumbprint != "" {
			return p.refusal(
				dpop.ErrorInvalidToken,
				"The token is bound to a key and must be presented with the DPoP scheme.",
				altshiftErrors.NewWithTrace(
					fmt.Errorf(
						"%w: a bound token was presented without the dpop scheme",
						altshiftErrors.ErrVerificationError,
					),
					scheme, keyThumbprint,
				),
			)
		}

		if p.requireBoundToken {
			return p.refusal(
				dpop.ErrorInvalidToken,
				"A key-bound token is required.",
				altshiftErrors.NewWithTrace(
					fmt.Errorf("%w: the token is bound to no key", altshiftErrors.ErrVerificationError),
					scheme,
				),
			)
		}

		return nil
	}

	if keyThumbprint == "" {
		return p.refusal(
			dpop.ErrorInvalidToken,
			"The token is not bound to a key.",
			altshiftErrors.NewWithTrace(
				fmt.Errorf(
					"%w: an unbound token was presented with the dpop scheme",
					altshiftErrors.ErrVerificationError,
				),
			),
		)
	}

	proofVerifier := p.proofVerifier
	if proofVerifier == nil {
		// New refuses an extractor that reads the scheme without a verifier to check it, so this is a
		// parser assembled by hand.
		return &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("proof verifier")),
		}
	}

	if _, err := proofVerifier.VerifyRequest(request.Context(), request, accessToken, keyThumbprint); err != nil {
		wrappedErr := altshiftErrors.New(fmt.Errorf("proof verifier verify request: %w", err), keyThumbprint)

		switch {
		case errors.Is(err, dpopErrors.ErrMissingProof):
			return p.refusal(dpop.ErrorInvalidDpopProof, "A DPoP proof is required.", wrappedErr)
		case errors.Is(err, dpopErrors.ErrMultipleProofs):
			return p.refusal(dpop.ErrorInvalidDpopProof, "Multiple DPoP proofs.", wrappedErr)
		case errors.Is(err, dpopErrors.ErrReplayedProof):
			return p.refusal(dpop.ErrorInvalidDpopProof, "The DPoP proof has already been used.", wrappedErr)
		case errors.Is(err, dpopErrors.ErrKeyMismatch):
			// A token error, as RFC 9449 §7.1 answers a failed binding (its Figure 16): the proof may
			// be sound and the token the one at fault, and a client told so gets a token for its key
			// rather than retrying proofs that can never match.
			return p.refusal(dpop.ErrorInvalidToken, "The token is bound to another key.", wrappedErr)
		case altshiftErrors.IsAny(
			err,
			altshiftErrors.ErrParseError,
			altshiftErrors.ErrValidationError,
			altshiftErrors.ErrVerificationError,
		):
			return p.refusal(dpop.ErrorInvalidDpopProof, "The DPoP proof is not valid.", wrappedErr)
		default:
			return &response_error.ResponseError{ServerError: wrappedErr}
		}
	}

	return nil
}

// refusal is a 401 for a credential refused, with the challenge the extractor renders for it.
func (p *Parser) refusal(errorCode string, detail string, err error) *response_error.ResponseError {
	responseError := &response_error.ResponseError{
		ProblemDetail: problem_detail.New(
			http.StatusUnauthorized,
			problem_detail_config.WithDetail(detail),
		),
		ClientError: err,
	}

	if challenger, ok := p.tokenExtractor().(challenger); ok && !utils.IsNil(challenger) {
		if value := challenger.Challenge(errorCode, detail); value != "" {
			responseError.Headers = append(
				responseError.Headers,
				&muxResponse.HeaderEntry{Name: dpop.WwwAuthenticateHeaderName, Value: value},
			)
		}
	}

	return responseError
}

func (p *Parser) tokenExtractor() request_parser.RequestParser[string] {
	if p.JwtExtractor == nil {
		return nil
	}
	return p.JwtExtractor.TokenExtractor
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

	// Both refused here, at startup, rather than at the first request that would find out: an
	// authorizer that requires bound tokens, or reads the DPoP scheme, with nothing to check a proof
	// would refuse every such token, and look like working code until one arrived.
	if config.ProofVerifier == nil {
		if config.RequireBoundToken {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("bound tokens are required and nothing would check their proofs: %w", nil_error.New("proof verifier")),
			)
		}
		if _, ok := config.TokenExtractor.(SchemeReporter); ok {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("the token extractor reads the dpop scheme and nothing would check its proofs: %w", nil_error.New("proof verifier")),
			)
		}
	}

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
					// How the holder came by the token is part of what the token is authorized
					// for, not merely something it reports: an authorizer built for browser
					// sessions refuses a token minted against a registered key, and one built for
					// those keys refuses a session cookie presented as a bearer token. Neither
					// needs a separate audience to say so.
					Expected: &session_claims_validator.ExpectedClaims{
						AuthenticationMethodsComparer: comparer.NewEqualComparer(
							config.AuthenticationMethods...,
						),
					},
				},
			),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("jwt extractor new: %w", err)
	}

	return &Parser{
		JwtExtractor:      jwtExtractor,
		AllowedRoles:      config.AllowedRoles,
		AllowedTenantId:   config.AllowedTenantId,
		SuperAdminRoles:   config.SuperAdminRoles,
		verifier:          verifier,
		proofVerifier:     config.ProofVerifier,
		requireBoundToken: config.RequireBoundToken,
	}, nil
}
