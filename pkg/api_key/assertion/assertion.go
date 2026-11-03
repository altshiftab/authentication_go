// Package assertion verifies what a client signs to mint a token: a short-lived JWT, signed by the
// private half of a key the account registered, saying which key is asking and what it is asking of.
//
// The shape is RFC 7523's client assertion, which every JOSE library and every service-account flow
// already speaks, and it takes one request: the client signs a statement with a lifetime and an
// identifier of its own, rather than fetching a challenge to sign. A challenge would buy freshness
// that the expiry already bounds and the remembered identifier already enforces, at the price of an
// unauthenticated endpoint handing out state to anyone who asks for it.
package assertion

import (
	"fmt"
	"time"

	"github.com/altshiftab/authentication_go/pkg/api_key/public_key"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/interfaces/comparer"
	altshiftJwtToken "github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/token"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/token/authenticated_token"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/token/authenticated_token/authenticated_token_config"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/validator"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/validator/header_validator"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/validator/registered_claims_validator"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/validator/setting"
	"github.com/altshiftab/utils_go/pkg/utils"
)

// Type is what an assertion must say it is, in the JWS header.
//
// It is what keeps the two kinds of token this service handles apart in the one place where they
// could otherwise meet: a session token signed by the service, whose signing key somebody had
// registered as their own API key, would verify as a signature and then be read as a mint request.
// It carries no "typ" of this kind, so it is refused before its claims are looked at.
const Type = "api-key+jwt"

// Lifetime is the longest an assertion may be presentable for. Short because it needs to survive
// only the one request it is made for, and because every second of it is a second in which a copy
// taken off the wire is as good as the original.
const Lifetime = 5 * time.Minute

// Leeway is what a client's clock may be out by, in either direction.
//
// Applied by hand, because the claims validator compares times exactly: left to it, an assertion
// issued a second into the future would be a forgery and one written by a runner whose clock is a
// minute behind would arrive already expired. Neither is, and both happen.
const Leeway = 60 * time.Second

// Assertion is a verified mint request: which key made it, and what identifies it.
//
// It carries no expiry. How long the identifier has to be remembered is decided where the record is
// written, from the server's own clock; what a client writes in "exp" says whether the assertion is
// still presentable, and nothing past that.
type Assertion struct {
	KeyId string
	Jti   string
}

// Subject reads the "sub" of an assertion without verifying anything, which is how the key it
// claims to be from is looked up.
//
// Nothing about the token is trusted at this point. What comes back is used to fetch a key, and the
// signature is then checked against that stored key: a key the token itself carried would let
// anyone mint for any subject by bringing their own.
func Subject(tokenString string) (string, error) {
	if tokenString == "" {
		return "", altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, empty_error.New("token string")),
		)
	}

	token, err := altshiftJwtToken.New(tokenString)
	if err != nil {
		return "", altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: jwt token new: %w", altshiftErrors.ErrParseError, err),
		)
	}
	if token == nil {
		return "", altshiftErrors.NewWithTrace(nil_error.New("jwt token"))
	}

	subject, err := utils.MapGetConvert[string](token.Payload, "sub")
	if err != nil {
		return "", altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the assertion names no key: %w", altshiftErrors.ErrValidationError, err),
		)
	}
	if subject == "" {
		return "", altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, empty_error.New("subject")),
		)
	}

	return subject, nil
}

/*
 * Verify checks an assertion against a key that was registered, and returns what the caller needs
 * to stop it being presented twice.
 *
 * What is checked, and why each of them:
 *
 *   - the signature, by a verifier built from the stored key, whose name is the algorithm the key
 *     was registered as -- so an assertion whose header names another algorithm is refused rather
 *     than verified under one;
 *   - "typ", so that no other token this service signs or accepts can be presented here;
 *   - "sub", the key's id, so an assertion made for one key cannot be replayed under another's
 *     lookup -- and "iss", the same id, where a client sends it, which RFC 7523 says to do and
 *     which adds nothing "sub" has not already settled;
 *   - "aud", where a client sends one, the service's own origin -- so an assertion made for the
 *     development service cannot be presented to the production one;
 *   - "iat" and "nbf", where a client sends them, neither in the future: an assertion cannot have
 *     been made later than it arrived, nor say it is not yet usable and be used;
 *   - "exp", required, inside the lifetime, so a captured assertion stops working; and
 *   - "jti", required, which is what the caller then remembers for as long as an assertion can be
 *     presented for.
 *
 * Only "sub", "exp" and "jti" have to be there. The rest are checked when they are there and not
 * missed when they are not, which is a weaker rule than it sounds: every claim is inside what was
 * signed, so leaving one out is open to the key's holder alone. Whoever captures an assertion can
 * relay it but cannot edit it -- strip a claim and the signature no longer verifies. A client that
 * omits "aud" gives up deployment binding for its own assertions and for nobody else's.
 */
func Verify(
	tokenString string,
	key *public_key.Key,
	audience string,
	now time.Time,
) (*Assertion, error) {
	if tokenString == "" {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, empty_error.New("token string")),
		)
	}

	if key == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("key"))
	}

	if audience == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("audience"))
	}

	verifier, err := key.NamedVerifier()
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("named verifier: %w", err), key.Id)
	}

	tokenValidator := &validator.Validator{
		HeaderValidator: &header_validator.Validator{
			Settings: map[string]setting.Setting{
				"alg": setting.Required,
				"typ": setting.Required,
			},
			Expected: &header_validator.ExpectedFields{
				Alg: comparer.NewEqualComparer(key.Algorithm),
				Typ: comparer.NewEqualComparer(Type),
			},
		},
		PayloadValidator: &registered_claims_validator.Validator{
			Settings: map[string]setting.Setting{
				"sub": setting.Required,
				"jti": setting.Required,
				// Optional in the sense that they may be absent, not in the sense that they are
				// waved through. Absence is a choice only the key's holder can make, because every
				// claim here is inside what was signed: whoever captures an assertion can relay it,
				// but cannot take a claim out of it without breaking the signature. So a client
				// that omits one gives up what it buys for its own assertions and for nobody
				// else's, and one that sends it is held to it.
				"iss": setting.Optional,
				"aud": setting.Optional,
				// The times are checked below rather than here, because the validator compares them
				// exactly and Leeway is the whole point. "exp" is required all the same -- its
				// presence is enforced where its window is.
				"exp": setting.Skip,
				"iat": setting.Skip,
				"nbf": setting.Skip,
			},
			Expected: &registered_claims_validator.ExpectedClaims{
				IssuerComparer:   comparer.NewEqualComparer(key.Id),
				SubjectComparer:  comparer.NewEqualComparer(key.Id),
				AudienceComparer: comparer.NewEqualComparer(audience),
			},
		},
	}

	authenticatedToken, err := authenticated_token.New(
		tokenString,
		authenticated_token_config.WithSignatureVerifier(verifier),
		authenticated_token_config.WithTokenValidator(tokenValidator),
	)
	if err != nil {
		return nil, altshiftErrors.New(
			fmt.Errorf("%w: authenticated token new: %w", altshiftErrors.ErrVerificationError, err),
			key.Id,
		)
	}
	if authenticatedToken == nil || authenticatedToken.Token == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("authenticated token"))
	}

	payload := authenticatedToken.Payload

	expiresAtSeconds, err := utils.MapGetConvert[float64](payload, "exp")
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: map get convert (exp): %w", altshiftErrors.ErrValidationError, err),
		)
	}
	expiresAt := time.Unix(int64(expiresAtSeconds), 0)

	if !expiresAt.After(now.Add(-Leeway)) {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the assertion has expired", altshiftErrors.ErrVerificationError),
		)
	}

	// An assertion good for longer than the lifetime is one a copy of stays useful for longer, so
	// the window is enforced here rather than left to whatever the client chose to write.
	if expiresAt.After(now.Add(Lifetime + Leeway)) {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf(
				"%w: the assertion expires more than %s from now",
				altshiftErrors.ErrValidationError,
				Lifetime,
			),
		)
	}

	if issuedAtSeconds, err := utils.MapGetConvert[float64](payload, "iat"); err == nil {
		if issuedAt := time.Unix(int64(issuedAtSeconds), 0); issuedAt.After(now.Add(Leeway)) {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: the assertion is issued in the future", altshiftErrors.ErrValidationError),
			)
		}
	}

	// Nothing here needs a "nbf", and a client that writes one is still held to it: an assertion
	// saying it is not yet usable is not usable, whatever else about it checks out.
	if notBeforeSeconds, err := utils.MapGetConvert[float64](payload, "nbf"); err == nil {
		if notBefore := time.Unix(int64(notBeforeSeconds), 0); notBefore.After(now.Add(Leeway)) {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: the assertion is not yet usable", altshiftErrors.ErrValidationError),
			)
		}
	}

	jti, err := utils.MapGetConvert[string](payload, "jti")
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: map get convert (jti): %w", altshiftErrors.ErrValidationError, err),
		)
	}
	if jti == "" {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, empty_error.New("jti")),
		)
	}

	// Bounded because it is stored until the assertion can no longer be presented, and an identifier
	// is only there to be compared: nothing needs it to be long.
	const maximumJtiLength = 256
	if len(jti) > maximumJtiLength {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the assertion's jti is too long", altshiftErrors.ErrValidationError),
		)
	}

	return &Assertion{KeyId: key.Id, Jti: jti}, nil
}
