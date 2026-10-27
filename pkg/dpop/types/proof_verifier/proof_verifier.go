// Package proof_verifier checks a DPoP proof (RFC 9449 §4.3): that it was made, just now, for this
// request, by the key the token it comes with is bound to.
//
// Verification is stateless unless a replay detector is configured. Everything a check needs is in
// the request or was configured at startup: the proof carries its key, the token carries the
// thumbprint of the key it is bound to, and the issuer's signature on the token is what makes that
// thumbprint worth trusting. Nothing is looked up.
package proof_verifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/subtle"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/altshiftab/authentication_go/pkg/dpop"
	dpopErrors "github.com/altshiftab/authentication_go/pkg/dpop/errors"
	"github.com/altshiftab/authentication_go/pkg/dpop/types/proof_key"
	"github.com/altshiftab/authentication_go/pkg/dpop/types/proof_verifier/proof_verifier_config"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/mismatch_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	altshiftJwtToken "github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/token"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/token/authenticated_token"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/token/authenticated_token/authenticated_token_config"
	"github.com/altshiftab/utils_go/pkg/utils"
)

// Input is what a proof is checked against.
type Input struct {
	// Proof is the DPoP header's value.
	Proof string

	// Method is the request's method, which "htm" must name exactly.
	Method string

	// Url is the request's URL. Only its path is read: the scheme and host a proof may name are the
	// verifier's configured origins, never what the request says about itself.
	Url *url.URL

	// AccessToken is the token the proof is sent with, exactly as the client sent it, which "ath"
	// must hash to. It is empty at a token endpoint, where there is no token yet and a proof that
	// carries "ath" -- one made for a resource request -- is refused.
	AccessToken string

	// KeyThumbprint is the "cnf.jkt" of the token, which the proof's key must have. It is empty
	// where nothing is bound yet, as at a token endpoint about to bind a token to the proof's key.
	KeyThumbprint string
}

// Proof is a verified proof: which key made it, and what it said.
type Proof struct {
	// KeyThumbprint is the RFC 7638 thumbprint of the proof's key: what a token endpoint writes into
	// the token it mints as "cnf.jkt".
	KeyThumbprint string

	// PublicKey is the proof's key, for an endpoint that registers the key it is binding to and
	// would otherwise have to parse the header a second time.
	PublicKey *ecdsa.PublicKey

	Id       string
	IssuedAt *time.Time

	// Nonce is the proof's "nonce", when it carries one. Nothing issues nonces yet; it is passed on
	// so that checking one later needs no change here.
	Nonce string
}

type Verifier struct {
	origins []string
	config  *proof_verifier_config.Config
}

/*
 * Verify checks a proof against what it must have been made for, and returns which key made it.
 *
 * In order, and why each:
 *
 *   - the length, before anything parses it;
 *   - "typ", so that no other JWT -- an access token, a client assertion -- is read as a proof;
 *   - "alg", which must be ES256, so that "none" and the symmetric algorithms are refused by name
 *     rather than by whatever a later step happens to make of them;
 *   - "jwk", a P-256 public key and nothing more (proof_key says what that excludes);
 *   - the key's thumbprint against the token's binding, where there is one. Before the signature,
 *     because it costs nothing to say -- the thumbprint is in a token the caller already holds --
 *     and a proof by the wrong key is refused whatever its signature says;
 *   - the signature, under the key in "jwk";
 *   - "htm" and "htu", the request the proof was made for: this method, at one of this service's
 *     origins, on this path. The query and fragment are not part of it (RFC 9449 §4.2);
 *   - "iat", inside the window: no older than the maximum age and no further ahead than the clock
 *     skew. This is the one thing RFC 9449 §11.1 requires of a stateless server;
 *   - "jti", present and bounded;
 *   - "ath", the token's hash, where the proof comes with a token, and absent where it does not;
 *   - and last, if one is configured, the replay detector -- last so that only a proof that would
 *     otherwise be accepted is stored.
 */
func (v *Verifier) Verify(ctx context.Context, input *Input, now time.Time) (*Proof, error) {
	if v == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("verifier"))
	}

	config := v.config
	if config == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("verifier config"))
	}

	if input == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("input"))
	}

	requestUrl := input.Url
	if requestUrl == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("request url"))
	}

	proofString := input.Proof
	if proofString == "" {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, empty_error.New("proof")),
		)
	}

	if len(proofString) > config.MaxProofLength {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf(
				"%w: the proof is longer than %d bytes",
				altshiftErrors.ErrValidationError, config.MaxProofLength,
			),
		)
	}

	token, err := altshiftJwtToken.New(proofString)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: jwt token new: %w", altshiftErrors.ErrParseError, err),
		)
	}
	if token == nil || token.Header == nil || token.Payload == nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the proof has no header or no payload", altshiftErrors.ErrParseError),
		)
	}

	header := token.Header

	typ, err := utils.MapGetConvert[string](header, "typ")
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: map get convert (typ): %w", altshiftErrors.ErrValidationError, err),
		)
	}
	// A media type, and those are compared without regard to case (RFC 7515 §4.1.9).
	if !strings.EqualFold(typ, dpop.Type) {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, mismatch_error.New("typ", typ, dpop.Type)),
		)
	}

	alg, err := utils.MapGetConvert[string](header, "alg")
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: map get convert (alg): %w", altshiftErrors.ErrValidationError, err),
		)
	}
	if alg != dpop.Algorithm {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, mismatch_error.New("alg", alg, dpop.Algorithm)),
		)
	}

	jwk, err := utils.MapGetConvert[map[string]any](header, "jwk")
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: map get convert (jwk): %w", altshiftErrors.ErrValidationError, err),
		)
	}

	key, err := proof_key.Parse(jwk)
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("proof key parse: %w", err))
	}
	if key == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("proof key"))
	}

	if expected := input.KeyThumbprint; expected != "" && key.Thumbprint != expected {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrVerificationError, dpopErrors.ErrKeyMismatch),
			key.Thumbprint, expected,
		)
	}

	verifier, err := key.NamedVerifier()
	if err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("proof key named verifier: %w", err), key.Thumbprint)
	}

	// The signature only. The default validator checks "iat" against the process's own clock with no
	// leeway at all, so a client whose clock is a second ahead would be refused there; the claims are
	// checked below instead, against the window.
	if _, err := authenticated_token.New(
		proofString,
		authenticated_token_config.WithSignatureVerifier(verifier),
		authenticated_token_config.WithTokenValidator(nil),
	); err != nil {
		return nil, altshiftErrors.New(
			fmt.Errorf("%w: authenticated token new: %w", altshiftErrors.ErrVerificationError, err),
			key.Thumbprint,
		)
	}

	payload := token.Payload

	htm, err := utils.MapGetConvert[string](payload, "htm")
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: map get convert (htm): %w", altshiftErrors.ErrValidationError, err),
		)
	}
	// Methods are case-sensitive (RFC 9110 §9.1): "get" is not GET.
	if htm != input.Method {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, mismatch_error.New("htm", htm, input.Method)),
		)
	}

	htu, err := utils.MapGetConvert[string](payload, "htu")
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: map get convert (htu): %w", altshiftErrors.ErrValidationError, err),
		)
	}
	if err := v.matchTargetUri(htu, requestUrl); err != nil {
		return nil, altshiftErrors.New(fmt.Errorf("match target uri: %w", err), htu)
	}

	issuedAtSeconds, err := utils.MapGetConvert[float64](payload, "iat")
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: map get convert (iat): %w", altshiftErrors.ErrValidationError, err),
		)
	}

	// Compared as seconds, before anything converts the claim to a time: a value far out of range
	// would otherwise overflow on the way and could land inside the window.
	nowSeconds := float64(now.UnixNano()) / float64(time.Second)
	if issuedAtSeconds < nowSeconds-(config.MaxAge+config.ClockSkew).Seconds() {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the proof is too old", altshiftErrors.ErrValidationError),
			issuedAtSeconds,
		)
	}
	if issuedAtSeconds > nowSeconds+config.ClockSkew.Seconds() {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the proof is issued in the future", altshiftErrors.ErrValidationError),
			issuedAtSeconds,
		)
	}
	wholeSeconds, fraction := math.Modf(issuedAtSeconds)
	issuedAt := time.Unix(int64(wholeSeconds), int64(fraction*float64(time.Second)))

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
	if len(jti) > config.MaxIdLength {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the proof's jti is too long", altshiftErrors.ErrValidationError),
		)
	}

	ath, hasAth := payload["ath"]
	if accessToken := input.AccessToken; accessToken != "" {
		athString, ok := ath.(string)
		if !hasAth || !ok {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: the proof names no access token", altshiftErrors.ErrValidationError),
			)
		}
		if subtle.ConstantTimeCompare([]byte(athString), []byte(dpop.AccessTokenHash(accessToken))) != 1 {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: the proof was made for another access token", altshiftErrors.ErrValidationError),
			)
		}
	} else if hasAth {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf(
				"%w: the proof names an access token where there is none",
				altshiftErrors.ErrValidationError,
			),
		)
	}

	var nonce string
	if value, ok := payload["nonce"]; ok {
		nonce, ok = value.(string)
		if !ok {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: the proof's nonce is not a string", altshiftErrors.ErrValidationError),
			)
		}
	}

	if replayDetector := config.ReplayDetector; !utils.IsNil(replayDetector) {
		// The proof stops being acceptable once its "iat" falls out of the window, which is when it
		// stops being worth remembering.
		expiresAt := issuedAt.Add(config.MaxAge + config.ClockSkew)
		seen, err := replayDetector.Observe(ctx, key.Thumbprint, jti, now, expiresAt)
		if err != nil {
			// The store's fault, not the client's, and so not wrapped as a client error: a service
			// that cannot tell whether a proof is a replay answers 500 rather than guess.
			return nil, altshiftErrors.New(fmt.Errorf("replay detector observe: %w", err), key.Thumbprint)
		}
		if seen {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: %w", altshiftErrors.ErrVerificationError, dpopErrors.ErrReplayedProof),
				key.Thumbprint,
			)
		}
	}

	return &Proof{
		KeyThumbprint: key.Thumbprint,
		PublicKey:     key.PublicKey,
		Id:            jti,
		IssuedAt:      &issuedAt,
		Nonce:         nonce,
	}, nil
}

// VerifyRequest is Verify for the proof a request carries, made for that request now.
//
// A request carrying no DPoP header gives ErrMissingProof, so that a token endpoint can tell a
// client that asked for a bound token from one that did not; one carrying more than one gives
// ErrMultipleProofs (RFC 9449 §4.3). Both are wrapped as ErrValidationError.
func (v *Verifier) VerifyRequest(
	ctx context.Context,
	request *http.Request,
	accessToken string,
	keyThumbprint string,
) (*Proof, error) {
	if request == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("request"))
	}

	values := request.Header.Values(dpop.HeaderName)
	switch len(values) {
	case 0:
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, dpopErrors.ErrMissingProof),
		)
	case 1:
	default:
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, dpopErrors.ErrMultipleProofs),
		)
	}

	proof, err := v.Verify(
		ctx,
		&Input{
			Proof:         values[0],
			Method:        request.Method,
			Url:           request.URL,
			AccessToken:   accessToken,
			KeyThumbprint: keyThumbprint,
		},
		time.Now(),
	)
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}

	return proof, nil
}

// matchTargetUri checks a proof's "htu" against the request: one of the configured origins, and the
// request's path. Compared after syntax-based normalisation (RFC 3986 §6.2.2) -- scheme and host
// without regard to case, a scheme's default port the same as none, the path as normalizePath has
// it -- so that two spellings of one URI are one URI and two URIs are never one.
func (v *Verifier) matchTargetUri(htu string, requestUrl *url.URL) error {
	parsed, err := url.Parse(htu)
	if err != nil {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: url parse (htu): %w", altshiftErrors.ErrValidationError, err),
		)
	}
	if parsed == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("parsed htu"))
	}
	if !parsed.IsAbs() || parsed.Opaque != "" || parsed.User != nil {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the htu is not an absolute http uri", altshiftErrors.ErrValidationError),
		)
	}

	origin, err := makeOrigin(parsed)
	if err != nil {
		return altshiftErrors.New(fmt.Errorf("make origin (htu): %w", err))
	}
	if !slices.Contains(v.origins, origin) {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the htu names another origin", altshiftErrors.ErrValidationError),
			origin,
		)
	}

	if requestUrl == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("request url"))
	}

	if path, want := normalizePath(parsed.EscapedPath()), normalizePath(requestUrl.EscapedPath()); path != want {
		return altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, mismatch_error.New("htu path", path, want)),
		)
	}

	return nil
}

// normalizePath is an escaped path after RFC 3986's syntax-based normalisation: the hexadecimal
// digits of a percent-encoding in upper case (§6.2.2.1), and an unreserved character that was
// percent-encoded decoded (§6.2.2.2). Every other encoding is kept, so that "a%2Fb", one segment,
// is not "a/b", two: a router tells them apart, and a proof for one must not be good for the other.
// An empty path is "/".
func normalizePath(escapedPath string) string {
	if escapedPath == "" {
		return "/"
	}

	var builder strings.Builder
	for i := 0; i < len(escapedPath); i++ {
		if escapedPath[i] == '%' && i+2 < len(escapedPath) {
			if value, err := strconv.ParseUint(escapedPath[i+1:i+3], 16, 8); err == nil {
				if character := byte(value); isUnreserved(character) {
					builder.WriteByte(character)
				} else {
					builder.WriteByte('%')
					builder.WriteString(strings.ToUpper(escapedPath[i+1 : i+3]))
				}
				i += 2
				continue
			}
		}
		builder.WriteByte(escapedPath[i])
	}

	return builder.String()
}

// isUnreserved is RFC 3986 §2.3's unreserved set: letters, digits, and "-._~".
func isUnreserved(character byte) bool {
	switch {
	case 'a' <= character && character <= 'z', 'A' <= character && character <= 'Z', '0' <= character && character <= '9':
		return true
	default:
		return strings.IndexByte("-._~", character) >= 0
	}
}

// makeOrigin is a URL's scheme and authority as a proof's "htu" is compared by them: lowercased
// (RFC 3986 §6.2.2.1), with the scheme's default port dropped (§6.2.3).
func makeOrigin(parsed *url.URL) (string, error) {
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the scheme is not http or https", altshiftErrors.ErrValidationError),
			scheme,
		)
	}

	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return "", altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, empty_error.New("host")),
		)
	}
	if strings.Contains(hostname, ":") {
		hostname = "[" + hostname + "]"
	}

	port := parsed.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		hostname += ":" + port
	}

	return new(url.URL{Scheme: scheme, Host: hostname}).String(), nil
}

// New makes a verifier for proofs made for the given origins: the scheme and host, and port where
// it is not the default, at which clients reach the service, such as "https://api.example.com".
//
// The origins are configured rather than read from the request because the request's own account
// of where it was sent -- Host, X-Forwarded-Host -- is the client's to write, and behind a load
// balancer or Firebase Hosting it is not the address the client signed for in any case. More than
// one is for a service reached at several addresses. A service mounted under a path prefix that a
// proxy strips is not provided for: the path is compared as the service receives it.
func New(origins []string, options ...proof_verifier_config.Option) (*Verifier, error) {
	if len(origins) == 0 {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("origins"))
	}

	normalizedOrigins := make([]string, 0, len(origins))
	for _, origin := range origins {
		parsed, err := url.Parse(origin)
		if err != nil {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("url parse (origin): %w", err), origin)
		}
		if parsed == nil {
			return nil, altshiftErrors.NewWithTrace(nil_error.New("parsed origin"))
		}
		if parsed.Opaque != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery ||
			parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
			return nil, altshiftErrors.NewWithTrace(
				fmt.Errorf("%w: an origin is a scheme and a host, and nothing else", altshiftErrors.ErrValidationError),
				origin,
			)
		}

		normalizedOrigin, err := makeOrigin(parsed)
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("make origin: %w", err), origin)
		}
		normalizedOrigins = append(normalizedOrigins, normalizedOrigin)
	}

	config := proof_verifier_config.New(options...)
	if config.MaxAge <= 0 {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the maximum age is not positive", altshiftErrors.ErrValidationError),
			config.MaxAge,
		)
	}
	if config.ClockSkew < 0 {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: the clock skew is negative", altshiftErrors.ErrValidationError),
			config.ClockSkew,
		)
	}

	return &Verifier{origins: normalizedOrigins, config: config}, nil
}
