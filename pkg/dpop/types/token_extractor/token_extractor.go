// Package token_extractor reads an access token from "Authorization: DPoP" and, unless told
// otherwise, "Authorization: Bearer", and says which of the two it came under.
//
// The scheme matters as much as the token: a bound token must arrive as DPoP (RFC 9449 §7.2) and an
// unbound one must not (§7.1), and the extractor is the one thing that sees the header. The
// authorizer asks it through Scheme. Challenge renders a refusal's WWW-Authenticate; utils_go's
// jwt_extractor looks for that method from v1.71.0 on, so at a consumer on a newer utils_go the
// challenge is on that extractor's own refusals too.
package token_extractor

import (
	"net/http"
	"strings"

	"github.com/altshiftab/authentication_go/pkg/dpop"
	"github.com/altshiftab/authentication_go/pkg/dpop/types/token_extractor/token_extractor_config"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	muxResponse "github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail/problem_detail_config"
)

const (
	headerName   = "Authorization"
	bearerScheme = "Bearer"
)

type Parser struct {
	config *token_extractor_config.Config
}

// Parse returns the credentials of the one Authorization header, under a scheme it accepts, exactly
// as the client sent them less the surrounding whitespace: "ath" is a hash of those bytes.
//
// Every refusal is a 401 with a challenge, which HTTP requires of one: no header is a request
// without a token, and more than one is a malformed request (RFC 6750 §3.1).
func (p *Parser) Parse(request *http.Request) (string, *response_error.ResponseError) {
	if request == nil {
		return "", &response_error.ResponseError{
			ServerError: altshiftErrors.NewWithTrace(nil_error.New("request")),
		}
	}

	values := request.Header.Values(headerName)
	switch len(values) {
	case 0:
		return "", p.refusal("", "Missing token header.")
	case 1:
	default:
		return "", p.refusal(dpop.ErrorInvalidRequest, "Multiple token header values.")
	}

	scheme, credentials := split(values[0])
	if p.canonicalScheme(scheme) == "" {
		return "", p.refusal("", "Unsupported authentication scheme.")
	}
	if credentials == "" {
		return "", p.refusal(dpop.ErrorInvalidRequest, "Empty token.")
	}

	return credentials, nil
}

// Scheme is the scheme the request's token is presented under, as dpop.Scheme or "Bearer" whatever
// case the client wrote it in, or empty when there is no single header under a scheme the extractor
// accepts -- in which case Parse refuses the request anyway.
func (p *Parser) Scheme(request *http.Request) string {
	if request == nil {
		return ""
	}

	values := request.Header.Values(headerName)
	if len(values) != 1 {
		return ""
	}

	scheme, _ := split(values[0])
	return p.canonicalScheme(scheme)
}

// Challenge is the WWW-Authenticate value for a refusal: the DPoP challenge, and the Bearer one
// after it when Bearer is accepted too (RFC 9110 §11.6.1 allows a list).
func (p *Parser) Challenge(errorCode string, errorDescription string) string {
	challenge := dpop.Challenge(errorCode, errorDescription)
	if p.acceptsBearer() {
		challenge += ", " + dpop.BearerChallenge(errorCode, errorDescription)
	}

	return challenge
}

func (p *Parser) refusal(errorCode string, detail string) *response_error.ResponseError {
	return &response_error.ResponseError{
		ProblemDetail: problem_detail.New(
			http.StatusUnauthorized,
			problem_detail_config.WithDetail(detail),
		),
		Headers: []*muxResponse.HeaderEntry{
			{Name: dpop.WwwAuthenticateHeaderName, Value: p.Challenge(errorCode, detail)},
		},
	}
}

// canonicalScheme compares without regard to case, as authentication schemes are (RFC 9110 §11.1).
func (p *Parser) canonicalScheme(scheme string) string {
	switch {
	case strings.EqualFold(scheme, dpop.Scheme):
		return dpop.Scheme
	case p.acceptsBearer() && strings.EqualFold(scheme, bearerScheme):
		return bearerScheme
	default:
		return ""
	}
}

// acceptsBearer reads the setting, as the defaults have it for a parser not made by New.
func (p *Parser) acceptsBearer() bool {
	if p == nil || p.config == nil {
		return token_extractor_config.New().AcceptBearer
	}
	return p.config.AcceptBearer
}

// split separates the scheme from the credentials at the first space (RFC 9110 §11.4).
func split(value string) (string, string) {
	scheme, credentials, _ := strings.Cut(strings.TrimSpace(value), " ")
	return scheme, strings.TrimSpace(credentials)
}

func New(options ...token_extractor_config.Option) *Parser {
	return &Parser{config: token_extractor_config.New(options...)}
}
