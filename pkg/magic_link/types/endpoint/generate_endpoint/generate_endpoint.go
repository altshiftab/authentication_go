package generate_endpoint

import (
	"context"
	"encoding/json/v2"
	stdErrors "errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/altshiftab/authentication_go/pkg/magic_link/types/endpoint/generate_endpoint/generate_endpoint_config"
	"github.com/altshiftab/authentication_go/pkg/magic_link/types/mail_sender"
	altshiftCryptoInterfaces "github.com/altshiftab/utils_go/pkg/crypto/interfaces"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/body_loader"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/body_loader/body_setting"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/body_parser"
	bodyParserAdapter "github.com/altshiftab/utils_go/pkg/http/mux/types/body_parser/adapter"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/body_parser/json_body_parser"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/endpoint/initialization_endpoint"
	processorPkg "github.com/altshiftab/utils_go/pkg/http/mux/types/processor"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/adapter"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/query_extractor"
	muxResponse "github.com/altshiftab/utils_go/pkg/http/mux/types/response"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	muxUtils "github.com/altshiftab/utils_go/pkg/http/mux/utils"
	altshiftHttpTypes "github.com/altshiftab/utils_go/pkg/http/types"
	"github.com/altshiftab/utils_go/pkg/http/types/accept_language"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail/problem_detail_config"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claims/registered_claims"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/numeric_date"
	altshiftJwtToken "github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/token"
	altshiftMail "github.com/altshiftab/utils_go/pkg/mail"
	"github.com/altshiftab/utils_go/pkg/mail/types/message"
	"github.com/altshiftab/utils_go/pkg/mail/types/message/message_config"
	altshiftNet "github.com/altshiftab/utils_go/pkg/net"
	"github.com/altshiftab/utils_go/pkg/net/types/domain_parts"
	altshiftReflect "github.com/altshiftab/utils_go/pkg/reflect"
	"github.com/altshiftab/utils_go/pkg/utils"
)

type BodyInput struct {
	EmailAddress string `json:"email_address" jsonschema:"email_address,format:email"`
	RedirectUrl  string `json:"redirect,omitzero" jsonschema:"redirect,optional,format:uri"`
}

type ParsedBodyInput struct {
	EmailAddress *mail.Address
	RedirectUrl  *url.URL
}

func makeBodyProcessor(domain string) processorPkg.Processor[*ParsedBodyInput, *BodyInput] {
	return processorPkg.New(func(_ context.Context, input *BodyInput) (*ParsedBodyInput, *response_error.ResponseError) {
		if input == nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(nil_error.New("body input")),
			}
		}

		emailAddressString := strings.ToLower(strings.TrimSpace(input.EmailAddress))
		if emailAddressString == "" {
			return nil, &response_error.ResponseError{
				ProblemDetail: problem_detail.New(
					http.StatusUnprocessableEntity,
					problem_detail_config.WithDetail("The email address is empty."),
				),
			}
		}

		if err := altshiftMail.ValidateAddress(emailAddressString); err != nil {
			if stdErrors.Is(err, altshiftErrors.ErrValidationError) {
				return nil, &response_error.ResponseError{
					ClientError: altshiftErrors.New(fmt.Errorf("validate address: %w", err), emailAddressString),
					ProblemDetail: problem_detail.New(
						http.StatusUnprocessableEntity,
						problem_detail_config.WithDetail("The email address is invalid."),
					),
				}
			}
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.New(fmt.Errorf("validate address: %w", err), emailAddressString),
			}
		}

		emailAddress, err := mail.ParseAddress(emailAddressString)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.New(fmt.Errorf("mail parse address: %w", err), emailAddressString),
			}
		}

		var redirectUrl *url.URL
		if rawRedirect := strings.TrimSpace(input.RedirectUrl); rawRedirect != "" {
			parsedRedirect, err := url.Parse(rawRedirect)
			if err != nil {
				return nil, &response_error.ResponseError{
					ClientError: altshiftErrors.New(fmt.Errorf("url parse (redirect): %w", err), rawRedirect),
					ProblemDetail: problem_detail.New(
						http.StatusUnprocessableEntity,
						problem_detail_config.WithDetail("The redirect URL is malformed."),
					),
				}
			}

			hostname := parsedRedirect.Hostname()
			if !altshiftNet.IsLocalhost(domain) || !altshiftNet.IsLocalhost(hostname) {
				parts := domain_parts.New(hostname)
				if parts == nil || parts.RegisteredDomain != domain {
					return nil, &response_error.ResponseError{
						ClientError: altshiftErrors.NewWithTrace(fmt.Errorf("disallowed redirect hostname: %q", hostname)),
						ProblemDetail: problem_detail.New(
							http.StatusUnprocessableEntity,
							problem_detail_config.WithDetail("The redirect URL hostname is not allowed."),
						),
					}
				}
			}

			redirectUrl = parsedRedirect
		}

		return &ParsedBodyInput{EmailAddress: emailAddress, RedirectUrl: redirectUrl}, nil
	})
}

type Endpoint struct {
	*initialization_endpoint.Endpoint
	LinkExpiration     time.Duration
	SubjectBuilder     generate_endpoint_config.SubjectBuilder
	ReplyToAddresses   []*mail.Address
	MessageBuilder     generate_endpoint_config.MessageBuilder
	AccountChecker     generate_endpoint_config.AccountChecker
	MinResponseLatency time.Duration
	makeNonce          func() string
}

func (e *Endpoint) Initialize(
	mailSender mail_sender.Sender,
	signer altshiftCryptoInterfaces.NamedSigner,
	fromAddress *mail.Address,
	linkBaseUrl *url.URL,
	domain string,
) error {
	if utils.IsNil(mailSender) {
		return altshiftErrors.NewWithTrace(nil_error.New("mail sender"))
	}

	if utils.IsNil(signer) {
		return altshiftErrors.NewWithTrace(nil_error.New("signer"))
	}

	if fromAddress == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("from address"))
	}

	if linkBaseUrl == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("link base url"))
	}

	if domain == "" {
		return altshiftErrors.NewWithTrace(empty_error.New("domain"))
	}

	if e.MessageBuilder == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("message builder"))
	}

	if e.makeNonce == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("make nonce"))
	}

	if e.SubjectBuilder == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("subject builder"))
	}

	if e.AccountChecker == nil {
		return altshiftErrors.NewWithTrace(nil_error.New("account checker"))
	}

	e.BodyLoader.Parser = bodyParserAdapter.New(
		body_parser.NewWithProcessor(
			json_body_parser.New[*BodyInput](),
			makeBodyProcessor(domain),
		),
	)

	e.Handler = func(request *http.Request, _ []byte) (*muxResponse.Response, *response_error.ResponseError) {
		ctx := request.Context()

		body, responseError := muxUtils.GetServerNonZeroParsedRequestBody[*ParsedBodyInput](ctx)
		if responseError != nil {
			return nil, responseError
		}

		if e.MinResponseLatency > 0 {
			startTime := time.Now()
			defer func() {
				if remaining := e.MinResponseLatency - time.Since(startTime); remaining > 0 {
					select {
					case <-time.After(remaining):
					case <-ctx.Done():
					}
				}
			}()
		}

		toAddress := body.EmailAddress

		accountExists, err := e.AccountChecker(ctx, toAddress.Address)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.New(fmt.Errorf("account checker: %w", err), toAddress.Address),
			}
		}
		if !accountExists {
			return nil, nil
		}

		nonce := e.makeNonce()
		if nonce == "" {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(empty_error.New("nonce")),
			}
		}

		now := time.Now()
		expiresAt := now.Add(e.LinkExpiration)

		claims := &registered_claims.Claims{
			Id:        nonce,
			Subject:   toAddress.Address,
			IssuedAt:  numeric_date.New(now),
			ExpiresAt: numeric_date.New(expiresAt),
		}
		claimsData, err := json.Marshal(claims)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("json marshal (claims): %w", err)),
			}
		}
		var payload map[string]any
		if err := json.Unmarshal(claimsData, &payload); err != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("json unmarshal (claims data): %w", err), claimsData),
			}
		}
		if body.RedirectUrl != nil {
			payload["redirect"] = body.RedirectUrl.String()
		}

		token := &altshiftJwtToken.Token{Payload: payload}
		tokenString, err := token.Encode(signer)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("token encode: %w", err)),
			}
		}

		linkUrl := *linkBaseUrl
		query := linkUrl.Query()
		query.Set("token", tokenString)
		linkUrl.RawQuery = query.Encode()

		var acceptLanguage *altshiftHttpTypes.AcceptLanguage
		if raw := strings.TrimSpace(request.Header.Get("Accept-Language")); raw != "" {
			parsed, parseErr := accept_language.Parse([]byte(raw))
			if parseErr == nil {
				acceptLanguage = parsed
			}
		}

		messageBody, err := e.MessageBuilder(toAddress, &linkUrl, expiresAt, acceptLanguage)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("message builder: %w", err)),
			}
		}
		if messageBody == nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(nil_error.New("message body")),
			}
		}

		var messageOptions []message_config.Option
		if len(e.ReplyToAddresses) > 0 {
			messageOptions = append(messageOptions, message_config.WithReplyTo(e.ReplyToAddresses))
		}

		subject := e.SubjectBuilder(acceptLanguage)

		msg, err := message.New(fromAddress, []*mail.Address{toAddress}, subject, messageBody, messageOptions...)
		if err != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.NewWithTrace(fmt.Errorf("message new: %w", err)),
			}
		}

		if err := mailSender.SendMessage(ctx, msg); err != nil {
			return nil, &response_error.ResponseError{
				ServerError: altshiftErrors.New(fmt.Errorf("mail sender send message: %w", err)),
			}
		}

		return nil, nil
	}

	e.Initialized = true

	return nil
}

func New(options ...generate_endpoint_config.Option) *Endpoint {
	config := generate_endpoint_config.New(options...)
	return &Endpoint{
		Endpoint: &initialization_endpoint.Endpoint{
			Endpoint: &endpoint.Endpoint{
				Path:      config.Path,
				Method:    http.MethodPost,
				UrlParser: adapter.New(query_extractor.Empty),
				Public:    true,
				BodyLoader: &body_loader.Loader{
					Setting:     body_setting.Required,
					ContentType: "application/json",
					MaxBytes:    config.MaxBytes,
				},
				Hint: &endpoint.Hint{
					InputType: altshiftReflect.TypeOf[BodyInput](),
				},
			},
		},
		LinkExpiration:     config.LinkExpiration,
		SubjectBuilder:     config.SubjectBuilder,
		ReplyToAddresses:   config.ReplyToAddresses,
		MessageBuilder:     config.MessageBuilder,
		AccountChecker:     config.AccountChecker,
		MinResponseLatency: config.MinResponseLatency,
		makeNonce:          config.MakeNonce,
	}
}
