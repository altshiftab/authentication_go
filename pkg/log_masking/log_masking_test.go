package log_masking

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/altshiftab/authentication_go/pkg/magic_link/types/endpoint/generate_endpoint"
	"github.com/altshiftab/authentication_go/pkg/magic_link/types/endpoint/landing_endpoint"
	"github.com/altshiftab/authentication_go/pkg/magic_link/types/endpoint/validate_endpoint"
	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/callback_endpoint"
	"github.com/altshiftab/authentication_go/pkg/sso/types/endpoint/id_token_endpoint"
	"github.com/altshiftab/authentication_go/pkg/sso/types/provider_claims"
	altshiftHttpContext "github.com/altshiftab/utils_go/pkg/http/context"
	altshiftHttpTypes "github.com/altshiftab/utils_go/pkg/http/types"
	"github.com/altshiftab/utils_go/pkg/http/types/http_context_extractor"
	"github.com/altshiftab/utils_go/pkg/http/types/http_context_extractor/http_context_extractor_config"
	"github.com/altshiftab/utils_go/pkg/schema"
)

// The endpoints that carry credentials say so.
var (
	_ Masker = (*callback_endpoint.Endpoint[*provider_claims.GoogleClaims])(nil)
	_ Masker = (*validate_endpoint.Endpoint)(nil)
	_ Masker = (*landing_endpoint.Endpoint)(nil)
	_ Masker = (*generate_endpoint.Endpoint)(nil)
	_ Masker = (*id_token_endpoint.Endpoint[*provider_claims.GoogleClaims])(nil)
)

type fakeMasker struct {
	urlParams   []*schema.Url
	bodyUrls    []*schema.Url
	bodyUrlsErr error
	headers     []*http_context_extractor_config.MaskedHeader
}

func (m *fakeMasker) MaskedUrlParams() []*schema.Url { return m.urlParams }
func (m *fakeMasker) MaskedHeaders() []*http_context_extractor_config.MaskedHeader {
	return m.headers
}
func (m *fakeMasker) MaskedBodyUrls() ([]*schema.Url, error) {
	return m.bodyUrls, m.bodyUrlsErr
}

var errNotInitialized = errors.New("not initialized")

func TestApply(t *testing.T) {
	t.Parallel()

	own := &schema.Url{Path: "/api/own", Query: "secret"}
	callback := &schema.Url{Path: "/api/login/test/callback", Query: "code&state"}
	tokenEndpoint := &schema.Url{Domain: "token.example.test", Path: "/token"}
	authorization := &http_context_extractor_config.MaskedHeader{
		Url:     &schema.Url{Path: "/api/login/test/id-token"},
		Headers: []string{"Authorization"},
	}

	testCases := []struct {
		name      string
		extractor *http_context_extractor.Extractor
		maskers   []Masker
		wantErr   bool
	}{
		{
			name:      "alongside what a service set itself",
			extractor: &http_context_extractor.Extractor{MaskedUrlParams: []*schema.Url{own}},
			maskers: []Masker{&fakeMasker{
				urlParams: []*schema.Url{callback},
				bodyUrls:  []*schema.Url{tokenEndpoint},
				headers:   []*http_context_extractor_config.MaskedHeader{authorization},
			}},
		},
		{name: "no extractor", maskers: []Masker{&fakeMasker{}}, wantErr: true},
		{name: "no masker", extractor: &http_context_extractor.Extractor{}, maskers: []Masker{nil}, wantErr: true},
		{
			// An endpoint asked before it knows its body URLs refuses, and nothing is applied.
			name:      "a masker that does not know its body urls yet",
			extractor: &http_context_extractor.Extractor{},
			maskers:   []Masker{&fakeMasker{urlParams: []*schema.Url{callback}, bodyUrlsErr: errNotInitialized}},
			wantErr:   true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := Apply(testCase.extractor, testCase.maskers...)
			if testCase.wantErr {
				if err == nil {
					t.Errorf("%s: applied", testCase.name)
				}
				if extractor := testCase.extractor; extractor != nil && len(extractor.MaskedUrlParams) != 0 {
					t.Errorf("%s: masked url params %+v applied all the same", testCase.name, extractor.MaskedUrlParams)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: apply: %v", testCase.name, err)
			}

			extractor := testCase.extractor
			if len(extractor.MaskedUrlParams) != 2 || extractor.MaskedUrlParams[0] != own || extractor.MaskedUrlParams[1] != callback {
				t.Errorf("%s: masked url params %+v", testCase.name, extractor.MaskedUrlParams)
			}
			if len(extractor.MaskedHeaders) != 1 || extractor.MaskedHeaders[0] != authorization {
				t.Errorf("%s: masked headers %+v", testCase.name, extractor.MaskedHeaders)
			}
			for name, bodyUrls := range map[string][]*schema.Url{
				"request":  extractor.MaskedRequestBodyUrls,
				"response": extractor.MaskedResponseBodyUrls,
			} {
				if len(bodyUrls) != 1 || bodyUrls[0] != tokenEndpoint {
					t.Errorf("%s: masked %s body urls %+v", testCase.name, name, bodyUrls)
				}
			}
		})
	}
}

func TestMagicLinkEndpoints_Masks(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		masker Masker
		path   string
		// wantQuery is the parameters masked in the URL, and none where it is empty.
		wantQuery string
		// wantBody is whether the endpoint's own bodies are masked.
		wantBody bool
	}{
		{name: "validate", masker: validate_endpoint.New(), path: validate_endpoint.New().Path, wantQuery: "token"},
		{name: "landing", masker: landing_endpoint.New(), path: landing_endpoint.New().Path, wantQuery: "token"},
		// The address is asked for in the body, which is masked whole.
		{name: "generate", masker: generate_endpoint.New(), path: generate_endpoint.New().Path, wantBody: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			urlParams := testCase.masker.MaskedUrlParams()
			if testCase.wantQuery == "" {
				if len(urlParams) != 0 {
					t.Errorf("%s: masked url params %+v, want none", testCase.name, urlParams)
				}
			} else if len(urlParams) != 1 || urlParams[0].Path != testCase.path || urlParams[0].Query != testCase.wantQuery {
				t.Errorf("%s: masked url params %+v", testCase.name, urlParams)
			}

			bodyUrls, err := testCase.masker.MaskedBodyUrls()
			if err != nil {
				t.Fatalf("%s: masked body urls: %v", testCase.name, err)
			}
			if !testCase.wantBody {
				if len(bodyUrls) != 0 {
					t.Errorf("%s: masked body urls %+v, want none", testCase.name, bodyUrls)
				}
			} else if len(bodyUrls) != 1 || bodyUrls[0].Path != testCase.path || bodyUrls[0].Domain != "" {
				t.Errorf("%s: masked body urls %+v, want the endpoint's own path", testCase.name, bodyUrls)
			}
		})
	}
}

// The ID-token endpoint's token is in its Authorization header, whose claims name the person: the
// header is masked whole on the endpoint's path, and nothing else is.
func TestIdTokenEndpoint_Masks(t *testing.T) {
	t.Parallel()

	endpoint, err := id_token_endpoint.New[*provider_claims.GoogleClaims]("/api/login/test/id-token")
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	headers := endpoint.MaskedHeaders()
	if len(headers) != 1 || headers[0].Url == nil || headers[0].Url.Path != endpoint.Path ||
		len(headers[0].Headers) != 1 || headers[0].Headers[0] != "Authorization" {
		t.Errorf("masked headers %+v, want Authorization on %s", headers, endpoint.Path)
	}
	if urlParams := endpoint.MaskedUrlParams(); len(urlParams) != 0 {
		t.Errorf("masked url params %+v, want none", urlParams)
	}
	if bodyUrls, err := endpoint.MaskedBodyUrls(); err != nil || len(bodyUrls) != 0 {
		t.Errorf("masked body urls %+v, %v, want none", bodyUrls, err)
	}
}

/*
 * What Apply puts on the extractor is what the log then writes: a callback's code and state, and a
 * token exchange's bodies, do not reach it. Rendered against an extractor without the masks too,
 * so that the test is known to be looking where the log writes them.
 */
func TestApply_Rendering(t *testing.T) {
	t.Parallel()

	const (
		code         = "a-test-authorization-code"
		clientSecret = "a-test-client-secret" //nolint:gosec // A made-up secret.
	)

	masker := &fakeMasker{
		urlParams: []*schema.Url{{Path: "/api/login/test/callback", Query: "code&state"}},
		bodyUrls:  []*schema.Url{{Domain: "token.example.test", Path: "/token"}},
	}

	render := func(t *testing.T, extractor *http_context_extractor.Extractor, httpContext *altshiftHttpTypes.HttpContext) string {
		t.Helper()

		record := slog.NewRecord(time.Now(), slog.LevelError, "An error occurred.", 0)
		if err := extractor.Handle(altshiftHttpContext.WithHttpContextValue(t.Context(), httpContext), &record); err != nil {
			t.Fatalf("handle: %v", err)
		}

		var written strings.Builder
		record.Attrs(func(attr slog.Attr) bool {
			written.WriteString(attr.String())
			return true
		})
		return written.String()
	}

	testCases := []struct {
		name        string
		httpContext func(t *testing.T) *altshiftHttpTypes.HttpContext
		secret      string
	}{
		{
			name: "the callback's code",
			httpContext: func(t *testing.T) *altshiftHttpTypes.HttpContext {
				return &altshiftHttpTypes.HttpContext{
					Request: httptest.NewRequestWithContext(
						t.Context(), http.MethodGet,
						"https://login.example.test/api/login/test/callback?code="+code+"&state=a-state", nil,
					),
				}
			},
			secret: code,
		},
		{
			name: "the token exchange's client secret",
			httpContext: func(t *testing.T) *altshiftHttpTypes.HttpContext {
				return &altshiftHttpTypes.HttpContext{
					Request:     httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://token.example.test/token", nil),
					RequestBody: []byte("client_secret=" + clientSecret + "&code=" + code),
				}
			},
			secret: clientSecret,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if unmasked := render(t, http_context_extractor.New(), testCase.httpContext(t)); !strings.Contains(unmasked, testCase.secret) {
				t.Fatalf("%s: not written out even without the masks: %s", testCase.name, unmasked)
			}

			extractor := http_context_extractor.New()
			if err := Apply(extractor, masker); err != nil {
				t.Fatalf("%s: apply: %v", testCase.name, err)
			}
			if written := render(t, extractor, testCase.httpContext(t)); strings.Contains(written, testCase.secret) {
				t.Errorf("%s: written out: %s", testCase.name, written)
			}
		})
	}
}
