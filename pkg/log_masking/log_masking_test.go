// An external test: the endpoints it holds to the interface import the package themselves.
package log_masking_test

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/altshiftab/authentication_go/pkg/log_masking"
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
	_ log_masking.Masker = (*callback_endpoint.Endpoint[*provider_claims.GoogleClaims])(nil)
	_ log_masking.Masker = (*validate_endpoint.Endpoint)(nil)
	_ log_masking.Masker = (*landing_endpoint.Endpoint)(nil)
	_ log_masking.Masker = (*generate_endpoint.Endpoint)(nil)
	_ log_masking.Masker = (*id_token_endpoint.Endpoint[*provider_claims.GoogleClaims])(nil)
)

type fakeMasker struct {
	urlParams     []*schema.Url
	bodyFields    *log_masking.BodyFields
	bodyFieldsErr error
	headers       []*http_context_extractor_config.MaskedHeader
}

func (m *fakeMasker) MaskedUrlParams() []*schema.Url { return m.urlParams }
func (m *fakeMasker) MaskedHeaders() []*http_context_extractor_config.MaskedHeader {
	return m.headers
}
func (m *fakeMasker) MaskedBodyFields() (*log_masking.BodyFields, error) {
	return m.bodyFields, m.bodyFieldsErr
}

var errNotInitialized = errors.New("not initialized")

func TestApply(t *testing.T) {
	t.Parallel()

	own := &schema.Url{Path: "/api/own", Query: "secret"}
	callback := &schema.Url{Path: "/api/login/test/callback", Query: "code&state"}
	tokenEndpoint := &schema.Url{Domain: "token.example.test", Path: "/token"}
	requestFields := &http_context_extractor_config.MaskedBodyFields{Url: tokenEndpoint, Fields: []string{"client_secret"}}
	responseFields := &http_context_extractor_config.MaskedBodyFields{Url: tokenEndpoint, Fields: []string{"access_token"}}
	authorization := &http_context_extractor_config.MaskedHeader{
		Url:     &schema.Url{Path: "/api/login/test/id-token"},
		Headers: []string{"Authorization"},
	}

	testCases := []struct {
		name      string
		extractor *http_context_extractor.Extractor
		maskers   []log_masking.Masker
		wantErr   bool
	}{
		{
			name:      "alongside what a service set itself",
			extractor: &http_context_extractor.Extractor{MaskedUrlParams: []*schema.Url{own}},
			maskers: []log_masking.Masker{
				&fakeMasker{
					urlParams: []*schema.Url{callback},
					bodyFields: &log_masking.BodyFields{
						Request:  []*http_context_extractor_config.MaskedBodyFields{requestFields},
						Response: []*http_context_extractor_config.MaskedBodyFields{responseFields},
					},
				},
				// An endpoint with no body fields to mask.
				&fakeMasker{headers: []*http_context_extractor_config.MaskedHeader{authorization}},
			},
		},
		{name: "no extractor", maskers: []log_masking.Masker{&fakeMasker{}}, wantErr: true},
		{name: "no masker", extractor: &http_context_extractor.Extractor{}, maskers: []log_masking.Masker{nil}, wantErr: true},
		{
			// An endpoint asked before it knows its body fields refuses, and nothing is applied.
			name:      "a masker that does not know its body fields yet",
			extractor: &http_context_extractor.Extractor{},
			maskers:   []log_masking.Masker{&fakeMasker{urlParams: []*schema.Url{callback}, bodyFieldsErr: errNotInitialized}},
			wantErr:   true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := log_masking.Apply(testCase.extractor, testCase.maskers...)
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
			if fields := extractor.MaskedRequestBodyFields; len(fields) != 1 || fields[0] != requestFields {
				t.Errorf("%s: masked request body fields %+v", testCase.name, fields)
			}
			if fields := extractor.MaskedResponseBodyFields; len(fields) != 1 || fields[0] != responseFields {
				t.Errorf("%s: masked response body fields %+v", testCase.name, fields)
			}
			// What masks a body whole is left as the service set it.
			if len(extractor.MaskedRequestBodyUrls) != 0 || len(extractor.MaskedResponseBodyUrls) != 0 {
				t.Errorf("%s: whole bodies masked: %+v, %+v", testCase.name, extractor.MaskedRequestBodyUrls, extractor.MaskedResponseBodyUrls)
			}
		})
	}
}

func TestMagicLinkEndpoints_Masks(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name   string
		masker log_masking.Masker
		path   string
		// wantQuery is the parameters masked in the URL, and none where it is empty.
		wantQuery string
		// wantAllValues is whether every value of the endpoint's own request bodies is masked.
		wantAllValues bool
	}{
		{name: "validate", masker: validate_endpoint.New(), path: validate_endpoint.New().Path, wantQuery: "token"},
		{name: "landing", masker: landing_endpoint.New(), path: landing_endpoint.New().Path, wantQuery: "token"},
		// The address is asked for in the body, whose fields the client chooses.
		{name: "generate", masker: generate_endpoint.New(), path: generate_endpoint.New().Path, wantAllValues: true},
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

			bodyFields, err := testCase.masker.MaskedBodyFields()
			if err != nil {
				t.Fatalf("%s: masked body fields: %v", testCase.name, err)
			}
			if !testCase.wantAllValues {
				if bodyFields != nil {
					t.Errorf("%s: masked body fields %+v, want none", testCase.name, bodyFields)
				}
			} else if bodyFields == nil || len(bodyFields.Request) != 1 || bodyFields.Request[0].Url == nil ||
				bodyFields.Request[0].Url.Path != testCase.path || bodyFields.Request[0].Url.Domain != "" ||
				!bodyFields.Request[0].AllValues || len(bodyFields.Response) != 0 {
				t.Errorf("%s: masked body fields %+v, want every value of the requests on its own path", testCase.name, bodyFields)
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
	if bodyFields, err := endpoint.MaskedBodyFields(); err != nil || bodyFields != nil {
		t.Errorf("masked body fields %+v, %v, want none", bodyFields, err)
	}
}

/*
 * What Apply puts on the extractor is what the log then writes: a callback's code and state, and a
 * token exchange's credentials, do not reach it, and what says why an exchange failed does.
 * Rendered against an extractor without the masks too, so that the test is known to be looking
 * where the log writes them.
 */
func TestApply_Rendering(t *testing.T) {
	t.Parallel()

	const (
		code         = "a-test-authorization-code"
		clientSecret = "a-test-client-secret" //nolint:gosec // A made-up secret.
		accessToken  = "a-test-access-token"  //nolint:gosec // A made-up token.
	)

	tokenEndpoint := &schema.Url{Domain: "token.example.test", Path: "/token"}
	masker := &fakeMasker{
		urlParams: []*schema.Url{{Path: "/api/login/test/callback", Query: "code&state"}},
		bodyFields: &log_masking.BodyFields{
			Request: []*http_context_extractor_config.MaskedBodyFields{
				{Url: tokenEndpoint, Fields: []string{"client_secret", "code"}},
			},
			Response: []*http_context_extractor_config.MaskedBodyFields{
				{Url: tokenEndpoint, Fields: []string{"access_token"}},
			},
		},
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
		secrets     []string
		kept        []string
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
			secrets: []string{code},
		},
		{
			name: "the token exchange's credentials",
			httpContext: func(t *testing.T) *altshiftHttpTypes.HttpContext {
				request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://token.example.test/token", nil)
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return &altshiftHttpTypes.HttpContext{
					Request:     request,
					RequestBody: []byte("grant_type=authorization_code&client_secret=" + clientSecret + "&code=" + code),
					Response: &http.Response{
						StatusCode: http.StatusBadRequest,
						Header:     http.Header{"Content-Type": {"application/json"}},
					},
					ResponseBody: []byte(`{"error":"invalid_grant","access_token":"` + accessToken + `"}`),
				}
			},
			secrets: []string{clientSecret, code, accessToken},
			kept:    []string{"grant_type=authorization_code", "invalid_grant"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			unmasked := render(t, http_context_extractor.New(), testCase.httpContext(t))
			for _, secret := range testCase.secrets {
				if !strings.Contains(unmasked, secret) {
					t.Fatalf("%s: %q not written out even without the masks: %s", testCase.name, secret, unmasked)
				}
			}

			extractor := http_context_extractor.New()
			if err := log_masking.Apply(extractor, masker); err != nil {
				t.Fatalf("%s: apply: %v", testCase.name, err)
			}
			written := render(t, extractor, testCase.httpContext(t))
			for _, secret := range testCase.secrets {
				if strings.Contains(written, secret) {
					t.Errorf("%s: %q written out: %s", testCase.name, secret, written)
				}
			}
			for _, kept := range testCase.kept {
				if !strings.Contains(written, kept) {
					t.Errorf("%s: %q not written out: %s", testCase.name, kept, written)
				}
			}
		})
	}
}
