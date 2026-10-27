package token_extractor

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/altshiftab/authentication_go/pkg/dpop/types/token_extractor/token_extractor_config"
)

func TestParser_Parse(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		headers       []string
		refuseBearer  bool
		wantToken     string
		wantScheme    string
		wantChallenge string
	}{
		{name: "DPoP", headers: []string{"DPoP a.b.c"}, wantToken: "a.b.c", wantScheme: "DPoP"},
		{name: "DPoP in lower case", headers: []string{"dpop a.b.c"}, wantToken: "a.b.c", wantScheme: "DPoP"},
		{name: "Bearer", headers: []string{"Bearer a.b.c"}, wantToken: "a.b.c", wantScheme: "Bearer"},
		{name: "Bearer in lower case", headers: []string{"bearer a.b.c"}, wantToken: "a.b.c", wantScheme: "Bearer"},
		{
			// The token comes back as it was sent, which is what its hash in "ath" was taken over.
			name:       "spaces around the token",
			headers:    []string{"DPoP    a.b.c  "},
			wantToken:  "a.b.c",
			wantScheme: "DPoP",
		},
		{
			name:          "Bearer, where it is refused",
			headers:       []string{"Bearer a.b.c"},
			refuseBearer:  true,
			wantChallenge: `DPoP algs="ES256"`,
		},
		{
			name:          "DPoP, where Bearer is refused",
			headers:       []string{"DPoP a.b.c"},
			refuseBearer:  true,
			wantToken:     "a.b.c",
			wantScheme:    "DPoP",
			wantChallenge: "",
		},
		{
			name:          "another scheme",
			headers:       []string{"Basic dXNlcjpwYXNz"},
			wantChallenge: `DPoP algs="ES256", Bearer`,
		},
		{
			name:          "no header",
			wantChallenge: `DPoP algs="ES256", Bearer`,
		},
		{
			name:          "two headers",
			headers:       []string{"DPoP a.b.c", "DPoP d.e.f"},
			wantChallenge: `DPoP error="invalid_request", error_description="Multiple token header values.", algs="ES256", Bearer error="invalid_request", error_description="Multiple token header values."`,
		},
		{
			// The scheme is still the one named, though Parse refuses the request for its token.
			name:          "a scheme and no token",
			headers:       []string{"DPoP"},
			wantScheme:    "DPoP",
			wantChallenge: `DPoP error="invalid_request", error_description="Empty token.", algs="ES256", Bearer error="invalid_request", error_description="Empty token."`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			parser := New(token_extractor_config.WithAcceptBearer(!testCase.refuseBearer))

			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			for _, header := range testCase.headers {
				request.Header.Add("Authorization", header)
			}

			token, responseError := parser.Parse(request)

			if scheme := parser.Scheme(request); scheme != testCase.wantScheme {
				t.Errorf("%s: scheme %q, want %q", testCase.name, scheme, testCase.wantScheme)
			}

			if testCase.wantToken != "" {
				if responseError != nil {
					t.Fatalf("%s: refused: %+v", testCase.name, responseError)
				}
				if token != testCase.wantToken {
					t.Errorf("%s: token %q, want %q", testCase.name, token, testCase.wantToken)
				}
				return
			}

			if responseError == nil || responseError.ProblemDetail == nil {
				t.Fatalf("%s: accepted, or refused without a problem detail: %+v", testCase.name, responseError)
			}
			if status := responseError.ProblemDetail.Status; status != http.StatusUnauthorized {
				t.Errorf("%s: status %d, want %d", testCase.name, status, http.StatusUnauthorized)
			}
			if responseError.ServerError != nil {
				t.Errorf("%s: a server error: %v", testCase.name, responseError.ServerError)
			}

			var challenge string
			for _, header := range responseError.Headers {
				if header != nil && header.Name == "WWW-Authenticate" {
					challenge = header.Value
				}
			}
			if challenge != testCase.wantChallenge {
				t.Errorf("%s: challenge %q, want %q", testCase.name, challenge, testCase.wantChallenge)
			}
		})
	}
}

func TestParser_Challenge(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		refuseBearer     bool
		errorCode        string
		errorDescription string
		want             string
	}{
		{name: "no error", want: `DPoP algs="ES256", Bearer`},
		{name: "no error, Bearer refused", refuseBearer: true, want: `DPoP algs="ES256"`},
		{
			name:             "a token error names both",
			errorCode:        "invalid_token",
			errorDescription: "Invalid token.",
			want:             `DPoP error="invalid_token", error_description="Invalid token.", algs="ES256", Bearer error="invalid_token", error_description="Invalid token."`,
		},
		{
			name:             "a proof error names DPoP alone",
			errorCode:        "invalid_dpop_proof",
			errorDescription: "The DPoP proof is not valid.",
			want:             `DPoP error="invalid_dpop_proof", error_description="The DPoP proof is not valid.", algs="ES256", Bearer`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			parser := New(token_extractor_config.WithAcceptBearer(!testCase.refuseBearer))
			if got := parser.Challenge(testCase.errorCode, testCase.errorDescription); got != testCase.want {
				t.Errorf("%s: got %q, want %q", testCase.name, got, testCase.want)
			}
		})
	}
}

// A parser not made by New reads as the defaults do, rather than panicking in the request path.
func TestParser_ZeroValue(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		header        string
		wantToken     string
		wantChallenge string
	}{
		{name: "Bearer, accepted as by default", header: "Bearer a.b.c", wantToken: "a.b.c"},
		{name: "no header", wantChallenge: `DPoP algs="ES256", Bearer`},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			parser := &Parser{}
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			if testCase.header != "" {
				request.Header.Set("Authorization", testCase.header)
			}

			token, responseError := parser.Parse(request)
			if testCase.wantToken != "" {
				if responseError != nil || token != testCase.wantToken {
					t.Errorf("%s: got %q, %+v", testCase.name, token, responseError)
				}
				return
			}
			if responseError == nil {
				t.Fatalf("%s: accepted", testCase.name)
			}
			if got := parser.Challenge("", ""); got != testCase.wantChallenge {
				t.Errorf("%s: challenge %q, want %q", testCase.name, got, testCase.wantChallenge)
			}
		})
	}
}
