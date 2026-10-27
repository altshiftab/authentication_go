package authorizer_request_parser

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dpopTesting "github.com/altshiftab/authentication_go/pkg/dpop/testing"
	"github.com/altshiftab/authentication_go/pkg/dpop/types/memory_replay_detector"
	"github.com/altshiftab/authentication_go/pkg/dpop/types/proof_verifier"
	"github.com/altshiftab/authentication_go/pkg/dpop/types/proof_verifier/proof_verifier_config"
	"github.com/altshiftab/authentication_go/pkg/dpop/types/token_extractor"
	"github.com/altshiftab/authentication_go/pkg/dpop/types/token_extractor/token_extractor_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/authentication_method"
	"github.com/altshiftab/authentication_go/pkg/session/types/authorizer_request_parser/authorizer_request_parser_config"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_cookie"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
	altshiftCryptoEddsa "github.com/altshiftab/utils_go/pkg/crypto/eddsa"
	altshiftCryptoInterfaces "github.com/altshiftab/utils_go/pkg/crypto/interfaces"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/token_cookie_extractor/token_cookie_extractor_config"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser/token_header_extractor"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claim_strings"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claims/registered_claims"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/claims/session_claims"
	"github.com/altshiftab/utils_go/pkg/json/jose/jwt/types/numeric_date"
	"github.com/altshiftab/utils_go/pkg/utils"
)

const (
	dpopOrigin = "https://api.example.com"
	dpopPath   = "/resource"
)

// makeTokenString is a session token as MintToken issues one, bound to the key with keyThumbprint
// when that is not empty.
func makeTokenString(signer altshiftCryptoInterfaces.NamedSigner, keyThumbprint string, methods ...string) string {
	if utils.IsNil(signer) {
		panic(altshiftErrors.NewWithTrace(nil_error.New("signer")))
	}

	sessionClaims := &session_claims.Claims{
		Claims: registered_claims.Claims{
			Issuer:    issuer,
			Subject:   "test-subject-id:test@example.com",
			Audience:  claim_strings.ClaimStrings{audience},
			ExpiresAt: numeric_date.New(time.Now().Add(time.Hour)),
			NotBefore: numeric_date.New(time.Now()),
			IssuedAt:  numeric_date.New(time.Now()),
			Id:        strings.Join([]string{authenticationId, sessionId}, ":"),
		},
		AuthenticationMethods: methods,
		Roles:                 []string{role},
	}

	sessionToken, err := session_token.Parse(sessionClaims)
	if err != nil {
		panic(altshiftErrors.New(fmt.Errorf("session token parse: %w", err), sessionClaims))
	}
	if sessionToken == nil {
		panic(altshiftErrors.NewWithTrace(nil_error.New("session token")))
	}
	sessionToken.KeyThumbprint = keyThumbprint

	tokenString, err := sessionToken.Encode(signer)
	if err != nil {
		panic(altshiftErrors.New(fmt.Errorf("session token encode: %w", err), sessionToken))
	}

	return tokenString
}

func makeTokenCookie(tokenString string) string {
	sessionCookie, err := session_cookie.New(tokenString, time.Now().Add(time.Hour), token_cookie_extractor_config.DefaultName, domain)
	if err != nil {
		panic(altshiftErrors.New(fmt.Errorf("session cookie new: %w", err), tokenString))
	}

	return sessionCookie.String()
}

type dpopRequest struct {
	authorization []string
	cookie        string
	proofs        []string
}

func newDpopRequest(t *testing.T, method string, request *dpopRequest) *http.Request {
	t.Helper()

	httpRequest := httptest.NewRequestWithContext(t.Context(), method, dpopOrigin+dpopPath, nil)
	for _, value := range request.authorization {
		httpRequest.Header.Add("Authorization", value)
	}
	if request.cookie != "" {
		httpRequest.Header.Set("Cookie", request.cookie)
	}
	for _, proof := range request.proofs {
		httpRequest.Header.Add("DPoP", proof)
	}

	return httpRequest
}

func TestParser_Parse_Dpop(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}
	signer := &altshiftCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey}

	key := dpopTesting.NewKey()
	otherKey := dpopTesting.NewKey()
	thumbprint := dpopTesting.KeyThumbprint(&key.PublicKey)

	proofVerifier, err := proof_verifier.New([]string{dpopOrigin})
	if err != nil {
		t.Fatalf("proof verifier new: %v", err)
	}

	boundToken := makeTokenString(signer, thumbprint, authentication_method.ApiKey)
	unboundToken := makeTokenString(signer, "", authentication_method.ApiKey)
	boundSession := makeTokenString(signer, thumbprint, authentication_method.Sso)
	unboundSession := makeTokenString(signer, "", authentication_method.Sso)

	proof := func(signedBy *ecdsa.PrivateKey, method string, htu string, accessToken string) string {
		return dpopTesting.MakeProof(signedBy, method, htu, accessToken, nil)
	}

	const (
		dpopExtractor         = "dpop"
		dpopOnlyExtractor     = "dpop only"
		bearerHeaderExtractor = "bearer header"
		cookieExtractor       = "cookie"
	)

	testCases := []struct {
		name              string
		extractor         string
		requireBoundToken bool
		request           *dpopRequest
		// Zero for a request that is let through.
		wantStatus        int
		wantDetail        string
		wantChallenge     string
		wantKeyThumbprint string
	}{
		{
			// The regression guard: an authorizer that learns DPoP still takes the tokens it took.
			name:      "an unbound token as Bearer",
			extractor: dpopExtractor,
			request:   &dpopRequest{authorization: []string{"Bearer " + unboundToken}},
		},
		{
			name:      "an unbound token as Bearer, through utils_go's header extractor",
			extractor: bearerHeaderExtractor,
			request:   &dpopRequest{authorization: []string{"Bearer " + unboundToken}},
		},
		{
			name:              "a bound token with its proof",
			extractor:         dpopExtractor,
			request:           &dpopRequest{authorization: []string{"DPoP " + boundToken}, proofs: []string{proof(key, "GET", dpopOrigin+dpopPath, boundToken)}},
			wantKeyThumbprint: thumbprint,
		},
		{
			name:              "a bound token with its proof, the scheme in lower case",
			extractor:         dpopExtractor,
			request:           &dpopRequest{authorization: []string{"dpop " + boundToken}, proofs: []string{proof(key, "GET", dpopOrigin+dpopPath, boundToken)}},
			wantKeyThumbprint: thumbprint,
		},
		{
			// The point of the binding: a copy of the token is refused when presented as a bearer
			// token, which is how anyone without the key would present it.
			name:          "a bound token as Bearer",
			extractor:     dpopExtractor,
			request:       &dpopRequest{authorization: []string{"Bearer " + boundToken}},
			wantStatus:    http.StatusUnauthorized,
			wantDetail:    "The token is bound to a key and must be presented with the DPoP scheme.",
			wantChallenge: `DPoP error="invalid_token", error_description="The token is bound to a key and must be presented with the DPoP scheme.", algs="ES256", Bearer error="invalid_token", error_description="The token is bound to a key and must be presented with the DPoP scheme."`,
		},
		{
			// An authorizer that never heard of DPoP refuses a bound token all the same, so no
			// existing endpoint becomes a way around the binding. The challenge is the extractor's
			// own, in the one scheme it reads.
			name:          "a bound token as Bearer, through utils_go's header extractor",
			extractor:     bearerHeaderExtractor,
			request:       &dpopRequest{authorization: []string{"Bearer " + boundToken}},
			wantStatus:    http.StatusUnauthorized,
			wantDetail:    "The token is bound to a key and must be presented with the DPoP scheme.",
			wantChallenge: `Bearer error="invalid_token", error_description="The token is bound to a key and must be presented with the DPoP scheme."`,
		},
		{
			name:       "a bound token in a cookie",
			extractor:  cookieExtractor,
			request:    &dpopRequest{cookie: makeTokenCookie(boundSession)},
			wantStatus: http.StatusUnauthorized,
			wantDetail: "The token is bound to a key and must be presented with the DPoP scheme.",
		},
		{
			name:          "an unbound token as DPoP",
			extractor:     dpopExtractor,
			request:       &dpopRequest{authorization: []string{"DPoP " + unboundToken}, proofs: []string{proof(key, "GET", dpopOrigin+dpopPath, unboundToken)}},
			wantStatus:    http.StatusUnauthorized,
			wantDetail:    "The token is not bound to a key.",
			wantChallenge: `DPoP error="invalid_token", error_description="The token is not bound to a key.", algs="ES256", Bearer error="invalid_token", error_description="The token is not bound to a key."`,
		},
		{
			name:          "a bound token as DPoP without a proof",
			extractor:     dpopExtractor,
			request:       &dpopRequest{authorization: []string{"DPoP " + boundToken}},
			wantStatus:    http.StatusUnauthorized,
			wantDetail:    "A DPoP proof is required.",
			wantChallenge: `DPoP error="invalid_dpop_proof", error_description="A DPoP proof is required.", algs="ES256", Bearer`,
		},
		{
			name:      "a bound token with two proofs",
			extractor: dpopExtractor,
			request: &dpopRequest{
				authorization: []string{"DPoP " + boundToken},
				proofs:        []string{proof(key, "GET", dpopOrigin+dpopPath, boundToken), proof(key, "GET", dpopOrigin+dpopPath, boundToken)},
			},
			wantStatus: http.StatusUnauthorized,
			wantDetail: "Multiple DPoP proofs.",
		},
		{
			// What a thief holding the token and a key of their own can send.
			name:          "a bound token with a proof by another key",
			extractor:     dpopExtractor,
			request:       &dpopRequest{authorization: []string{"DPoP " + boundToken}, proofs: []string{proof(otherKey, "GET", dpopOrigin+dpopPath, boundToken)}},
			wantStatus:    http.StatusUnauthorized,
			wantDetail:    "The token is bound to another key.",
			wantChallenge: `DPoP error="invalid_token", error_description="The token is bound to another key.", algs="ES256", Bearer error="invalid_token", error_description="The token is bound to another key."`,
		},
		{
			// A browser endpoint built to require bound tokens refuses every session, rather than
			// letting one through for want of a scheme to check.
			name:              "an unbound session in a cookie, where bound tokens are required",
			extractor:         cookieExtractor,
			requireBoundToken: true,
			request:           &dpopRequest{cookie: makeTokenCookie(unboundSession)},
			wantStatus:        http.StatusUnauthorized,
			wantDetail:        "A key-bound token is required.",
		},
		{
			// A proof the client made for another service, replayed here.
			name:       "a bound token with a proof for another host",
			extractor:  dpopExtractor,
			request:    &dpopRequest{authorization: []string{"DPoP " + boundToken}, proofs: []string{proof(key, "GET", "https://other.example.com"+dpopPath, boundToken)}},
			wantStatus: http.StatusUnauthorized,
			wantDetail: "The DPoP proof is not valid.",
		},
		{
			name:       "a bound token with a proof for another method",
			extractor:  dpopExtractor,
			request:    &dpopRequest{authorization: []string{"DPoP " + boundToken}, proofs: []string{proof(key, "POST", dpopOrigin+dpopPath, boundToken)}},
			wantStatus: http.StatusUnauthorized,
			wantDetail: "The DPoP proof is not valid.",
		},
		{
			name:       "a bound token with a proof made for another token",
			extractor:  dpopExtractor,
			request:    &dpopRequest{authorization: []string{"DPoP " + boundToken}, proofs: []string{proof(key, "GET", dpopOrigin+dpopPath, unboundToken)}},
			wantStatus: http.StatusUnauthorized,
			wantDetail: "The DPoP proof is not valid.",
		},
		{
			name:              "an unbound token as Bearer, where bound tokens are required",
			extractor:         dpopExtractor,
			requireBoundToken: true,
			request:           &dpopRequest{authorization: []string{"Bearer " + unboundToken}},
			wantStatus:        http.StatusUnauthorized,
			wantDetail:        "A key-bound token is required.",
		},
		{
			name:              "a bound token with its proof, where bound tokens are required",
			extractor:         dpopExtractor,
			requireBoundToken: true,
			request:           &dpopRequest{authorization: []string{"DPoP " + boundToken}, proofs: []string{proof(key, "GET", dpopOrigin+dpopPath, boundToken)}},
			wantKeyThumbprint: thumbprint,
		},
		{
			name:          "an unbound token as Bearer, where the extractor refuses Bearer",
			extractor:     dpopOnlyExtractor,
			request:       &dpopRequest{authorization: []string{"Bearer " + unboundToken}},
			wantStatus:    http.StatusUnauthorized,
			wantDetail:    "Unsupported authentication scheme.",
			wantChallenge: `DPoP algs="ES256"`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			options := []authorizer_request_parser_config.Option{
				authorizer_request_parser_config.WithRequireBoundToken(testCase.requireBoundToken),
				authorizer_request_parser_config.WithProofVerifier(proofVerifier),
			}

			var tokenExtractor request_parser.RequestParser[string]
			switch testCase.extractor {
			case dpopExtractor:
				tokenExtractor = token_extractor.New()
			case dpopOnlyExtractor:
				tokenExtractor = token_extractor.New(token_extractor_config.WithAcceptBearer(false))
			case bearerHeaderExtractor:
				tokenExtractor = token_header_extractor.New()
			}
			if tokenExtractor != nil {
				options = append(
					options,
					authorizer_request_parser_config.WithTokenExtractor(tokenExtractor),
					authorizer_request_parser_config.WithAuthenticationMethods(authentication_method.ApiKey),
				)
			}

			parser, err := New(signer, issuer, audience, options...)
			if err != nil {
				t.Fatalf("%s: new: %v", testCase.name, err)
			}

			sessionToken, responseError := parser.Parse(newDpopRequest(t, "GET", testCase.request))

			if testCase.wantStatus == 0 {
				if responseError != nil {
					t.Fatalf("%s: refused: %+v (%v)", testCase.name, responseError.ProblemDetail, responseError.ClientError)
				}
				if sessionToken == nil {
					t.Fatalf("%s: no token", testCase.name)
				}
				if sessionToken.KeyThumbprint != testCase.wantKeyThumbprint {
					t.Errorf("%s: key thumbprint %q, want %q", testCase.name, sessionToken.KeyThumbprint, testCase.wantKeyThumbprint)
				}
				return
			}

			if responseError == nil {
				t.Fatalf("%s: let through", testCase.name)
			}
			if sessionToken != nil {
				t.Errorf("%s: a token came back with the refusal", testCase.name)
			}
			if responseError.ServerError != nil {
				t.Errorf("%s: a server error: %v", testCase.name, responseError.ServerError)
			}

			problemDetail := responseError.ProblemDetail
			if problemDetail == nil {
				t.Fatalf("%s: no problem detail", testCase.name)
			}
			if problemDetail.Status != testCase.wantStatus {
				t.Errorf("%s: status %d, want %d", testCase.name, problemDetail.Status, testCase.wantStatus)
			}
			if problemDetail.Detail != testCase.wantDetail {
				t.Errorf("%s: detail %q, want %q", testCase.name, problemDetail.Detail, testCase.wantDetail)
			}

			var challenge string
			for _, header := range responseError.Headers {
				if header != nil && header.Name == "WWW-Authenticate" {
					challenge = header.Value
				}
			}
			if testCase.wantChallenge != "" && challenge != testCase.wantChallenge {
				t.Errorf("%s: challenge %q, want %q", testCase.name, challenge, testCase.wantChallenge)
			}
			// A cookie has no challenge to give.
			if testCase.extractor == cookieExtractor {
				if challenge != "" {
					t.Errorf("%s: challenge %q, want none", testCase.name, challenge)
				}
			}
		})
	}
}

func TestParser_Parse_DpopReplay(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}
	signer := &altshiftCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey}

	key := dpopTesting.NewKey()
	boundToken := makeTokenString(signer, dpopTesting.KeyThumbprint(&key.PublicKey), authentication_method.ApiKey)
	proof := dpopTesting.MakeProof(key, "GET", dpopOrigin+dpopPath, boundToken, nil)

	testCases := []struct {
		name           string
		replayDetector proof_verifier_config.ReplayDetector
		wantSecond     string
	}{
		{
			name:           "remembered",
			replayDetector: memory_replay_detector.New(),
			wantSecond:     "The DPoP proof has already been used.",
		},
		{
			// Stateless: the same proof, for the same request, inside its window.
			name: "not remembered",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var verifierOptions []proof_verifier_config.Option
			if testCase.replayDetector != nil {
				verifierOptions = append(verifierOptions, proof_verifier_config.WithReplayDetector(testCase.replayDetector))
			}
			proofVerifier, err := proof_verifier.New([]string{dpopOrigin}, verifierOptions...)
			if err != nil {
				t.Fatalf("%s: proof verifier new: %v", testCase.name, err)
			}

			parser, err := New(
				signer, issuer, audience,
				authorizer_request_parser_config.WithTokenExtractor(token_extractor.New()),
				authorizer_request_parser_config.WithAuthenticationMethods(authentication_method.ApiKey),
				authorizer_request_parser_config.WithProofVerifier(proofVerifier),
			)
			if err != nil {
				t.Fatalf("%s: new: %v", testCase.name, err)
			}

			request := &dpopRequest{authorization: []string{"DPoP " + boundToken}, proofs: []string{proof}}

			if _, responseError := parser.Parse(newDpopRequest(t, "GET", request)); responseError != nil {
				t.Fatalf("%s: first presentation refused: %+v", testCase.name, responseError.ProblemDetail)
			}

			_, responseError := parser.Parse(newDpopRequest(t, "GET", request))
			if testCase.wantSecond == "" {
				if responseError != nil {
					t.Errorf("%s: second presentation refused: %+v", testCase.name, responseError.ProblemDetail)
				}
				return
			}
			if responseError == nil || responseError.ProblemDetail == nil {
				t.Fatalf("%s: second presentation let through", testCase.name)
			}
			if detail := responseError.ProblemDetail.Detail; detail != testCase.wantSecond {
				t.Errorf("%s: detail %q, want %q", testCase.name, detail, testCase.wantSecond)
			}
		})
	}
}

func TestNew_Dpop(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}
	signer := &altshiftCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey}

	proofVerifier, err := proof_verifier.New([]string{dpopOrigin})
	if err != nil {
		t.Fatalf("proof verifier new: %v", err)
	}

	testCases := []struct {
		name    string
		options []authorizer_request_parser_config.Option
		wantErr bool
	}{
		{name: "nothing about DPoP"},
		{
			name: "the DPoP extractor with a verifier",
			options: []authorizer_request_parser_config.Option{
				authorizer_request_parser_config.WithTokenExtractor(token_extractor.New()),
				authorizer_request_parser_config.WithProofVerifier(proofVerifier),
			},
		},
		{
			name: "the DPoP extractor without a verifier",
			options: []authorizer_request_parser_config.Option{
				authorizer_request_parser_config.WithTokenExtractor(token_extractor.New()),
			},
			wantErr: true,
		},
		{
			name: "bound tokens required without a verifier",
			options: []authorizer_request_parser_config.Option{
				authorizer_request_parser_config.WithRequireBoundToken(true),
			},
			wantErr: true,
		},
		{
			name: "bound tokens required with a verifier",
			options: []authorizer_request_parser_config.Option{
				authorizer_request_parser_config.WithTokenExtractor(token_extractor.New()),
				authorizer_request_parser_config.WithRequireBoundToken(true),
				authorizer_request_parser_config.WithProofVerifier(proofVerifier),
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			parser, err := New(signer, issuer, audience, testCase.options...)
			if testCase.wantErr {
				if err == nil {
					t.Errorf("%s: accepted", testCase.name)
				}
				if parser != nil {
					t.Errorf("%s: a parser came back with the error", testCase.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", testCase.name, err)
			}
			if parser == nil {
				t.Fatalf("%s: no parser", testCase.name)
			}
		})
	}
}

var errStoreUnavailable = errors.New("store unavailable")

type failingReplayDetector struct{}

func (failingReplayDetector) Observe(context.Context, string, string, time.Time, time.Time) (bool, error) {
	return false, errStoreUnavailable
}

// A store that cannot say whether a proof is a replay is the service's fault, and answered as one:
// a 401 would tell an honest client its proof was wrong.
func TestParser_Parse_DpopReplayStoreFailure(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}
	signer := &altshiftCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey}

	key := dpopTesting.NewKey()
	boundToken := makeTokenString(signer, dpopTesting.KeyThumbprint(&key.PublicKey), authentication_method.ApiKey)

	testCases := []struct {
		name           string
		replayDetector proof_verifier_config.ReplayDetector
	}{
		{name: "a store that fails", replayDetector: failingReplayDetector{}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			proofVerifier, err := proof_verifier.New(
				[]string{dpopOrigin},
				proof_verifier_config.WithReplayDetector(testCase.replayDetector),
			)
			if err != nil {
				t.Fatalf("%s: proof verifier new: %v", testCase.name, err)
			}

			parser, err := New(
				signer, issuer, audience,
				authorizer_request_parser_config.WithTokenExtractor(token_extractor.New()),
				authorizer_request_parser_config.WithAuthenticationMethods(authentication_method.ApiKey),
				authorizer_request_parser_config.WithProofVerifier(proofVerifier),
			)
			if err != nil {
				t.Fatalf("%s: new: %v", testCase.name, err)
			}

			request := &dpopRequest{
				authorization: []string{"DPoP " + boundToken},
				proofs:        []string{dpopTesting.MakeProof(key, "GET", dpopOrigin+dpopPath, boundToken, nil)},
			}

			sessionToken, responseError := parser.Parse(newDpopRequest(t, "GET", request))
			if sessionToken != nil {
				t.Errorf("%s: let through", testCase.name)
			}
			if responseError == nil || responseError.ServerError == nil {
				t.Fatalf("%s: got %+v, want a server error", testCase.name, responseError)
			}
			if !errors.Is(responseError.ServerError, errStoreUnavailable) {
				t.Errorf("%s: server error %v does not carry the store's", testCase.name, responseError.ServerError)
			}
		})
	}
}
