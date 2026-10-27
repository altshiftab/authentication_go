package proof_verifier

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	dpopErrors "github.com/altshiftab/authentication_go/pkg/dpop/errors"
	dpopTesting "github.com/altshiftab/authentication_go/pkg/dpop/testing"
	"github.com/altshiftab/authentication_go/pkg/dpop/types/memory_replay_detector"
	"github.com/altshiftab/authentication_go/pkg/dpop/types/proof_verifier/proof_verifier_config"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
)

const (
	origin      = "https://api.example.com"
	otherOrigin = "https://api.example.net"
	path        = "/resource"
	accessToken = "header.payload.signature"
)

var now = time.Unix(1_800_000_000, 0)

func makeProof(
	key *ecdsa.PrivateKey,
	method string,
	htu string,
	accessToken string,
	mutate func(header map[string]any, payload map[string]any),
) string {
	return dpopTesting.MakeProof(key, method, htu, accessToken, func(header map[string]any, payload map[string]any) {
		payload["iat"] = now.Unix()
		if mutate != nil {
			mutate(header, payload)
		}
	})
}

func setClaim(name string, value any) func(map[string]any, map[string]any) {
	return func(_ map[string]any, payload map[string]any) {
		if value == nil {
			delete(payload, name)
			return
		}
		payload[name] = value
	}
}

func setHeader(name string, value any) func(map[string]any, map[string]any) {
	return func(header map[string]any, _ map[string]any) {
		if value == nil {
			delete(header, name)
			return
		}
		header[name] = value
	}
}

func TestVerifier_Verify(t *testing.T) {
	t.Parallel()

	key := dpopTesting.NewKey()
	otherKey := dpopTesting.NewKey()
	thumbprint := dpopTesting.KeyThumbprint(&key.PublicKey)

	verifier, err := New([]string{origin, otherOrigin})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	withPrivateKey := dpopTesting.Jwk(&key.PublicKey)
	withPrivateKey["d"] = withPrivateKey["x"]

	testCases := []struct {
		name          string
		proof         string
		method        string
		accessToken   string
		keyThumbprint string
		// The request's URL, when it is not the default path.
		requestUrl *url.URL
		// The class of the refusal, nil for a proof that is accepted.
		wantErr error
		// What the refusal must say, so that a case cannot pass on a fault other than its own.
		wantErrContains string
		wantNonce       string
	}{
		{
			name:  "a proof for a token endpoint",
			proof: makeProof(key, "POST", origin+path, "", nil),
		},
		{
			name:        "a proof for a resource",
			proof:       makeProof(key, "GET", origin+path, accessToken, nil),
			method:      "GET",
			accessToken: accessToken,
		},
		{
			name:          "a proof by the key the token is bound to",
			proof:         makeProof(key, "GET", origin+path, accessToken, nil),
			method:        "GET",
			accessToken:   accessToken,
			keyThumbprint: thumbprint,
		},
		{
			name:            "the empty string",
			proof:           "",
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "proof",
		},
		{
			name:            "not a JWT",
			proof:           "not a jwt",
			wantErr:         altshiftErrors.ErrParseError,
			wantErrContains: "jwt token new",
		},
		{
			name:            "longer than allowed",
			proof:           makeProof(key, "POST", origin+path, "", setClaim("padding", strings.Repeat("x", 4096))),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "longer than",
		},
		{
			name:            "no typ",
			proof:           makeProof(key, "POST", origin+path, "", setHeader("typ", nil)),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "(typ)",
		},
		{
			// An access token or an assertion is not a proof, whoever signed it.
			name:            "another typ",
			proof:           makeProof(key, "POST", origin+path, "", setHeader("typ", "JWT")),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "typ",
		},
		{
			name:  "the typ in upper case",
			proof: makeProof(key, "POST", origin+path, "", setHeader("typ", "DPOP+JWT")),
		},
		{
			name:            "alg none",
			proof:           makeProof(key, "POST", origin+path, "", setHeader("alg", "none")),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "alg",
		},
		{
			name:            "alg HS256",
			proof:           makeProof(key, "POST", origin+path, "", setHeader("alg", "HS256")),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "alg",
		},
		{
			name:            "alg ES384",
			proof:           makeProof(key, "POST", origin+path, "", setHeader("alg", "ES384")),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "alg",
		},
		{
			name:            "no jwk",
			proof:           makeProof(key, "POST", origin+path, "", setHeader("jwk", nil)),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "(jwk)",
		},
		{
			name:            "a jwk holding the private key",
			proof:           makeProof(key, "POST", origin+path, "", setHeader("jwk", withPrivateKey)),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "private key",
		},
		{
			name:            "a signature by a key other than the jwk",
			proof:           makeProof(key, "POST", origin+path, "", setHeader("jwk", dpopTesting.Jwk(&otherKey.PublicKey))),
			wantErr:         altshiftErrors.ErrVerificationError,
			wantErrContains: "authenticated token new",
		},
		{
			name:            "a proof by a key the token is not bound to",
			proof:           makeProof(otherKey, "GET", origin+path, accessToken, nil),
			method:          "GET",
			accessToken:     accessToken,
			keyThumbprint:   thumbprint,
			wantErr:         dpopErrors.ErrKeyMismatch,
			wantErrContains: "binding",
		},
		{
			// The binding is checked first, so a proof by the wrong key says so whatever else is
			// wrong with it.
			name:            "a proof by another key, whose signature would also fail",
			proof:           makeProof(key, "GET", origin+path, accessToken, setHeader("jwk", dpopTesting.Jwk(&otherKey.PublicKey))),
			method:          "GET",
			accessToken:     accessToken,
			keyThumbprint:   thumbprint,
			wantErr:         dpopErrors.ErrKeyMismatch,
			wantErrContains: "binding",
		},
		{
			name:            "another method",
			proof:           makeProof(key, "GET", origin+path, "", nil),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "htm",
		},
		{
			name:            "the method in lower case",
			proof:           makeProof(key, "post", origin+path, "", nil),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "htm",
		},
		{
			name:            "no htm",
			proof:           makeProof(key, "POST", origin+path, "", setClaim("htm", nil)),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "(htm)",
		},
		{
			name:            "another host",
			proof:           makeProof(key, "POST", "https://evil.example.com"+path, "", nil),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "another origin",
		},
		{
			name:            "another scheme",
			proof:           makeProof(key, "POST", "http://api.example.com"+path, "", nil),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "another origin",
		},
		{
			name:            "another port",
			proof:           makeProof(key, "POST", "https://api.example.com:8443"+path, "", nil),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "another origin",
		},
		{
			name:            "another path",
			proof:           makeProof(key, "POST", origin+"/other", "", nil),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "htu path",
		},
		{
			// One segment holding a slash is not two segments: a router sends them to different
			// handlers, so a proof for one is not good for the other.
			name:            "an encoded slash, for a request with a plain one",
			proof:           makeProof(key, "POST", origin+"/items/a%2Fb", "", nil),
			requestUrl:      &url.URL{Path: "/items/a/b"},
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "htu path",
		},
		{
			name:       "an encoded slash, for a request with the same",
			proof:      makeProof(key, "POST", origin+"/items/a%2Fb", "", nil),
			requestUrl: &url.URL{Path: "/items/a/b", RawPath: "/items/a%2Fb"},
		},
		{
			name:       "an encoding in lower case, for the same in upper case",
			proof:      makeProof(key, "POST", origin+"/items/a%2fb", "", nil),
			requestUrl: &url.URL{Path: "/items/a/b", RawPath: "/items/a%2Fb"},
		},
		{
			name:       "an unreserved character encoded, for the same written plainly",
			proof:      makeProof(key, "POST", origin+"/%7Euser", "", nil),
			requestUrl: &url.URL{Path: "/~user"},
		},
		{
			name:  "a query and a fragment, which are not part of it",
			proof: makeProof(key, "POST", origin+path+"?a=b#c", "", nil),
		},
		{
			name:  "the host in upper case and the default port spelled out",
			proof: makeProof(key, "POST", "HTTPS://API.EXAMPLE.COM:443"+path, "", nil),
		},
		{
			name:  "the second configured origin",
			proof: makeProof(key, "POST", otherOrigin+path, "", nil),
		},
		{
			name:            "a relative htu",
			proof:           makeProof(key, "POST", path, "", nil),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "absolute",
		},
		{
			name:            "an htu with user information",
			proof:           makeProof(key, "POST", "https://user@api.example.com"+path, "", nil),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "absolute",
		},
		{
			name:            "no htu",
			proof:           makeProof(key, "POST", origin+path, "", setClaim("htu", nil)),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "(htu)",
		},
		{
			name:            "older than the window",
			proof:           makeProof(key, "POST", origin+path, "", setClaim("iat", now.Add(-21*time.Second).Unix())),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "too old",
		},
		{
			// The maximum age and the clock skew together.
			name:  "at the start of the window",
			proof: makeProof(key, "POST", origin+path, "", setClaim("iat", now.Add(-20*time.Second).Unix())),
		},
		{
			name:            "further ahead than the clock skew",
			proof:           makeProof(key, "POST", origin+path, "", setClaim("iat", now.Add(11*time.Second).Unix())),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "future",
		},
		{
			name:  "ahead by less than the clock skew",
			proof: makeProof(key, "POST", origin+path, "", setClaim("iat", now.Add(5*time.Second).Unix())),
		},
		{
			name:            "an iat far out of range",
			proof:           makeProof(key, "POST", origin+path, "", setClaim("iat", 1e300)),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "future",
		},
		{
			name:            "no iat",
			proof:           makeProof(key, "POST", origin+path, "", setClaim("iat", nil)),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "(iat)",
		},
		{
			name:            "an iat that is a string",
			proof:           makeProof(key, "POST", origin+path, "", setClaim("iat", "1800000000")),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "(iat)",
		},
		{
			name:            "no jti",
			proof:           makeProof(key, "POST", origin+path, "", setClaim("jti", nil)),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "(jti)",
		},
		{
			name:            "an empty jti",
			proof:           makeProof(key, "POST", origin+path, "", setClaim("jti", "")),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "jti",
		},
		{
			name:            "a jti longer than allowed",
			proof:           makeProof(key, "POST", origin+path, "", setClaim("jti", strings.Repeat("x", 257))),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "too long",
		},
		{
			name:            "no ath, with a token",
			proof:           makeProof(key, "GET", origin+path, "", nil),
			method:          "GET",
			accessToken:     accessToken,
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "names no access token",
		},
		{
			name:            "the ath of another token",
			proof:           makeProof(key, "GET", origin+path, "other.access.token", nil),
			method:          "GET",
			accessToken:     accessToken,
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "another access token",
		},
		{
			// Made for a resource request, presented to a token endpoint.
			name:            "an ath, without a token",
			proof:           makeProof(key, "POST", origin+path, accessToken, nil),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "where there is none",
		},
		{
			name:      "a nonce, carried through",
			proof:     makeProof(key, "POST", origin+path, "", setClaim("nonce", "server-nonce")),
			wantNonce: "server-nonce",
		},
		{
			name:            "a nonce that is not a string",
			proof:           makeProof(key, "POST", origin+path, "", setClaim("nonce", 1.0)),
			wantErr:         altshiftErrors.ErrValidationError,
			wantErrContains: "nonce",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			method := testCase.method
			if method == "" {
				method = "POST"
			}
			requestUrl := testCase.requestUrl
			if requestUrl == nil {
				requestUrl = &url.URL{Path: path}
			}

			proof, err := verifier.Verify(
				t.Context(),
				&Input{
					Proof:         testCase.proof,
					Method:        method,
					Url:           requestUrl,
					AccessToken:   testCase.accessToken,
					KeyThumbprint: testCase.keyThumbprint,
				},
				now,
			)

			if testCase.wantErr == nil {
				if err != nil {
					t.Fatalf("%s: unexpected error: %v", testCase.name, err)
				}
				if proof == nil {
					t.Fatalf("%s: no proof", testCase.name)
				}
				wantThumbprint := thumbprint
				if proof.KeyThumbprint != wantThumbprint {
					t.Errorf("%s: thumbprint %q, want %q", testCase.name, proof.KeyThumbprint, wantThumbprint)
				}
				if proof.PublicKey == nil || !proof.PublicKey.Equal(&key.PublicKey) {
					t.Errorf("%s: the public key is not the one that signed", testCase.name)
				}
				if proof.Id == "" {
					t.Errorf("%s: no id", testCase.name)
				}
				if proof.IssuedAt == nil {
					t.Errorf("%s: no issued at", testCase.name)
				}
				if proof.Nonce != testCase.wantNonce {
					t.Errorf("%s: nonce %q, want %q", testCase.name, proof.Nonce, testCase.wantNonce)
				}
				return
			}

			if err == nil {
				t.Fatalf("%s: accepted", testCase.name)
			}
			if proof != nil {
				t.Errorf("%s: a proof came back with the refusal", testCase.name)
			}
			if !errors.Is(err, testCase.wantErr) {
				t.Errorf("%s: error %v is not %v", testCase.name, err, testCase.wantErr)
			}
			if !strings.Contains(err.Error(), testCase.wantErrContains) {
				t.Errorf("%s: error %q does not mention %q", testCase.name, err, testCase.wantErrContains)
			}
		})
	}
}

var errStoreUnavailable = errors.New("store unavailable")

// countingReplayDetector records what it is asked, and fails when told to.
type countingReplayDetector struct {
	observed int
	err      error
}

func (d *countingReplayDetector) Observe(context.Context, string, string, time.Time, time.Time) (bool, error) {
	d.observed++
	return false, d.err
}

func TestVerifier_Verify_Replay(t *testing.T) {
	t.Parallel()

	key := dpopTesting.NewKey()
	otherKey := dpopTesting.NewKey()
	thumbprint := dpopTesting.KeyThumbprint(&key.PublicKey)

	verify := func(verifier *Verifier, proof string) error {
		_, err := verifier.Verify(
			t.Context(),
			&Input{Proof: proof, Method: "GET", Url: &url.URL{Path: path}, AccessToken: accessToken, KeyThumbprint: thumbprint},
			now,
		)
		return err
	}

	testCases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "a proof presented twice",
			run: func(t *testing.T) {
				verifier, err := New([]string{origin}, proof_verifier_config.WithReplayDetector(memory_replay_detector.New()))
				if err != nil {
					t.Fatalf("new: %v", err)
				}
				proof := makeProof(key, "GET", origin+path, accessToken, nil)

				if err := verify(verifier, proof); err != nil {
					t.Fatalf("first presentation: %v", err)
				}
				err = verify(verifier, proof)
				if !errors.Is(err, dpopErrors.ErrReplayedProof) {
					t.Errorf("second presentation: got %v, want %v", err, dpopErrors.ErrReplayedProof)
				}
				if !errors.Is(err, altshiftErrors.ErrVerificationError) {
					t.Errorf("second presentation: %v is not a verification error", err)
				}
			},
		},
		{
			// Without a detector the verifier is stateless, and a proof can be presented again
			// within its window, for the request it was made for.
			name: "a proof presented twice, with nothing remembering it",
			run: func(t *testing.T) {
				verifier, err := New([]string{origin})
				if err != nil {
					t.Fatalf("new: %v", err)
				}
				proof := makeProof(key, "GET", origin+path, accessToken, nil)

				for i := range 2 {
					if err := verify(verifier, proof); err != nil {
						t.Fatalf("presentation %d: %v", i, err)
					}
				}
			},
		},
		{
			// A party with any key pair can make a proof that verifies; only one by the bound key
			// is allowed to take up room in the store.
			name: "a proof by another key is not stored",
			run: func(t *testing.T) {
				detector := &countingReplayDetector{}
				verifier, err := New([]string{origin}, proof_verifier_config.WithReplayDetector(detector))
				if err != nil {
					t.Fatalf("new: %v", err)
				}

				if err := verify(verifier, makeProof(otherKey, "GET", origin+path, accessToken, nil)); err == nil {
					t.Fatal("a proof by another key was accepted")
				}
				if detector.observed != 0 {
					t.Errorf("the detector was asked %d times", detector.observed)
				}
			},
		},
		{
			// A store that fails is the service's fault: answering 4xx would tell an honest client
			// its proof was wrong.
			name: "a detector that fails",
			run: func(t *testing.T) {
				detector := &countingReplayDetector{err: errStoreUnavailable}
				verifier, err := New([]string{origin}, proof_verifier_config.WithReplayDetector(detector))
				if err != nil {
					t.Fatalf("new: %v", err)
				}

				err = verify(verifier, makeProof(key, "GET", origin+path, accessToken, nil))
				if err == nil {
					t.Fatal("accepted")
				}
				if altshiftErrors.IsAny(
					err,
					altshiftErrors.ErrParseError,
					altshiftErrors.ErrValidationError,
					altshiftErrors.ErrVerificationError,
				) {
					t.Errorf("a store failure was reported as a client error: %v", err)
				}
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			testCase.run(t)
		})
	}
}

func TestVerifier_VerifyRequest(t *testing.T) {
	t.Parallel()

	key := dpopTesting.NewKey()

	verifier, err := New([]string{origin})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	testCases := []struct {
		name    string
		proofs  []string
		wantErr error
	}{
		{
			name:   "one proof",
			proofs: []string{dpopTesting.MakeProof(key, "POST", origin+path, "", nil)},
		},
		{
			name:    "no proof",
			wantErr: dpopErrors.ErrMissingProof,
		},
		{
			name: "two proofs",
			proofs: []string{
				dpopTesting.MakeProof(key, "POST", origin+path, "", nil),
				dpopTesting.MakeProof(key, "POST", origin+path, "", nil),
			},
			wantErr: dpopErrors.ErrMultipleProofs,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, origin+path+"?x=y", nil)
			for _, proof := range testCase.proofs {
				// Added under the name RFC 9449 writes, which Go files under "Dpop".
				request.Header.Add("DPoP", proof)
			}

			proof, err := verifier.VerifyRequest(t.Context(), request, "", "")

			if testCase.wantErr == nil {
				if err != nil {
					t.Fatalf("%s: unexpected error: %v", testCase.name, err)
				}
				if proof == nil {
					t.Fatalf("%s: no proof", testCase.name)
				}
				return
			}

			if !errors.Is(err, testCase.wantErr) {
				t.Errorf("%s: got %v, want %v", testCase.name, err, testCase.wantErr)
			}
			if !errors.Is(err, altshiftErrors.ErrValidationError) {
				t.Errorf("%s: %v is not a validation error", testCase.name, err)
			}
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	key := dpopTesting.NewKey()

	testCases := []struct {
		name    string
		origins []string
		options []proof_verifier_config.Option
		wantErr bool
	}{
		{name: "an origin", origins: []string{origin}},
		{name: "an origin with a trailing slash", origins: []string{origin + "/"}},
		{
			// Normalised as the proofs are, so the proof made for origin below is accepted.
			name:    "an origin in upper case with its default port",
			origins: []string{"HTTPS://API.EXAMPLE.COM:443"},
		},
		{name: "no origins", wantErr: true},
		{name: "an origin with a path", origins: []string{origin + "/api"}, wantErr: true},
		{name: "an origin with a query", origins: []string{origin + "?a=b"}, wantErr: true},
		{name: "an origin with a fragment", origins: []string{origin + "#a"}, wantErr: true},
		{name: "an origin with user information", origins: []string{"https://user@api.example.com"}, wantErr: true},
		{name: "an origin of another scheme", origins: []string{"ftp://api.example.com"}, wantErr: true},
		{name: "an origin without a host", origins: []string{"https://"}, wantErr: true},
		{
			name:    "no maximum age",
			origins: []string{origin},
			options: []proof_verifier_config.Option{proof_verifier_config.WithMaxAge(0)},
			wantErr: true,
		},
		{
			name:    "a negative clock skew",
			origins: []string{origin},
			options: []proof_verifier_config.Option{proof_verifier_config.WithClockSkew(-time.Second)},
			wantErr: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			verifier, err := New(testCase.origins, testCase.options...)

			if testCase.wantErr {
				if err == nil {
					t.Errorf("%s: accepted", testCase.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", testCase.name, err)
			}

			if _, err := verifier.Verify(
				t.Context(),
				&Input{Proof: makeProof(key, "POST", origin+path, "", nil), Method: "POST", Url: &url.URL{Path: path}},
				now,
			); err != nil {
				t.Errorf("%s: a proof for the origin was refused: %v", testCase.name, err)
			}
		})
	}
}
