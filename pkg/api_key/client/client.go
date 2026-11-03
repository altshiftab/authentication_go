// Package client is the holder's side of an API key: the assertion it signs with the private half of
// a key its account registered, wherever that half is kept -- a file, a key manager, a TPM, anything a
// crypto.Signer reaches -- and the exchange of the assertion for a session token at the login
// service's token endpoint.
//
// The assertion is the one package assertion verifies: RFC 7523's shape, typed "api-key+jwt", naming
// the key by its RFC 7638 thumbprint in "iss" and "sub", bound to the login service by "aud", good for
// a minute, and new every time by its "jti".
package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/altshiftab/authentication_go/pkg/api_key/assertion"
	"github.com/altshiftab/authentication_go/pkg/api_key/public_key"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
)

// AssertionLifetime is how long an assertion is good for: one request's worth, well inside what the
// service accepts.
const AssertionLifetime = time.Minute

// TokenPath is where the login service exchanges an assertion for a token.
const TokenPath = "/api/token"

// maxResponseBytes bounds what is read of the service's answer.
const maxResponseBytes = 1 << 20

// Assert signs an assertion for the audience -- the login service's origin -- at the instant now, with
// the key the signer holds the private half of.
func Assert(signer crypto.Signer, audience string, now time.Time) (string, error) {
	if signer == nil {
		return "", altshiftErrors.NewWithTrace(nil_error.New("signer"))
	}
	if audience == "" {
		return "", altshiftErrors.NewWithTrace(empty_error.New("audience"))
	}

	key, err := public_key.FromPublicKey(signer.Public())
	if err != nil {
		return "", altshiftErrors.New(fmt.Errorf("public key from public key: %w", err))
	}

	identifier := make([]byte, 16)
	if _, err := rand.Read(identifier); err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("rand read: %w", err))
	}

	header, err := json.Marshal(map[string]string{"alg": key.Algorithm, "typ": assertion.Type})
	if err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("json marshal (header): %w", err))
	}
	payload, err := json.Marshal(map[string]any{
		"iss": key.Id,
		"sub": key.Id,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(AssertionLifetime).Unix(),
		"jti": base64.RawURLEncoding.EncodeToString(identifier),
	})
	if err != nil {
		return "", altshiftErrors.NewWithTrace(fmt.Errorf("json marshal (payload): %w", err))
	}

	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	signature, err := sign(signer, key.Algorithm, []byte(signingInput))
	if err != nil {
		return "", altshiftErrors.New(fmt.Errorf("sign: %w", err), key.Id)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// ecdsaSignature is the ASN.1 form a crypto.Signer gives an ECDSA signature in.
type ecdsaSignature struct {
	R, S *big.Int
}

// sign is the JWS signature of the input: Ed25519 over the input itself, ES256 over its SHA-256 as the
// two integers side by side at 32 bytes each, which is JWS's form, not the ASN.1 a signer returns.
func sign(signer crypto.Signer, algorithm string, signingInput []byte) ([]byte, error) {
	switch algorithm {
	case public_key.AlgorithmEddsa:
		signature, err := signer.Sign(rand.Reader, signingInput, crypto.Hash(0))
		if err != nil {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("signer sign: %w", err))
		}
		return signature, nil
	case public_key.AlgorithmEs256:
		digest := sha256.Sum256(signingInput)
		der, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("signer sign: %w", err))
		}
		var parsed ecdsaSignature
		rest, err := asn1.Unmarshal(der, &parsed)
		if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil {
			return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: the signature is no ECDSA signature", altshiftErrors.ErrUnexpectedType))
		}
		const size = 32
		signature := make([]byte, 2*size)
		parsed.R.FillBytes(signature[:size])
		parsed.S.FillBytes(signature[size:])
		return signature, nil
	default:
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: %s", altshiftErrors.ErrUnexpectedType, algorithm))
	}
}

// Token is a session token minted against the key, and when it stops being good.
type Token struct {
	AccessToken string
	ExpiresAt   time.Time
}

// Mint exchanges the assertion for a token at the login service's token endpoint.
func Mint(ctx context.Context, httpClient *http.Client, service *url.URL, assertionString string, now time.Time) (*Token, error) {
	if service == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("service"))
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, service.JoinPath(TokenPath).String(), nil)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("http new request with context: %w", err))
	}
	request.Header.Set("Authorization", "Bearer "+assertionString)

	response, err := httpClient.Do(request)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("http client do: %w", err))
	}
	if response == nil || response.Body == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("response"))
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("io read all: %w", err))
	}
	if response.StatusCode != http.StatusOK {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: %d %s", ErrRefused, response.StatusCode, bytes.TrimSpace(body)))
	}

	var answer struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("json unmarshal: %w", err))
	}
	if answer.AccessToken == "" || answer.ExpiresIn <= 0 {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: no token", ErrRefused))
	}
	return &Token{AccessToken: answer.AccessToken, ExpiresAt: now.Add(time.Duration(answer.ExpiresIn) * time.Second)}, nil
}

// Source is a token kept until near its end and minted again then: what a job that calls a service
// now and again holds rather than minting for every call.
type Source struct {
	Signer     crypto.Signer
	Service    *url.URL
	HttpClient *http.Client
	// Margin is how long before its end a token is no longer handed out; a minute if not given.
	Margin time.Duration
	// Now is the clock; time.Now if not given.
	Now func() time.Time

	mutex   sync.Mutex
	current *Token
}

// Token is a token good for at least the margin, the one kept if it still is.
func (s *Source) Token(ctx context.Context) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	margin := s.Margin
	if margin == 0 {
		margin = time.Minute
	}
	if s.current != nil && now.Add(margin).Before(s.current.ExpiresAt) {
		return s.current.AccessToken, nil
	}
	if s.Service == nil {
		return "", altshiftErrors.NewWithTrace(nil_error.New("service"))
	}

	// The assertion names the login service by its origin, the issuer its tokens carry.
	origin := &url.URL{Scheme: s.Service.Scheme, Host: s.Service.Host}
	assertionString, err := Assert(s.Signer, origin.String(), now)
	if err != nil {
		return "", altshiftErrors.New(fmt.Errorf("assert: %w", err))
	}
	token, err := Mint(ctx, s.HttpClient, s.Service, assertionString, now)
	if err != nil {
		return "", altshiftErrors.New(fmt.Errorf("mint: %w", err))
	}
	s.current = token
	return token.AccessToken, nil
}
