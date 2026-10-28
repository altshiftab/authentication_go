// Package client_registrar is dynamic client registration (RFC 7591) without a store: a client's id
// is what it registered, signed, and resolving it is checking the signature and reading it back.
//
// Registration is open, as the RFC has it, so what decides which applications can ask is where they
// may be sent back to: a loopback address, which only an application on the user's own machine
// listens on, or an address matching a rule the server is configured with -- Gemini's, say. A
// registration naming any other is refused, and with it whatever site would have received the code.
//
// Nothing is kept, so a client registering again on every sign-in, as Gemini CLI does, costs
// nothing; and a key that changes makes every id issued under the old one unknown, after which the
// clients register again.
package client_registrar

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/altshiftab/authentication_go/pkg/oauth/types/client"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
)

const (
	// IdPrefix begins every id the registrar issues, which is how one is told from a URL or a
	// static id.
	IdPrefix = "dcr."
	// MinKeyLength is the shortest key the ids are signed with.
	MinKeyLength = 32

	maxRedirectUris   = 10
	maxRedirectUriLen = 512
	maxClientNameLen  = 100
)

var (
	ErrInvalidRedirectUri = errors.New("invalid redirect uri")
	ErrInvalidMetadata    = errors.New("invalid client metadata")
	ErrUnknownClient      = errors.New("unknown client")
	ErrKeyTooShort        = errors.New("key too short")
)

// RedirectRule is an address a registered client may be sent back to: https, on the host, at a path
// that is the prefix followed by one segment, with no query, fragment, port or user.
type RedirectRule struct {
	Host       string
	PathPrefix string
}

func (r *RedirectRule) matches(u *url.URL) bool {
	if u.Scheme != "https" || u.Host != r.Host || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	rest, ok := strings.CutPrefix(u.EscapedPath(), r.PathPrefix)
	return ok && rest != "" && !strings.ContainsAny(rest, "/?#%") && rest != "." && rest != ".."
}

// GeminiRedirectRules are where the Gemini app's custom MCP connectors are sent back to: a path of
// their own per user and server, on Google's redirect hosts. The hosts are matched whole, never by
// suffix: googleusercontent.com serves what users upload.
func GeminiRedirectRules() []*RedirectRule {
	return []*RedirectRule{
		{Host: "oauth-redirect.googleusercontent.com", PathPrefix: "/r/user_bound_custom-mcp-"},
		{Host: "oauth-redirect-sandbox.googleusercontent.com", PathPrefix: "/r/user_bound_custom-mcp-"},
	}
}

// Metadata is a registration request's client metadata (RFC 7591 section 2), as much of it as a
// public client using the authorization code flow has.
type Metadata struct {
	RedirectUris            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name,omitzero"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitzero"`
	GrantTypes              []string `json:"grant_types,omitzero"`
	ResponseTypes           []string `json:"response_types,omitzero"`
}

// registration is what an id carries.
type registration struct {
	Name         string   `json:"n"`
	RedirectUris []string `json:"r"`
	IssuedAt     int64    `json:"t"`
}

type Registrar struct {
	key           []byte
	allowLoopback bool
	rules         []*RedirectRule
	now           func() time.Time
}

// New is a registrar signing ids with the key, letting clients register loopback addresses if
// allowLoopback, and the addresses of the rules.
func New(key []byte, allowLoopback bool, rules ...*RedirectRule) (*Registrar, error) {
	if len(key) < MinKeyLength {
		return nil, altshiftErrors.NewWithTrace(ErrKeyTooShort, len(key))
	}
	var kept []*RedirectRule
	for _, rule := range rules {
		if rule == nil {
			continue
		}
		if rule.Host == "" || !strings.HasPrefix(rule.PathPrefix, "/") {
			return nil, altshiftErrors.NewWithTrace(empty_error.New("redirect rule"), rule.Host, rule.PathPrefix)
		}
		kept = append(kept, rule)
	}
	return &Registrar{key: append([]byte(nil), key...), allowLoopback: allowLoopback, rules: kept, now: time.Now}, nil
}

func (r *Registrar) allowsRedirect(raw string) bool {
	if len(raw) > maxRedirectUriLen {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" {
		return false
	}
	if client.IsLoopback(u) {
		return r.allowLoopback && u.RawQuery == "" && u.Opaque == ""
	}
	for _, rule := range r.rules {
		if rule.matches(u) {
			return true
		}
	}
	return false
}

// RefusalError is a registration refused, and why, in words a client can be told.
type RefusalError struct {
	Sentinel error
	Reason   string
}

func (e *RefusalError) Error() string {
	return e.Sentinel.Error() + ": " + e.Reason
}

func (e *RefusalError) Unwrap() []error {
	return []error{altshiftErrors.ErrValidationError, e.Sentinel}
}

func invalid(sentinel error, reason string) error {
	return altshiftErrors.NewWithTrace(&RefusalError{Sentinel: sentinel, Reason: reason})
}

// Register is the client the metadata registers, with its id and when it was issued. A refusal is
// a *RefusalError of ErrInvalidRedirectUri or ErrInvalidMetadata.
func (r *Registrar) Register(metadata *Metadata) (*client.Client, int64, error) {
	if metadata == nil {
		return nil, 0, invalid(ErrInvalidMetadata, "no metadata")
	}
	if method := metadata.TokenEndpointAuthMethod; method != "" && method != "none" {
		return nil, 0, invalid(ErrInvalidMetadata, fmt.Sprintf("token endpoint auth method %q: only public clients register", method))
	}
	for _, grantType := range metadata.GrantTypes {
		if grantType != "authorization_code" && grantType != "refresh_token" {
			return nil, 0, invalid(ErrInvalidMetadata, fmt.Sprintf("grant type %q", grantType))
		}
	}
	for _, responseType := range metadata.ResponseTypes {
		if responseType != "code" {
			return nil, 0, invalid(ErrInvalidMetadata, fmt.Sprintf("response type %q", responseType))
		}
	}
	name := strings.TrimSpace(metadata.ClientName)
	if len([]rune(name)) > maxClientNameLen {
		return nil, 0, invalid(ErrInvalidMetadata, "client name too long")
	}
	if len(metadata.RedirectUris) == 0 || len(metadata.RedirectUris) > maxRedirectUris {
		return nil, 0, invalid(ErrInvalidRedirectUri, fmt.Sprintf("%d redirect uris", len(metadata.RedirectUris)))
	}
	for _, redirectUri := range metadata.RedirectUris {
		if !r.allowsRedirect(redirectUri) {
			return nil, 0, invalid(ErrInvalidRedirectUri, fmt.Sprintf("%q is not an address a registered client may be sent back to", redirectUri))
		}
	}
	if name == "" {
		name = "An unnamed application"
	}

	issuedAt := r.now().Unix()
	payload, err := json.Marshal(&registration{Name: name, RedirectUris: metadata.RedirectUris, IssuedAt: issuedAt})
	if err != nil {
		return nil, 0, altshiftErrors.NewWithTrace(fmt.Errorf("json marshal (registration): %w", err))
	}
	signed := IdPrefix + base64.RawURLEncoding.EncodeToString(payload)
	id := signed + "." + base64.RawURLEncoding.EncodeToString(r.sign(signed))

	return &client.Client{Id: id, Name: name, RedirectUris: metadata.RedirectUris, SelfRegistered: true}, issuedAt, nil
}

func (r *Registrar) sign(signed string) []byte {
	mac := hmac.New(sha256.New, r.key)
	mac.Write([]byte(signed))
	return mac.Sum(nil)
}

// Allows says whether the id is of the form the registrar issues; whether it issued it is for
// Resolve.
func (r *Registrar) Allows(clientId string) bool {
	return strings.HasPrefix(clientId, IdPrefix)
}

// Resolve is the client the id registered, if the registrar issued it, with the redirect URIs it
// registered that the rules still allow: the rules are what is in force, not what they were when it
// registered. One with none left, as one not issued, is ErrUnknownClient.
func (r *Registrar) Resolve(clientId string) (*client.Client, error) {
	unknown := altshiftErrors.NewWithTrace(fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, ErrUnknownClient))

	// The prefix, the payload, a dot, and the signature of the two before it.
	rest, found := strings.CutPrefix(clientId, IdPrefix)
	if !found {
		return nil, unknown
	}
	encodedPayload, encodedSignature, cut := strings.Cut(rest, ".")
	if !cut {
		return nil, unknown
	}

	given, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil || !hmac.Equal(given, r.sign(IdPrefix+encodedPayload)) {
		return nil, unknown
	}
	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, unknown
	}
	var registered registration
	if err := json.Unmarshal(payload, &registered); err != nil {
		return nil, unknown
	}
	var allowed []string
	for _, redirectUri := range registered.RedirectUris {
		if r.allowsRedirect(redirectUri) {
			allowed = append(allowed, redirectUri)
		}
	}
	if len(allowed) == 0 {
		return nil, unknown
	}

	return &client.Client{Id: clientId, Name: registered.Name, RedirectUris: allowed, SelfRegistered: true}, nil
}
