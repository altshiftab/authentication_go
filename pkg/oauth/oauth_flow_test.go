package oauth_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/altshiftab/authentication_go/pkg/oauth"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/access_token_parser"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/client"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/client_registrar"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/client_resolver"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/endpoint/authorize_endpoint"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/endpoint/decision_endpoint"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/endpoint/registration_endpoint"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/endpoint/revocation_endpoint"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/endpoint/token_endpoint"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/memory_store"
	"github.com/altshiftab/authentication_go/pkg/pkce"
	"github.com/altshiftab/authentication_go/pkg/session/types/session_token"
	altshiftCryptoEddsa "github.com/altshiftab/utils_go/pkg/crypto/eddsa"
	muxPkg "github.com/altshiftab/utils_go/pkg/http/mux"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/request_parser"
	"github.com/altshiftab/utils_go/pkg/http/mux/types/response_error"
	"github.com/altshiftab/utils_go/pkg/http/types/problem_detail"
)

const (
	issuer      = "https://login.example.test"
	resource    = "https://vocab.example.test/mcp"
	clientId    = "https://client.example.test/metadata"
	redirectUri = "https://client.example.test/callback"
	accountId   = "an-account"
	// appClientId is an app on a phone, sent back to by its own scheme.
	appClientId    = "se.vvvp.vocab"
	appRedirectUri = "se.vvvp.vocab:/oauth2redirect"
	otherId        = "another-account"
	// accountHeader stands in for the session: the account it names is signed in.
	accountHeader = "X-Test-Account"
)

// testAuthorizer is the session as the endpoints see it: the account the header names, or nobody.
var testAuthorizer = request_parser.New(func(request *http.Request) (*session_token.Token, *response_error.ResponseError) {
	account := request.Header.Get(accountHeader)
	if account == "" {
		return nil, &response_error.ResponseError{ProblemDetail: problem_detail.New(http.StatusUnauthorized)}
	}
	return &session_token.Token{SubjectId: account}, nil
})

type harness struct {
	server   *httptest.Server
	store    *memory_store.Store
	verifier *access_token_parser.Parser
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519 generate key: %v", err)
	}
	signer := &altshiftCryptoEddsa.Method{PrivateKey: privateKey, PublicKey: publicKey}

	store := memory_store.New(accountId, otherId)
	resources := []*oauth.Resource{{Url: resource, Name: "Vocab", Scopes: []string{"vocab"}}}
	registrar, err := client_registrar.New(bytes.Repeat([]byte{7}, 32), true, client_registrar.GeminiRedirectRules()...)
	if err != nil {
		t.Fatalf("client registrar new: %v", err)
	}
	register := registration_endpoint.New()
	if err := register.Initialize(registrar); err != nil {
		t.Fatalf("registration initialize: %v", err)
	}
	clients := client_resolver.New(nil, registrar,
		&client.Client{Id: clientId, Name: "Test client", RedirectUris: []string{redirectUri}},
		&client.Client{Id: appClientId, Name: "Vocab (Android)", RedirectUris: []string{appRedirectUri}},
	)

	authorize := authorize_endpoint.New()
	if err := authorize.Initialize(testAuthorizer, issuer, clients, store, resources); err != nil {
		t.Fatalf("authorize initialize: %v", err)
	}
	decision := decision_endpoint.New()
	if err := decision.Initialize(testAuthorizer, issuer, store); err != nil {
		t.Fatalf("decision initialize: %v", err)
	}
	token := token_endpoint.New()
	if err := token.Initialize(issuer, signer, "oauth-1", store, resources); err != nil {
		t.Fatalf("token initialize: %v", err)
	}

	revoke := revocation_endpoint.New()
	if err := revoke.Initialize(store); err != nil {
		t.Fatalf("revocation initialize: %v", err)
	}

	verifier, err := access_token_parser.New(&altshiftCryptoEddsa.Method{PublicKey: publicKey}, issuer, resource, "vocab", resource+"/metadata")
	if err != nil {
		t.Fatalf("access token parser new: %v", err)
	}

	server := httptest.NewServer(muxPkg.New(authorize.Endpoint.Endpoint, decision.Endpoint.Endpoint, token.Endpoint.Endpoint, revoke.Endpoint.Endpoint, register.Endpoint.Endpoint))
	t.Cleanup(server.Close)

	return &harness{server: server, store: store, verifier: verifier}
}

// client is the server's own, which no other test's server closes the connections of, following
// no redirect.
func (h *harness) client() *http.Client {
	c := *h.server.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

// reply is what came back to a request, read through.
type reply struct {
	status int
	header http.Header
	body   string
}

func (h *harness) do(t *testing.T, method string, path string, account string, form url.Values) *reply {
	t.Helper()

	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	request, err := http.NewRequestWithContext(t.Context(), method, h.server.URL+path, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if account != "" {
		request.Header.Set(accountHeader, account)
	}

	response, err := h.client().Do(request)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	if response == nil {
		t.Fatal("no response")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	// No endpoint of the flow issues a session, or anything else to be kept by the browser.
	if cookies := response.Header.Values("Set-Cookie"); len(cookies) != 0 {
		t.Errorf("%s %s set a cookie: %v", method, path, cookies)
	}

	return &reply{status: response.StatusCode, header: response.Header, body: string(data)}
}

const verifier = "a-code-verifier-of-at-least-forty-three-characters-xyz"

func authorizeQuery(changes map[string]string) string {
	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientId},
		"redirect_uri":          {redirectUri},
		"state":                 {"a-state"},
		"code_challenge":        {pkce.ChallengeS256(verifier)},
		"code_challenge_method": {"S256"},
		"resource":              {resource},
		"scope":                 {"vocab"},
	}
	for name, value := range changes {
		if value == "" {
			query.Del(name)
		} else {
			query.Set(name, value)
		}
	}
	return authorize_endpoint.DefaultPath + "?" + query.Encode()
}

var requestIdPattern = regexp.MustCompile(`name="request_id" value="([^"]+)"`)

// consent opens the consent page as the account and returns the request it holds.
func (h *harness) consent(t *testing.T, account string) string {
	t.Helper()

	response := h.do(t, http.MethodGet, authorizeQuery(nil), account, nil)
	if response.status != http.StatusOK {
		t.Fatalf("authorize: status %d: %s", response.status, response.body)
	}
	for _, want := range []string{"Test client", "Vocab", "client.example.test"} {
		if !strings.Contains(response.body, want) {
			t.Errorf("the consent page does not name %q: %s", want, response.body)
		}
	}
	if policy := response.header.Get("Content-Security-Policy"); !strings.Contains(policy, "frame-ancestors 'none'") ||
		!strings.Contains(policy, "form-action 'self' https://client.example.test") {
		t.Errorf("the consent page's policy is %q", policy)
	}

	match := requestIdPattern.FindStringSubmatch(response.body)
	if match == nil {
		t.Fatalf("no request id on the consent page: %s", response.body)
	}
	return match[1]
}

// callback is the parameters the user was sent back to the client with.
func callback(t *testing.T, response *reply) url.Values {
	t.Helper()

	if response.status != http.StatusSeeOther {
		t.Fatalf("status %d, want a redirect", response.status)
	}
	location, err := url.Parse(response.header.Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if got := location.Scheme + "://" + location.Host + location.Path; got != redirectUri {
		t.Fatalf("sent back to %s, want %s", got, redirectUri)
	}
	query := location.Query()
	if query.Get("iss") != issuer {
		t.Errorf("iss %q, want %q", query.Get("iss"), issuer)
	}
	return query
}

// token posts the form to the token endpoint: the tokens issued, or the refusal, the other of the
// two left empty.
func (h *harness) token(t *testing.T, form url.Values) (int, *token_endpoint.Response, *token_endpoint.ErrorResponse) {
	t.Helper()

	response := h.do(t, http.MethodPost, token_endpoint.DefaultPath, "", form)
	if response.header.Get("Cache-Control") != "no-store" {
		t.Errorf("token response cache control %q", response.header.Get("Cache-Control"))
	}
	issued, refused := &token_endpoint.Response{}, &token_endpoint.ErrorResponse{}
	parsed := any(refused)
	if response.status == http.StatusOK {
		parsed = issued
	}
	if err := json.Unmarshal([]byte(response.body), parsed); err != nil {
		t.Fatalf("token response: %v: %s", err, response.body)
	}
	return response.status, issued, refused
}

func redeem(code string, changes map[string]string) url.Values {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectUri},
		"client_id":     {clientId},
		"code_verifier": {verifier},
		"resource":      {resource},
	}
	for name, value := range changes {
		if value == "" {
			form.Del(name)
		} else {
			form.Set(name, value)
		}
	}
	return form
}

func refresh(refreshToken string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {clientId}}
}

// authorized is a code the account has authorized the client for.
func (h *harness) authorized(t *testing.T) string {
	t.Helper()

	requestId := h.consent(t, accountId)
	query := callback(t, h.do(t, http.MethodPost, decision_endpoint.DefaultPath, accountId, url.Values{"request_id": {requestId}, "decision": {"allow"}}))
	if query.Get("state") != "a-state" || query.Get("code") == "" {
		t.Fatalf("callback %v", query)
	}
	return query.Get("code")
}

func TestFlow(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	code := h.authorized(t)

	status, issued, refused := h.token(t, redeem(code, nil))
	if status != http.StatusOK {
		t.Fatalf("redeem: %d %+v", status, refused)
	}
	if issued.TokenType != "Bearer" || issued.Scope != "vocab" || issued.RefreshToken == "" || issued.ExpiresIn <= 0 {
		t.Errorf("token response %+v", issued)
	}

	// The resource takes the token, as the account it was issued for.
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, resource, nil)
	request.Header.Set("Authorization", "Bearer "+issued.AccessToken)
	accessToken, responseError := h.verifier.Parse(request)
	if responseError != nil || accessToken == nil || accessToken.Subject != accountId || accessToken.ClientId != clientId {
		t.Fatalf("the resource refused the token: %+v, %+v", accessToken, responseError)
	}

	// A code is redeemed once.
	if status, _, refused := h.token(t, redeem(code, nil)); status != http.StatusBadRequest || refused.Error != "invalid_grant" {
		t.Errorf("the code again: %d %+v", status, refused)
	}

	status, renewed, refused := h.token(t, refresh(issued.RefreshToken))
	if status != http.StatusOK || renewed.RefreshToken == "" || renewed.RefreshToken == issued.RefreshToken {
		t.Fatalf("refresh: %d %+v %+v", status, renewed, refused)
	}

	// The spent token again: the grant is revoked, and with it the token that replaced it.
	if status, _, refused := h.token(t, refresh(issued.RefreshToken)); status != http.StatusBadRequest || refused.Error != "invalid_grant" {
		t.Errorf("the spent refresh token again: %d %+v", status, refused)
	}
	if status, _, refused := h.token(t, refresh(renewed.RefreshToken)); status != http.StatusBadRequest || refused.Error != "invalid_grant" {
		t.Errorf("its successor after the grant was revoked: %d %+v", status, refused)
	}
}

func TestAuthorize_Refusals(t *testing.T) {
	t.Parallel()

	h := newHarness(t)

	testCases := []struct {
		name    string
		changes map[string]string
		account string
		// wantPage is a refusal shown to the user rather than sent to the client.
		wantPage   bool
		wantStatus int
		wantError  string
	}{
		{name: "nobody signed in", changes: nil, wantStatus: http.StatusUnauthorized},
		{name: "an unknown client", changes: map[string]string{"client_id": "https://evil.example/metadata"}, account: accountId, wantPage: true},
		{name: "a redirect uri the client does not have", changes: map[string]string{"redirect_uri": "https://evil.example/callback"}, account: accountId, wantPage: true},
		{name: "no client id", changes: map[string]string{"client_id": ""}, account: accountId, wantPage: true},
		{name: "another response type", changes: map[string]string{"response_type": "token"}, account: accountId, wantError: "unsupported_response_type"},
		{name: "no challenge", changes: map[string]string{"code_challenge": ""}, account: accountId, wantError: "invalid_request"},
		{name: "a plain challenge", changes: map[string]string{"code_challenge_method": "plain"}, account: accountId, wantError: "invalid_request"},
		// OAuth 2.1 has the challenge do what the state did.
		{name: "no state", changes: map[string]string{"state": ""}, account: accountId, wantStatus: http.StatusOK},
		{name: "another resource", changes: map[string]string{"resource": "https://feeds.example.test/mcp"}, account: accountId, wantError: "invalid_target"},
		{name: "a scope the resource lacks", changes: map[string]string{"scope": "admin"}, account: accountId, wantError: "invalid_scope"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			response := h.do(t, http.MethodGet, authorizeQuery(testCase.changes), testCase.account, nil)
			switch {
			case testCase.wantStatus != 0:
				if response.status != testCase.wantStatus {
					t.Errorf("%s: status %d, want %d", testCase.name, response.status, testCase.wantStatus)
				}
			case testCase.wantPage:
				if response.status != http.StatusBadRequest || response.header.Get("Location") != "" || strings.Contains(response.body, "request_id") {
					t.Errorf("%s: status %d, location %q, want a page and no redirect", testCase.name, response.status, response.header.Get("Location"))
				}
			default:
				query := callback(t, response)
				if query.Get("error") != testCase.wantError {
					t.Errorf("%s: callback %v, want error %q", testCase.name, query, testCase.wantError)
				}
				// The client's state goes back with its refusal, where it sent one.
				if _, sentState := testCase.changes["state"]; !sentState && query.Get("state") != "a-state" {
					t.Errorf("%s: callback %v, want the state back", testCase.name, query)
				}
			}
		})
	}
}

func TestDecision(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	answer := func(t *testing.T, account string, requestId string, decision string) *reply {
		t.Helper()
		return h.do(t, http.MethodPost, decision_endpoint.DefaultPath, account, url.Values{"request_id": {requestId}, "decision": {decision}})
	}

	t.Run("denied", func(t *testing.T) {
		t.Parallel()

		response := answer(t, accountId, h.consent(t, accountId), "deny")
		if query := callback(t, response); query.Get("error") != "access_denied" || query.Get("code") != "" || query.Get("state") != "a-state" {
			t.Errorf("callback %v", query)
		}
	})

	t.Run("answered by someone else", func(t *testing.T) {
		t.Parallel()

		response := answer(t, otherId, h.consent(t, accountId), "allow")
		if response.status != http.StatusForbidden || response.header.Get("Location") != "" {
			t.Errorf("status %d, location %q", response.status, response.header.Get("Location"))
		}
	})

	t.Run("answered twice", func(t *testing.T) {
		t.Parallel()

		requestId := h.consent(t, accountId)
		callback(t, answer(t, accountId, requestId, "allow"))
		second := answer(t, accountId, requestId, "allow")
		if second.status != http.StatusBadRequest || second.header.Get("Location") != "" {
			t.Errorf("status %d, location %q", second.status, second.header.Get("Location"))
		}
	})

	t.Run("an unknown request", func(t *testing.T) {
		t.Parallel()

		if response := answer(t, accountId, "never-made", "allow"); response.status != http.StatusBadRequest {
			t.Errorf("status %d", response.status)
		}
	})
}

func TestToken_Refusals(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		changes   map[string]string
		lock      bool
		wantError string
	}{
		{name: "another verifier", changes: map[string]string{"code_verifier": "another-code-verifier-of-at-least-forty-three-characters"}, wantError: "invalid_grant"},
		{name: "another redirect uri", changes: map[string]string{"redirect_uri": "https://client.example.test/other"}, wantError: "invalid_grant"},
		{name: "another client", changes: map[string]string{"client_id": "https://other.example.test/metadata"}, wantError: "invalid_grant"},
		{name: "another resource", changes: map[string]string{"resource": "https://feeds.example.test/mcp"}, wantError: "invalid_target"},
		{name: "no verifier", changes: map[string]string{"code_verifier": ""}, wantError: "invalid_request"},
		{name: "another grant type", changes: map[string]string{"grant_type": "client_credentials"}, wantError: "unsupported_grant_type"},
		{name: "a locked account", lock: true, wantError: "invalid_grant"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			// A harness of its own, the account locked in it locked nowhere else.
			h := newHarness(t)
			code := h.authorized(t)
			if testCase.lock {
				h.store.LockAccount(accountId)
			}

			status, issued, refused := h.token(t, redeem(code, testCase.changes))
			if status == http.StatusOK || refused.Error != testCase.wantError {
				t.Errorf("%s: %d %+v %+v, want %s", testCase.name, status, issued, refused, testCase.wantError)
			}
		})
	}

	t.Run("a repeated parameter", func(t *testing.T) {
		t.Parallel()

		h := newHarness(t)
		form := redeem(h.authorized(t), nil)
		form.Add("code", "another-code")
		if status, _, refused := h.token(t, form); status != http.StatusBadRequest || refused.Error != "invalid_request" {
			t.Errorf("%d %+v", status, refused)
		}
	})
}

// A refresh refused for what it asked costs the client nothing: the token it has still renews.
func TestRefresh_RefusalKeepsToken(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	status, issued, refused := h.token(t, redeem(h.authorized(t), nil))
	if status != http.StatusOK {
		t.Fatalf("redeem: %d %+v", status, refused)
	}

	testCases := []struct {
		name      string
		form      url.Values
		lock      bool
		wantError string
	}{
		{
			name:      "another client",
			form:      url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}, "client_id": {"https://other.example.test/metadata"}},
			wantError: "invalid_grant",
		},
		{
			name:      "another resource",
			form:      url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}, "client_id": {clientId}, "resource": {"https://feeds.example.test/mcp"}},
			wantError: "invalid_target",
		},
		{
			name:      "more scope",
			form:      url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}, "client_id": {clientId}, "scope": {"vocab admin"}},
			wantError: "invalid_scope",
		},
		{name: "a locked account", form: refresh(issued.RefreshToken), lock: true, wantError: "invalid_grant"},
	}
	// In order, on the one token: each refusal must leave it as it was for the next.
	for _, testCase := range testCases {
		if testCase.lock {
			h.store.LockAccount(accountId)
		}
		status, _, refused := h.token(t, testCase.form)
		if testCase.lock {
			h.store.UnlockAccount(accountId)
		}
		if status != http.StatusBadRequest || refused.Error != testCase.wantError {
			t.Errorf("%s: %d %+v, want %s", testCase.name, status, refused, testCase.wantError)
		}
	}

	if status, renewed, refused := h.token(t, refresh(issued.RefreshToken)); status != http.StatusOK || renewed.RefreshToken == "" {
		t.Errorf("the token after the refusals: %d %+v", status, refused)
	}
}

// OAuth 2.1 has the client leave the redirect URI out of the token request, the verifier binding
// the code; one sent is held to the code's.
func TestRedeem_WithoutRedirectUri(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	if status, _, refused := h.token(t, redeem(h.authorized(t), map[string]string{"redirect_uri": ""})); status != http.StatusOK {
		t.Errorf("redeem without a redirect uri: %d %+v", status, refused)
	}
}

// A client giving its grant up, as Claude does when the connector is removed: what renewed it no
// longer does.
func TestRevoke(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	status, issued, refused := h.token(t, redeem(h.authorized(t), nil))
	if status != http.StatusOK {
		t.Fatalf("redeem: %d %+v", status, refused)
	}

	revoked := h.do(t, http.MethodPost, revocation_endpoint.DefaultPath, "", url.Values{"token": {issued.RefreshToken}, "token_type_hint": {"refresh_token"}})
	if revoked.status != http.StatusOK {
		t.Fatalf("revoke: %d %s", revoked.status, revoked.body)
	}
	if status, _, refused := h.token(t, refresh(issued.RefreshToken)); status != http.StatusBadRequest || refused.Error != "invalid_grant" {
		t.Errorf("refresh after revoking: %d %+v", status, refused)
	}
}

// A client that registers itself, as Gemini CLI does, on a loopback port it is answered at: it
// signs the user in with the id it was given, the consent page saying its name is its own word,
// and redeems the code at whatever port it listens on that time.
func TestFlow_RegisteredClient(t *testing.T) {
	t.Parallel()

	h := newHarness(t)

	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, h.server.URL+registration_endpoint.DefaultPath,
		strings.NewReader(`{"client_name":"Gemini CLI","redirect_uris":["http://localhost:7777/oauth/callback"],"token_endpoint_auth_method":"none"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := h.client().Do(request)
	if err != nil || response == nil {
		t.Fatalf("register: %v", err)
	}
	defer response.Body.Close()
	var registered registration_endpoint.Response
	if err := json.UnmarshalRead(response.Body, &registered); err != nil || response.StatusCode != http.StatusCreated {
		t.Fatalf("register: %d, %v", response.StatusCode, err)
	}

	const callback = "http://localhost:53682/oauth/callback"
	query := url.Values{
		"response_type": {"code"}, "client_id": {registered.ClientId}, "redirect_uri": {callback}, "state": {"s"},
		"code_challenge": {pkce.ChallengeS256(verifier)}, "code_challenge_method": {"S256"}, "resource": {resource},
	}
	consent := h.do(t, http.MethodGet, authorize_endpoint.DefaultPath+"?"+query.Encode(), accountId, nil)
	if consent.status != http.StatusOK || !strings.Contains(consent.body, "Gemini CLI, as it calls itself") ||
		!strings.Contains(consent.body, "on this computer") || strings.Contains(consent.body, registered.ClientId) {
		t.Fatalf("consent: %d %s", consent.status, consent.body)
	}
	match := requestIdPattern.FindStringSubmatch(consent.body)
	if match == nil {
		t.Fatalf("no request id: %s", consent.body)
	}

	decided := h.do(t, http.MethodPost, decision_endpoint.DefaultPath, accountId, url.Values{"request_id": {match[1]}, "decision": {"allow"}})
	location, err := url.Parse(decided.header.Get("Location"))
	if err != nil || decided.status != http.StatusSeeOther || location.Host != "localhost:53682" || location.Query().Get("iss") != issuer {
		t.Fatalf("decision: %d %q", decided.status, decided.header.Get("Location"))
	}

	status, issued, refused := h.token(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")}, "client_id": {registered.ClientId},
		"redirect_uri": {callback}, "code_verifier": {verifier},
	})
	if status != http.StatusOK || issued.AccessToken == "" {
		t.Fatalf("redeem: %d %+v", status, refused)
	}

	// An id it was not given is no client's.
	query.Set("client_id", registered.ClientId+"x")
	if forged := h.do(t, http.MethodGet, authorize_endpoint.DefaultPath+"?"+query.Encode(), accountId, nil); forged.status != http.StatusBadRequest ||
		forged.header.Get("Location") != "" {
		t.Errorf("a forged id: %d %q", forged.status, forged.header.Get("Location"))
	}
}

// An app on a phone, a client registered beforehand, is sent back to by its own scheme, which the
// consent page's form may go on to.
func TestFlow_AppScheme(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	query := url.Values{
		"response_type": {"code"}, "client_id": {appClientId}, "redirect_uri": {appRedirectUri}, "state": {"s"},
		"code_challenge": {pkce.ChallengeS256(verifier)}, "code_challenge_method": {"S256"}, "resource": {resource},
	}
	consent := h.do(t, http.MethodGet, authorize_endpoint.DefaultPath+"?"+query.Encode(), accountId, nil)
	if consent.status != http.StatusOK || !strings.Contains(consent.body, "by its link se.vvvp.vocab:") ||
		!strings.Contains(consent.header.Get("Content-Security-Policy"), "form-action 'self' se.vvvp.vocab:;") {
		t.Fatalf("consent: %d %q %s", consent.status, consent.header.Get("Content-Security-Policy"), consent.body)
	}
	match := requestIdPattern.FindStringSubmatch(consent.body)
	if match == nil {
		t.Fatalf("no request id: %s", consent.body)
	}

	decided := h.do(t, http.MethodPost, decision_endpoint.DefaultPath, accountId, url.Values{"request_id": {match[1]}, "decision": {"allow"}})
	location, err := url.Parse(decided.header.Get("Location"))
	if err != nil || decided.status != http.StatusSeeOther || location.Scheme != "se.vvvp.vocab" || location.Path != "/oauth2redirect" ||
		location.Query().Get("code") == "" || location.Query().Get("iss") != issuer {
		t.Fatalf("decision: %d %q", decided.status, decided.header.Get("Location"))
	}

	status, _, refused := h.token(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")}, "client_id": {appClientId},
		"redirect_uri": {appRedirectUri}, "code_verifier": {verifier},
	})
	if status != http.StatusOK {
		t.Errorf("redeem: %d %+v", status, refused)
	}
}
