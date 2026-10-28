package revocation_endpoint

import (
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/altshiftab/authentication_go/pkg/oauth"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/memory_store"
	muxResponse "github.com/altshiftab/utils_go/pkg/http/mux/types/response"
)

func TestEndpoint(t *testing.T) {
	t.Parallel()

	const accountId = "an-account"
	now := time.Now()
	store := memory_store.New(accountId)
	grant := func(refreshToken string) string {
		id, err := store.InsertGrant(t.Context(), &oauth.Grant{AccountId: accountId, ClientId: "a-client", Resource: "r", Scope: "vocab", CreatedAt: now},
			oauth.HashSecret(refreshToken), now.Add(time.Hour))
		if err != nil {
			t.Fatalf("insert grant: %v", err)
		}
		return id
	}
	revokedGrant := grant("a-refresh-token")
	keptGrant := grant("another-refresh-token")

	endpoint := New()
	if err := endpoint.Initialize(store); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	testCases := []struct {
		name       string
		body       string
		wantStatus int
		wantError  string
	}{
		{name: "a refresh token", body: url.Values{"token": {"a-refresh-token"}, "token_type_hint": {"refresh_token"}}.Encode(), wantStatus: http.StatusOK},
		{name: "the same again", body: url.Values{"token": {"a-refresh-token"}}.Encode(), wantStatus: http.StatusOK},
		{name: "a token not known", body: url.Values{"token": {"eyJ.an.access-token"}, "token_type_hint": {"access_token"}}.Encode(), wantStatus: http.StatusOK},
		{name: "no token", body: url.Values{"client_id": {"a-client"}}.Encode(), wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "a token twice", body: "token=a&token=b", wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
		{name: "no form", body: "%zz", wantStatus: http.StatusBadRequest, wantError: "invalid_request"},
	}

	for _, testCase := range testCases {
		response, responseError := endpoint.Handler(httptest.NewRequestWithContext(t.Context(), http.MethodPost, DefaultPath, nil), []byte(testCase.body))
		if responseError != nil || response == nil {
			t.Fatalf("%s: handler: %+v", testCase.name, responseError)
		}
		status := response.StatusCode
		if status == 0 {
			status = http.StatusOK
		}
		if status != testCase.wantStatus {
			t.Errorf("%s: status %d, want %d", testCase.name, status, testCase.wantStatus)
		}
		if testCase.wantError != "" {
			var refused ErrorResponse
			if err := json.Unmarshal(response.Body, &refused); err != nil || refused.Error != testCase.wantError {
				t.Errorf("%s: body %s, want %s", testCase.name, response.Body, testCase.wantError)
			}
		}
		if !slices.ContainsFunc(response.Headers, func(header *muxResponse.HeaderEntry) bool {
			return header != nil && header.Name == "Cache-Control" && header.Value == "no-store"
		}) {
			t.Errorf("%s: headers %+v, want no-store", testCase.name, response.Headers)
		}
	}

	if !store.GrantRevoked(revokedGrant) || store.GrantRevoked(keptGrant) {
		t.Errorf("revoked %t, kept %t", store.GrantRevoked(revokedGrant), store.GrantRevoked(keptGrant))
	}
	if _, err := store.RotateRefreshToken(t.Context(), oauth.HashSecret("a-refresh-token"), oauth.HashSecret("next"), now.Add(time.Hour), now, nil); !errors.Is(err, oauth.ErrNotFound) {
		t.Errorf("rotate a revoked token: %v, want ErrNotFound", err)
	}

	if err := New().Initialize(nil); err == nil {
		t.Error("initialized without a store")
	}
}

func TestEndpoint_MaskedBodyFields(t *testing.T) {
	t.Parallel()

	fields, err := New().MaskedBodyFields()
	if err != nil || fields == nil || len(fields.Request) != 1 || fields.Request[0] == nil ||
		fields.Request[0].Url == nil || fields.Request[0].Url.Path != DefaultPath || !slices.Equal(fields.Request[0].Fields, []string{"token"}) {
		t.Errorf("masked body fields %+v, %v", fields, err)
	}
}
