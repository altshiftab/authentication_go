package postgres_store

import (
	"testing"
	"time"

	"github.com/altshiftab/authentication_go/pkg/oauth"
	altshiftSqlTesting "github.com/altshiftab/utils_go/pkg/database/sql/testing"
)

// What is here is what the store refuses before it asks the database anything. The queries are run
// against Postgres by a service holding the schema -- vvvp_login's backend tests run oauth/testing's
// StoreContract on its own -- as nothing here has a database to run them on.
func TestStore_Refusals(t *testing.T) {
	t.Parallel()

	if _, err := New(nil); err == nil {
		t.Error("a store without a database")
	}

	store, err := New(altshiftSqlTesting.NewDb())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx := t.Context()

	testCases := []struct {
		name string
		call func() error
	}{
		{name: "no request", call: func() error { _, err := store.InsertAuthorizationRequest(ctx, nil); return err }},
		{name: "a request of no account", call: func() error {
			_, err := store.InsertAuthorizationRequest(ctx, &oauth.AuthorizationRequest{})
			return err
		}},
		{name: "no request id", call: func() error { _, err := store.PopAuthorizationRequest(ctx, ""); return err }},
		{name: "no code hash", call: func() error { return store.InsertAuthorizationCode(ctx, nil, &oauth.AuthorizationCode{}) }},
		{name: "no code", call: func() error { return store.InsertAuthorizationCode(ctx, []byte("h"), nil) }},
		{name: "no code hash to pop", call: func() error { _, err := store.PopAuthorizationCode(ctx, nil); return err }},
		{name: "no grant", call: func() error { _, err := store.InsertGrant(ctx, nil, []byte("h"), time.Now()); return err }},
		{name: "no refresh token hash", call: func() error { _, err := store.InsertGrant(ctx, &oauth.Grant{}, nil, time.Now()); return err }},
		{name: "no refresh token to rotate", call: func() error {
			_, err := store.RotateRefreshToken(ctx, nil, []byte("n"), time.Now(), time.Now(), nil)
			return err
		}},
		{name: "no refresh token to revoke", call: func() error { return store.RevokeRefreshToken(ctx, nil) }},
		{name: "no account", call: func() error { _, err := store.AccountActive(ctx, ""); return err }},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if err := testCase.call(); err == nil {
				t.Errorf("%s: no error", testCase.name)
			}
		})
	}
}

func TestIsUuid(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		id   string
		want bool
	}{
		{name: "as Postgres writes one", id: "0b0e7c4c-8f0b-4c5e-9d3a-2f6a1c9e7b10", want: true},
		{name: "in capitals", id: "0B0E7C4C-8F0B-4C5E-9D3A-2F6A1C9E7B10", want: true},
		{name: "not one at all", id: "never-made"},
		{name: "without hyphens", id: "0b0e7c4c8f0b4c5e9d3a2f6a1c9e7b10"},
		{name: "a hyphen out of place", id: "0b0e7c4c8-f0b-4c5e-9d3a-2f6a1c9e7b10"},
		{name: "a letter beyond f", id: "0b0e7c4c-8f0b-4c5e-9d3a-2f6a1c9e7b1g"},
		{name: "in braces", id: "{0b0e7c4c-8f0b-4c5e-9d3a-2f6a1c9e7b}"},
		{name: "empty", id: ""},
	}
	for _, testCase := range testCases {
		if got := isUuid(testCase.id); got != testCase.want {
			t.Errorf("%s: got %t, want %t", testCase.name, got, testCase.want)
		}
	}
}
