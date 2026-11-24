package token_endpoint

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	apiKeyTesting "github.com/altshiftab/authentication_go/pkg/api_key/testing"
	"github.com/altshiftab/authentication_go/pkg/oauth"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/postgres_store"
)

func TestMain(m *testing.M) {
	os.Exit(apiKeyTesting.Main(m, "token_endpoint"))
}

/*
 * Refreshes against Postgres through pools as small as a service may bound its own, under a
 * deadline. A refresh that wanted a second connection while it held the first would wait for one
 * until the deadline: twelve at once on a pool of ten did, when claude.ai renewed its connectors.
 */
func TestEndpoint_RefreshPool(t *testing.T) {
	t.Parallel()

	db := apiKeyTesting.Db(t)
	active, err := apiKeyTesting.InsertAccount(t.Context(), db, apiKeyTesting.Unique("account@example.test"), "")
	if err != nil {
		t.Fatalf("insert account: %v", err)
	}
	locked, err := apiKeyTesting.InsertAccount(t.Context(), db, apiKeyTesting.Unique("account@example.test"), "")
	if err != nil {
		t.Fatalf("insert account: %v", err)
	}
	if _, err := db.ExecContext(t.Context(), `UPDATE account SET locked = true WHERE id = $1;`, locked.Id); err != nil {
		t.Fatalf("lock account: %v", err)
	}

	testCases := []struct {
		name         string
		maxOpenConns int
		refreshes    int
		accountId    string
		wantStatus   int
	}{
		{name: "one refresh on a pool of one connection", maxOpenConns: 1, refreshes: 1, accountId: active.Id, wantStatus: http.StatusOK},
		{name: "twelve refreshes at once on a pool of two", maxOpenConns: 2, refreshes: 12, accountId: active.Id, wantStatus: http.StatusOK},
		{name: "a locked account's refresh on a pool of one connection", maxOpenConns: 1, refreshes: 1, accountId: locked.Id, wantStatus: http.StatusBadRequest},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			store, err := postgres_store.New(apiKeyTesting.Pool(t, testCase.maxOpenConns))
			if err != nil {
				t.Fatalf("postgres store new: %v", err)
			}
			now := time.Now().Truncate(time.Second)
			endpoint := newEndpoint(t, store, &now)

			refreshTokens := make([]string, testCase.refreshes)
			for i := range refreshTokens {
				refreshTokens[i] = rand.Text()
				if _, err := store.InsertGrant(t.Context(), &oauth.Grant{
					AccountId: testCase.accountId, ClientId: clientId, Resource: resource, Scope: "vocab", CreatedAt: now,
				}, oauth.HashSecret(refreshTokens[i]), now.Add(time.Hour)); err != nil {
					t.Fatalf("insert grant: %v", err)
				}
			}

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			statuses := make([]int, len(refreshTokens))
			errs := make([]error, len(refreshTokens))
			var group sync.WaitGroup
			for i, refreshToken := range refreshTokens {
				group.Go(func() {
					statuses[i], _, errs[i] = tryPost(ctx, endpoint, url.Values{
						"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {clientId},
					})
				})
			}
			group.Wait()

			for i := range refreshTokens {
				if errs[i] != nil || statuses[i] != testCase.wantStatus {
					t.Errorf("refresh %d: status %d, %v; want %d", i, statuses[i], errs[i], testCase.wantStatus)
				}
			}
		})
	}
}
