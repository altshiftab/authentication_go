// Package testing holds what tests of the OAuth authorization server share: the behaviour every
// store must have, as a test any of them can be run through.
package testing

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/altshiftab/authentication_go/pkg/oauth"
)

// errRefused is what the contract's grant check refuses with.
var errRefused = errors.New("refused by the check")

const (
	contractClientId      = "a-client"
	contractCodeChallenge = "a-challenge"
	contractResource      = "https://resource.example/mcp"
	contractScope         = "vocab"
)

// StoreContract runs the store through what the authorization server relies on: requests and
// codes are had once, a refresh token is spent once, and a spent one coming back revokes its grant.
// accountId is an account the store knows and that is active. The cases run in parallel with one
// another, as the endpoints use the store.
func StoreContract(t *testing.T, store oauth.Store, accountId string) {
	t.Helper()

	now := time.Now().Truncate(time.Second)

	// One group, which returns once every case in it has: the cases are run in parallel, and run
	// after their parent returns, and the store is for the caller to close once this one does.
	t.Run("store contract", func(t *testing.T) {
		t.Run("an authorization request is had once", func(t *testing.T) {
			t.Parallel()

			id, err := store.InsertAuthorizationRequest(t.Context(), &oauth.AuthorizationRequest{
				AccountId: accountId, ClientId: contractClientId, ClientName: "A client", RedirectUri: "https://client.example/cb",
				State: "a-state", CodeChallenge: contractCodeChallenge, Resource: contractResource, Scope: contractScope,
				ExpiresAt: now.Add(5 * time.Minute),
			})
			if err != nil || id == "" {
				t.Fatalf("insert authorization request: %q, %v", id, err)
			}

			request, err := store.PopAuthorizationRequest(t.Context(), id)
			if err != nil || request == nil {
				t.Fatalf("pop authorization request: %v, %v", request, err)
			}
			if request.Id != id || request.AccountId != accountId || request.State != "a-state" || request.Resource != contractResource ||
				!request.ExpiresAt.Equal(now.Add(5*time.Minute)) {
				t.Errorf("popped %+v", request)
			}

			if _, err := store.PopAuthorizationRequest(t.Context(), id); !errors.Is(err, oauth.ErrNotFound) {
				t.Errorf("popped again: %v, want ErrNotFound", err)
			}
		})

		t.Run("an authorization code is redeemed once", func(t *testing.T) {
			t.Parallel()

			codeHash := oauth.HashSecret("a-code")
			if err := store.InsertAuthorizationCode(t.Context(), codeHash, &oauth.AuthorizationCode{
				AccountId: accountId, ClientId: contractClientId, RedirectUri: "https://client.example/cb", CodeChallenge: contractCodeChallenge,
				Resource: contractResource, Scope: contractScope, ExpiresAt: now.Add(time.Minute),
			}); err != nil {
				t.Fatalf("insert authorization code: %v", err)
			}

			code, err := store.PopAuthorizationCode(t.Context(), codeHash)
			if err != nil || code == nil || code.AccountId != accountId || code.CodeChallenge != contractCodeChallenge {
				t.Fatalf("pop authorization code: %+v, %v", code, err)
			}
			if _, err := store.PopAuthorizationCode(t.Context(), codeHash); !errors.Is(err, oauth.ErrNotFound) {
				t.Errorf("redeemed again: %v, want ErrNotFound", err)
			}
			if _, err := store.PopAuthorizationCode(t.Context(), oauth.HashSecret("never-issued")); !errors.Is(err, oauth.ErrNotFound) {
				t.Errorf("a code never issued: %v, want ErrNotFound", err)
			}
		})

		newGrant := func(t *testing.T, refreshTokenHash []byte, expiresAt time.Time) string {
			t.Helper()
			id, err := store.InsertGrant(t.Context(), &oauth.Grant{
				AccountId: accountId, ClientId: contractClientId, Resource: contractResource, Scope: contractScope, CreatedAt: now,
			}, refreshTokenHash, expiresAt)
			if err != nil || id == "" {
				t.Fatalf("insert grant: %q, %v", id, err)
			}
			return id
		}

		t.Run("a refresh token is spent once, its successor in its place", func(t *testing.T) {
			t.Parallel()

			first, second, third := oauth.HashSecret("rt-1"), oauth.HashSecret("rt-2"), oauth.HashSecret("rt-3")
			grantId := newGrant(t, first, now.Add(time.Hour))

			grant, err := store.RotateRefreshToken(t.Context(), first, second, now.Add(time.Hour), now, nil)
			if err != nil || grant == nil || grant.Id != grantId || grant.AccountId != accountId || grant.Resource != contractResource {
				t.Fatalf("rotate: %+v, %v", grant, err)
			}
			if _, err := store.RotateRefreshToken(t.Context(), second, third, now.Add(time.Hour), now, nil); err != nil {
				t.Fatalf("rotate the successor: %v", err)
			}
		})

		t.Run("a spent refresh token coming back revokes the grant", func(t *testing.T) {
			t.Parallel()

			first, second, third, fourth := oauth.HashSecret("rr-1"), oauth.HashSecret("rr-2"), oauth.HashSecret("rr-3"), oauth.HashSecret("rr-4")
			newGrant(t, first, now.Add(time.Hour))

			if _, err := store.RotateRefreshToken(t.Context(), first, second, now.Add(time.Hour), now, nil); err != nil {
				t.Fatalf("rotate: %v", err)
			}
			if _, err := store.RotateRefreshToken(t.Context(), first, third, now.Add(time.Hour), now, nil); !errors.Is(err, oauth.ErrRefreshTokenReused) {
				t.Fatalf("the spent token again: %v, want ErrRefreshTokenReused", err)
			}
			// The successor, which the client may hold, goes with the grant.
			if _, err := store.RotateRefreshToken(t.Context(), second, fourth, now.Add(time.Hour), now, nil); !errors.Is(err, oauth.ErrNotFound) {
				t.Errorf("the successor after the grant was revoked: %v, want ErrNotFound", err)
			}
		})

		t.Run("a refused check leaves the refresh token unspent", func(t *testing.T) {
			t.Parallel()

			token, successor := oauth.HashSecret("rc-1"), oauth.HashSecret("rc-2")
			grantId := newGrant(t, token, now.Add(time.Hour))

			var checked *oauth.Grant
			_, err := store.RotateRefreshToken(t.Context(), token, successor, now.Add(time.Hour), now, func(grant *oauth.Grant) error {
				checked = grant
				return errRefused
			})
			if !errors.Is(err, errRefused) {
				t.Fatalf("rotate refused: %v, want the check's error", err)
			}
			if checked == nil || checked.Id != grantId || checked.AccountId != accountId || checked.Resource != contractResource {
				t.Errorf("checked %+v", checked)
			}
			// The successor was never recorded, and the token is as it was.
			if _, err := store.RotateRefreshToken(t.Context(), successor, oauth.HashSecret("rc-3"), now.Add(time.Hour), now, nil); !errors.Is(err, oauth.ErrNotFound) {
				t.Errorf("the successor of a refused rotation: %v, want ErrNotFound", err)
			}
			if _, err := store.RotateRefreshToken(t.Context(), token, successor, now.Add(time.Hour), now, nil); err != nil {
				t.Errorf("rotate after the refusal: %v", err)
			}
		})

		t.Run("a refresh token presented twice at once renews once", func(t *testing.T) {
			t.Parallel()

			token := oauth.HashSecret("rx-1")
			newGrant(t, token, now.Add(time.Hour))

			successors := [][]byte{oauth.HashSecret("rx-2"), oauth.HashSecret("rx-3")}
			errs := make([]error, len(successors))
			var group sync.WaitGroup
			for i, successor := range successors {
				group.Go(func() {
					_, errs[i] = store.RotateRefreshToken(t.Context(), token, successor, now.Add(time.Hour), now, nil)
				})
			}
			group.Wait()

			renewed, reused := 0, 0
			for _, err := range errs {
				switch {
				case err == nil:
					renewed++
				case errors.Is(err, oauth.ErrRefreshTokenReused):
					reused++
				default:
					t.Errorf("rotate: %v", err)
				}
			}
			if renewed != 1 || reused != 1 {
				t.Fatalf("%d renewed, %d reused, want one of each", renewed, reused)
			}
			// The grant went with the second, and its one successor with it.
			for _, successor := range successors {
				if _, err := store.RotateRefreshToken(t.Context(), successor, oauth.HashSecret("rx-4"), now.Add(time.Hour), now, nil); !errors.Is(err, oauth.ErrNotFound) {
					t.Errorf("a successor after the grant was revoked: %v, want ErrNotFound", err)
				}
			}
		})

		t.Run("a revoked refresh token renews nothing", func(t *testing.T) {
			t.Parallel()

			token := oauth.HashSecret("rv-1")
			newGrant(t, token, now.Add(time.Hour))
			if err := store.RevokeRefreshToken(t.Context(), token); err != nil {
				t.Fatalf("revoke: %v", err)
			}
			if _, err := store.RotateRefreshToken(t.Context(), token, oauth.HashSecret("rv-2"), now.Add(time.Hour), now, nil); !errors.Is(err, oauth.ErrNotFound) {
				t.Errorf("a revoked token: %v, want ErrNotFound", err)
			}
			if err := store.RevokeRefreshToken(t.Context(), oauth.HashSecret("rv-never")); err != nil {
				t.Errorf("revoke a token never issued: %v, want nothing", err)
			}
		})

		t.Run("an unknown request id is not found", func(t *testing.T) {
			t.Parallel()

			for _, id := range []string{"never-made", "00000000-0000-0000-0000-000000000000"} {
				if _, err := store.PopAuthorizationRequest(t.Context(), id); !errors.Is(err, oauth.ErrNotFound) {
					t.Errorf("pop %q: %v, want ErrNotFound", id, err)
				}
			}
		})

		t.Run("an expired or unknown refresh token renews nothing", func(t *testing.T) {
			t.Parallel()

			expired := oauth.HashSecret("re-1")
			newGrant(t, expired, now.Add(-time.Minute))
			if _, err := store.RotateRefreshToken(t.Context(), expired, oauth.HashSecret("re-2"), now.Add(time.Hour), now, nil); !errors.Is(err, oauth.ErrNotFound) {
				t.Errorf("an expired token: %v, want ErrNotFound", err)
			}
			if _, err := store.RotateRefreshToken(t.Context(), oauth.HashSecret("re-never"), oauth.HashSecret("re-3"), now.Add(time.Hour), now, nil); !errors.Is(err, oauth.ErrNotFound) {
				t.Errorf("a token never issued: %v, want ErrNotFound", err)
			}
		})

		t.Run("the account is active", func(t *testing.T) {
			t.Parallel()

			if active, err := store.AccountActive(t.Context(), accountId); err != nil || !active {
				t.Errorf("account active: %t, %v", active, err)
			}
		})
	})
}
