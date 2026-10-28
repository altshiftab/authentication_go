package memory_store

import (
	"testing"

	oauthTesting "github.com/altshiftab/authentication_go/pkg/oauth/testing"
)

const accountId = "an-account"

func TestStore_Contract(t *testing.T) {
	t.Parallel()

	oauthTesting.StoreContract(t, New(accountId), accountId)
}

func TestStore_AccountActive(t *testing.T) {
	t.Parallel()

	store := New(accountId)
	testCases := []struct {
		name      string
		accountId string
		lock      bool
		want      bool
	}{
		{name: "a known account", accountId: accountId, want: true},
		{name: "an unknown account", accountId: "another-account"},
		{name: "a locked account", accountId: accountId, lock: true},
	}
	for _, testCase := range testCases {
		if testCase.lock {
			store.LockAccount(testCase.accountId)
		}
		if active, err := store.AccountActive(t.Context(), testCase.accountId); err != nil || active != testCase.want {
			t.Errorf("%s: active %t, %v, want %t", testCase.name, active, err, testCase.want)
		}
	}
}
