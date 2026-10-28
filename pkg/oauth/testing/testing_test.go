package testing

import (
	"testing"

	"github.com/altshiftab/authentication_go/pkg/oauth/types/memory_store"
)

// The contract holds of the memory store, so that it is known to ask only what a store can answer.
//
//nolint:tparallel // The contract's group is serial so that it has run when StoreContract returns; its cases are parallel.
func TestStoreContract(t *testing.T) {
	t.Parallel()

	StoreContract(t, memory_store.New("an-account"), "an-account")
}
