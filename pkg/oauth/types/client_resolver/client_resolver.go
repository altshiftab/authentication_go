// Package client_resolver is how the authorization server knows a client: one registered with it
// beforehand, one that registered itself and holds the id it was given, or one whose id is the URL
// of a metadata document on a host it allows.
package client_resolver

import (
	"context"
	"errors"
	"fmt"

	"github.com/altshiftab/authentication_go/pkg/oauth/types/cimd_fetcher"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/client"
	"github.com/altshiftab/authentication_go/pkg/oauth/types/client_registrar"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
)

// ErrUnknownClient is a client the server knows nothing of.
var ErrUnknownClient = errors.New("unknown client")

type Resolver struct {
	// Clients are those registered beforehand, by id.
	Clients map[string]*client.Client
	// Fetcher reads the metadata documents of the clients that have one; nil for none.
	Fetcher *cimd_fetcher.Fetcher
	// Registrar reads back the ids of the clients that registered themselves; nil for none.
	Registrar *client_registrar.Registrar
}

// New is a resolver of the clients given and, where fetcher and registrar are not nil, of those
// with a document and those that registered.
func New(fetcher *cimd_fetcher.Fetcher, registrar *client_registrar.Registrar, clients ...*client.Client) *Resolver {
	registered := make(map[string]*client.Client, len(clients))
	for _, c := range clients {
		if c != nil && c.Id != "" {
			registered[c.Id] = c
		}
	}
	return &Resolver{Clients: registered, Fetcher: fetcher, Registrar: registrar}
}

func (r *Resolver) Resolve(ctx context.Context, clientId string) (*client.Client, error) {
	if registered, ok := r.Clients[clientId]; ok {
		return registered, nil
	}

	if r.Registrar != nil && r.Registrar.Allows(clientId) {
		resolved, err := r.Registrar.Resolve(clientId)
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("client registrar resolve: %w", err))
		}
		return resolved, nil
	}

	if r.Fetcher != nil && r.Fetcher.Allows(clientId) {
		fetched, err := r.Fetcher.Fetch(ctx, clientId)
		if err != nil {
			return nil, altshiftErrors.New(fmt.Errorf("cimd fetcher fetch: %w", err))
		}
		return fetched, nil
	}

	return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: %w", altshiftErrors.ErrValidationError, ErrUnknownClient), clientId)
}
