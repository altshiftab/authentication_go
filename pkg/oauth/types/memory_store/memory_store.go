// Package memory_store keeps what the OAuth authorization server hands out in memory, for tests:
// nothing expired is ever swept, so a server kept running on it would grow without end.
package memory_store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/altshiftab/authentication_go/pkg/oauth"
)

type refreshToken struct {
	grantId   string
	expiresAt time.Time
	used      bool
}

type grant struct {
	*oauth.Grant
	revoked bool
}

type Store struct {
	mutex          sync.Mutex
	requests       map[string]*oauth.AuthorizationRequest
	codes          map[string]*oauth.AuthorizationCode
	grants         map[string]*grant
	refreshTokens  map[string]*refreshToken
	lockedAccounts map[string]bool
	// Accounts are the accounts the store knows, by id; an account not among them is not active.
	Accounts map[string]bool
}

var _ oauth.Store = (*Store)(nil)

// New is an empty store knowing the accounts given, each active.
func New(accountIds ...string) *Store {
	accounts := make(map[string]bool, len(accountIds))
	for _, accountId := range accountIds {
		accounts[accountId] = true
	}
	return &Store{
		requests:       make(map[string]*oauth.AuthorizationRequest),
		codes:          make(map[string]*oauth.AuthorizationCode),
		grants:         make(map[string]*grant),
		refreshTokens:  make(map[string]*refreshToken),
		lockedAccounts: make(map[string]bool),
		Accounts:       accounts,
	}
}

// LockAccount locks the account, as an administrator would.
func (s *Store) LockAccount(accountId string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.lockedAccounts[accountId] = true
}

// UnlockAccount unlocks the account again.
func (s *Store) UnlockAccount(accountId string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.lockedAccounts, accountId)
}

// GrantRevoked says whether the grant has been revoked.
func (s *Store) GrantRevoked(grantId string) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	g, ok := s.grants[grantId]
	return ok && g != nil && g.revoked
}

func newId() string {
	data := make([]byte, 16)
	_, _ = rand.Read(data)
	return hex.EncodeToString(data)
}

func (s *Store) InsertAuthorizationRequest(_ context.Context, request *oauth.AuthorizationRequest) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	stored := *request
	stored.Id = newId()
	s.requests[stored.Id] = &stored
	return stored.Id, nil
}

func (s *Store) PopAuthorizationRequest(_ context.Context, id string) (*oauth.AuthorizationRequest, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	request, ok := s.requests[id]
	if !ok {
		return nil, oauth.ErrNotFound
	}
	delete(s.requests, id)
	popped := *request
	return &popped, nil
}

func (s *Store) InsertAuthorizationCode(_ context.Context, codeHash []byte, code *oauth.AuthorizationCode) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	stored := *code
	s.codes[string(codeHash)] = &stored
	return nil
}

func (s *Store) PopAuthorizationCode(_ context.Context, codeHash []byte) (*oauth.AuthorizationCode, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	code, ok := s.codes[string(codeHash)]
	if !ok {
		return nil, oauth.ErrNotFound
	}
	delete(s.codes, string(codeHash))
	popped := *code
	return &popped, nil
}

func (s *Store) InsertGrant(_ context.Context, g *oauth.Grant, refreshTokenHash []byte, refreshTokenExpiresAt time.Time) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	stored := *g
	stored.Id = newId()
	s.grants[stored.Id] = &grant{Grant: &stored}
	s.refreshTokens[string(refreshTokenHash)] = &refreshToken{grantId: stored.Id, expiresAt: refreshTokenExpiresAt}
	return stored.Id, nil
}

func (s *Store) RotateRefreshToken(
	_ context.Context,
	refreshTokenHash []byte,
	newRefreshTokenHash []byte,
	newExpiresAt time.Time,
	now time.Time,
	check oauth.GrantCheck,
) (*oauth.Grant, error) {
	g, err := s.renewable(refreshTokenHash, now)
	if err != nil {
		return nil, err
	}

	// Asked without the lock, which the check may want for asking about the account; the token
	// is looked at again once it is held, in case it was spent meanwhile.
	if check != nil {
		if err := check(g); err != nil {
			return nil, err
		}
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	token, current, err := s.find(refreshTokenHash, now)
	if err != nil {
		return nil, err
	}
	token.used = true
	s.refreshTokens[string(newRefreshTokenHash)] = &refreshToken{grantId: current.Id, expiresAt: newExpiresAt}

	rotated := *current.Grant
	return &rotated, nil
}

// renewable is a copy of the grant the token renews, if it can be renewed.
func (s *Store) renewable(refreshTokenHash []byte, now time.Time) (*oauth.Grant, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	_, g, err := s.find(refreshTokenHash, now)
	if err != nil {
		return nil, err
	}
	copied := *g.Grant
	return &copied, nil
}

// find is the token and its grant, if the token can be spent; one spent before revokes its grant.
// The lock is held.
func (s *Store) find(refreshTokenHash []byte, now time.Time) (*refreshToken, *grant, error) {
	token, ok := s.refreshTokens[string(refreshTokenHash)]
	if !ok || token == nil {
		return nil, nil, oauth.ErrNotFound
	}
	g, ok := s.grants[token.grantId]
	if !ok || g == nil || g.Grant == nil {
		return nil, nil, oauth.ErrNotFound
	}

	if token.used {
		g.revoked = true
		return nil, nil, oauth.ErrRefreshTokenReused
	}
	if g.revoked || !now.Before(token.expiresAt) {
		return nil, nil, oauth.ErrNotFound
	}

	return token, g, nil
}

func (s *Store) RevokeRefreshToken(_ context.Context, refreshTokenHash []byte) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	token, ok := s.refreshTokens[string(refreshTokenHash)]
	if !ok || token == nil {
		return nil
	}
	if g, ok := s.grants[token.grantId]; ok && g != nil {
		g.revoked = true
	}
	return nil
}

func (s *Store) AccountActive(_ context.Context, accountId string) (bool, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.Accounts[accountId] && !s.lockedAccounts[accountId], nil
}
