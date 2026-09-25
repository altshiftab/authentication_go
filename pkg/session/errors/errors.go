package errors

import "errors"

var (
	ErrEndedAuthentication   = errors.New("ended authentication")
	ErrExpiredAuthentication = errors.New("expired authentication")
	ErrLockedAccount         = errors.New("locked account")
	// The holder's tenant is not the one an authorizer allows.
	ErrTenantNotAllowed = errors.New("tenant not allowed")
	// None of the holder's roles is one an authorizer allows.
	ErrRolesNotAllowed = errors.New("roles not allowed")
	// A refresh proof names a challenge the store does not hold. The challenge is single use, so a
	// browser replaying one it has already spent produces this; it is the proof that is at fault,
	// not the store.
	ErrNoDbscChallenge = errors.New("no dbsc challenge matches the proof")
	// A refresh proof names a challenge that has passed its expiry. The browser signs the challenge
	// it cached at the previous refresh, so a gap longer than the challenge's lifetime -- an idle
	// session, most often -- produces this.
	ErrExpiredDbscChallenge = errors.New("the dbsc challenge the proof names has expired")
)
