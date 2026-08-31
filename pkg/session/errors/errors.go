package errors

import "errors"

var (
	ErrEndedAuthentication   = errors.New("ended authentication")
	ErrExpiredAuthentication = errors.New("expired authentication")
	ErrLockedAccount         = errors.New("locked account")
	// A refresh proof names a challenge the store does not hold. The challenge is single use, so a
	// browser replaying one it has already spent produces this; it is the proof that is at fault,
	// not the store.
	ErrNoDbscChallenge = errors.New("no dbsc challenge matches the proof")
)
