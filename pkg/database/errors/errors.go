package errors

import "errors"

var (
	ErrIdTokenAlreadyUsed = errors.New("id token already used")
	// A device key is registered for the authentication already, and is never replaced.
	ErrDbscPublicKeyRegistered = errors.New("dbsc public key already registered")
)
