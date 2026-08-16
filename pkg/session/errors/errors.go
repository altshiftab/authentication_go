package errors

import "errors"

var (
	ErrEndedAuthentication   = errors.New("ended authentication")
	ErrExpiredAuthentication = errors.New("expired authentication")
	ErrLockedAccount         = errors.New("locked account")
)
