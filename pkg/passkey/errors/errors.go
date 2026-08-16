package errors

import "errors"

var (
	ErrEmailAddressUserIdConflict = errors.New("email address user id conflict")
	ErrNoPublicKeyCredential      = errors.New("no public key credential")
	ErrNoChallenge                = errors.New("no challenge")
	ErrExpiredChallenge           = errors.New("expired challenge")
)
