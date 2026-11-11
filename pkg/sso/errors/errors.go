package errors

import "errors"

var (
	ErrForbiddenUser = errors.New("forbidden user")

	// ErrEmailDomainOwnerNotSaid is a callback told to require a verified email domain of claims
	// that cannot say whether it is.
	ErrEmailDomainOwnerNotSaid = errors.New("the claims do not say whether the email domain is verified")
	// No cookie presented at the callback names a flow that was started. The
	// callback stops there rather than falling back to the state in the url.
	ErrNoMatchingOauthFlow = errors.New("no oauth flow matches a callback cookie")
	// The browser came back from the provider after the flow expired, so the sign-in is restarted.
	ErrExpiredOauthFlow = errors.New("expired oauth flow")
)
