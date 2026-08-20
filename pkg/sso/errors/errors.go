package errors

import "errors"

var (
	ErrForbiddenUser = errors.New("forbidden user")
	// No cookie presented at the callback names a flow that was started. The
	// callback stops there rather than falling back to the state in the url.
	ErrNoMatchingOauthFlow = errors.New("no oauth flow matches a callback cookie")
)
