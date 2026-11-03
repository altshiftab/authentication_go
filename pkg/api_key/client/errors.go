package client

import "errors"

// ErrRefused is the login service's refusal of an assertion, or an answer with no token in it.
var ErrRefused = errors.New("the login service refused the assertion")
