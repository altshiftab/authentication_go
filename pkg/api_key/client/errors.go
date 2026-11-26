package client

import (
	"errors"
	"fmt"
)

// ErrRefused is the login service's refusal of an assertion, or an answer with no token in it.
var ErrRefused = errors.New("the login service refused the assertion")

// RefusedError is the login service's answer other than 200 to an assertion: its status, and what it
// said. The status tells the key from the moment: 401 is a key the service does not know or a
// signature not the key's, 403 a key revoked or expired, 400 an assertion malformed or used before,
// and a 5xx the service's own failure.
type RefusedError struct {
	Status int
	Body   string
}

func (e *RefusedError) Error() string {
	return fmt.Sprintf("%s: %d %s", ErrRefused, e.Status, e.Body)
}

// Is makes a refusal ErrRefused.
func (e *RefusedError) Is(target error) bool {
	return target == ErrRefused
}
