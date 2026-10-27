package errors

import "errors"

// Each is returned wrapped in the client-error class it belongs to -- ErrValidationError or
// ErrVerificationError from utils_go -- so that an endpoint mapping by class answers 4xx, and one
// that wants to say more can still tell them apart.
var (
	// A request that needed a proof carried no DPoP header.
	ErrMissingProof = errors.New("missing dpop proof")
	// A request carried more than one DPoP header, which RFC 9449 §4.3 refuses rather than choose.
	ErrMultipleProofs = errors.New("multiple dpop proofs")
	// A proof was presented again while it could still be accepted.
	ErrReplayedProof = errors.New("replayed dpop proof")
	// A proof was made by a key other than the one the token is bound to.
	ErrKeyMismatch = errors.New("dpop proof key does not match the token's binding")
)
