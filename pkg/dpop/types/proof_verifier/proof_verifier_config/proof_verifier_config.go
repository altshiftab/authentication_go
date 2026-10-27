// Package proof_verifier_config sets how a DPoP proof is verified: how old it may be, how far the
// client's clock may be off, and whether the proofs accepted are remembered so that none is accepted
// twice.
package proof_verifier_config

import (
	"context"
	"time"
)

var (
	// DefaultMaxAge is how long after it was made a proof is accepted. RFC 9449 §11.1 asks for
	// seconds or minutes. A client makes a proof just before the request it is for, so ten seconds
	// covers the signing and the network; and with no replay detector configured, the window is
	// also how long a copy of a proof is good for, which is the reason not to make it longer.
	DefaultMaxAge = 10 * time.Second

	// DefaultClockSkew is how far a client's clock may be out, in either direction. Ten seconds is
	// what FAPI 2.0 requires a server to accept of an "iat" in the future. A client further out than
	// that wants its clock fixed, or a server nonce, rather than a wider window for every client.
	DefaultClockSkew = 10 * time.Second

	// DefaultMaxProofLength bounds the header before anything parses it. A P-256 proof carrying
	// "ath" and a nonce is well under a kilobyte.
	DefaultMaxProofLength = 4096

	// DefaultMaxIdLength bounds "jti", which a replay detector stores and nothing else reads: an
	// identifier is only there to be compared, and nothing needs it to be long.
	DefaultMaxIdLength = 256
)

// ReplayDetector remembers the proofs accepted, for as long as each could still be accepted.
//
// It is asked last, once everything else about a proof has checked out -- the binding to the token
// included, where there is one -- so that only proofs which would otherwise be accepted take up
// room in it.
type ReplayDetector interface {
	// Observe records the proof that the key with keyThumbprint made with the identifier jti, to be
	// remembered until expiresAt, and reports whether that proof had been recorded before and is
	// still remembered at now. now is the verifier's clock, so that the window a proof is accepted
	// in and the one it is remembered for are measured by the same one.
	Observe(ctx context.Context, keyThumbprint string, jti string, now time.Time, expiresAt time.Time) (bool, error)
}

type Config struct {
	MaxAge         time.Duration
	ClockSkew      time.Duration
	MaxProofLength int
	MaxIdLength    int

	// ReplayDetector is nil unless one is asked for, which leaves the verifier stateless: a proof can
	// then be presented again until it is too old, and only for the request it was made for.
	ReplayDetector ReplayDetector
}

type Option func(*Config)

func New(options ...Option) *Config {
	config := &Config{
		MaxAge:         DefaultMaxAge,
		ClockSkew:      DefaultClockSkew,
		MaxProofLength: DefaultMaxProofLength,
		MaxIdLength:    DefaultMaxIdLength,
	}
	for _, option := range options {
		option(config)
	}

	return config
}

func WithMaxAge(maxAge time.Duration) Option {
	return func(config *Config) {
		config.MaxAge = maxAge
	}
}

func WithClockSkew(clockSkew time.Duration) Option {
	return func(config *Config) {
		config.ClockSkew = clockSkew
	}
}

func WithReplayDetector(replayDetector ReplayDetector) Option {
	return func(config *Config) {
		config.ReplayDetector = replayDetector
	}
}
