package memory_replay_detector

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/altshiftab/authentication_go/pkg/dpop/types/proof_verifier/proof_verifier_config"
)

var _ proof_verifier_config.ReplayDetector = (*Detector)(nil)

// now is fixed, as the verifier's clock is in its tests: the detector must judge by the time it is
// given and not by its own.
var now = time.Unix(1_800_000_000, 0)

type observation struct {
	keyThumbprint string
	jti           string
	expiresIn     time.Duration
	wantSeen      bool
}

func TestDetector_Observe(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		observations []*observation
	}{
		{
			name: "the first presentation",
			observations: []*observation{
				{keyThumbprint: "a", jti: "1", expiresIn: time.Minute, wantSeen: false},
			},
		},
		{
			name: "the second presentation",
			observations: []*observation{
				{keyThumbprint: "a", jti: "1", expiresIn: time.Minute, wantSeen: false},
				{keyThumbprint: "a", jti: "1", expiresIn: time.Minute, wantSeen: true},
			},
		},
		{
			// Once a proof could no longer be accepted, remembering it is no longer worth anything.
			name: "a presentation after the first has expired",
			observations: []*observation{
				{keyThumbprint: "a", jti: "1", expiresIn: -time.Second, wantSeen: false},
				{keyThumbprint: "a", jti: "1", expiresIn: time.Minute, wantSeen: false},
			},
		},
		{
			name: "two keys with the same identifier",
			observations: []*observation{
				{keyThumbprint: "a", jti: "1", expiresIn: time.Minute, wantSeen: false},
				{keyThumbprint: "b", jti: "1", expiresIn: time.Minute, wantSeen: false},
			},
		},
		{
			name: "one key with two identifiers",
			observations: []*observation{
				{keyThumbprint: "a", jti: "1", expiresIn: time.Minute, wantSeen: false},
				{keyThumbprint: "a", jti: "2", expiresIn: time.Minute, wantSeen: false},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			detector := New()
			for i, observation := range testCase.observations {
				seen, err := detector.Observe(
					t.Context(),
					observation.keyThumbprint,
					observation.jti,
					now,
					now.Add(observation.expiresIn),
				)
				if err != nil {
					t.Fatalf("%s: observation %d: %v", testCase.name, i, err)
				}
				if seen != observation.wantSeen {
					t.Errorf("%s: observation %d: seen = %v, want %v", testCase.name, i, seen, observation.wantSeen)
				}
			}
		})
	}
}

func TestDetector_Sweep(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		expired   int
		live      int
		wantAtMax int
	}{
		{
			// Expired proofs are dropped once the threshold is reached, rather than accumulating.
			name:      "expired proofs past the threshold",
			expired:   3 * minimumSweepThreshold,
			wantAtMax: minimumSweepThreshold,
		},
		{
			// Live proofs are kept however many there are: forgetting one would let it be replayed.
			name:      "live proofs past the threshold",
			live:      3 * minimumSweepThreshold,
			wantAtMax: 3 * minimumSweepThreshold,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var detector Detector
			for i := range testCase.expired {
				if _, err := detector.Observe(t.Context(), "a", fmt.Sprintf("expired-%d", i), now, now.Add(-time.Second)); err != nil {
					t.Fatalf("%s: observe: %v", testCase.name, err)
				}
			}
			for i := range testCase.live {
				if _, err := detector.Observe(t.Context(), "a", fmt.Sprintf("live-%d", i), now, now.Add(time.Hour)); err != nil {
					t.Fatalf("%s: observe: %v", testCase.name, err)
				}
			}

			if got := len(detector.expiresAt); got > testCase.wantAtMax {
				t.Errorf("%s: %d proofs remembered, want at most %d", testCase.name, got, testCase.wantAtMax)
			}
			for i := range testCase.live {
				seen, err := detector.Observe(t.Context(), "a", fmt.Sprintf("live-%d", i), now, now.Add(time.Hour))
				if err != nil {
					t.Fatalf("%s: observe: %v", testCase.name, err)
				}
				if !seen {
					t.Fatalf("%s: live proof %d was forgotten", testCase.name, i)
				}
			}
		})
	}
}

func TestDetector_MaxEntries(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		expiresIn time.Duration
		wantErr   bool
	}{
		{
			// Full of live proofs: none can be forgotten, so a new one cannot be vouched for.
			name:      "full of live proofs",
			expiresIn: time.Hour,
			wantErr:   true,
		},
		{
			// Full of expired ones, which make room as soon as they are swept.
			name:      "full of expired proofs",
			expiresIn: -time.Second,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			detector := &Detector{MaxEntries: 3}
			for i := range 3 {
				if _, err := detector.Observe(t.Context(), "a", fmt.Sprintf("%d", i), now, now.Add(testCase.expiresIn)); err != nil {
					t.Fatalf("%s: observe %d: %v", testCase.name, i, err)
				}
			}

			seen, err := detector.Observe(t.Context(), "a", "new", now, now.Add(time.Hour))
			if testCase.wantErr {
				if !errors.Is(err, ErrFull) {
					t.Errorf("%s: got %v, want %v", testCase.name, err, ErrFull)
				}
				return
			}
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", testCase.name, err)
			}
			if seen {
				t.Errorf("%s: a new proof was reported seen", testCase.name)
			}
		})
	}
}
