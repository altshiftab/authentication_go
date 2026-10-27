// Package memory_replay_detector remembers the DPoP proofs a process has accepted, for as long as
// each could still be accepted, so that a second presentation of one is refused.
//
// It is per process. A service running as several instances -- Cloud Run scaling out -- refuses a
// replay that reaches the instance which saw the original and not one that reaches another, so it
// narrows replay rather than preventing it. A store the instances share is what prevents it, and
// the verifier takes one through the same interface.
//
// It holds at most MaxEntries proofs. Only proofs that would otherwise be accepted are stored, but
// the holder of one key and its token can make a fresh one per request, so a service exposed to
// more than a handful of clients wants a rate limit in front of it as well; once full, the detector
// refuses to vouch for new proofs rather than forget live ones, which would let them be replayed.
package memory_replay_detector

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
)

// ErrFull is what Observe answers when the detector holds as many live proofs as it may.
var ErrFull = errors.New("the replay detector is full")

// DefaultMaxEntries is a hundred thousand proofs, some tens of megabytes: five thousand requests a
// second sustained across a twenty-second window.
const DefaultMaxEntries = 100_000

// minimumSweepThreshold is how many proofs are remembered before the first sweep for expired ones.
// After a sweep the threshold is twice what survived it, so a sweep runs once per that many new
// proofs and its cost is spread over them rather than paid on every call.
const minimumSweepThreshold = 1024

type entryKey struct {
	keyThumbprint string
	id            string
}

// Detector is safe for concurrent use. The zero value is ready to use.
type Detector struct {
	// MaxEntries is how many proofs it holds at most; zero is DefaultMaxEntries.
	MaxEntries int

	mutex          sync.Mutex
	expiresAt      map[entryKey]*time.Time
	sweepThreshold int
}

// Observe records a proof until expiresAt and reports whether it had been recorded before and is
// still remembered at now. Two keys may each use the same "jti" without either being a replay.
//
// A full detector is an error, which the verifier answers as the service's fault rather than the
// client's: it cannot say the proof is not a replay, and it will not say that it is.
func (d *Detector) Observe(
	_ context.Context,
	keyThumbprint string,
	jti string,
	now time.Time,
	expiresAt time.Time,
) (bool, error) {
	if d == nil {
		return false, altshiftErrors.NewWithTrace(nil_error.New("detector"))
	}

	maxEntries := d.MaxEntries
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}

	d.mutex.Lock()
	defer d.mutex.Unlock()

	if d.expiresAt == nil {
		d.expiresAt = make(map[entryKey]*time.Time)
	}

	key := entryKey{keyThumbprint: keyThumbprint, id: jti}
	if remembered := d.expiresAt[key]; remembered != nil && remembered.After(now) {
		return true, nil
	}

	if len(d.expiresAt) >= min(max(d.sweepThreshold, minimumSweepThreshold), maxEntries) {
		d.sweep(now)
		d.sweepThreshold = max(2*len(d.expiresAt), minimumSweepThreshold)
	}

	if len(d.expiresAt) >= maxEntries {
		return false, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: it holds %d live proofs", ErrFull, len(d.expiresAt)),
		)
	}

	d.expiresAt[key] = &expiresAt

	return false, nil
}

func (d *Detector) sweep(now time.Time) {
	for key, expiresAt := range d.expiresAt {
		if expiresAt == nil || !expiresAt.After(now) {
			delete(d.expiresAt, key)
		}
	}
}

func New() *Detector {
	return &Detector{}
}
