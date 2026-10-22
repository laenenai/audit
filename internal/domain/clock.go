package domain

import "time"

// Clock abstracts the current time so that an append's recorded instant,
// and the timestamp component of a minted EventID, can be driven
// deterministically in tests. Nothing in this module reads the wall clock
// except through a Clock it was given.
type Clock interface {
	Now() time.Time
}

// SystemClock is the production Clock, backed by the real wall clock.
type SystemClock struct{}

// Now returns the current wall-clock time.
func (SystemClock) Now() time.Time { return time.Now() }

var _ Clock = SystemClock{}

// FixedClock is a test Clock that returns a fixed instant until advanced.
//
// It is not safe for concurrent use, and deliberately not made so: a lock
// here would hide, rather than reveal, a test that depends on the order of
// concurrent clock reads. An adapter that reads its Clock inside the same
// critical section that assigns sequence numbers — which every adapter
// must do anyway, since the sequence and the timestamp are both part of
// the entry being hashed — can use a FixedClock under concurrency safely.
type FixedClock struct {
	now time.Time
}

// NewFixedClock returns a FixedClock starting at t.
func NewFixedClock(t time.Time) *FixedClock {
	return &FixedClock{now: t}
}

// Now returns the clock's current fixed instant.
func (c *FixedClock) Now() time.Time { return c.now }

// Advance moves the clock's fixed instant forward by d.
func (c *FixedClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

var _ Clock = (*FixedClock)(nil)
