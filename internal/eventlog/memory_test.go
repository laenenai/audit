package eventlog_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/laenen-ai/audit/internal/domain"
	"github.com/laenen-ai/audit/internal/eventlog"
)

func newMemoryLog(t *testing.T) eventlog.Log {
	t.Helper()
	return eventlog.NewMemory(eventlog.MemoryConfig{})
}

func TestMemory_PassesLogSuite(t *testing.T) {
	eventlog.RunLogSuite(t, newMemoryLog)
}

// The suite covers the contract; what follows is specific to this adapter.

// A FixedClock is not safe for concurrent use on its own, so an adapter
// that read its clock outside the critical section assigning sequence
// numbers would be racy with one — and racy about the timestamp it
// commits to. This test is the reason that is not merely asserted in a
// doc comment; it fails under -race if the clock read escapes the lock.
func TestMemory_UsesTheInjectedClockUnderConcurrency(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, time.October, 23, 15, 0, 0, 0, time.UTC)
	log := eventlog.NewMemory(eventlog.MemoryConfig{Clock: domain.NewFixedClock(start)})
	ctx := context.Background()

	const total = 64
	done := make(chan error, total)
	for i := range total {
		go func() {
			_, err := log.Append(ctx, domain.Record{
				Actor:   "p",
				Action:  "a",
				Outcome: "o",
				Detail:  []byte{byte(i & 0xff)},
			})
			done <- err
		}()
	}
	for range total {
		if err := <-done; err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	entries, err := log.Entries(ctx, domain.FirstSequence, total)
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	for _, e := range entries {
		if !e.Event.Timestamp.Equal(start) {
			t.Fatalf("entry %d timestamp = %v, want the fixed clock's %v",
				e.Event.Sequence, e.Event.Timestamp, start)
		}
	}
}

func TestMemory_DefaultsToTheSystemClock(t *testing.T) {
	t.Parallel()

	before := domain.CanonicalTime(time.Now())
	log := eventlog.NewMemory(eventlog.MemoryConfig{})

	appended, err := log.Append(context.Background(), domain.Record{Actor: "p", Action: "a", Outcome: "o"})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if appended.Event.Timestamp.Before(before) {
		t.Fatalf("timestamp %v predates the start of the test (%v)", appended.Event.Timestamp, before)
	}
}

// Entries must hand out copies: a caller that mutates what it read must
// not be able to change what the log holds, or the tamper subtests would
// be testing their own mutations rather than the stored chain.
func TestMemory_EntriesReturnsCopies(t *testing.T) {
	t.Parallel()

	log := eventlog.NewMemory(eventlog.MemoryConfig{})
	ctx := context.Background()

	if _, err := log.Append(ctx, domain.Record{
		Actor: "p", Action: "a", Outcome: "o", Detail: []byte("original"),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	first, err := log.Entries(ctx, domain.FirstSequence, 1)
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	first[0].Event.Detail[0] = 'X'
	first[0].Link.Self = domain.Digest{}

	second, err := log.Entries(ctx, domain.FirstSequence, 1)
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if string(second[0].Event.Detail) != "original" {
		t.Fatalf("stored detail = %q after a caller mutated what it read", second[0].Event.Detail)
	}
	if second[0].Link.Self.IsZero() {
		t.Fatal("stored link was zeroed by a caller mutating what it read")
	}
	if _, err := eventlog.Verify(ctx, log, eventlog.VerifyOptions{}); err != nil {
		t.Fatalf("Verify after a caller mutated what it read: %v", err)
	}
}

func TestMemory_HeadIsStableAcrossReads(t *testing.T) {
	t.Parallel()

	log := eventlog.NewMemory(eventlog.MemoryConfig{})
	ctx := context.Background()

	appended, err := log.Append(ctx, domain.Record{Actor: "p", Action: "a", Outcome: "o"})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	want := domain.Checkpoint{Sequence: appended.Event.Sequence, Digest: appended.Link.Self}

	for i := range 3 {
		got, err := log.Head(ctx)
		if err != nil {
			t.Fatalf("Head %d: %v", i, err)
		}
		if got != want {
			t.Fatalf("Head %d = %s, want %s", i, got, want)
		}
	}
}

func TestMemory_DeadlineExceededIsReported(t *testing.T) {
	t.Parallel()

	log := eventlog.NewMemory(eventlog.MemoryConfig{})
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	if _, err := log.Append(ctx, domain.Record{Actor: "p", Action: "a", Outcome: "o"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Append error = %v, want context.DeadlineExceeded", err)
	}
}
