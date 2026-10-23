// Package audittest is the conformance suite for the audit module's Log
// port: RunLogSuite is the authoritative description of the contract's
// edge-case behaviour, and an adapter counts as correct when it passes
// the suite unchanged.
//
// It is a sibling package rather than a suite.go inside the port's own
// package, and rather than a _test.go file, because both alternatives
// fail a requirement:
//
//   - Identifiers declared in a _test.go file are not importable from
//     outside that package, and this suite must be callable from another
//     module entirely. CHARTER.md counts a consumer as having adopted
//     this module when this suite runs green in that consumer's CI
//     against its own wiring — which is what makes "adopted" testable
//     rather than asserted, and which a test-only identifier could not
//     support.
//   - A non-test file that imports testing makes testing a dependency of
//     the production package, so every consumer's binary links it and
//     inherits its flag registrations. Keeping the suite here keeps
//     testing out of the production import graph.
//
// This is the standard library's own shape: net/http/httptest is a
// sibling of net/http, and testing/fstest.TestFS verifies any fs.FS.
//
// The suite imports the module's internal packages, which is legal from
// inside the module and invisible from outside it: every type in
// RunLogSuite's signature is re-exported from the root package as an
// alias, so a consumer writes func(t *testing.T) audit.Log and gets the
// identical type.
//
// Within this file the naming follows one rule: facade names (audit.Entry,
// audit.Record, audit.VerifyOptions) wherever the facade re-exports the
// type, so the suite reads the way a consumer's own code reads, and
// internal names (domain.FirstSequence, eventlog.Verify) only for what the
// facade deliberately re-exports nothing for yet — constants and the
// verification functions, which wait for the increment that adds Open.
package audittest

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/laenenai/audit"
	"github.com/laenenai/audit/internal/domain"
	"github.com/laenenai/audit/internal/eventlog"
)

// RunLogSuite runs the contract every audit.Log adapter must satisfy.
// newLog is called once per subtest, receiving that subtest's own *T, so
// an adapter that needs per-test setup and teardown (a scratch schema, a
// transaction that rolls back, a container it starts) can register it with
// t.Cleanup inside newLog and get fresh, isolated state for every subtest.
// Each subtest assumes it is handed an empty log.
//
// Every assertion here must hold for any append-only store — a slice
// behind a mutex, a Postgres table, an object-store manifest. Nothing here
// inspects storage directly or assumes a particular backend;
// adapter-specific mechanics (how appends are serialized, how a
// transaction is joined, what happens when the database is unreachable)
// belong in that adapter's own test file.
//
// The tamper subtests work on entries read back out of the log rather than
// by corrupting the adapter's storage, which the port offers no way to do
// — and should not. They assert the property that actually matters: that
// the chain this adapter produces is one in which a modification, a
// deletion, a reordering, and a truncation are each detectable. An adapter
// that fabricated its links, reused a digest, or numbered its entries from
// zero fails these, which is the point; whether the adapter's own storage
// can be corrupted is a question about the storage, not about the chain.
func RunLogSuite(t *testing.T, newLog func(t *testing.T) audit.Log) {
	t.Helper()

	t.Run("EmptyLogHasZeroHeadAndVerifiesClean", func(t *testing.T) {
		log := newLog(t)
		ctx := context.Background()

		head, err := log.Head(ctx)
		if err != nil {
			t.Fatalf("Head of an empty log: %v", err)
		}
		if !head.IsZero() {
			t.Fatalf("Head of an empty log = %s, want the zero checkpoint", head)
		}

		entries, err := log.Entries(ctx, domain.FirstSequence, 10)
		if err != nil {
			t.Fatalf("Entries of an empty log: %v", err)
		}
		if len(entries) != 0 {
			t.Fatalf("Entries of an empty log returned %d entries", len(entries))
		}

		got, err := eventlog.Verify(ctx, log, audit.VerifyOptions{})
		if err != nil {
			t.Fatalf("Verify of an empty log: %v", err)
		}
		if !got.IsZero() {
			t.Fatalf("Verify of an empty log = %s, want the zero checkpoint", got)
		}
	})

	// The log, not the caller, assigns identity, position and time. A
	// caller able to choose its own sequence number could overwrite
	// history by renumbering; one able to choose its own timestamp could
	// backdate an entry past a retention boundary.
	t.Run("AppendAssignsIdentityPositionAndTime", func(t *testing.T) {
		log := newLog(t)
		ctx := context.Background()

		first, err := log.Append(ctx, testRecord(1))
		if err != nil {
			t.Fatalf("first Append: %v", err)
		}
		if first.Event.Sequence != domain.FirstSequence {
			t.Fatalf("first entry's sequence = %d, want %d", first.Event.Sequence, domain.FirstSequence)
		}
		if !first.Link.Prev.IsZero() {
			t.Fatalf("genesis entry's Link.Prev = %s, want the zero digest", first.Link.Prev)
		}
		if _, err := domain.ParseEventID(string(first.Event.ID)); err != nil {
			t.Fatalf("assigned event id is not canonical: %v", err)
		}
		if got := first.ComputeDigest(); !got.Equal(first.Link.Self) {
			t.Fatalf("entry's Link.Self = %s, but its contents hash to %s", first.Link.Self, got)
		}

		// The recorded instant must be exactly what the chain committed
		// to, or verification fails after a storage round trip for a
		// reason that has nothing to do with tampering.
		if ts := first.Event.Timestamp; !ts.Equal(domain.CanonicalTime(ts)) {
			t.Fatalf("assigned timestamp %v is not canonical (see domain.CanonicalTime)", ts)
		}
		if first.Event.Timestamp.IsZero() {
			t.Fatal("assigned timestamp is the zero time: the log did not record when it recorded")
		}

		second, err := log.Append(ctx, testRecord(2))
		if err != nil {
			t.Fatalf("second Append: %v", err)
		}
		if second.Event.Sequence != first.Event.Sequence+1 {
			t.Fatalf("second entry's sequence = %d, want %d", second.Event.Sequence, first.Event.Sequence+1)
		}
		if !second.Link.Prev.Equal(first.Link.Self) {
			t.Fatalf("second entry's Link.Prev = %s, want the first entry's Self %s", second.Link.Prev, first.Link.Self)
		}
		if second.Event.ID == first.Event.ID {
			t.Fatal("two appends were assigned the same event id")
		}

		head, err := log.Head(ctx)
		if err != nil {
			t.Fatalf("Head: %v", err)
		}
		want := audit.Checkpoint{Sequence: second.Event.Sequence, Digest: second.Link.Self}
		if head != want {
			t.Fatalf("Head = %s, want %s", head, want)
		}
	})

	t.Run("AppendRoundTripsEverySubmittedField", func(t *testing.T) {
		log := newLog(t)
		ctx := context.Background()

		records := []audit.Record{
			testRecord(1),
			{Actor: "system", Action: "key.rotate", Outcome: "succeeded"},
			{Actor: "svc-1", Subject: audit.SubjectRef{Kind: "policy", ID: "p-9"}, Action: "policy.change", Outcome: "denied", Detail: nil},
			{Actor: "svc-1", Subject: audit.SubjectRef{Kind: "document", ID: "d-1"}, Action: "content.read", Outcome: "partial", Detail: []byte{0x00, 0xff, 0x7f}},
			{Actor: "svc-1", Action: "retrieval.query", Outcome: "allowed", Detail: randomDetail(t, domain.MaxDetailLen)},
		}

		for i, rec := range records {
			appended, err := log.Append(ctx, rec)
			if err != nil {
				t.Fatalf("Append(records[%d]): %v", i, err)
			}
			assertRecordRoundTrip(t, rec, appended.Event)
		}

		read, err := log.Entries(ctx, domain.FirstSequence, len(records))
		if err != nil {
			t.Fatalf("Entries: %v", err)
		}
		if len(read) != len(records) {
			t.Fatalf("Entries returned %d entries, want %d", len(read), len(records))
		}
		for i, rec := range records {
			assertRecordRoundTrip(t, rec, read[i].Event)
		}
	})

	t.Run("AppendRejectsAnInvalidRecordWithoutTouchingTheChain", func(t *testing.T) {
		log := newLog(t)
		ctx := context.Background()

		if _, err := log.Append(ctx, testRecord(1)); err != nil {
			t.Fatalf("Append: %v", err)
		}
		before, err := log.Head(ctx)
		if err != nil {
			t.Fatalf("Head: %v", err)
		}

		invalid := map[string]audit.Record{
			"no_actor":                {Action: "a", Outcome: "o"},
			"no_action":               {Actor: "p", Outcome: "o"},
			"no_outcome":              {Actor: "p", Action: "a"},
			"subject_kind_without_id": {Actor: "p", Action: "a", Outcome: "o", Subject: audit.SubjectRef{Kind: "document"}},
			"subject_id_without_kind": {Actor: "p", Action: "a", Outcome: "o", Subject: audit.SubjectRef{ID: "d-1"}},
			"detail_too_large":        {Actor: "p", Action: "a", Outcome: "o", Detail: make([]byte, domain.MaxDetailLen+1)},
		}
		for name, rec := range invalid {
			t.Run(name, func(t *testing.T) {
				if _, err := log.Append(ctx, rec); !errors.Is(err, domain.ErrInvalidRecord) {
					t.Fatalf("Append error = %v, want ErrInvalidRecord", err)
				}
			})
		}

		after, err := log.Head(ctx)
		if err != nil {
			t.Fatalf("Head: %v", err)
		}
		if after != before {
			t.Fatalf("Head moved from %s to %s: a rejected append consumed a sequence number", before, after)
		}
		if _, err := eventlog.Verify(ctx, log, audit.VerifyOptions{Witness: before}); err != nil {
			t.Fatalf("Verify after rejected appends: %v", err)
		}
	})

	// A caller that reuses its Detail buffer — a pooled encoder, a loop
	// variable — must not be able to change what the log already hashed.
	t.Run("AppendCopiesDetailRatherThanRetainingIt", func(t *testing.T) {
		log := newLog(t)
		ctx := context.Background()

		detail := []byte(`{"n":1}`)
		appended, err := log.Append(ctx, audit.Record{
			Actor: "p", Action: "a", Outcome: "o", Detail: detail,
		})
		if err != nil {
			t.Fatalf("Append: %v", err)
		}

		original := append([]byte(nil), detail...)
		for i := range detail {
			detail[i] = 'X'
		}
		appended.Event.Detail[0] = 'Y'

		read, err := log.Entries(ctx, domain.FirstSequence, 1)
		if err != nil {
			t.Fatalf("Entries: %v", err)
		}
		if !bytes.Equal(read[0].Event.Detail, original) {
			t.Fatalf("stored detail changed when the caller reused its buffer or mutated the returned entry")
		}
		if _, err := eventlog.Verify(ctx, log, audit.VerifyOptions{}); err != nil {
			t.Fatalf("Verify after mutating the caller's buffer: %v", err)
		}
	})

	t.Run("EntriesPagesInAscendingSequenceOrder", func(t *testing.T) {
		log := newLog(t)
		ctx := context.Background()

		const total = 7
		for i := 1; i <= total; i++ {
			if _, err := log.Append(ctx, testRecord(i)); err != nil {
				t.Fatalf("Append %d: %v", i, err)
			}
		}

		for _, limit := range []int{1, 2, 3, total, total + 1} {
			t.Run(fmt.Sprintf("limit=%d", limit), func(t *testing.T) {
				var seen []uint64
				for from := domain.FirstSequence; ; {
					page, err := log.Entries(ctx, from, limit)
					if err != nil {
						t.Fatalf("Entries(from=%d, limit=%d): %v", from, limit, err)
					}
					if len(page) == 0 {
						break
					}
					if len(page) > limit {
						t.Fatalf("Entries returned %d entries for limit %d", len(page), limit)
					}
					for _, e := range page {
						seen = append(seen, e.Event.Sequence)
					}
					if len(page) < limit {
						break
					}
					from = page[len(page)-1].Event.Sequence + 1
				}

				if len(seen) != total {
					t.Fatalf("paging saw %d entries, want %d (%v)", len(seen), total, seen)
				}
				for i, seq := range seen {
					if want := domain.FirstSequence + uint64(i); seq != want { //nolint:gosec // i indexes a 7-element slice
						t.Fatalf("paging saw sequence %d at position %d, want %d", seq, i, want)
					}
				}
			})
		}

		t.Run("from_zero_is_from_the_genesis", func(t *testing.T) {
			page, err := log.Entries(ctx, 0, 1)
			if err != nil {
				t.Fatalf("Entries(from=0): %v", err)
			}
			if len(page) != 1 || page[0].Event.Sequence != domain.FirstSequence {
				t.Fatalf("Entries(from=0) = %v, want the genesis entry", page)
			}
		})

		t.Run("from_past_the_end_is_empty_not_an_error", func(t *testing.T) {
			page, err := log.Entries(ctx, total+1, 10)
			if err != nil {
				t.Fatalf("Entries past the end: %v", err)
			}
			if len(page) != 0 {
				t.Fatalf("Entries past the end returned %d entries", len(page))
			}
		})

		t.Run("non_positive_limit_is_an_error", func(t *testing.T) {
			for _, limit := range []int{0, -1} {
				if _, err := log.Entries(ctx, domain.FirstSequence, limit); !errors.Is(err, domain.ErrInvalidArgument) {
					t.Fatalf("Entries(limit=%d) error = %v, want ErrInvalidArgument", limit, err)
				}
			}
		})
	})

	t.Run("VerifyAcceptsAnIntactChain", func(t *testing.T) {
		log := newLog(t)
		ctx := context.Background()

		const total = 25
		var last audit.Entry
		for i := 1; i <= total; i++ {
			appended, err := log.Append(ctx, testRecord(i))
			if err != nil {
				t.Fatalf("Append %d: %v", i, err)
			}
			last = appended
		}

		want := audit.Checkpoint{Sequence: last.Event.Sequence, Digest: last.Link.Self}

		// Verified with and without a witness, and at a page size that
		// forces several pages, since a paging bug in an adapter looks
		// exactly like tampering.
		for _, opt := range []audit.VerifyOptions{
			{},
			{PageSize: 1},
			{PageSize: 4},
			{Witness: want},
			{Witness: audit.Checkpoint{Sequence: 1, Digest: mustFirstDigest(t, log)}},
		} {
			got, err := eventlog.Verify(ctx, log, opt)
			if err != nil {
				t.Fatalf("Verify(%+v): %v", opt, err)
			}
			if got != want {
				t.Fatalf("Verify(%+v) head = %s, want %s", opt, got, want)
			}
		}
	})

	t.Run("VerifyDetectsAModifiedEntry", func(t *testing.T) {
		entries := appendAndRead(t, newLog, 5)
		entries[2].Event.Detail = []byte(`{"tampered":true}`)

		_, err := eventlog.VerifyEntries(entries, audit.VerifyOptions{})
		assertBreak(t, err, domain.BreakDigestMismatch)
	})

	t.Run("VerifyDetectsADeletedEntry", func(t *testing.T) {
		entries := appendAndRead(t, newLog, 5)
		withHole := append(append([]audit.Entry{}, entries[:2]...), entries[3:]...)

		_, err := eventlog.VerifyEntries(withHole, audit.VerifyOptions{})
		assertBreak(t, err, domain.BreakSequenceMismatch)
	})

	t.Run("VerifyDetectsAReorderedEntry", func(t *testing.T) {
		entries := appendAndRead(t, newLog, 5)
		entries[1], entries[3] = entries[3], entries[1]

		_, err := eventlog.VerifyEntries(entries, audit.VerifyOptions{})
		assertBreak(t, err, domain.BreakSequenceMismatch)
	})

	// Truncation is the one tamper mode a chain cannot catch on its own:
	// a prefix of a valid chain is a valid chain. Both halves are asserted
	// here, because an adapter that somehow "detected" the second half
	// would be claiming knowledge it cannot have. See Verify's doc
	// comment.
	t.Run("VerifyDetectsATruncatedTailOnlyAgainstAWitness", func(t *testing.T) {
		entries := appendAndRead(t, newLog, 5)
		witness := audit.Checkpoint{
			Sequence: entries[4].Event.Sequence,
			Digest:   entries[4].Link.Self,
		}
		truncated := entries[:3]

		_, err := eventlog.VerifyEntries(truncated, audit.VerifyOptions{Witness: witness})
		assertBreak(t, err, domain.BreakTruncated)

		if _, err := eventlog.VerifyEntries(truncated, audit.VerifyOptions{}); err != nil {
			t.Fatalf("a truncated chain with no witness must verify clean, but did not: %v", err)
		}
	})

	// The strongest attack a witness defends against: the suffix is not
	// removed but replaced with a different, internally consistent one.
	t.Run("VerifyDetectsAReplacedSuffixAgainstAWitness", func(t *testing.T) {
		entries := appendAndRead(t, newLog, 5)
		witness := audit.Checkpoint{
			Sequence: entries[4].Event.Sequence,
			Digest:   entries[4].Link.Self,
		}

		forged := make([]audit.Entry, len(entries))
		copy(forged, entries)
		forged[3].Event.Detail = []byte(`{"forged":true}`)
		prev := forged[2].Link.Self
		for i := 3; i < len(forged); i++ {
			forged[i] = domain.NewEntry(prev, forged[i].Event)
			prev = forged[i].Link.Self
		}

		if _, err := eventlog.VerifyEntries(forged, audit.VerifyOptions{}); err != nil {
			t.Fatalf("the forged chain should be internally consistent, so that only the witness catches it: %v", err)
		}
		_, err := eventlog.VerifyEntries(forged, audit.VerifyOptions{Witness: witness})
		assertBreak(t, err, domain.BreakCheckpointMismatch)
	})

	// Concurrent appends must produce one chain, not several interleaved
	// ones: contiguous sequences with no gaps and no repeats, every link
	// matching, every submitted record present exactly once, and a head
	// that agrees with the entries. An adapter that reads the head
	// outside the critical section that writes the entry fails this.
	t.Run("ConcurrentAppendsProduceOneWellOrderedChain", func(t *testing.T) {
		log := newLog(t)
		ctx := context.Background()

		const (
			goroutines       = 8
			appendsPerWorker = 16
			total            = goroutines * appendsPerWorker
		)

		var wg sync.WaitGroup
		errs := make([]error, goroutines)
		for g := range goroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range appendsPerWorker {
					rec := audit.Record{
						Actor:   audit.ActorID(fmt.Sprintf("worker-%d", g)),
						Subject: audit.SubjectRef{Kind: "document", ID: fmt.Sprintf("doc-%d-%d", g, i)},
						Action:  "content.read",
						Outcome: "allowed",
						Detail:  []byte(fmt.Sprintf(`{"worker":%d,"i":%d}`, g, i)),
					}
					if _, err := log.Append(ctx, rec); err != nil {
						errs[g] = fmt.Errorf("worker %d append %d: %w", g, i, err)
						return
					}
				}
			}()
		}
		wg.Wait()

		for _, err := range errs {
			if err != nil {
				t.Fatalf("concurrent append failed: %v", err)
			}
		}

		head, err := eventlog.Verify(ctx, log, audit.VerifyOptions{PageSize: 10})
		if err != nil {
			t.Fatalf("Verify after concurrent appends: %v", err)
		}
		if head.Sequence != total {
			t.Fatalf("head sequence after %d concurrent appends = %d, want %d", total, head.Sequence, total)
		}

		entries, err := readAll(ctx, log, 32)
		if err != nil {
			t.Fatalf("read back: %v", err)
		}
		if len(entries) != total {
			t.Fatalf("read back %d entries, want %d", len(entries), total)
		}

		subjects := make(map[string]int, total)
		ids := make(map[domain.EventID]int, total)
		for _, e := range entries {
			subjects[e.Event.Subject.ID]++
			ids[e.Event.ID]++
		}
		if len(subjects) != total {
			t.Fatalf("saw %d distinct subjects, want %d: an append was lost or duplicated", len(subjects), total)
		}
		if len(ids) != total {
			t.Fatalf("saw %d distinct event ids, want %d: ids are not unique under concurrency", len(ids), total)
		}
	})

	// NoEventDetailLeaksInErrors is the security invariant every adapter
	// is forced to exercise: an audit detail payload may carry sensitive
	// content, and the error paths are where it would escape into a log
	// file. The payload is pushed through both error paths that ever see
	// it — a rejected append, which holds the record, and a failed
	// verification, which holds the entry — and the sentinel must appear
	// in neither.
	t.Run("NoEventDetailLeaksInErrors", func(t *testing.T) {
		log := newLog(t)
		ctx := context.Background()

		const sentinel = "sentinel-5d2e8c-do-not-leak-this-value"

		oversized := audit.Record{
			Actor:   audit.ActorID(sentinel),
			Action:  "content.read",
			Outcome: "allowed",
			Detail:  append([]byte(sentinel), make([]byte, domain.MaxDetailLen)...),
		}
		_, err := log.Append(ctx, oversized)
		if err == nil {
			t.Fatal("an oversized detail payload was accepted")
		}
		if strings.Contains(err.Error(), sentinel) {
			t.Fatalf("Append error leaked event content: %v", err)
		}

		appended, err := log.Append(ctx, audit.Record{
			Actor:   audit.ActorID(sentinel),
			Action:  "content.read",
			Outcome: "allowed",
			Detail:  []byte(sentinel),
		})
		if err != nil {
			t.Fatalf("Append: %v", err)
		}

		tampered := []audit.Entry{appended.Clone()}
		tampered[0].Event.Detail = []byte(sentinel + "-modified")
		if _, err := eventlog.VerifyEntries(tampered, audit.VerifyOptions{}); err == nil {
			t.Fatal("tampering was not detected")
		} else if strings.Contains(err.Error(), sentinel) {
			t.Fatalf("verification error leaked event content: %v", err)
		}
	})

	// Every method takes a context as its first argument, and a canceled
	// one must be honoured rather than ignored. An adapter that silently
	// completes an append for a request that has already gone away is
	// recording something that did not happen.
	t.Run("CanceledContextIsRefused", func(t *testing.T) {
		log := newLog(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		if _, err := log.Append(ctx, testRecord(1)); !errors.Is(err, context.Canceled) {
			t.Fatalf("Append with a canceled context error = %v, want context.Canceled", err)
		}
		if _, err := log.Head(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("Head with a canceled context error = %v, want context.Canceled", err)
		}
		if _, err := log.Entries(ctx, domain.FirstSequence, 1); !errors.Is(err, context.Canceled) {
			t.Fatalf("Entries with a canceled context error = %v, want context.Canceled", err)
		}

		live := newLog(t)
		if _, err := live.Append(context.Background(), testRecord(1)); err != nil {
			t.Fatalf("a canceled context must not have broken the adapter: %v", err)
		}
	})
}

// testRecord returns a valid record distinguishable by n.
func testRecord(n int) audit.Record {
	return audit.Record{
		Actor:   "principal-1",
		Subject: audit.SubjectRef{Kind: "document", ID: fmt.Sprintf("doc-%d", n)},
		Action:  "content.read",
		Outcome: "allowed",
		Detail:  []byte(fmt.Sprintf(`{"n":%d}`, n)),
	}
}

// assertRecordRoundTrip checks that every field a caller submitted came
// back unchanged. nil and empty Detail are both accepted for a submitted
// nil, since the canonical encoding length-prefixes and cannot tell them
// apart — an adapter whose storage normalizes one to the other is not
// wrong.
func assertRecordRoundTrip(t *testing.T, want audit.Record, got audit.Event) {
	t.Helper()

	if got.Actor != want.Actor {
		t.Fatalf("Actor = %q, want %q", got.Actor, want.Actor)
	}
	if got.Subject != want.Subject {
		t.Fatalf("Subject = %+v, want %+v", got.Subject, want.Subject)
	}
	if got.Action != want.Action {
		t.Fatalf("Action = %q, want %q", got.Action, want.Action)
	}
	if got.Outcome != want.Outcome {
		t.Fatalf("Outcome = %q, want %q", got.Outcome, want.Outcome)
	}
	if !bytes.Equal(got.Detail, want.Detail) {
		t.Fatalf("Detail round-tripped as %d bytes, want %d", len(got.Detail), len(want.Detail))
	}
}

// appendAndRead fills a fresh log with n entries and returns them as read
// back out of the log — the material the tamper subtests work on. Reading
// them back rather than keeping what Append returned is deliberate: it is
// the stored chain, not the returned value, that a verifier later sees.
func appendAndRead(t *testing.T, newLog func(t *testing.T) audit.Log, n int) []audit.Entry {
	t.Helper()

	log := newLog(t)
	ctx := context.Background()
	for i := 1; i <= n; i++ {
		if _, err := log.Append(ctx, testRecord(i)); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	entries, err := readAll(ctx, log, n)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(entries) != n {
		t.Fatalf("read back %d entries, want %d", len(entries), n)
	}
	if _, err := eventlog.VerifyEntries(entries, audit.VerifyOptions{}); err != nil {
		t.Fatalf("the chain this adapter produced does not verify before any tampering: %v", err)
	}
	return entries
}

// readAll pages the whole log into a slice.
func readAll(ctx context.Context, log audit.Log, pageSize int) ([]audit.Entry, error) {
	var all []audit.Entry
	for from := domain.FirstSequence; ; {
		page, err := log.Entries(ctx, from, pageSize)
		if err != nil {
			return nil, fmt.Errorf("read entries from sequence %d: %w", from, err)
		}
		if len(page) == 0 {
			return all, nil
		}
		all = append(all, page...)
		if len(page) < pageSize {
			return all, nil
		}
		from = page[len(page)-1].Event.Sequence + 1
	}
}

// assertBreak checks that err reports a broken chain of the given kind.
func assertBreak(t *testing.T, err error, kind audit.BreakKind) {
	t.Helper()

	if !errors.Is(err, domain.ErrChainBroken) {
		t.Fatalf("error = %v, want it to match domain.ErrChainBroken", err)
	}
	var chainErr *audit.ChainError
	if !errors.As(err, &chainErr) {
		t.Fatalf("error = %v, want a *audit.ChainError", err)
	}
	if chainErr.Kind != kind {
		t.Fatalf("break kind = %q, want %q", chainErr.Kind, kind)
	}
}

// mustFirstDigest returns the genesis entry's digest, for use as a witness
// at a position other than the head.
func mustFirstDigest(t *testing.T, log audit.Log) audit.Digest {
	t.Helper()

	page, err := log.Entries(context.Background(), domain.FirstSequence, 1)
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(page) == 0 {
		t.Fatal("Entries returned no genesis entry")
	}
	return page[0].Link.Self
}

// randomDetail returns n cryptographically random bytes, for an adapter
// test that wants a detail payload with no structure. crypto/rand rather
// than math/rand matches this codebase's convention and avoids a weak-RNG
// lint finding, even for a value with no security role.
func randomDetail(t *testing.T, n int) []byte {
	t.Helper()

	b := make([]byte, n)
	if _, err := cryptorand.Read(b); err != nil {
		t.Fatalf("generate random detail: %v", err)
	}
	return b
}
