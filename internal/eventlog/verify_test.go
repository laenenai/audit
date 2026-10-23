package eventlog_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/laenenai/audit/internal/domain"
	"github.com/laenenai/audit/internal/eventlog"
)

// buildChain returns an intact chain of n entries, built the way an adapter
// builds one. It does not go through any adapter: these tests are about the
// verifier, so the material under test is constructed directly and then
// tampered with in ways no adapter would let a caller perform.
func buildChain(t *testing.T, n int) []domain.Entry {
	t.Helper()

	clock := domain.NewFixedClock(time.Date(2026, time.October, 23, 12, 0, 0, 0, time.UTC))
	chain := domain.ChainID{Tenant: "tenant-1", Pool: "pool-1"}
	entries := make([]domain.Entry, 0, n)
	var prev domain.Digest

	for i := 1; i <= n; i++ {
		id, err := domain.NewEventID(clock)
		if err != nil {
			t.Fatalf("NewEventID: %v", err)
		}
		rec := domain.Record{
			Actor:   "principal-1",
			Subject: domain.SubjectRef{Kind: "document", ID: fmt.Sprintf("doc-%d", i)},
			Action:  "content.read",
			Outcome: "allowed",
			Detail:  []byte(fmt.Sprintf(`{"n":%d}`, i)),
		}
		//nolint:gosec // i is a small loop counter, not an external length
		entry := domain.NewEntry(prev, domain.NewEvent(chain, id, uint64(i), clock.Now(), rec))
		entries = append(entries, entry)
		prev = entry.Link.Self
		clock.Advance(time.Millisecond)
	}
	return entries
}

// rechain rebuilds the links of entries[from:] so the result is an
// internally consistent chain again. It is how these tests model an
// attacker who can rewrite history wholesale rather than just corrupt one
// row — the case a chain alone cannot catch and a witness can.
func rechain(entries []domain.Entry, from int) []domain.Entry {
	out := make([]domain.Entry, len(entries))
	copy(out, entries)

	var prev domain.Digest
	if from > 0 {
		prev = out[from-1].Link.Self
	}
	for i := from; i < len(out); i++ {
		out[i] = domain.NewEntry(prev, out[i].Event)
		prev = out[i].Link.Self
	}
	return out
}

func headOf(entries []domain.Entry) domain.Checkpoint {
	if len(entries) == 0 {
		return domain.Checkpoint{}
	}
	last := entries[len(entries)-1]
	return domain.Checkpoint{Sequence: last.Event.Sequence, Digest: last.Link.Self}
}

func wantBreak(t *testing.T, err error, kind domain.BreakKind, sequence uint64) {
	t.Helper()

	if !errors.Is(err, domain.ErrChainBroken) {
		t.Fatalf("error = %v, want it to match ErrChainBroken", err)
	}
	var chainErr *domain.ChainError
	if !errors.As(err, &chainErr) {
		t.Fatalf("error = %v, want it to be a *domain.ChainError", err)
	}
	if chainErr.Kind != kind {
		t.Fatalf("break kind = %q, want %q", chainErr.Kind, kind)
	}
	if chainErr.Sequence != sequence {
		t.Fatalf("break sequence = %d, want %d", chainErr.Sequence, sequence)
	}
}

func TestVerifyEntriesAcceptsAnIntactChain(t *testing.T) {
	t.Parallel()

	entries := buildChain(t, 5)
	got, err := eventlog.VerifyEntries(entries, eventlog.VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyEntries: %v", err)
	}
	if want := headOf(entries); got != want {
		t.Fatalf("head = %s, want %s", got, want)
	}
}

func TestVerifyEntriesAcceptsAnIntactChainAgainstItsOwnHeadAsWitness(t *testing.T) {
	t.Parallel()

	entries := buildChain(t, 5)
	opt := eventlog.VerifyOptions{Witness: headOf(entries)}
	if _, err := eventlog.VerifyEntries(entries, opt); err != nil {
		t.Fatalf("VerifyEntries with a matching witness: %v", err)
	}
}

func TestVerifyEntriesAcceptsAnEmptyChain(t *testing.T) {
	t.Parallel()

	got, err := eventlog.VerifyEntries(nil, eventlog.VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyEntries(nil): %v", err)
	}
	if !got.IsZero() {
		t.Fatalf("head of an empty chain = %s, want the zero checkpoint", got)
	}
}

// A chain is verified from its genesis entry, so a caller cannot hand the
// verifier a suffix and have it accept the suffix's first entry as a
// beginning.
func TestVerifyEntriesRequiresTheChainToStartAtItsGenesis(t *testing.T) {
	t.Parallel()

	entries := buildChain(t, 5)
	_, err := eventlog.VerifyEntries(entries[1:], eventlog.VerifyOptions{})
	wantBreak(t, err, domain.BreakSequenceMismatch, domain.FirstSequence)
}

func TestVerifyEntriesDetectsAModifiedEntry(t *testing.T) {
	t.Parallel()

	entries := buildChain(t, 5)
	entries[2].Event.Detail = []byte(`{"n":999}`)

	_, err := eventlog.VerifyEntries(entries, eventlog.VerifyOptions{})
	wantBreak(t, err, domain.BreakDigestMismatch, 3)
}

// An attacker who can also recompute the entry's own digest gets one entry
// further: the entry itself is self-consistent, and the next entry's Prev
// is what gives it away.
func TestVerifyEntriesDetectsAModifiedEntryWhoseDigestWasRecomputed(t *testing.T) {
	t.Parallel()

	entries := buildChain(t, 5)
	rewritten := entries[2].Event.Clone()
	rewritten.Detail = []byte(`{"n":999}`)
	entries[2] = domain.NewEntry(entries[2].Link.Prev, rewritten)

	_, err := eventlog.VerifyEntries(entries, eventlog.VerifyOptions{})
	wantBreak(t, err, domain.BreakLinkMismatch, 4)
}

func TestVerifyEntriesDetectsADeletedEntry(t *testing.T) {
	t.Parallel()

	entries := buildChain(t, 5)
	withHole := append(append([]domain.Entry{}, entries[:2]...), entries[3:]...)

	_, err := eventlog.VerifyEntries(withHole, eventlog.VerifyOptions{})
	wantBreak(t, err, domain.BreakSequenceMismatch, 3)
}

func TestVerifyEntriesDetectsReorderedEntries(t *testing.T) {
	t.Parallel()

	entries := buildChain(t, 5)
	entries[1], entries[2] = entries[2], entries[1]

	_, err := eventlog.VerifyEntries(entries, eventlog.VerifyOptions{})
	wantBreak(t, err, domain.BreakSequenceMismatch, 2)
}

func TestVerifyEntriesDetectsASpliceFromAnotherChain(t *testing.T) {
	t.Parallel()

	entries := buildChain(t, 5)
	other := buildChain(t, 5)
	entries[3] = other[3]

	_, err := eventlog.VerifyEntries(entries, eventlog.VerifyOptions{})
	wantBreak(t, err, domain.BreakLinkMismatch, 4)
}

// TestVerifyEntriesDetectsATruncatedTailAgainstAWitness and the test below
// it are a pair, and the pair is the whole truth about truncation: the
// chain catches it only with help from outside.
func TestVerifyEntriesDetectsATruncatedTailAgainstAWitness(t *testing.T) {
	t.Parallel()

	entries := buildChain(t, 5)
	witness := headOf(entries)

	_, err := eventlog.VerifyEntries(entries[:3], eventlog.VerifyOptions{Witness: witness})
	wantBreak(t, err, domain.BreakTruncated, 5)
}

// TestVerifyEntriesCannotDetectATruncatedTailWithoutAWitness pins the
// documented limitation rather than a behaviour anyone wants: a prefix of a
// valid chain is a valid chain, and no amount of hashing changes that. If
// this test ever fails because verification started rejecting prefixes,
// something has invented information it does not have.
func TestVerifyEntriesCannotDetectATruncatedTailWithoutAWitness(t *testing.T) {
	t.Parallel()

	entries := buildChain(t, 5)

	got, err := eventlog.VerifyEntries(entries[:3], eventlog.VerifyOptions{})
	if err != nil {
		t.Fatalf("a truncated chain with no witness must verify clean: %v", err)
	}
	if want := headOf(entries[:3]); got != want {
		t.Fatalf("head = %s, want %s", got, want)
	}
}

// A witness also catches the stronger attack: replacing a suffix with a
// different, internally consistent one. Nothing inside the returned chain
// is wrong; only the witnessed digest disagrees.
func TestVerifyEntriesDetectsAReplacedSuffixAgainstAWitness(t *testing.T) {
	t.Parallel()

	entries := buildChain(t, 5)
	witness := headOf(entries)

	forged := make([]domain.Entry, len(entries))
	copy(forged, entries)
	forged[3].Event.Detail = []byte(`{"n":"forged"}`)
	forged = rechain(forged, 3)

	if _, err := eventlog.VerifyEntries(forged, eventlog.VerifyOptions{}); err != nil {
		t.Fatalf("the forged chain should be internally consistent, so that the witness is what catches it: %v", err)
	}

	_, err := eventlog.VerifyEntries(forged, eventlog.VerifyOptions{Witness: witness})
	wantBreak(t, err, domain.BreakCheckpointMismatch, 5)
}

// A witness from a position the chain has not reached yet is truncation as
// far as the verifier can tell, which is the correct reading: the caller
// says it saw sequence 9 and the log can only show 5.
func TestVerifyEntriesTreatsAWitnessBeyondTheHeadAsTruncation(t *testing.T) {
	t.Parallel()

	entries := buildChain(t, 5)
	witness := domain.Checkpoint{Sequence: 9, Digest: domain.Digest{1}}

	_, err := eventlog.VerifyEntries(entries, eventlog.VerifyOptions{Witness: witness})
	wantBreak(t, err, domain.BreakTruncated, 9)
}

// TestChainErrorCarriesNoEventContent is the no-leak invariant at the
// verifier: a verification failure is reported to whoever runs the
// verifier, often into a log file, over material an attacker influenced.
func TestChainErrorCarriesNoEventContent(t *testing.T) {
	t.Parallel()

	const sentinel = "sentinel-91ab3f-do-not-leak-this-value"

	entries := buildChain(t, 3)
	tampered := entries[1].Event.Clone()
	tampered.Detail = []byte(sentinel)
	tampered.Actor = domain.ActorID(sentinel)
	entries[1].Event = tampered

	_, err := eventlog.VerifyEntries(entries, eventlog.VerifyOptions{})
	if err == nil {
		t.Fatal("tampering was not detected")
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Fatalf("verification error leaked event content: %v", err)
	}
}

// stubLog serves a fixed slice of entries. It exists so the paging and
// head-agreement logic in Verify can be tested against a log that is
// deliberately inconsistent in ways no real adapter would be.
type stubLog struct {
	entries []domain.Entry
	head    domain.Checkpoint
	readErr error
	pages   int
}

func (s *stubLog) Append(context.Context, domain.Record) (domain.Entry, error) {
	return domain.Entry{}, errors.New("stubLog is read-only")
}

func (s *stubLog) Head(context.Context) (domain.Checkpoint, error) {
	return s.head, nil
}

func (s *stubLog) Entries(_ context.Context, from uint64, limit int) ([]domain.Entry, error) {
	if s.readErr != nil {
		return nil, s.readErr
	}
	if limit <= 0 {
		return nil, domain.ErrInvalidArgument
	}
	s.pages++

	var out []domain.Entry
	for _, e := range s.entries {
		if e.Event.Sequence >= from && len(out) < limit {
			out = append(out, e)
		}
	}
	return out, nil
}

var _ eventlog.Log = (*stubLog)(nil)

func TestVerifyPagesThroughTheWholeLog(t *testing.T) {
	t.Parallel()

	entries := buildChain(t, 10)
	want := headOf(entries)

	for _, pageSize := range []int{0, 1, 2, 3, 9, 10, 11, 1000} {
		t.Run(fmt.Sprintf("pageSize=%d", pageSize), func(t *testing.T) {
			t.Parallel()

			log := &stubLog{entries: entries, head: want}
			got, err := eventlog.Verify(context.Background(), log, eventlog.VerifyOptions{PageSize: pageSize})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if got != want {
				t.Fatalf("head = %s, want %s", got, want)
			}
		})
	}
}

// An adapter whose reported head is not the end of the chain it serves is
// an adapter whose truncation cannot be detected, so a disagreement is a
// verification failure in its own right.
func TestVerifyDetectsAHeadThatDisagreesWithTheEntries(t *testing.T) {
	t.Parallel()

	entries := buildChain(t, 5)

	cases := map[string]domain.Checkpoint{
		"stale_sequence": {Sequence: 4, Digest: entries[3].Link.Self},
		"ahead":          {Sequence: 6, Digest: entries[4].Link.Self},
		"wrong_digest":   {Sequence: 5, Digest: domain.Digest{7}},
		"zero":           {},
	}
	for name, head := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			log := &stubLog{entries: entries, head: head}
			_, err := eventlog.Verify(context.Background(), log, eventlog.VerifyOptions{})
			wantBreak(t, err, domain.BreakHeadMismatch, 5)
		})
	}
}

func TestVerifyWrapsReadErrors(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("storage is on fire")
	log := &stubLog{readErr: sentinel}

	_, err := eventlog.Verify(context.Background(), log, eventlog.VerifyOptions{})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Verify error = %v, want it to wrap the read error", err)
	}
	if errors.Is(err, domain.ErrChainBroken) {
		t.Fatal("a storage read failure must not be reported as a broken chain")
	}
}

func TestVerifyOfAnEmptyLogIsTheZeroCheckpoint(t *testing.T) {
	t.Parallel()

	log := &stubLog{}
	got, err := eventlog.Verify(context.Background(), log, eventlog.VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !got.IsZero() {
		t.Fatalf("head = %s, want the zero checkpoint", got)
	}
}

// VerifyOptions.Root is what makes retention and tamper-evidence
// compatible: retention drops whole partitions at a checkpoint boundary, so
// the entries before that checkpoint are *gone* and a verifier walking from
// the genesis would report the hole as tampering. Verifying from the
// checkpoint instead treats it as the chain's new root.

func TestVerifyEntriesFromARootAcceptsTheRemainingSuffix(t *testing.T) {
	t.Parallel()

	entries := buildChain(t, 6)
	root := domain.Checkpoint{Sequence: entries[2].Event.Sequence, Digest: entries[2].Link.Self}
	suffix := entries[3:]

	got, err := eventlog.VerifyEntries(suffix, eventlog.VerifyOptions{Root: root})
	if err != nil {
		t.Fatalf("VerifyEntries from root %s: %v", root, err)
	}
	if want := headOf(entries); got != want {
		t.Fatalf("head = %s, want %s", got, want)
	}

	// Without the root, the same suffix is a chain that does not start at
	// its genesis — which is exactly the error the root exists to answer.
	_, err = eventlog.VerifyEntries(suffix, eventlog.VerifyOptions{})
	wantBreak(t, err, domain.BreakSequenceMismatch, domain.FirstSequence)
}

// The root is a digest, not merely a sequence number: a suffix whose first
// entry does not actually follow the witnessed root is a spliced chain, and
// saying "start at sequence 4" must not be enough to make it verify.
func TestVerifyEntriesFromARootRejectsASuffixThatDoesNotFollowIt(t *testing.T) {
	t.Parallel()

	entries := buildChain(t, 6)
	suffix := entries[3:]

	t.Run("wrong_digest", func(t *testing.T) {
		t.Parallel()
		root := domain.Checkpoint{Sequence: 3, Digest: domain.Digest{0xaa}}
		_, err := eventlog.VerifyEntries(suffix, eventlog.VerifyOptions{Root: root})
		wantBreak(t, err, domain.BreakLinkMismatch, 4)
	})

	t.Run("wrong_sequence", func(t *testing.T) {
		t.Parallel()
		root := domain.Checkpoint{Sequence: 2, Digest: entries[2].Link.Self}
		_, err := eventlog.VerifyEntries(suffix, eventlog.VerifyOptions{Root: root})
		wantBreak(t, err, domain.BreakSequenceMismatch, 3)
	})

	t.Run("tampered_suffix", func(t *testing.T) {
		t.Parallel()
		root := domain.Checkpoint{Sequence: 3, Digest: entries[2].Link.Self}
		tampered := make([]domain.Entry, len(suffix))
		copy(tampered, suffix)
		tampered[1].Event.Detail = []byte(`{"tampered":true}`)
		_, err := eventlog.VerifyEntries(tampered, eventlog.VerifyOptions{Root: root})
		wantBreak(t, err, domain.BreakDigestMismatch, 5)
	})
}

// A root at the chain's own head is the degenerate case retention produces
// when the most recent partition is the only one left and it is empty: there
// is nothing after the root to walk, and the root itself is the head. It must
// verify rather than being mistaken for an empty log that lost its history.
func TestVerifyEntriesFromARootAtTheHeadIsTheRoot(t *testing.T) {
	t.Parallel()

	entries := buildChain(t, 4)
	root := headOf(entries)

	got, err := eventlog.VerifyEntries(nil, eventlog.VerifyOptions{Root: root})
	if err != nil {
		t.Fatalf("VerifyEntries of nothing after root %s: %v", root, err)
	}
	if got != root {
		t.Fatalf("head = %s, want the root %s", got, root)
	}
}

// Root and Witness are independent and compose: the root says where
// verification may begin, the witness says what must still be there. A
// witness at or after the root behaves exactly as it does from the genesis.
func TestVerifyEntriesFromARootStillHonoursAWitness(t *testing.T) {
	t.Parallel()

	entries := buildChain(t, 6)
	root := domain.Checkpoint{Sequence: 3, Digest: entries[2].Link.Self}

	t.Run("witness_met", func(t *testing.T) {
		t.Parallel()
		opt := eventlog.VerifyOptions{Root: root, Witness: headOf(entries)}
		if _, err := eventlog.VerifyEntries(entries[3:], opt); err != nil {
			t.Fatalf("VerifyEntries: %v", err)
		}
	})

	t.Run("witness_beyond_a_truncated_tail", func(t *testing.T) {
		t.Parallel()
		opt := eventlog.VerifyOptions{Root: root, Witness: headOf(entries)}
		_, err := eventlog.VerifyEntries(entries[3:5], opt)
		wantBreak(t, err, domain.BreakTruncated, 6)
	})

	// A witness behind the root is unverifiable by construction: the
	// entry it names is one of the ones retention removed. Reporting it as
	// a truncated tail is right — the chain genuinely cannot show it —
	// and quietly accepting it would make the witness worthless.
	t.Run("witness_behind_the_root", func(t *testing.T) {
		t.Parallel()
		opt := eventlog.VerifyOptions{Root: root, Witness: domain.Checkpoint{Sequence: 1, Digest: entries[0].Link.Self}}
		_, err := eventlog.VerifyEntries(entries[3:], opt)
		wantBreak(t, err, domain.BreakTruncated, 1)
	})
}

func TestVerifyFromARootPagesFromTheRootRatherThanTheGenesis(t *testing.T) {
	t.Parallel()

	entries := buildChain(t, 10)
	root := domain.Checkpoint{Sequence: 4, Digest: entries[3].Link.Self}
	want := headOf(entries)

	// The log holds only what survived the partition drop.
	for _, pageSize := range []int{1, 2, 6, 100} {
		t.Run(fmt.Sprintf("pageSize=%d", pageSize), func(t *testing.T) {
			t.Parallel()

			log := &stubLog{entries: entries[4:], head: want}
			got, err := eventlog.Verify(context.Background(), log, eventlog.VerifyOptions{Root: root, PageSize: pageSize})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if got != want {
				t.Fatalf("head = %s, want %s", got, want)
			}
		})
	}
}

func TestVerifyFromARootAtTheHeadAgreesWithTheLogsHead(t *testing.T) {
	t.Parallel()

	entries := buildChain(t, 4)
	root := headOf(entries)

	log := &stubLog{head: root}
	got, err := eventlog.Verify(context.Background(), log, eventlog.VerifyOptions{Root: root})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != root {
		t.Fatalf("head = %s, want the root %s", got, root)
	}
}
