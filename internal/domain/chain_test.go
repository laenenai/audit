package domain_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/laenen-ai/audit/internal/domain"
)

// referenceEncode is a deliberately independent, hand-written implementation
// of the canonical encoding documented in chain.go. It exists so the digest
// tests do not merely assert that the production encoder agrees with itself:
// if the documented spec and the code ever diverge, this test is what
// notices. Keep it in step with chain.go's doc comment, not with chain.go's
// code.
func referenceEncode(e domain.Event) []byte {
	var b bytes.Buffer

	b.WriteByte(1) // format version

	writeLenPrefixed := func(s []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		b.Write(n[:])
		b.Write(s)
	}
	writeU64 := func(v uint64) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], v)
		b.Write(n[:])
	}

	writeLenPrefixed([]byte(e.ID))
	writeU64(e.Sequence)
	writeU64(uint64(e.Timestamp.Unix())) //nolint:gosec // two's-complement reinterpretation, by spec
	var nanos [4]byte
	binary.BigEndian.PutUint32(nanos[:], uint32(e.Timestamp.Nanosecond())) //nolint:gosec // 0..1e9-1
	b.Write(nanos[:])
	writeLenPrefixed([]byte(e.Actor))
	writeLenPrefixed([]byte(e.Subject.Kind))
	writeLenPrefixed([]byte(e.Subject.ID))
	writeLenPrefixed([]byte(e.Action))
	writeLenPrefixed([]byte(e.Outcome))
	writeLenPrefixed(e.Detail)

	return b.Bytes()
}

// referenceDigest recomputes an entry digest the way chain.go's doc comment
// describes it, independently of chain.go's code.
func referenceDigest(prev domain.Digest, e domain.Event) domain.Digest {
	const tag = "laenen-ai/audit:entry:v1"

	h := sha256.New()
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(tag)))
	h.Write(n[:])
	h.Write([]byte(tag))
	h.Write(prev[:])
	h.Write(referenceEncode(e))

	var out domain.Digest
	copy(out[:], h.Sum(nil))
	return out
}

func testEvent() domain.Event {
	return domain.Event{
		ID:        domain.EventID("0193a1b2c3d4e5f60718293a4b5c6d7e"),
		Sequence:  7,
		Timestamp: time.Date(2026, time.October, 23, 11, 22, 33, 123456000, time.UTC),
		Actor:     domain.ActorID("principal-01HQ"),
		Subject:   domain.SubjectRef{Kind: "document", ID: "doc-42"},
		Action:    domain.Action("content.read"),
		Outcome:   domain.Outcome("allowed"),
		Detail:    []byte(`{"bytes":4096}`),
	}
}

func TestEntryDigestMatchesDocumentedCanonicalEncoding(t *testing.T) {
	t.Parallel()

	e := testEvent()
	for _, prev := range []domain.Digest{{}, {1, 2, 3}} {
		want := referenceDigest(prev, e)
		got := domain.EntryDigest(prev, e)
		if got != want {
			t.Fatalf("EntryDigest = %s, independent reference encoding gives %s", got, want)
		}
	}
}

// TestEntryDigestGoldenVector pins the wire format. The vector was produced
// by the independent reference encoder above, not copied out of the
// production encoder's output, so a change to chain.go that silently alters
// the canonical form fails here — which matters because the format is a
// persistence format: every previously written chain was hashed with it.
func TestEntryDigestGoldenVector(t *testing.T) {
	t.Parallel()

	const want = "aa02bce01ee568a16d1c0ab117857f4a25fb8de333b8f79bd1248696b0901204"

	got := domain.EntryDigest(domain.Digest{}, testEvent()).String()
	if got != want {
		t.Fatalf("golden entry digest = %s, want %s\n"+
			"a deliberate format change must bump the version byte and the domain tag, "+
			"and must be stated in chain.go's doc comment", got, want)
	}
}

func TestEntryDigestCoversEveryField(t *testing.T) {
	t.Parallel()

	base := testEvent()
	baseDigest := domain.EntryDigest(domain.Digest{}, base)

	mutations := map[string]func(e *domain.Event){
		"id":        func(e *domain.Event) { e.ID = domain.EventID("ffffffffffffffffffffffffffffffff") },
		"sequence":  func(e *domain.Event) { e.Sequence = 8 },
		"seconds":   func(e *domain.Event) { e.Timestamp = e.Timestamp.Add(time.Second) },
		"nanos":     func(e *domain.Event) { e.Timestamp = e.Timestamp.Add(time.Microsecond) },
		"actor":     func(e *domain.Event) { e.Actor = domain.ActorID("principal-other") },
		"kind":      func(e *domain.Event) { e.Subject.Kind = "fileset" },
		"subjectid": func(e *domain.Event) { e.Subject.ID = "doc-43" },
		"action":    func(e *domain.Event) { e.Action = domain.Action("content.write") },
		"outcome":   func(e *domain.Event) { e.Outcome = domain.Outcome("denied") },
		"detail":    func(e *domain.Event) { e.Detail = []byte(`{"bytes":4097}`) },
	}

	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := base.Clone()
			mutate(&e)
			if got := domain.EntryDigest(domain.Digest{}, e); got == baseDigest {
				t.Fatalf("mutating %s left the digest unchanged: the field is not committed to", name)
			}
		})
	}
}

// TestEntryDigestIsUnambiguousAcrossFieldBoundaries is the property that
// makes the encoding a canonicalization rather than a concatenation: moving
// a character across a field boundary must change the digest. A naive
// "join the fields with a separator" encoding fails this as soon as a field
// may legitimately contain the separator.
func TestEntryDigestIsUnambiguousAcrossFieldBoundaries(t *testing.T) {
	t.Parallel()

	left := testEvent()
	left.Actor = "ab"
	left.Subject = domain.SubjectRef{Kind: "c", ID: "d"}
	left.Action = "e"
	left.Outcome = "f"

	right := testEvent()
	right.Actor = "a"
	right.Subject = domain.SubjectRef{Kind: "bc", ID: "d"}
	right.Action = "e"
	right.Outcome = "f"

	if domain.EntryDigest(domain.Digest{}, left) == domain.EntryDigest(domain.Digest{}, right) {
		t.Fatal("two events differing only in where a field boundary falls hash the same")
	}
}

func TestEntryDigestCommitsToPredecessor(t *testing.T) {
	t.Parallel()

	e := testEvent()
	a := domain.EntryDigest(domain.Digest{}, e)
	b := domain.EntryDigest(domain.Digest{0: 1}, e)
	if a == b {
		t.Fatal("the same event under different predecessors hashes the same: the chain does not chain")
	}
}

// TestEntryDigestIgnoresLocationAndMonotonicReading pins the one place where
// Go's time.Time could make a chain unverifiable after a round trip: the
// digest must depend on the instant, never on the zone the instant is
// rendered in or on whether a monotonic reading is still attached.
func TestEntryDigestIgnoresLocationAndMonotonicReading(t *testing.T) {
	t.Parallel()

	utc := domain.CanonicalTime(time.Now())
	loc := time.FixedZone("UTC+7", 7*60*60)

	variants := map[string]time.Time{
		"utc":             utc,
		"other_zone":      utc.In(loc),
		"local":           utc.Local(),
		"wall_clock_only": utc.Round(0),
	}

	e := testEvent()
	e.Timestamp = utc
	want := domain.EntryDigest(domain.Digest{}, e)

	for name, ts := range variants {
		v := e.Clone()
		v.Timestamp = ts
		if got := domain.EntryDigest(domain.Digest{}, v); got != want {
			t.Fatalf("%s rendering of the same instant hashes to %s, want %s", name, got, want)
		}
	}
}

// TestCanonicalTimeIsRoundTrippableThroughMicrosecondStorage pins the
// precision contract: an adapter whose timestamp column holds microseconds
// (every SQL timestamp type this module targets) must be able to store and
// return the exact instant that was hashed.
func TestCanonicalTimeIsRoundTrippableThroughMicrosecondStorage(t *testing.T) {
	t.Parallel()

	for _, in := range []time.Time{
		time.Now(),
		time.Date(2026, time.October, 23, 0, 0, 0, 999999999, time.UTC),
		time.Date(1970, time.January, 1, 0, 0, 0, 1, time.UTC),
	} {
		got := domain.CanonicalTime(in)
		if got.Nanosecond()%1000 != 0 {
			t.Fatalf("CanonicalTime(%v).Nanosecond() = %d, want a whole number of microseconds",
				in, got.Nanosecond())
		}
		if got.Location() != time.UTC {
			t.Fatalf("CanonicalTime(%v) is in %v, want UTC", in, got.Location())
		}
		if again := domain.CanonicalTime(got); !again.Equal(got) {
			t.Fatalf("CanonicalTime is not idempotent: %v then %v", got, again)
		}
	}
}

func TestNewEntryComputesItsOwnLink(t *testing.T) {
	t.Parallel()

	prev := domain.Digest{9}
	e := testEvent()

	entry := domain.NewEntry(prev, e)
	if entry.Link.Prev != prev {
		t.Fatalf("Link.Prev = %s, want %s", entry.Link.Prev, prev)
	}
	if want := domain.EntryDigest(prev, e); entry.Link.Self != want {
		t.Fatalf("Link.Self = %s, want %s", entry.Link.Self, want)
	}
	if got := entry.ComputeDigest(); got != entry.Link.Self {
		t.Fatalf("ComputeDigest = %s, want the stored Link.Self %s", got, entry.Link.Self)
	}
}

func TestEntryCloneDoesNotShareDetail(t *testing.T) {
	t.Parallel()

	original := domain.NewEntry(domain.Digest{}, testEvent())
	clone := original.Clone()
	clone.Event.Detail[0] = 'X'

	if original.Event.Detail[0] == 'X' {
		t.Fatal("Clone shares the Detail backing array with the original")
	}
	if original.ComputeDigest() != original.Link.Self {
		t.Fatal("mutating a clone invalidated the original's digest")
	}
}

func TestDigestStringRoundTrip(t *testing.T) {
	t.Parallel()

	want := domain.EntryDigest(domain.Digest{}, testEvent())
	got, err := domain.ParseDigest(want.String())
	if err != nil {
		t.Fatalf("ParseDigest: %v", err)
	}
	if got != want {
		t.Fatalf("round trip = %s, want %s", got, want)
	}
	if len(want.String()) != 2*sha256.Size {
		t.Fatalf("Digest.String() = %q, want %d hex characters", want.String(), 2*sha256.Size)
	}
}

func TestParseDigestRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	long := hex.EncodeToString(make([]byte, sha256.Size+1))
	cases := map[string]string{
		"empty":     "",
		"too_short": "abcd",
		"too_long":  long,
		"not_hex":   "zz" + hex.EncodeToString(make([]byte, sha256.Size))[2:],
		"uppercase": "AB" + hex.EncodeToString(make([]byte, sha256.Size))[2:],
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := domain.ParseDigest(in); !errors.Is(err, domain.ErrMalformedDigest) {
				t.Fatalf("ParseDigest(%q) error = %v, want ErrMalformedDigest", in, err)
			}
		})
	}
}

func TestZeroDigestIsTheGenesisPredecessor(t *testing.T) {
	t.Parallel()

	var zero domain.Digest
	if !zero.IsZero() {
		t.Fatal("the zero Digest does not report IsZero")
	}
	if domain.EntryDigest(zero, testEvent()).IsZero() {
		t.Fatal("a computed digest reports IsZero; the sentinel is not distinguishable from a real digest")
	}
}

func TestCheckpointZeroMeansEmptyLog(t *testing.T) {
	t.Parallel()

	var zero domain.Checkpoint
	if !zero.IsZero() {
		t.Fatal("the zero Checkpoint does not report IsZero")
	}
	nonEmpty := domain.Checkpoint{Sequence: domain.FirstSequence, Digest: domain.Digest{1}}
	if nonEmpty.IsZero() {
		t.Fatal("a checkpoint at the first sequence reports IsZero")
	}
}
