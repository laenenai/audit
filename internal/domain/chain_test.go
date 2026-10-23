package domain_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/laenen-ai/audit/internal/domain"
)

// writer is the shared primitive the two reference encoders below are
// written in: an 8-byte big-endian length prefix followed by the bytes, the
// framing chain.go's doc comment specifies for every variable-length field.
type writer struct{ b bytes.Buffer }

func (w *writer) lenPrefixed(s []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(s)))
	w.b.Write(n[:])
	w.b.Write(s)
}

func (w *writer) u64(v uint64) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], v)
	w.b.Write(n[:])
}

func (w *writer) timestamp(t time.Time) {
	w.u64(uint64(t.Unix())) //nolint:gosec // two's-complement reinterpretation, by spec
	var nanos [4]byte
	binary.BigEndian.PutUint32(nanos[:], uint32(t.Nanosecond())) //nolint:gosec // 0..1e9-1
	w.b.Write(nanos[:])
}

// referenceEncode is a deliberately independent, hand-written implementation
// of the canonical encoding documented in chain.go. It exists so the digest
// tests do not merely assert that the production encoder agrees with itself:
// if the documented spec and the code ever diverge, this test is what
// notices. Keep it in step with chain.go's doc comment, not with chain.go's
// code.
func referenceEncode(e domain.Event) []byte {
	var w writer

	w.b.WriteByte(2) // format version

	w.lenPrefixed([]byte(e.Chain.Tenant))
	w.lenPrefixed([]byte(e.Chain.Pool))
	w.lenPrefixed([]byte(e.ID))
	w.u64(e.Sequence)
	w.timestamp(e.Timestamp)
	w.lenPrefixed([]byte(e.Actor))
	w.lenPrefixed([]byte(e.Subject.Kind))
	w.lenPrefixed([]byte(e.Subject.ID))
	w.lenPrefixed([]byte(e.Action))
	w.lenPrefixed([]byte(e.Outcome))
	w.lenPrefixed(e.Detail)

	return w.b.Bytes()
}

// referenceEncodeV1 is the *frozen* version 1 encoding: the format before
// the envelope gained a chain identifier. It is kept, unchanged and never
// to be changed, for exactly one purpose — so that
// TestEntryDigestGoldenVectorV1 can still produce version 1's recorded
// vector and TestEntryDigestFormatVersionBumpIsVisible can show that the
// current encoder no longer produces it. Nothing in the module calls it,
// and no chain was ever persisted with it (version 1 shipped with an
// in-memory adapter only), so it is a record of a format change rather
// than a compatibility path.
func referenceEncodeV1(e domain.Event) []byte {
	var w writer

	w.b.WriteByte(1) // format version

	w.lenPrefixed([]byte(e.ID))
	w.u64(e.Sequence)
	w.timestamp(e.Timestamp)
	w.lenPrefixed([]byte(e.Actor))
	w.lenPrefixed([]byte(e.Subject.Kind))
	w.lenPrefixed([]byte(e.Subject.ID))
	w.lenPrefixed([]byte(e.Action))
	w.lenPrefixed([]byte(e.Outcome))
	w.lenPrefixed(e.Detail)

	return w.b.Bytes()
}

// referenceDigest recomputes an entry digest the way chain.go's doc comment
// describes it, independently of chain.go's code.
func referenceDigest(prev domain.Digest, e domain.Event) domain.Digest {
	return taggedDigest("laenen-ai/audit:entry:v2", prev, referenceEncode(e))
}

// referenceDigestV1 is the frozen version 1 digest, with version 1's
// domain-separation tag. See referenceEncodeV1.
func referenceDigestV1(prev domain.Digest, e domain.Event) domain.Digest {
	return taggedDigest("laenen-ai/audit:entry:v1", prev, referenceEncodeV1(e))
}

// taggedDigest is SHA-256( len(tag) || tag || prev || canonical ), the
// construction chain.go's EntryDigest doc comment specifies.
func taggedDigest(tag string, prev domain.Digest, canonical []byte) domain.Digest {
	h := sha256.New()
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(tag)))
	h.Write(n[:])
	h.Write([]byte(tag))
	h.Write(prev[:])
	h.Write(canonical)

	var out domain.Digest
	copy(out[:], h.Sum(nil))
	return out
}

func testEvent() domain.Event {
	return domain.Event{
		Chain:     domain.ChainID{Tenant: "tenant-01HQ", Pool: "pool-main"},
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

// testEventV1 is testEvent with no chain identifier: the shape an Event had
// under format version 1, which is what version 1's recorded golden vector
// was computed over.
func testEventV1() domain.Event {
	e := testEvent()
	e.Chain = domain.ChainID{}
	return e
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

// goldenV1 is format version 1's recorded vector: the digest of testEventV1
// under the zero predecessor, as version 1 computed it. It is frozen
// history. referenceEncodeV1 still produces it, which is what makes the
// version bump below demonstrable rather than asserted.
const goldenV1 = "aa02bce01ee568a16d1c0ab117857f4a25fb8de333b8f79bd1248696b0901204"

// goldenV2 is format version 2's recorded vector: the same fields plus the
// chain identifier the envelope gained, under version 2's own domain tag.
const goldenV2 = "fa2aa0fdea0687ef91eee874a6307eceaa1aedd072eb560b5dbbede101be0728"

// TestEntryDigestGoldenVectorV2 pins the current wire format. The vector was
// produced by the independent reference encoder above, not copied out of the
// production encoder's output, so a change to chain.go that silently alters
// the canonical form fails here — which matters because the format is a
// persistence format: every chain ever written was hashed with it.
func TestEntryDigestGoldenVectorV2(t *testing.T) {
	t.Parallel()

	if got := referenceDigest(domain.Digest{}, testEvent()).String(); got != goldenV2 {
		t.Fatalf("the independent reference encoder gives %s, want the recorded vector %s", got, goldenV2)
	}
	if got := domain.EntryDigest(domain.Digest{}, testEvent()).String(); got != goldenV2 {
		t.Fatalf("golden entry digest = %s, want %s\n"+
			"a deliberate format change must bump the version byte and the domain tag, "+
			"and must be stated in chain.go's doc comment", got, goldenV2)
	}
}

// TestEntryDigestGoldenVectorV1 keeps format version 1's vector reproducible
// from the frozen version 1 reference encoder. It is not a compatibility
// path — nothing durable was ever written under version 1 — it is the record
// that lets the next format change be audited the same way this one is.
func TestEntryDigestGoldenVectorV1(t *testing.T) {
	t.Parallel()

	if got := referenceDigestV1(domain.Digest{}, testEventV1()).String(); got != goldenV1 {
		t.Fatalf("the frozen version 1 encoder gives %s, want version 1's recorded vector %s\n"+
			"referenceEncodeV1 is history and must not be edited", got, goldenV1)
	}
}

// TestEntryDigestFormatVersionBumpIsVisible is the guard the notes ask for:
// adding the chain identifier changed the encoding, so the current encoder
// must *not* reproduce version 1's vector, and the two versions must differ
// even for an event with no chain identifier at all — because the version
// byte and the domain tag both changed, not only the field list.
func TestEntryDigestFormatVersionBumpIsVisible(t *testing.T) {
	t.Parallel()

	if got := domain.EntryDigest(domain.Digest{}, testEventV1()).String(); got == goldenV1 {
		t.Fatal("the current encoder still produces version 1's vector: the format changed without bumping the version byte and the domain tag")
	}
	if referenceDigest(domain.Digest{}, testEventV1()) == referenceDigestV1(domain.Digest{}, testEventV1()) {
		t.Fatal("version 1 and version 2 hash an unchained event identically: the version byte or the domain tag is not mixed in")
	}
}

// The chain identifier is the field version 2 exists for, so it gets its own
// assertion rather than only a row in TestEntryDigestCoversEveryField: two
// chains must never produce the same digest for the same event, or an entry
// could be moved from one tenant's chain into another's undetected.
func TestEntryDigestCommitsToTheChainIdentifier(t *testing.T) {
	t.Parallel()

	base := testEvent()
	variants := map[string]domain.ChainID{
		"other_tenant":   {Tenant: "tenant-other", Pool: base.Chain.Pool},
		"other_pool":     {Tenant: base.Chain.Tenant, Pool: "pool-other"},
		"no_chain":       {},
		"swapped_halves": {Tenant: domain.TenantID(base.Chain.Pool), Pool: domain.PoolID(base.Chain.Tenant)},
	}

	want := domain.EntryDigest(domain.Digest{}, base)
	for name, chain := range variants {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := base.Clone()
			e.Chain = chain
			if domain.EntryDigest(domain.Digest{}, e) == want {
				t.Fatalf("an event on chain %s hashes the same as one on chain %s", chain, base.Chain)
			}
		})
	}
}

func TestChainIDValidate(t *testing.T) {
	t.Parallel()

	long := domain.ChainID{Tenant: domain.TenantID(strings.Repeat("t", 257)), Pool: "p"}
	invalid := map[string]domain.ChainID{
		"empty":           {},
		"no_tenant":       {Pool: "p"},
		"no_pool":         {Tenant: "t"},
		"tenant_too_long": long,
		"pool_too_long":   {Tenant: "t", Pool: domain.PoolID(strings.Repeat("p", 257))},
	}
	for name, chain := range invalid {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := chain.Validate(); !errors.Is(err, domain.ErrInvalidArgument) {
				t.Fatalf("ChainID.Validate() error = %v, want ErrInvalidArgument", err)
			}
		})
	}

	valid := domain.ChainID{Tenant: "tenant-1", Pool: "pool-1"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("ChainID.Validate() of %s: %v", valid, err)
	}
	if valid.IsZero() {
		t.Fatalf("%s reports IsZero", valid)
	}
	if !(domain.ChainID{}).IsZero() {
		t.Fatal("the zero ChainID does not report IsZero")
	}
	if got, want := valid.String(), "tenant-1/pool-1"; got != want {
		t.Fatalf("ChainID.String() = %q, want %q", got, want)
	}
}

// A chain identifier is opaque, exactly like an actor id or an action: this
// module stores it, hashes it, and returns it. A Validate that rejected
// anything but a particular id shape would be owning identity semantics,
// which the charter places outside this module.
func TestChainIDIsOpaque(t *testing.T) {
	t.Parallel()

	for _, chain := range []domain.ChainID{
		{Tenant: "01HQ3M4Z8R7K2V9X0Y1A2B3C4D", Pool: "default"},
		{Tenant: "acme.example.com", Pool: "eu-west-1/shard-3"},
		{Tenant: "t", Pool: "p"},
	} {
		if err := chain.Validate(); err != nil {
			t.Fatalf("ChainID.Validate() of %s: %v", chain, err)
		}
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
