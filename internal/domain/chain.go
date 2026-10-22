// This file defines the hash chain: the canonical encoding of an Event,
// the digest computed over it, and the link that binds each entry to its
// predecessor. It is the whole of the module's cryptographic content and
// is pure — no I/O, no clock, no map iteration, no randomness.
//
// # The canonical encoding
//
// A chain is only a chain if two independent verifiers, on two machines,
// on two Go releases, hash the same stored entry to the same digest. That
// rules out every encoding whose output depends on something other than
// the values being encoded: encoding/json (map key order is sorted today
// but struct field order is declaration order, and either is a
// reflection-driven implementation detail), fmt verbs (%v's output for a
// struct is explicitly not a stable format), encoding/gob (self-describing
// and version-sensitive), and anything that walks a Go map.
//
// So the encoding is written out by hand, byte for byte, in a fixed field
// order that is part of the format and not of the struct declaration. The
// canonical encoding of an Event is the concatenation, with no separators
// and no padding:
//
//	 1. canonicalVersion            1 byte, currently 0x01
//	 2. ID                          8-byte big-endian length, then that many bytes
//	 3. Sequence                    8 bytes, big-endian unsigned
//	 4. Timestamp seconds           8 bytes, big-endian two's-complement
//	                                (time.Time.Unix(), so pre-1970 is negative)
//	 5. Timestamp nanoseconds       4 bytes, big-endian unsigned, 0..999_999_999
//	 6. Actor                       8-byte length, then bytes
//	 7. Subject.Kind                8-byte length, then bytes
//	 8. Subject.ID                  8-byte length, then bytes
//	 9. Action                      8-byte length, then bytes
//	10. Outcome                     8-byte length, then bytes
//	11. Detail                      8-byte length, then bytes
//
// Every variable-length field is length-prefixed, which is what makes the
// encoding injective: the decoder (which this module does not need, but
// whose existence is the proof) can recover the field boundaries from the
// bytes alone, so no two distinct Events share an encoding. A
// separator-joined encoding would not have that property — an Actor of
// "a|b" and an Actor of "a" followed by a Kind of "b" would collide, and
// the collision is attacker-chosen. TestEntryDigestIsUnambiguousAcross-
// FieldBoundaries is that property as a test.
//
// The timestamp is encoded as seconds plus nanoseconds rather than as a
// formatted string or a single nanosecond count. A string would drag in
// layout, zone and locale questions; a single int64 of nanoseconds
// overflows outside 1678-2262. Unix seconds and the nanosecond field are
// both independent of time.Time's Location and of any attached monotonic
// reading, so the digest depends on the instant and nothing else — see
// TestEntryDigestIgnoresLocationAndMonotonicReading.
//
// # Changing the format
//
// The encoding is a persistence format: every chain ever written was
// hashed with it, and re-hashing them with a different one would report
// every historical entry as tampered. A change therefore requires a new
// canonicalVersion byte *and* a new entryDomainTag, and a verifier that
// dispatches on the version byte of the entry it is checking. Nothing in
// this increment does that, because there is only one version.

package domain

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
)

// canonicalVersion is the leading byte of every canonical encoding. It
// exists so that a future format change is detectable in the bytes rather
// than inferred from a digest that no longer matches.
const canonicalVersion byte = 0x01

// entryDomainTag is the domain-separation string mixed into every entry
// digest. Without it, a SHA-256 digest computed by this module over some
// other protocol's bytes could be mistaken for an entry digest, and
// vice versa. It changes whenever canonicalVersion does.
const entryDomainTag = "laenen-ai/audit:entry:v1"

// FirstSequence is the sequence number of the first entry in every chain.
// Numbering starts at 1 rather than 0 so that the zero Checkpoint — the
// zero digest at sequence 0 — unambiguously means "this log is empty" and
// can never be confused with a witnessed position in a real chain.
const FirstSequence uint64 = 1

// Digest is a SHA-256 digest: the identity of one entry, and the value its
// successor commits to.
//
// It is a fixed-size array rather than a []byte so that it is comparable
// with ==, usable as a map key, and impossible to hand around as a nil or
// wrong-length slice. The zero Digest is reserved: it is the predecessor
// of the genesis entry and means "there is nothing before this". A real
// SHA-256 digest of zero is not reachable in practice, which is what makes
// the reservation safe.
type Digest [sha256.Size]byte

// String returns the digest as 64 lowercase hex characters.
func (d Digest) String() string { return hex.EncodeToString(d[:]) }

// IsZero reports whether d is the reserved zero digest: the genesis
// entry's predecessor.
func (d Digest) IsZero() bool { return d == Digest{} }

// Equal reports whether d and other are the same digest, compared in
// constant time.
//
// A chain digest is not a secret, so the timing of a mismatch leaks
// nothing worth having; the constant-time comparison is here because
// Verify's comparisons are the module's security-relevant ones and a
// uniform habit at those sites is cheaper to keep than a case-by-case
// argument about which of them could ever be in a loop an attacker times.
func (d Digest) Equal(other Digest) bool {
	return subtle.ConstantTimeCompare(d[:], other[:]) == 1
}

// ParseDigest parses s as 64 lowercase hex characters. Uppercase is
// rejected rather than normalized, for the same reason ParseEventID
// rejects it: the canonical spelling is the one the chain committed to.
func ParseDigest(s string) (Digest, error) {
	var d Digest
	if len(s) != 2*sha256.Size {
		return Digest{}, fmt.Errorf("%w: %q is %d characters, want %d", ErrMalformedDigest, s, len(s), 2*sha256.Size)
	}
	if !isLowerHex(s) {
		return Digest{}, fmt.Errorf("%w: %q is not lowercase hex", ErrMalformedDigest, s)
	}
	if _, err := hex.Decode(d[:], []byte(s)); err != nil {
		return Digest{}, fmt.Errorf("%w: %q: %w", ErrMalformedDigest, s, err)
	}
	return d, nil
}

// ChainLink is an entry's position in the chain, expressed as hashes
// rather than as an index: Prev is the digest of the entry before it, Self
// is the digest of this entry including that Prev.
//
// Because Self commits to Prev, and Prev is the predecessor's Self, an
// entry cannot be altered, moved, or removed from the middle of a chain
// without every later Self becoming wrong. That is the whole mechanism;
// everything in Verify is an application of it.
type ChainLink struct {
	// Prev is the predecessor's Self, or the zero Digest for the genesis
	// entry.
	Prev Digest
	// Self is the digest of this entry: EntryDigest(Prev, Event).
	Self Digest
}

// Entry is one event together with its link: the unit a log stores and a
// verifier walks.
type Entry struct {
	Event Event
	Link  ChainLink
}

// NewEntry builds the Entry for e following the entry whose digest is
// prev, computing the link. prev is the zero Digest for the genesis entry.
// It is the one place an adapter's append path forms a link, so that no
// adapter can invent its own chaining rule.
func NewEntry(prev Digest, e Event) Entry {
	return Entry{
		Event: e,
		Link:  ChainLink{Prev: prev, Self: EntryDigest(prev, e)},
	}
}

// ComputeDigest recomputes the entry's own digest from its stored event
// and stored Prev. An intact entry's ComputeDigest equals its Link.Self;
// a modified one's does not, which is how Verify detects a rewritten
// entry.
func (e Entry) ComputeDigest() Digest { return EntryDigest(e.Link.Prev, e.Event) }

// Clone returns a deep copy of e, with the event's Detail bytes copied
// rather than aliased.
func (e Entry) Clone() Entry {
	return Entry{Event: e.Event.Clone(), Link: e.Link}
}

// EntryDigest returns the digest of e as the successor of the entry whose
// digest is prev. It is
//
//	SHA-256( len(tag) || tag || prev || canonical(e) )
//
// where len is an 8-byte big-endian length, tag is entryDomainTag, prev is
// the 32 raw bytes of the predecessor's digest (all zero for the genesis
// entry), and canonical(e) is the encoding this file's doc comment
// specifies. The tag and its length come first so that the digest cannot
// be confused with a digest over any other protocol's bytes; prev is
// fixed-width, so it needs no length prefix of its own.
func EntryDigest(prev Digest, e Event) Digest {
	h := sha256.New()

	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(entryDomainTag)))
	h.Write(length[:])
	h.Write([]byte(entryDomainTag))
	h.Write(prev[:])
	h.Write(appendCanonical(nil, e))

	var d Digest
	h.Sum(d[:0])
	return d
}

// appendCanonical appends the canonical encoding of e to dst and returns
// the extended slice. The field order here *is* the format — see this
// file's doc comment. Reordering these statements changes every digest
// this module has ever produced, so it is a format change and needs a new
// canonicalVersion.
func appendCanonical(dst []byte, e Event) []byte {
	dst = append(dst, canonicalVersion)
	dst = appendLenPrefixed(dst, []byte(e.ID))
	dst = binary.BigEndian.AppendUint64(dst, e.Sequence)
	dst = appendInt64(dst, e.Timestamp.Unix())
	dst = appendUint32(dst, e.Timestamp.Nanosecond())
	dst = appendLenPrefixed(dst, []byte(e.Actor))
	dst = appendLenPrefixed(dst, []byte(e.Subject.Kind))
	dst = appendLenPrefixed(dst, []byte(e.Subject.ID))
	dst = appendLenPrefixed(dst, []byte(e.Action))
	dst = appendLenPrefixed(dst, []byte(e.Outcome))
	dst = appendLenPrefixed(dst, e.Detail)
	return dst
}

// appendLenPrefixed appends an 8-byte big-endian length followed by b.
// Eight bytes is more than any field here needs, and is used for every
// field so that the framing is uniform and a reader of the format does not
// have to remember which field got which width.
func appendLenPrefixed(dst, b []byte) []byte {
	dst = binary.BigEndian.AppendUint64(dst, uint64(len(b)))
	return append(dst, b...)
}

// appendInt64 appends v as 8 bytes of big-endian two's complement. The
// bytes are produced by shifting the signed value, not by converting it to
// an unsigned type, so there is no conversion for a reader (or a linter)
// to have to reason about: a negative Unix timestamp encodes as its
// two's-complement bit pattern, which is what the format specifies.
func appendInt64(dst []byte, v int64) []byte {
	for shift := 56; shift >= 0; shift -= 8 {
		dst = append(dst, byte((v>>shift)&0xff))
	}
	return dst
}

// appendUint32 appends v as 4 bytes of big-endian unsigned. v is an int
// because its only caller is time.Time.Nanosecond, whose range is
// 0..999_999_999 and therefore always fits; values outside that range
// would be a bug in the caller rather than something to encode.
func appendUint32(dst []byte, v int) []byte {
	for shift := 24; shift >= 0; shift -= 8 {
		dst = append(dst, byte((v>>shift)&0xff))
	}
	return dst
}

// CanonicalTime normalizes t to the precision and zone the chain commits
// to: UTC, truncated to whole microseconds.
//
// Microseconds, not nanoseconds, because the timestamp has to survive a
// round trip through storage unchanged or the entry's digest stops
// matching after it is read back. Postgres `timestamptz` holds
// microseconds; so do most other SQL timestamp types. A chain whose
// verification depended on an adapter preserving nanoseconds would verify
// in memory and fail the moment it was persisted — and it would fail as
// "tampered", which is the worst possible way for a precision mismatch to
// present itself. Truncating here makes the round trip exact by
// construction.
//
// The cost is that two events within the same microsecond have the same
// recorded time. They remain distinct entries with distinct sequences and
// distinct ids; only the ordering information in the timestamp is coarse,
// and Sequence is the chain's authority on order anyway.
//
// Truncate also strips any monotonic reading, which is what keeps a
// time.Now() value and its serialized form hashing identically.
func CanonicalTime(t time.Time) time.Time {
	return t.UTC().Truncate(time.Microsecond)
}

// Checkpoint is a witnessed position in a chain: the sequence of some
// entry and that entry's digest. It is what a caller keeps in order to be
// able to detect a truncated tail later — see the Verify documentation for
// exactly what a checkpoint does and does not let a verifier prove.
//
// The zero Checkpoint means "empty log" and is also the way a caller says
// "I have no witness" when verifying. Sequence numbering starts at
// FirstSequence precisely so those two are not confusable.
type Checkpoint struct {
	// Sequence is the entry's position in the chain.
	Sequence uint64
	// Digest is that entry's Link.Self.
	Digest Digest
}

// IsZero reports whether c is the zero Checkpoint: an empty log, or the
// absence of a witness.
func (c Checkpoint) IsZero() bool { return c.Sequence == 0 && c.Digest.IsZero() }

// String renders the checkpoint as "<sequence>:<digest hex>", a form
// compact enough to log, print in a receipt, or paste into an issue. It is
// not parsed back by anything in this increment; a caller that needs to
// persist a checkpoint stores the two fields.
func (c Checkpoint) String() string {
	return fmt.Sprintf("%d:%s", c.Sequence, c.Digest)
}
