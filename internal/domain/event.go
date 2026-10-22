// Package domain is the single home for every value object in the audit
// module: the event envelope a caller submits and the log returns (this
// file), the hash chain that makes a sequence of those envelopes
// tamper-evident (chain.go), the clock abstraction (clock.go), and the
// error taxonomy (errors.go). The root package audit re-exports what a
// consumer needs to name as type aliases, so this package stays the only
// one that defines them.
//
// The invariant this package holds is that an event's identity is its
// bytes. Every field of an Event is committed to by a single SHA-256
// digest over a canonical, unambiguous encoding (see chain.go), and every
// digest commits to its predecessor's. Nothing here performs I/O, reads a
// clock on its own, or decides what an event means.
//
// What this package deliberately does not know, per CHARTER.md:
//
//   - What an action, an outcome, an actor, or a subject *is*. Action and
//     Outcome are opaque strings, never a closed enum: "content.read" and
//     "allowed" are a caller's vocabulary, and a module that enumerated
//     them would own event semantics, which belong to the caller.
//   - What a Detail payload contains. It is opaque bytes, not a decoded
//     structure — see Record.Detail for why that choice is load-bearing
//     for the chain and not merely a simplification.
//   - Who is allowed to read any of this. That is an iam permission.
//
// A Detail payload may carry sensitive content, so no error returned from
// this package, and no error returned by any adapter, may reproduce any
// part of it. Errors name the offending field and its length, never its
// bytes. See Record.Validate, and the NoEventDetailLeaksInErrors subtest
// that every adapter exercises.
package domain

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// EventID identifies one event globally and permanently: it stays valid
// when the event is exported, copied into a report, or referenced from
// another system, none of which an Event.Sequence survives.
//
// Sequence and ID answer different questions and neither replaces the
// other. Sequence is the event's position in one particular chain, dense
// and meaningless outside it; ID is the event's name. Both are committed
// to by the entry digest.
//
// The canonical form is exactly 32 lowercase hex characters encoding 16
// bytes: a 48-bit big-endian milliseconds-since-Unix-epoch timestamp
// followed by 80 bits of cryptographically random entropy. That is a ULID
// by construction, rendered in hex rather than Crockford base32 because
// this module takes no third-party dependency; the useful consequence is
// that lexicographic order on the string is chronological order on the
// mint time, so an id sorts usefully in an index and in a log line.
type EventID string

// ActorID references whoever or whatever caused an event. It is an opaque
// identifier: this module stores it, hashes it, and returns it, and never
// resolves, validates, or interprets it. A principal id, a service account
// name, and the string "system" are all equally valid here, because which
// of those a deployment uses is not this module's business.
type ActorID string

// SubjectRef references the thing an event is about — the document that
// was read, the policy that changed, the key that was rotated.
//
// Kind and ID are both opaque strings, and are meaningful only together:
// an event either has a subject (both set) or has none (both empty). A
// half-populated SubjectRef is rejected by Record.Validate, because a
// reference to an unnamed kind of thing, or to a kind of thing with no
// name, is a bug at the call site rather than a record worth keeping
// forever.
type SubjectRef struct {
	// Kind names the sort of thing ID refers to, in the caller's own
	// vocabulary ("document", "fileset", "policy", "key").
	Kind string
	// ID names the particular thing, in the caller's own vocabulary.
	ID string
}

// IsZero reports whether the reference names nothing: an event with no
// subject.
func (s SubjectRef) IsZero() bool { return s.Kind == "" && s.ID == "" }

// Action names what happened, in the caller's vocabulary. It is
// deliberately an open string rather than a closed enum: enumerating the
// actions a system can audit is event semantics, which CHARTER.md places
// outside this module. A caller that wants a closed set declares its own
// constants of this type.
type Action string

// Outcome names how it ended, in the caller's vocabulary ("allowed",
// "denied", "failed", "partial"). Open for the same reason as Action: the
// set of outcomes that matter is a property of what is being audited, not
// of the log.
//
// It is nonetheless required to be non-empty. An audit record whose
// outcome was never stated is not a cheaper record, it is an unreadable
// one, and the field exists precisely so that the question cannot be left
// unanswered at the call site.
type Outcome string

// MaxDetailLen bounds Record.Detail at 64 KiB. The limit is not a storage
// decision — it keeps one crafted or runaway call from putting an
// unbounded blob into an append-only, permanently retained log, where it
// could never be reclaimed without breaking the chain. 64 KiB is roughly
// three orders of magnitude more than the largest detail payload the
// design anticipates (one retrieval event listing the ids of every chunk
// it disclosed).
const MaxDetailLen = 64 * 1024

// maxFieldLen bounds every other variable-length field: the actor id, the
// subject's kind and id, the action, and the outcome. Generous relative to
// any real identifier, and present only to reject a deliberately oversized
// value before it is hashed and stored forever.
const maxFieldLen = 256

// Record is what a caller submits to a log: the fields only the caller can
// know. Everything else on the resulting Event — its id, its position in
// the chain, and the instant it was recorded — is assigned by the log, so
// that a caller cannot choose its own sequence number or backdate its own
// entry.
type Record struct {
	// Actor references who caused the event. Required.
	Actor ActorID
	// Subject references what the event is about. Optional: either both
	// of its fields are set or neither is.
	Subject SubjectRef
	// Action names what happened. Required.
	Action Action
	// Outcome names how it ended. Required.
	Outcome Outcome

	// Detail carries whatever else the caller wants committed to the
	// chain, as opaque bytes. The caller chooses the encoding (JSON,
	// protobuf, CBOR) and this module never parses it.
	//
	// Opaque bytes rather than, say, a map[string]any is a deliberate
	// design choice and the single most important one in this type. A
	// chain whose entry digest depended on the iteration order of a Go
	// map would not be a chain: two verifiers walking the same stored
	// bytes could disagree about whether it is intact, and the same
	// process could disagree with itself between runs. Canonicalizing a
	// decoded structure is possible but puts a JSON (or CBOR, or
	// protobuf) canonicalization spec inside a module whose charter is a
	// hash chain. Committing to the exact submitted bytes moves that
	// decision to the caller, where the encoding is already known, and
	// leaves this module with a serialization whose only variable-length
	// inputs are byte strings.
	//
	// The consequence a caller must accept: two detail payloads that are
	// semantically equal but not byte-equal (different JSON key order,
	// different whitespace) are different events to this module. A caller
	// that needs them to be equal must canonicalize before appending.
	//
	// Detail is copied on append, never retained by reference, so a
	// caller may reuse its buffer. At most MaxDetailLen bytes.
	Detail []byte
}

// Clone returns a deep copy of r, with Detail's bytes copied rather than
// aliased.
func (r Record) Clone() Record {
	out := r
	out.Detail = cloneBytes(r.Detail)
	return out
}

// Validate reports whether r is well-formed enough to be appended: the
// required fields are present, the subject is either fully set or fully
// empty, and no field exceeds its length bound. It returns a wrapped
// ErrInvalidRecord naming the offending field.
//
// It validates shape, never meaning. An Action of "frobnicate" and an
// Outcome of "maybe" are both valid here; whether they make sense is the
// caller's question. Per this package's doc comment, the error names the
// offending field and its length and never reproduces Detail's bytes.
func (r Record) Validate() error {
	if err := validateField("actor", string(r.Actor), true); err != nil {
		return err
	}
	if err := validateField("action", string(r.Action), true); err != nil {
		return err
	}
	if err := validateField("outcome", string(r.Outcome), true); err != nil {
		return err
	}

	if (r.Subject.Kind == "") != (r.Subject.ID == "") {
		return fmt.Errorf("%w: subject is half-populated: an event has either both a subject kind and a subject id, or neither", ErrInvalidRecord)
	}
	if err := validateField("subject kind", r.Subject.Kind, false); err != nil {
		return err
	}
	if err := validateField("subject id", r.Subject.ID, false); err != nil {
		return err
	}

	if len(r.Detail) > MaxDetailLen {
		return fmt.Errorf("%w: detail is %d bytes, limit is %d", ErrInvalidRecord, len(r.Detail), MaxDetailLen)
	}
	return nil
}

// validateField checks one variable-length string field: present if
// required, and within maxFieldLen either way.
func validateField(label, value string, required bool) error {
	if required && value == "" {
		return fmt.Errorf("%w: %s is required", ErrInvalidRecord, label)
	}
	if len(value) > maxFieldLen {
		return fmt.Errorf("%w: %s is %d bytes, limit is %d", ErrInvalidRecord, label, len(value), maxFieldLen)
	}
	return nil
}

// Event is one audited occurrence: a Record plus everything the log
// assigned to it. It is the unit the chain commits to; Entry pairs it with
// its link.
//
// Every field is committed to by the entry digest, so an Event returned
// from a log is only as trustworthy as the chain it arrived in — which is
// the point of Verify.
type Event struct {
	// ID names this event globally and permanently.
	ID EventID
	// Sequence is the event's 1-based position in its chain. The first
	// event appended to a log has Sequence == FirstSequence, and
	// sequences are contiguous with no gaps, which is what makes a
	// removed interior entry detectable without any external witness.
	Sequence uint64
	// Timestamp is when the log recorded the event, in UTC and truncated
	// to microseconds by CanonicalTime. It is the log's clock, not the
	// caller's assertion about when something happened; a caller whose
	// own notion of "when" differs puts it in Detail.
	Timestamp time.Time

	// Actor, Subject, Action, Outcome and Detail are the submitted
	// Record's fields, unchanged. See Record.
	Actor   ActorID
	Subject SubjectRef
	Action  Action
	Outcome Outcome
	Detail  []byte
}

// Clone returns a deep copy of e, with Detail's bytes copied rather than
// aliased. An adapter that hands a caller an Event it also keeps must
// clone it: a caller that could mutate Detail in place could otherwise
// make a stored entry disagree with its own digest.
func (e Event) Clone() Event {
	out := e
	out.Detail = cloneBytes(e.Detail)
	return out
}

// NewEvent assembles the Event for rec at the given sequence and instant.
// It is the one constructor an adapter's append path uses, so that every
// adapter assigns the same fields the same way: the timestamp is
// canonicalized, Detail is copied, and the id is minted fresh.
//
// It does not validate rec — an adapter validates first, so that a
// rejected record never consumes a sequence number.
func NewEvent(id EventID, sequence uint64, at time.Time, rec Record) Event {
	return Event{
		ID:        id,
		Sequence:  sequence,
		Timestamp: CanonicalTime(at),
		Actor:     rec.Actor,
		Subject:   rec.Subject,
		Action:    rec.Action,
		Outcome:   rec.Outcome,
		Detail:    cloneBytes(rec.Detail),
	}
}

// eventIDBytes is the decoded length of an EventID: 6 timestamp bytes plus
// 10 of entropy.
const eventIDBytes = 16

// eventIDTimeBytes is how many of those encode the timestamp — 48 bits of
// milliseconds, which overflows in the year 10889 and is therefore not a
// concern worth a longer field.
const eventIDTimeBytes = 6

// NewEventID mints a fresh EventID from clock's current time. See EventID
// for the encoding.
//
// It returns an error rather than panicking when the entropy source fails:
// forbidigo forbids panic outside cmd/, and an adapter that cannot mint an
// id has an append to fail, which is a strictly better outcome than a
// process-wide crash in a library a caller embedded.
func NewEventID(clock Clock) (EventID, error) {
	var raw [eventIDBytes]byte

	ms := clock.Now().UnixMilli()
	for i := range eventIDTimeBytes {
		shift := 8 * (eventIDTimeBytes - 1 - i)
		raw[i] = byte(ms >> shift) //nolint:gosec // deliberate truncation: the low 48 bits are the field
	}

	if _, err := rand.Read(raw[eventIDTimeBytes:]); err != nil {
		return "", fmt.Errorf("audit: mint event id: %w", err)
	}
	return EventID(hex.EncodeToString(raw[:])), nil
}

// ParseEventID parses s as an EventID, rejecting anything that is not
// exactly 32 lowercase hex characters. Uppercase hex is rejected rather
// than normalized: the canonical form is what the chain committed to, so
// accepting a second spelling of the same id would mean two different
// strings hash to two different entries for one event.
func ParseEventID(s string) (EventID, error) {
	if len(s) != 2*eventIDBytes {
		return "", fmt.Errorf("%w: %q is %d characters, want %d", ErrMalformedEventID, s, len(s), 2*eventIDBytes)
	}
	if !isLowerHex(s) {
		return "", fmt.Errorf("%w: %q is not lowercase hex", ErrMalformedEventID, s)
	}
	return EventID(s), nil
}

// Time returns the instant encoded in the id's leading timestamp field, in
// UTC. It is the mint time to millisecond precision and is derived from
// the id alone, so it is useful for ordering and bucketing ids whose
// events are not at hand — not as a substitute for Event.Timestamp, which
// is what the chain commits to.
//
// The returned time is meaningless for an id that did not come from
// NewEventID or ParseEventID.
func (id EventID) Time() time.Time {
	raw, err := hex.DecodeString(string(id))
	if err != nil || len(raw) != eventIDBytes {
		return time.Time{}
	}
	var ms int64
	for _, b := range raw[:eventIDTimeBytes] {
		ms = ms<<8 | int64(b)
	}
	return time.UnixMilli(ms).UTC()
}

// isLowerHex reports whether s consists only of 0-9 and a-f. Uppercase is
// not hex for this module's purposes; see ParseEventID.
func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return len(s) > 0
}

// cloneBytes returns a copy of b, preserving the nil/empty distinction so
// that a round trip through Clone does not change what the canonical
// encoding sees. (It does not need to: the encoding length-prefixes, so
// nil and empty encode identically. Preserving it anyway keeps Clone a
// true copy rather than a normalizer.)
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
