// This file declares the module's complete error taxonomy. There are five
// sentinels and one structured error, and the split between them is
// deliberate: the sentinels answer "what kind of failure is this" for a
// caller writing an errors.Is branch, and ChainError adds "where, and
// how" for a caller that has to act on a broken chain.
//
// No error in this module ever reproduces an event's Detail payload, or
// any other field's content beyond an identifier a caller already holds.
// ChainError in particular carries only a break kind and a sequence
// number, by construction: a verifier runs over material that is, by
// hypothesis, under an attacker's influence, and an error string is one of
// the few things from that material that reliably ends up in a log file
// someone else can read. See the package doc comment in event.go.

package domain

import (
	"errors"
	"fmt"
)

// ErrInvalidRecord is returned by Record.Validate, and therefore by every
// adapter's Append, when a submitted record is not well-formed: a missing
// actor, action or outcome, a half-populated subject, or a field over its
// length bound. It is a precondition error, asked before the record is
// given a sequence number — a rejected append leaves the chain exactly as
// it was.
var ErrInvalidRecord = errors.New("audit: invalid record")

// ErrInvalidArgument is returned when a read argument is unusable: a
// non-positive page size, for instance. Like ErrInvalidRecord it is a
// precondition error and says nothing about the state of the log.
var ErrInvalidArgument = errors.New("audit: invalid argument")

// ErrChainBroken is the single sentinel every verification failure
// matches, whatever its kind: a rewritten entry, a removed one, a
// reordered one, a tail truncated behind a witnessed checkpoint, or a log
// whose own reported head disagrees with its entries.
//
// It is one sentinel rather than five because the decision a caller makes
// is the same in every case — stop trusting this log and escalate — and a
// caller that branched on the specific kind would be deciding that some
// kinds of tampering are tolerable. The kind is available via ChainError
// for the report that follows the escalation, not for the decision.
var ErrChainBroken = errors.New("audit: chain broken")

// ErrMalformedDigest is returned by ParseDigest when a string is not
// exactly 64 lowercase hex characters.
var ErrMalformedDigest = errors.New("audit: malformed digest")

// ErrMalformedEventID is returned by ParseEventID when a string is not
// exactly 32 lowercase hex characters.
var ErrMalformedEventID = errors.New("audit: malformed event id")

// BreakKind names how a chain failed to verify. The set is closed: a
// verifier that cannot classify a failure as one of these has found a bug
// in the verifier, not a new kind of tampering.
type BreakKind string

const (
	// BreakSequenceMismatch means an entry did not carry the sequence
	// number the chain required at that position: a gap, a repeat, or a
	// descent. This is the kind a removed interior entry and a reordered
	// pair both produce, because a hash chain detects them by the same
	// mechanism — the position an entry claims is part of what its digest
	// commits to, so there is no way to move or drop one without the
	// claim going wrong.
	BreakSequenceMismatch BreakKind = "sequence_mismatch"

	// BreakLinkMismatch means an entry's Prev was not its predecessor's
	// Self: the chain has been spliced, or two intact chains have been
	// interleaved.
	BreakLinkMismatch BreakKind = "link_mismatch"

	// BreakDigestMismatch means an entry's stored Self is not the digest
	// of its own contents. This is the kind a rewritten entry produces —
	// any field, including its timestamp and its detail payload.
	BreakDigestMismatch BreakKind = "digest_mismatch"

	// BreakCheckpointMismatch means the entry at a witnessed sequence
	// exists but has a different digest than was witnessed: the entry at
	// that position has been replaced wholesale, along with everything
	// after it, by a chain that is internally consistent.
	BreakCheckpointMismatch BreakKind = "checkpoint_mismatch"

	// BreakTruncated means the chain ends before a witnessed sequence:
	// entries that were once there are gone, and what remains is a valid
	// prefix. This is the only kind that cannot be found by inspecting
	// the chain alone — see the Verify documentation.
	BreakTruncated BreakKind = "truncated"

	// BreakHeadMismatch means the log's own reported head does not agree
	// with the chain it returned. The entries may each be intact; the
	// adapter is reporting a position it cannot show. It is a correctness
	// failure in the adapter rather than evidence of tampering, and it is
	// a verification failure either way, because an adapter whose head is
	// not the end of its chain is an adapter whose truncation cannot be
	// detected.
	BreakHeadMismatch BreakKind = "head_mismatch"
)

// ChainError reports a verification failure: what kind, and the sequence
// number at which it was found. It wraps ErrChainBroken, so
// errors.Is(err, ErrChainBroken) matches every one of them and
// errors.As(err, &chainErr) recovers the detail.
type ChainError struct {
	// Kind is how the chain broke.
	Kind BreakKind
	// Sequence is where. For BreakSequenceMismatch it is the sequence the
	// chain required at that position, not the (wrong) one the entry
	// carried, since the required one is the position actually in
	// question. For BreakTruncated and BreakCheckpointMismatch it is the
	// witnessed sequence. Otherwise it is the offending entry's own
	// sequence.
	Sequence uint64
}

// Error implements error. It names only the kind and the sequence: see
// this file's doc comment for why it carries nothing from the entry.
func (e *ChainError) Error() string {
	return fmt.Sprintf("audit: chain broken at sequence %d: %s", e.Sequence, e.Kind)
}

// Unwrap returns ErrChainBroken, so every ChainError matches the single
// sentinel callers branch on.
func (e *ChainError) Unwrap() error { return ErrChainBroken }

// NewChainError returns a *ChainError for kind at sequence. It exists so
// that the verifier never constructs the error type inline and every
// failure site reads the same.
func NewChainError(kind BreakKind, sequence uint64) *ChainError {
	return &ChainError{Kind: kind, Sequence: sequence}
}
