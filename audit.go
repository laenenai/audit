// Package audit is the public facade for the audit module: an append-only
// hash-chained event log that can be independently verified.
//
// Every value object lives in internal/domain and the port and its
// adapters live in internal/eventlog; this file re-exports the ones a
// consumer must name as type aliases, so an importer of
// github.com/laenen-ai/audit gets one import and never reaches into an
// internal package directly (Go's internal package rule would refuse that
// anyway). Aliasing also means a value the internals produce — an
// audit.Entry returned from a log — and a value a consumer holds are the
// identical type, not a copy that needs converting at the boundary.
//
// What this module does and does not own, per CHARTER.md: it holds the
// chain. It does not hold event semantics — Action, Outcome, Actor and
// Detail are opaque strings and opaque bytes, and no enumeration of them
// appears anywhere in this module — and it does not hold the question of
// who may read the log, which is an iam permission.
//
// This file declares aliases and sentinel errors only — no behaviour, no
// constructors. The increment that adds the Postgres adapter is also the
// one that adds the single Open(ctx, Config) constructor and is the only
// one allowed to add further internal imports here. Until then a log is
// constructed inside the module and exercised through audittest.
package audit

import (
	"github.com/laenen-ai/audit/internal/domain"
	"github.com/laenen-ai/audit/internal/eventlog"
)

type (
	// Log is the append-only event log port. See eventlog.Log, whose doc
	// comment also records why an append can be made to participate in a
	// caller-supplied transaction.
	Log = eventlog.Log
	// VerifyOptions configures a verification pass, including the
	// witnessed checkpoint that makes a truncated tail detectable. See
	// eventlog.VerifyOptions.
	VerifyOptions = eventlog.VerifyOptions

	// Record is what a caller submits to a log. See domain.Record.
	Record = domain.Record
	// Event is one audited occurrence, as the log recorded it. See domain.Event.
	Event = domain.Event
	// Entry is an Event together with its chain link. See domain.Entry.
	Entry = domain.Entry

	// EventID identifies one event globally and permanently. See domain.EventID.
	EventID = domain.EventID
	// ActorID references whoever caused an event, opaquely. See domain.ActorID.
	ActorID = domain.ActorID
	// SubjectRef references what an event is about, opaquely. See domain.SubjectRef.
	SubjectRef = domain.SubjectRef
	// Action names what happened, in the caller's vocabulary. See domain.Action.
	Action = domain.Action
	// Outcome names how it ended, in the caller's vocabulary. See domain.Outcome.
	Outcome = domain.Outcome

	// Digest is a SHA-256 digest: one entry's identity. See domain.Digest.
	Digest = domain.Digest
	// ChainLink binds an entry to its predecessor. See domain.ChainLink.
	ChainLink = domain.ChainLink
	// Checkpoint is a witnessed position in a chain. See domain.Checkpoint.
	Checkpoint = domain.Checkpoint

	// BreakKind names how a chain failed to verify. See domain.BreakKind.
	BreakKind = domain.BreakKind
	// ChainError reports a verification failure and where it was found.
	// See domain.ChainError.
	ChainError = domain.ChainError

	// Clock abstracts the current time. See domain.Clock.
	Clock = domain.Clock
	// SystemClock is the production Clock. See domain.SystemClock.
	SystemClock = domain.SystemClock
	// FixedClock is a test Clock. See domain.FixedClock.
	FixedClock = domain.FixedClock
)

// Sentinel errors returned across every package boundary in this module.
// See internal/domain/errors.go for their full documentation.
var (
	// ErrInvalidRecord is domain.ErrInvalidRecord: a submitted record was
	// not well-formed, and the chain was left exactly as it was.
	ErrInvalidRecord = domain.ErrInvalidRecord
	// ErrInvalidArgument is domain.ErrInvalidArgument: a read argument
	// was unusable.
	ErrInvalidArgument = domain.ErrInvalidArgument
	// ErrChainBroken is domain.ErrChainBroken: the single sentinel every
	// verification failure matches, whatever its kind.
	ErrChainBroken = domain.ErrChainBroken
	// ErrMalformedDigest is domain.ErrMalformedDigest.
	ErrMalformedDigest = domain.ErrMalformedDigest
	// ErrMalformedEventID is domain.ErrMalformedEventID.
	ErrMalformedEventID = domain.ErrMalformedEventID
)
