// Package audit is the public facade for the audit module: an append-only
// hash-chained event log that can be independently verified.
//
// Every value object lives in internal/domain, the port and its in-memory
// adapter in internal/eventlog, the Postgres adapter in internal/pglog and
// the schema in internal/migrate; this file re-exports the ones a
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
// This file carries the module's aliases, sentinel errors, exported
// constants and entry points — and no logic. Every function here is a
// one-line forward to an internal package; the reason they are here at all
// is that a facade which hides what the module is for is not a facade, and
// Go's internal rule makes anything not re-exported here unreachable from
// outside the module.
package audit

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/laenen-ai/audit/internal/domain"
	"github.com/laenen-ai/audit/internal/eventlog"
	"github.com/laenen-ai/audit/internal/migrate"
	"github.com/laenen-ai/audit/internal/pglog"
)

type (
	// Log is the append-only event log port. See eventlog.Log, whose doc
	// comment also records why an append can be made to participate in a
	// caller-supplied transaction.
	Log = eventlog.Log
	// VerifyOptions configures a verification pass: the root it starts
	// from, and the witnessed checkpoint that makes a truncated tail
	// detectable. See eventlog.VerifyOptions.
	VerifyOptions = eventlog.VerifyOptions
	// MemoryConfig configures NewMemory. See eventlog.MemoryConfig.
	MemoryConfig = eventlog.MemoryConfig

	// Config configures Open: the database handle, the chain, and whether
	// the deployment requires Postgres to be enforcing append-only. See
	// pglog.Config.
	Config = pglog.Config
	// DB is the narrow Postgres handle Open reads and writes through, which
	// a tenancy data-plane handle satisfies without this module depending on
	// tenancy. See pglog.DB.
	DB = pglog.DB
	// Enforcement is what the database actually enforces about append-only,
	// for one role. See pglog.Enforcement.
	Enforcement = pglog.Enforcement

	// MigrateConfig configures Migrate: the application role whose name the
	// REVOKE must carry, and the partitioning. See migrate.Config.
	MigrateConfig = migrate.Config

	// Record is what a caller submits to a log. See domain.Record.
	Record = domain.Record
	// Event is one audited occurrence, as the log recorded it. See domain.Event.
	Event = domain.Event
	// Entry is an Event together with its chain link. See domain.Entry.
	Entry = domain.Entry

	// ChainID names one chain: one per (tenant, pool). See domain.ChainID.
	ChainID = domain.ChainID
	// TenantID references the tenant a chain belongs to, opaquely. See domain.TenantID.
	TenantID = domain.TenantID
	// PoolID references the pool a chain lives in, opaquely. See domain.PoolID.
	PoolID = domain.PoolID

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

	// ErrInvalidConfig is domain.ErrInvalidConfig: the module was wired up
	// wrongly and no retry will help.
	ErrInvalidConfig = domain.ErrInvalidConfig
	// ErrUnavailable is domain.ErrUnavailable: the store is reachable in
	// principle but was not just now. The one sentinel here that invites a
	// retry.
	ErrUnavailable = domain.ErrUnavailable
	// ErrStorage is domain.ErrStorage: the store refused or failed the
	// operation, for a reason that is neither configuration nor transient.
	ErrStorage = domain.ErrStorage
	// ErrNoAppendOnlyEnforcement is domain.ErrNoAppendOnlyEnforcement: this
	// deployment has no privilege separation, so append-only is enforced by
	// the Go API and by nothing else.
	ErrNoAppendOnlyEnforcement = domain.ErrNoAppendOnlyEnforcement
)

// BreakKind values: how a chain failed to verify. The set is closed; see
// domain's BreakKind constants for what each one means and why a caller
// should branch on ErrChainBroken rather than on these.
const (
	BreakSequenceMismatch   = domain.BreakSequenceMismatch
	BreakLinkMismatch       = domain.BreakLinkMismatch
	BreakDigestMismatch     = domain.BreakDigestMismatch
	BreakCheckpointMismatch = domain.BreakCheckpointMismatch
	BreakTruncated          = domain.BreakTruncated
	BreakHeadMismatch       = domain.BreakHeadMismatch
)

const (
	// FirstSequence is the sequence number of every chain's first entry.
	// See domain.FirstSequence for why numbering starts at one.
	FirstSequence = domain.FirstSequence
	// MaxDetailLen bounds Record.Detail. See domain.MaxDetailLen.
	MaxDetailLen = domain.MaxDetailLen
)

// Verify walks a log from its root to its end, re-deriving the hash chain,
// and returns the head it arrived at. See eventlog.Verify, whose doc comment
// is the contract — in particular what a verification pass can and cannot
// prove, and why truncation of the tail needs a witness.
func Verify(ctx context.Context, log Log, opt VerifyOptions) (Checkpoint, error) {
	return eventlog.Verify(ctx, log, opt)
}

// VerifyEntries applies the rules Verify applies to a chain already in
// memory — a page a caller read itself, or a chain exported to a file and
// verified on a machine with no access to the log at all. See
// eventlog.VerifyEntries.
func VerifyEntries(entries []Entry, opt VerifyOptions) (Checkpoint, error) {
	return eventlog.VerifyEntries(entries, opt)
}

// NewMemory returns an in-memory Log: the adapter a consumer runs its own
// unit tests against, and the one audittest.RunLogSuite is demonstrated on.
// It is not a production store — nothing in it survives the process. See
// eventlog.NewMemory.
func NewMemory(cfg MemoryConfig) Log {
	return eventlog.NewMemory(cfg)
}

// Open returns a Postgres-backed Log for one chain: the durable,
// append-only, hash-chained store this module exists to provide. See
// pglog.Open.
//
// It does not migrate anything — Migrate does, as a different identity with
// privileges this one is deliberately not meant to have. What Open does do
// is check whether that separation is actually in effect and report loudly
// when it is not, because a deployment running as the owner role has an
// audit log its own application could rewrite and nothing about the
// behaviour says so. See Config.RequireAppendOnlyEnforcement.
func Open(ctx context.Context, cfg Config) (Log, error) {
	return pglog.Open(ctx, cfg)
}

// Migrate applies this module's schema to pool: its own schema "audit", with
// its own goose version table inside it, so that a consumer's migrations and
// this module's cannot collide on one version table. See migrate.Up.
//
// pool must connect as a role that owns — or can create and grant in —
// schema "audit", and that role must not be the one the application runs as.
// That is the whole of the append-only guarantee: the application cannot
// UPDATE or DELETE what the owner created. A deployment may keep the two as
// two connection strings, or as one owner string that the runtime narrows
// with Config.AppRole.
//
// It takes a concrete *pgxpool.Pool rather than the narrow DB interface Open
// takes, because goose needs a database/sql handle and pgx can only build
// one from a real pool. Migration is a deployment-time operation with a
// deployment-time handle, so that is the right place for the concession.
//
// Calling it again is safe and expected: it applies nothing already applied,
// extends the partition window as time moves on, and re-asserts the
// privileges.
func Migrate(ctx context.Context, pool *pgxpool.Pool, cfg MigrateConfig) error {
	return migrate.Up(ctx, pool, cfg)
}

// CheckEnforcement reports what the database enforces about append-only for
// role, or for the role the handle connects as when role is empty. Open
// calls it and reports the result; this is here so a deployment's own health
// check can ask the same question rather than reimplementing it. See
// pglog.CheckEnforcement.
func CheckEnforcement(ctx context.Context, db DB, role string) (Enforcement, error) {
	return pglog.CheckEnforcement(ctx, db, role)
}

// WithTx returns a context carrying tx, so that an Append made with it joins
// the caller's transaction rather than committing on its own: the audit
// record and the thing it audits then commit together or not at all.
//
// A denial has no transaction to join and must still be recorded — nothing
// happened, and the record has to survive regardless. That is simply an
// Append with a context this was never called on. See pglog.WithTx.
func WithTx(ctx context.Context, tx pgx.Tx) context.Context {
	return pglog.WithTx(ctx, tx)
}
