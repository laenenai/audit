// This file is the Log implementation: the three port methods, the one
// transaction shape they share, and the row mapping.
//
// There is no SQL in it. Every statement it runs is in db/queries/*.sql and
// reaches Go through internal/pglog/gen, which sqlc generates against
// db/migrations — so a column renamed in the schema and not in a query is a
// generation failure rather than a run-time one. What is left here is the
// part a query file cannot hold: the transaction shape, and the conversions
// between a row's primitives and the domain types whose invariants a
// generated scan must not be allowed to bypass.

package pglog

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/laenen-ai/audit/internal/domain"
	"github.com/laenen-ai/audit/internal/pglog/gen"
)

// zeroDigest is the genesis entry's predecessor, as the 32 bytes a freshly
// created head row carries. The column requires exactly 32 bytes, so "no
// predecessor" is stored rather than left null: a nullable digest would make
// every read of it a special case, and the zero digest is already the
// reserved value the chain uses for that exact meaning.
var zeroDigest = make([]byte, len(domain.Digest{}))

// Append implements eventlog.Log.
//
// It is one read-modify-write the adapter owns entirely: it locks the
// chain's head row, computes the next entry from the head it read, inserts
// the entry, and moves the head. Nothing is cached between calls, so the
// whole of it fits inside a transaction the caller supplied and a rollback
// leaves no stale state behind for the next append to trip over.
//
// The head row lock is what makes the chain a chain under concurrency; see
// db/queries/chain_head.sql, where that reasoning sits next to the statement
// it is about.
func (l *pgLog) Append(ctx context.Context, rec domain.Record) (domain.Entry, error) {
	if err := ctx.Err(); err != nil {
		return domain.Entry{}, fmt.Errorf("audit: append: %w", err)
	}
	// Validated before anything is assigned or locked, so a rejected record
	// never consumes a sequence number and never makes another appender
	// wait for a transaction that was always going to fail.
	if err := rec.Validate(); err != nil {
		return domain.Entry{}, fmt.Errorf("audit: append: %w", err)
	}

	if tx := txFromContext(ctx); tx != nil {
		// Enlisted: the caller owns the commit, and the caller owns the
		// transaction's role and tenant scoping. We add statements to
		// their unit of work and change nothing about it.
		return l.appendIn(ctx, tx, rec)
	}

	tx, err := l.db.Begin(ctx)
	if err != nil {
		return domain.Entry{}, mapErr("append: begin", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := l.scopeTransaction(ctx, tx); err != nil {
		return domain.Entry{}, err
	}

	entry, err := l.appendIn(ctx, tx, rec)
	if err != nil {
		return domain.Entry{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.Entry{}, mapErr("append: commit", err)
	}
	return entry, nil
}

// Head implements eventlog.Log. A chain with no head row has never been
// appended to, which is the zero Checkpoint and not an error.
func (l *pgLog) Head(ctx context.Context) (domain.Checkpoint, error) {
	if err := ctx.Err(); err != nil {
		return domain.Checkpoint{}, fmt.Errorf("audit: head: %w", err)
	}

	q, release, err := l.reader(ctx)
	if err != nil {
		return domain.Checkpoint{}, err
	}
	defer release()

	row, err := q.ChainHead(ctx, gen.ChainHeadParams{
		TenantID: l.chain.Tenant,
		PoolID:   l.chain.Pool,
	})
	if err != nil {
		// A chain with no head row has never been appended to. That is the
		// zero Checkpoint, which is what an empty log reports, and not an
		// error — a log nobody has written to yet is an ordinary state.
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Checkpoint{}, nil
		}
		return domain.Checkpoint{}, mapErr("head", err)
	}
	return checkpointFrom(row.Sequence, row.Digest)
}

// Entries implements eventlog.Log. The predicate, the ordering and what the
// index does with them are documented beside the statement in
// db/queries/event.sql.
//
// Nothing is preallocated before the query runs: the generated layer appends
// rows as they arrive and this one sizes its own slice from what came back,
// so a caller asking for a billion entries costs a growing slice rather than
// an immediate multi-gigabyte reservation. The limit itself is still the
// caller's and is enforced by the query.
func (l *pgLog) Entries(ctx context.Context, from uint64, limit int) ([]domain.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("audit: entries: %w", err)
	}
	if limit <= 0 {
		return nil, fmt.Errorf("audit: entries: %w: limit is %d, want a positive page size", domain.ErrInvalidArgument, limit)
	}
	if from < domain.FirstSequence {
		from = domain.FirstSequence
	}

	q, release, err := l.reader(ctx)
	if err != nil {
		return nil, err
	}
	defer release()

	rows, err := q.EventsFromSequence(ctx, gen.EventsFromSequenceParams{
		TenantID:     l.chain.Tenant,
		PoolID:       l.chain.Pool,
		FromSequence: int64(from), //nolint:gosec // bounded by the caller's own page request
		PageLimit:    int64(limit),
	})
	if err != nil {
		return nil, mapErr("entries", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}

	out := make([]domain.Entry, 0, len(rows))
	for _, row := range rows {
		entry, err := l.entryFrom(row)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, nil
}

// reader returns something to read through, plus a function to release it.
//
// A caller's enlisted transaction is used when there is one, so that a
// caller reads back what its own uncommitted append wrote — anything else
// would make an enlisted append invisible to the transaction that made it.
// Otherwise a read gets its own transaction, scoped the same way an append's
// is: without the tenant scoping a read would return nothing under
// row-level security, and without the role switch it would run with more
// privilege than the deployment intends.
//
// # Verifying a live chain needs one snapshot, and enlistment is how to get it
//
// Each unenlisted read is its own transaction, so a verification pass that
// pages through a chain while appends are landing sees a moving target: the
// last page can be followed by a new append, and the head read after it is
// then ahead of the chain the walk saw, which Verify correctly reports as a
// head mismatch. That is not tampering, and it is not specific to this
// adapter — the in-memory one holds no lock across a Verify either — but
// here there is something to do about it.
//
// A caller that wants a verification pass over a live chain opens a
// REPEATABLE READ transaction, puts it in the context with WithTx, and calls
// Verify with that context: every read in the pass, the head read included,
// then comes from one snapshot. See
// TestPostgres_VerifyUnderConcurrentAppendsIsStableInOneSnapshot.
func (l *pgLog) reader(ctx context.Context) (*gen.Queries, func(), error) {
	if tx := txFromContext(ctx); tx != nil {
		return gen.New(tx), func() {}, nil
	}

	tx, err := l.db.Begin(ctx)
	if err != nil {
		return nil, nil, mapErr("begin read", err)
	}
	if err := l.scopeTransaction(ctx, tx); err != nil {
		_ = tx.Rollback(ctx)
		return nil, nil, err
	}
	// Rolled back rather than committed: a read changed nothing, and a
	// rollback is the cheaper and more honest way to end it.
	return gen.New(tx), func() { _ = tx.Rollback(ctx) }, nil
}

// scopeTransaction narrows a transaction this adapter opened for itself to
// the application role and to the chain's tenant, both for the lifetime of
// that transaction only.
//
// Both are SET LOCAL in effect — SET LOCAL ROLE, and set_config with
// is_local true — so they are gone the instant the transaction ends, whether
// by commit or rollback, and the pooled connection underneath can be handed
// to the next caller carrying no trace of either. That property is what the
// row-level security backstop depends on to stay fail-closed, and it is why
// this is never applied to a caller-supplied transaction: the scoping would
// outlive the append and silently re-scope every statement the caller runs
// afterwards.
//
// The tenant travels as a bound parameter, through the generated
// SetTenantScope. The role cannot — SET LOCAL ROLE takes no parameters, so
// the role name is the one value in this package that has to reach Postgres
// as SQL text, which is why it is validated as a plain identifier at Open
// and quoted here. That statement is this package's documented exception to
// sqlc; see the package doc comment.
func (l *pgLog) scopeTransaction(ctx context.Context, tx pgx.Tx) error {
	if l.appRole != "" {
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{l.appRole}.Sanitize()); err != nil {
			return mapErr("assume the application role", err)
		}
	}
	if err := gen.New(tx).SetTenantScope(ctx, string(l.chain.Tenant)); err != nil {
		return mapErr("set the tenant scope", err)
	}
	return nil
}

// appendIn performs the append inside tx, whoever owns tx.
func (l *pgLog) appendIn(ctx context.Context, tx pgx.Tx, rec domain.Record) (domain.Entry, error) {
	q := gen.New(tx)

	head, err := l.lockHead(ctx, q)
	if err != nil {
		return domain.Entry{}, err
	}

	id, err := domain.NewEventID(l.clock)
	if err != nil {
		return domain.Entry{}, fmt.Errorf("audit: append: %w", err)
	}

	event := domain.NewEvent(l.chain, id, head.Sequence+1, l.clock.Now(), rec)
	entry := domain.NewEntry(head.Digest, event)

	if err := l.insertEntry(ctx, q, entry); err != nil {
		return domain.Entry{}, err
	}
	if err := l.moveHead(ctx, q, entry); err != nil {
		return domain.Entry{}, err
	}
	return entry, nil
}

// lockHead takes the chain's head row for update, creating it if this is the
// chain's first append, and returns the checkpoint it names. It is two
// statements because a chain's first append has no row to lock; see
// db/queries/chain_head.sql for why each half is shaped the way it is.
func (l *pgLog) lockHead(ctx context.Context, q *gen.Queries) (domain.Checkpoint, error) {
	err := q.CreateChainHeadIfAbsent(ctx, gen.CreateChainHeadIfAbsentParams{
		TenantID: l.chain.Tenant,
		PoolID:   l.chain.Pool,
		Digest:   zeroDigest,
	})
	if err != nil {
		return domain.Checkpoint{}, mapErr("append: create the chain head", err)
	}

	row, err := q.LockChainHead(ctx, gen.LockChainHeadParams{
		TenantID: l.chain.Tenant,
		PoolID:   l.chain.Pool,
	})
	if err != nil {
		return domain.Checkpoint{}, mapErr("append: lock the chain head", err)
	}
	return checkpointFrom(row.Sequence, row.Digest)
}

// insertEntry writes the history row: the only INSERT on audit.event in this
// module, and the only privilege on that table the application role is meant
// to hold beyond SELECT.
func (l *pgLog) insertEntry(ctx context.Context, q *gen.Queries, entry domain.Entry) error {
	e := entry.Event
	err := q.InsertEvent(ctx, gen.InsertEventParams{
		TenantID:   e.Chain.Tenant,
		PoolID:     e.Chain.Pool,
		Sequence:   int64(e.Sequence), //nolint:gosec // a sequence is a positive counter, not an external length
		EventID:    e.ID,
		RecordedAt: e.Timestamp,

		ActorID:     e.Actor,
		SubjectKind: e.Subject.Kind,
		SubjectID:   e.Subject.ID,
		Action:      e.Action,
		Outcome:     e.Outcome,
		Detail:      detailBytes(e.Detail),

		LinkPrev: entry.Link.Prev[:],
		LinkSelf: entry.Link.Self[:],
	})
	if err != nil {
		return mapErr("append: insert the entry", err)
	}
	return nil
}

// moveHead advances the head row to the entry just written. Zero rows moved
// means the head was not where this append left the lock, which the query
// file explains and which is a failed append rather than a forked chain.
func (l *pgLog) moveHead(ctx context.Context, q *gen.Queries, entry domain.Entry) error {
	moved, err := q.MoveChainHead(ctx, gen.MoveChainHeadParams{
		TenantID: l.chain.Tenant,
		PoolID:   l.chain.Pool,
		Sequence: int64(entry.Event.Sequence), //nolint:gosec // a sequence is a positive counter
		Digest:   entry.Link.Self[:],
	})
	if err != nil {
		return mapErr("append: move the chain head", err)
	}
	if moved != 1 {
		return fmt.Errorf("%w: audit: append: the chain head moved underneath this append: it was not at sequence %d",
			domain.ErrUnavailable, entry.Event.Sequence-1)
	}
	return nil
}

// entryFrom maps one generated row onto an Entry.
//
// The generated row already carries the typed domain ids — the sqlc
// overrides in sqlc.yaml see to that, so there is no bare string to retype
// here. What is left is the three conversions a generated scan cannot do:
// the two digests, which go through domain's validating parser rather than
// through a Scanner method on Digest (see sqlc.yaml for why that method must
// not exist), the subject, which is one domain value spanning two columns,
// and the chain identifier, which is taken from the log rather than read
// back — it is the log's own binding and is already in every row's WHERE
// clause, so reading it would be asking the database to confirm a value we
// used to find the row.
func (l *pgLog) entryFrom(row gen.EventsFromSequenceRow) (domain.Entry, error) {
	if row.Sequence < 0 {
		return domain.Entry{}, fmt.Errorf("%w: audit: entries: a stored sequence is negative", domain.ErrStorage)
	}

	prev, err := digestFrom(row.LinkPrev)
	if err != nil {
		return domain.Entry{}, err
	}
	self, err := digestFrom(row.LinkSelf)
	if err != nil {
		return domain.Entry{}, err
	}

	return domain.Entry{
		Event: domain.Event{
			Chain:    l.chain,
			ID:       row.EventID,
			Sequence: uint64(row.Sequence),
			// Canonicalized on the way out as well as on the way in.
			// timestamptz round-trips at microsecond precision, and pgx
			// hands the value back in the session's offset rather than in
			// UTC; the digest committed to the canonical form, so anything
			// else here would report every entry as tampered.
			Timestamp: domain.CanonicalTime(row.RecordedAt),
			Actor:     row.ActorID,
			Subject:   domain.SubjectRef{Kind: row.SubjectKind, ID: row.SubjectID},
			Action:    row.Action,
			Outcome:   row.Outcome,
			Detail:    row.Detail,
		},
		Link: domain.ChainLink{Prev: prev, Self: self},
	}, nil
}

// checkpointFrom builds a Checkpoint from a head row's two columns.
func checkpointFrom(sequence int64, digest []byte) (domain.Checkpoint, error) {
	if sequence < 0 {
		return domain.Checkpoint{}, fmt.Errorf("%w: audit: the stored head sequence is negative", domain.ErrStorage)
	}
	if sequence == 0 {
		// A head row exists but nothing has been appended: the chain was
		// created by a first append that then rolled back, or by one still
		// in flight. Either way the chain is empty, which is the zero
		// Checkpoint — and specifically not a checkpoint at sequence zero
		// holding a zero digest, since the two must stay indistinguishable.
		return domain.Checkpoint{}, nil
	}

	d, err := digestFrom(digest)
	if err != nil {
		return domain.Checkpoint{}, err
	}
	return domain.Checkpoint{Sequence: uint64(sequence), Digest: d}, nil
}

// digestFrom converts stored bytes to a Digest, rejecting a wrong length
// rather than silently truncating or zero-padding. The column has a CHECK
// constraint for the same thing; this is the Go side of it, and the one that
// still holds if the row arrived from somewhere the constraint did not
// cover.
//
// It is also the reason no sqlc override maps a bytea column to Digest: the
// only way to make a generated scan produce one directly is a sql.Scanner on
// Digest, which would be an exported method anyone could call with arbitrary
// bytes. Converting here keeps the check in one place and the type
// unforgeable.
func digestFrom(b []byte) (domain.Digest, error) {
	var d domain.Digest
	if len(b) != len(d) {
		return domain.Digest{}, fmt.Errorf("%w: audit: a stored digest is %d bytes, want %d", domain.ErrStorage, len(b), len(d))
	}
	copy(d[:], b)
	return d, nil
}

// detailBytes maps a nil Detail onto an empty slice, because the column is
// NOT NULL and the canonical encoding length-prefixes — so nil and empty
// hash identically and the distinction is not one the chain can lose.
func detailBytes(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}
