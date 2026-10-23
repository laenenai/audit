// This file is the Log implementation: the three port methods, the one
// transaction shape they share, and the row mapping.

package pglog

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/laenen-ai/audit/internal/domain"
)

// zeroDigest is the genesis entry's predecessor, as the 32 bytes a freshly
// created head row carries. The column requires exactly 32 bytes, so "no
// predecessor" is stored rather than left null: a nullable digest would make
// every read of it a special case, and the zero digest is already the
// reserved value the chain uses for that exact meaning.
var zeroDigest = make([]byte, len(domain.Digest{}))

// eventColumns is the select list every read uses, in the order scanEntry
// expects. One constant rather than two literals, because a column added to
// one and not the other is a bug that compiles.
const eventColumns = `sequence, event_id, recorded_at, actor_id, subject_kind, subject_id, action, outcome, detail, link_prev, link_self`

// Append implements eventlog.Log.
//
// It is one read-modify-write the adapter owns entirely: it locks the
// chain's head row, computes the next entry from the head it read, inserts
// the entry, and moves the head. Nothing is cached between calls, so the
// whole of it fits inside a transaction the caller supplied and a rollback
// leaves no stale state behind for the next append to trip over.
//
// The head row lock is what makes the chain a chain under concurrency. Two
// appenders that both observed head N would both produce an entry claiming
// sequence N+1 with predecessor N, and one of them would have to be thrown
// away. Locking the head row means the second appender waits and then
// observes N+1, so the chain comes out contiguous and correctly linked with
// no retry loop anywhere. An append to a different chain locks a different
// row and is not delayed at all.
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

	var sequence int64
	var digest []byte
	err = q.QueryRow(ctx, `
		SELECT sequence, digest FROM `+headTable+`
		WHERE tenant_id = $1 AND pool_id = $2
	`, string(l.chain.Tenant), string(l.chain.Pool)).Scan(&sequence, &digest)
	if err != nil {
		// A chain with no head row has never been appended to. That is the
		// zero Checkpoint, which is what an empty log reports, and not an
		// error — a log nobody has written to yet is an ordinary state.
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.Checkpoint{}, nil
		}
		return domain.Checkpoint{}, mapErr("head", err)
	}
	return checkpointFrom(sequence, digest)
}

// Entries implements eventlog.Log.
//
// The predicate is (tenant_id, pool_id, sequence >= from) ordered by
// sequence, which is exactly the primary key's leading columns, so this is
// an index scan already in chain order rather than a sort. Partition pruning
// on tenant_id narrows it to one hash partition; there is no time predicate
// to prune the range partitions within it, because a chain walk is defined
// by sequence and asking for a time window would be asking a different
// question.
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

	rows, err := q.Query(ctx, `
		SELECT `+eventColumns+` FROM `+eventTable+`
		WHERE tenant_id = $1 AND pool_id = $2 AND sequence >= $3
		ORDER BY sequence
		LIMIT $4
	`, string(l.chain.Tenant), string(l.chain.Pool), int64(from), int64(limit)) //nolint:gosec // both are bounded by the caller's own page request
	if err != nil {
		return nil, mapErr("entries", err)
	}
	defer rows.Close()

	out := make([]domain.Entry, 0, limit)
	for rows.Next() {
		entry, err := l.scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr("entries: read", err)
	}
	if len(out) == 0 {
		return nil, nil
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
func (l *pgLog) reader(ctx context.Context) (querier, func(), error) {
	if tx := txFromContext(ctx); tx != nil {
		return tx, func() {}, nil
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
	return tx, func() { _ = tx.Rollback(ctx) }, nil
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
// The tenant travels as a bound parameter rather than as SQL text. The role
// cannot — SET LOCAL ROLE takes no parameters — so it is validated as a
// plain identifier at Open and quoted here.
func (l *pgLog) scopeTransaction(ctx context.Context, tx pgx.Tx) error {
	if l.appRole != "" {
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{l.appRole}.Sanitize()); err != nil {
			return mapErr("assume the application role", err)
		}
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", string(l.chain.Tenant)); err != nil {
		return mapErr("set the tenant scope", err)
	}
	return nil
}

// appendIn performs the append inside tx, whoever owns tx.
func (l *pgLog) appendIn(ctx context.Context, tx pgx.Tx, rec domain.Record) (domain.Entry, error) {
	head, err := l.lockHead(ctx, tx)
	if err != nil {
		return domain.Entry{}, err
	}

	id, err := domain.NewEventID(l.clock)
	if err != nil {
		return domain.Entry{}, fmt.Errorf("audit: append: %w", err)
	}

	event := domain.NewEvent(l.chain, id, head.Sequence+1, l.clock.Now(), rec)
	entry := domain.NewEntry(head.Digest, event)

	if err := l.insertEntry(ctx, tx, entry); err != nil {
		return domain.Entry{}, err
	}
	if err := l.moveHead(ctx, tx, entry); err != nil {
		return domain.Entry{}, err
	}
	return entry, nil
}

// lockHead takes the chain's head row for update, creating it if this is the
// chain's first append, and returns the checkpoint it names.
//
// It is two statements because a chain's first append has no row to lock.
// INSERT ... ON CONFLICT DO NOTHING is the race-safe half: a concurrent
// identical insert makes this one wait for that transaction and then insert
// nothing, and if that transaction aborted instead, Postgres retries the
// insertion rather than reporting a conflict with a row that no longer
// exists. The SELECT ... FOR UPDATE that follows is what every subsequent
// appender on this chain serializes on.
func (l *pgLog) lockHead(ctx context.Context, tx pgx.Tx) (domain.Checkpoint, error) {
	_, err := tx.Exec(ctx, `
		INSERT INTO `+headTable+` (tenant_id, pool_id, sequence, digest, updated_at)
		VALUES ($1, $2, 0, $3, now())
		ON CONFLICT (tenant_id, pool_id) DO NOTHING
	`, string(l.chain.Tenant), string(l.chain.Pool), zeroDigest)
	if err != nil {
		return domain.Checkpoint{}, mapErr("append: create the chain head", err)
	}

	var sequence int64
	var digest []byte
	err = tx.QueryRow(ctx, `
		SELECT sequence, digest FROM `+headTable+`
		WHERE tenant_id = $1 AND pool_id = $2
		FOR UPDATE
	`, string(l.chain.Tenant), string(l.chain.Pool)).Scan(&sequence, &digest)
	if err != nil {
		return domain.Checkpoint{}, mapErr("append: lock the chain head", err)
	}
	return checkpointFrom(sequence, digest)
}

// insertEntry writes the history row. It is the only INSERT in this package
// that touches audit.event, and the only privilege on that table the
// application role is meant to hold.
func (l *pgLog) insertEntry(ctx context.Context, tx pgx.Tx, entry domain.Entry) error {
	e := entry.Event
	_, err := tx.Exec(ctx, `
		INSERT INTO `+eventTable+` (
			tenant_id, pool_id, sequence, event_id, recorded_at,
			actor_id, subject_kind, subject_id, action, outcome, detail,
			link_prev, link_self
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`,
		string(e.Chain.Tenant), string(e.Chain.Pool), int64(e.Sequence), //nolint:gosec // a sequence is a positive counter, not an external length
		string(e.ID), e.Timestamp,
		string(e.Actor), e.Subject.Kind, e.Subject.ID, string(e.Action), string(e.Outcome), detailBytes(e.Detail),
		entry.Link.Prev[:], entry.Link.Self[:],
	)
	if err != nil {
		return mapErr("append: insert the entry", err)
	}
	return nil
}

// moveHead advances the head row to the entry just written.
//
// The WHERE clause names the sequence the head was expected to be at, so
// this is an optimistic check on top of the pessimistic row lock. The lock
// already makes a lost update impossible; the predicate is what turns a
// future bug that drops the lock into a failed append instead of a silently
// forked chain, and it costs nothing — the row is already locked and in
// cache.
func (l *pgLog) moveHead(ctx context.Context, tx pgx.Tx, entry domain.Entry) error {
	tag, err := tx.Exec(ctx, `
		UPDATE `+headTable+`
		SET sequence = $3, digest = $4, updated_at = now()
		WHERE tenant_id = $1 AND pool_id = $2 AND sequence = $3 - 1
	`,
		string(l.chain.Tenant), string(l.chain.Pool),
		int64(entry.Event.Sequence), //nolint:gosec // a sequence is a positive counter
		entry.Link.Self[:],
	)
	if err != nil {
		return mapErr("append: move the chain head", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("%w: audit: append: the chain head moved underneath this append: it was not at sequence %d",
			domain.ErrUnavailable, entry.Event.Sequence-1)
	}
	return nil
}

// scanEntry maps one row onto an Entry. The chain identifier is taken from
// the log rather than read back, because it is the log's own binding and is
// already in every row's WHERE clause: reading it would be asking the
// database to confirm a value we used to find the row.
func (l *pgLog) scanEntry(rows pgx.Rows) (domain.Entry, error) {
	var (
		sequence           int64
		eventID            string
		recordedAt         time.Time
		actor              string
		subjectKind        string
		subjectID          string
		action             string
		outcome            string
		detail             []byte
		linkPrev, linkSelf []byte
	)
	if err := rows.Scan(&sequence, &eventID, &recordedAt, &actor, &subjectKind, &subjectID,
		&action, &outcome, &detail, &linkPrev, &linkSelf); err != nil {
		return domain.Entry{}, mapErr("entries: scan", err)
	}
	if sequence < 0 {
		return domain.Entry{}, fmt.Errorf("%w: audit: entries: a stored sequence is negative", domain.ErrStorage)
	}

	prev, err := digestFrom(linkPrev)
	if err != nil {
		return domain.Entry{}, err
	}
	self, err := digestFrom(linkSelf)
	if err != nil {
		return domain.Entry{}, err
	}

	return domain.Entry{
		Event: domain.Event{
			Chain:    l.chain,
			ID:       domain.EventID(eventID),
			Sequence: uint64(sequence),
			// Canonicalized on the way out as well as on the way in.
			// timestamptz round-trips at microsecond precision, and pgx
			// hands the value back in the session's offset rather than in
			// UTC; the digest committed to the canonical form, so anything
			// else here would report every entry as tampered.
			Timestamp: domain.CanonicalTime(recordedAt),
			Actor:     domain.ActorID(actor),
			Subject:   domain.SubjectRef{Kind: subjectKind, ID: subjectID},
			Action:    domain.Action(action),
			Outcome:   domain.Outcome(outcome),
			Detail:    detail,
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
