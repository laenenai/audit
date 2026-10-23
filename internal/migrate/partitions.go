// This file is layer 2 of Up: the partitions of audit.event. See the
// package doc comment for why the partitions are reconciled on every run
// rather than written into a versioned migration, and 00001_audit.sql for
// why the partitioning strategy itself is fixed at creation.
//
// The shape is two levels, as CAS's design settled: audit.event is
// PARTITION BY HASH (tenant_id), each hash partition is PARTITION BY RANGE
// (recorded_at), and each range level holds one partition per month plus a
// default. Retention is then a partition drop — the only form of deletion a
// hash chain tolerates — and verification continues from the checkpoint at
// that boundary (eventlog.VerifyOptions.Root).

package migrate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/laenen-ai/audit/internal/domain"
)

// HashPartitionName returns the name of hash partition i of audit.event.
// Exported because a retention tool, and this module's own tests, need to
// name a partition in order to drop one, and deriving the name by hand in
// two places is how the two come to disagree.
func HashPartitionName(i int) string { return fmt.Sprintf("event_h%d", i) }

// RangePartitionName returns the name of the monthly range partition of hash
// partition i that holds at, which is the unit retention drops.
func RangePartitionName(i int, at time.Time) string {
	return fmt.Sprintf("%s_%s", HashPartitionName(i), monthOf(at).Format("200601"))
}

// defaultRangePartitionName returns the name of the catch-all range
// partition of hash partition i: where a row lands when its month has no
// partition of its own.
func defaultRangePartitionName(i int) string { return HashPartitionName(i) + "_default" }

// ensurePartitions brings the partitions of audit.event in line with cfg: it
// creates the hash partitions the first time, refuses to change their number
// afterwards, and extends the monthly window inside each of them.
func ensurePartitions(ctx context.Context, tx pgx.Tx, cfg resolvedConfig) error {
	existing, err := hashPartitionCount(ctx, tx)
	if err != nil {
		return err
	}

	switch {
	case existing == 0:
		if err := createHashPartitions(ctx, tx, cfg.hashPartitions); err != nil {
			return err
		}
	case existing != cfg.hashPartitions:
		// Loud rather than silent, and before anything is written: a
		// deployment that believes it changed the modulus and in fact did
		// not would be reasoning about partition pruning and retention
		// against a shape the database does not have.
		return fmt.Errorf("%w: migrate: audit.event already has %d hash partitions but HashPartitions is %d: "+
			"the modulus is fixed at creation because changing it redistributes every tenant's rows, which is a data migration and not a configuration change",
			domain.ErrInvalidConfig, existing, cfg.hashPartitions)
	}

	return ensureRangePartitions(ctx, tx, cfg)
}

// hashPartitionCount counts the direct partitions of audit.event.
func hashPartitionCount(ctx context.Context, tx pgx.Tx) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `
		SELECT count(*)
		FROM pg_inherits
		WHERE inhparent = ($1 || '.event')::regclass
	`, Schema).Scan(&n)
	if err != nil {
		return 0, classify("count hash partitions of "+Schema+".event", err)
	}
	return n, nil
}

// createHashPartitions creates n hash partitions of audit.event, each itself
// partitioned by range on recorded_at.
//
// Nothing is granted on these partitions, ever, and that is load-bearing
// rather than an omission. Postgres checks privileges against the table
// named in the statement, so an INSERT routed through audit.event needs no
// privilege on the partition it lands in — which means the application role
// can be given access to the parent and no access at all to any leaf. That
// closes the hole a row-level security policy on a partitioned table
// otherwise leaves open: a query aimed straight at a leaf partition is
// evaluated against that leaf's own policies, and a role with no privileges
// on the leaf never gets that far.
func createHashPartitions(ctx context.Context, tx pgx.Tx, n int) error {
	parent := qualified("event")
	for i := range n {
		name := qualified(HashPartitionName(i))
		stmt := fmt.Sprintf(
			"CREATE TABLE IF NOT EXISTS %s PARTITION OF %s FOR VALUES WITH (MODULUS %d, REMAINDER %d) PARTITION BY RANGE (recorded_at)",
			name, parent, n, i,
		)
		if err := execIdempotent(ctx, tx, stmt); err != nil {
			return fmt.Errorf("migrate: create hash partition %s: %w", name, err)
		}
	}
	return nil
}

// ensureRangePartitions makes sure every hash partition has a monthly
// partition for each month in cfg's window, plus a default.
//
// It reads the hash partitions out of the catalog rather than trusting
// cfg.hashPartitions, so the modulus used here is always the one the
// database actually has even when the configuration disagrees — the
// disagreement is reported by ensurePartitions, and this layer never makes
// it worse by writing against a shape that does not exist.
func ensureRangePartitions(ctx context.Context, tx pgx.Tx, cfg resolvedConfig) error {
	count, err := hashPartitionCount(ctx, tx)
	if err != nil {
		return err
	}

	months := windowMonths(cfg)
	for i := range count {
		if err := ensureDefaultRangePartition(ctx, tx, i); err != nil {
			return err
		}
		for _, month := range months {
			if err := ensureMonthRangePartition(ctx, tx, i, month); err != nil {
				return err
			}
		}
	}
	return nil
}

// ensureMonthRangePartition creates the partition of hash partition i that
// holds month, if it is not already there.
//
// The one failure it tolerates is check_violation (23514), which is how
// Postgres reports that attaching this month's partition would move rows out
// of the default partition: it has to re-check the default's constraint, and
// it refuses if the default already holds rows for this month. That happens
// when a deployment ran for longer than its window without restarting, so
// rows for the current month landed in the default.
//
// Tolerating it is the lesser evil, chosen deliberately. Failing Up would
// mean a process that cannot start, which means a system that cannot audit,
// which is strictly worse than a month's rows sitting in the default
// partition. The cost is real and worth stating: a row in the default
// partition is not droppable by retention until it is moved there from, so
// this condition is a retention gap rather than a correctness one — and it
// is exactly the condition a partition-maintenance schedule exists to
// prevent. That schedule is not this increment.
func ensureMonthRangePartition(ctx context.Context, tx pgx.Tx, i int, month time.Time) error {
	name := qualified(RangePartitionName(i, month))
	stmt := fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')",
		name, qualified(HashPartitionName(i)),
		month.Format(partitionBoundLayout), month.AddDate(0, 1, 0).Format(partitionBoundLayout),
	)

	err := execIdempotent(ctx, tx, stmt)
	if err == nil {
		return nil
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23514" {
		return nil
	}
	return fmt.Errorf("migrate: create range partition %s: %w", name, err)
}

// ensureDefaultRangePartition creates hash partition i's catch-all, so that
// an insert whose month has no partition is still recorded rather than
// refused.
//
// An audit log that drops a record because a partition was missing has
// failed at the one thing it is for, so the default partition is a
// deliberate safety net. See ensureMonthRangePartition for what it costs.
func ensureDefaultRangePartition(ctx context.Context, tx pgx.Tx, i int) error {
	name := qualified(defaultRangePartitionName(i))
	stmt := fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s PARTITION OF %s DEFAULT", name, qualified(HashPartitionName(i)))
	if err := execIdempotent(ctx, tx, stmt); err != nil {
		return fmt.Errorf("migrate: create default range partition %s: %w", name, err)
	}
	return nil
}

// partitionBoundLayout renders a partition bound as an unambiguous absolute
// instant: an explicit +00 offset, so the bound means the same thing
// whatever the session's time zone is. A bound written without one is
// interpreted in the session's TimeZone, which would put the same row in
// different partitions depending on who ran the migration.
const partitionBoundLayout = "2006-01-02 15:04:05+00"

// windowMonths returns the first instant of every month the configured
// window covers, oldest first.
func windowMonths(cfg resolvedConfig) []time.Time {
	start := monthOf(cfg.now()).AddDate(0, -cfg.monthsBehind, 0)
	months := make([]time.Time, 0, cfg.monthsBehind+cfg.monthsAhead+1)
	for n := range cfg.monthsBehind + cfg.monthsAhead + 1 {
		months = append(months, start.AddDate(0, n, 0))
	}
	return months
}

// monthOf truncates t to the first instant of its month, in UTC.
func monthOf(t time.Time) time.Time {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// qualified renders name as a safely quoted identifier in this module's
// schema. Every table name this file builds is derived from a loop counter
// and a month, so none of it is caller-controlled; it goes through Sanitize
// anyway, because an identifier built by string formatting is one edit away
// from being built from something else.
func qualified(name string) string {
	return pgx.Identifier{Schema, name}.Sanitize()
}

// execIdempotent runs a CREATE that is meant to be a no-op when the object
// already exists, inside a savepoint so that a duplicate-object error from a
// lost race does not poison the surrounding transaction.
//
// The savepoint is the point: in Postgres a failed statement aborts the
// whole transaction, so "try it and ignore the duplicate" is only available
// to a caller that can roll back to just before the attempt.
func execIdempotent(ctx context.Context, tx pgx.Tx, stmt string) error {
	nested, err := tx.Begin(ctx)
	if err != nil {
		return fmt.Errorf("%w: open savepoint: %w", domain.ErrUnavailable, err)
	}

	if _, err := nested.Exec(ctx, stmt); err != nil {
		_ = nested.Rollback(ctx)
		if isDuplicateObject(err) {
			return nil
		}
		return err
	}
	if err := nested.Commit(ctx); err != nil {
		return fmt.Errorf("%w: release savepoint: %w", domain.ErrUnavailable, err)
	}
	return nil
}
