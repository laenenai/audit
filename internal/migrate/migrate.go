// Package migrate applies this module's embedded schema migrations and
// reports on their state. It is the only package that imports goose;
// callers see Up, Status, Applied and Config.
//
// # A schema per module, with its own version table
//
// These tables live in the *consumer's* database, next to that consumer's
// own schema and its own goose sequence. Two independent migration owners
// writing one database collide on goose's single version table, so each
// shared module owns a Postgres schema and keeps its version table inside
// it: this one owns schema "audit" and records its state in
// audit.goose_db_version. Independent sequences, no shared ordering, no
// collision. A schema per module is also the unit privilege separation
// needs, which this module needs more than most.
//
// The schema is created by Up itself, before goose runs, rather than only by
// migration 00001. goose has to be able to create its bookkeeping table
// before any migration has run, and that table lives in the schema — so the
// schema has to exist first. (CAS hit the same ordering problem and resolved
// it by putting its version table in public; that is not available here,
// because the whole point is that two modules' version tables must not share
// a schema.)
//
// # What Up applies, and in which of three layers
//
// Up is three things in sequence, and which layer a piece of DDL belongs in
// is decided by one question: can a later deployment legitimately change it?
//
//  1. **The fixed schema**, as goose migrations (db/migrations/*.sql). The
//     tables, the partitioning strategy, the append-only trigger, the RLS
//     policies, the indexes. Versioned, applied once, never changed. These
//     are the decisions that cannot be revisited — "converting a populated
//     table to a partitioned one is an outage".
//
//  2. **The partitions**, reconciled on every Up (partitions.go). The number
//     of hash partitions is fixed the first time and refuses to change
//     afterwards, because changing the modulus is a data migration and not a
//     configuration edit. The range partitions within each hash partition
//     extend forward over time, so re-running Up — which a library-applied
//     migration model does at every startup — is how the window stays ahead
//     of the present.
//
//  3. **The privileges**, reconciled on every Up (privileges.go). The
//     application role's name is configuration, because the migration has to
//     name it in its REVOKE.
//
// Layers 2 and 3 are deliberately *not* versioned migrations, and this is a
// considered departure from "the migration does the revoke". A versioned
// migration records itself as applied; a deployment that then changed the
// application role's name, or added a hash partition, would have its
// migration silently skipped and would come up with no privilege separation
// at all while goose reported everything applied. Reconciling instead means
// the state of the database is a function of the configuration rather than
// of the order in which configurations were tried. Both steps are idempotent
// and both are safe to run concurrently; see lockKey.
package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/laenen-ai/audit/db/migrations"
	"github.com/laenen-ai/audit/internal/domain"
)

// Schema is the Postgres schema this module owns. Nothing this module
// creates lives outside it.
const Schema = "audit"

// versionTableName is where goose records which of this module's migrations
// have been applied: inside this module's own schema, which is the whole
// point — see the package doc comment.
const versionTableName = Schema + ".goose_db_version"

// lockKey is the Postgres session-level advisory lock key Up and Status take
// for the duration of their run, so that N processes starting against the
// same database serialize their migration attempts instead of racing. It is
// the CRC32 (IEEE) checksum of this package's import path — specific to this
// module, and vanishingly unlikely to collide with a lock taken by something
// else sharing the same Postgres cluster, including the consumer's own
// migrations:
//
//	crc32.ChecksumIEEE([]byte("github.com/laenen-ai/audit/internal/migrate"))
//
// It must never change: changing it would let an old and a new binary
// migrate concurrently against each other during a rolling deploy, which is
// the race it exists to prevent. That it differs from every other module's
// key is the point — two modules migrating two schemas in one database have
// no reason to wait for each other.
const lockKey int64 = 1966699558

// lockPollPeriodSeconds and lockMaxRetries bound how long Up and Status wait
// for the advisory lock before giving up as domain.ErrUnavailable. goose's
// session locker polls pg_try_advisory_lock rather than blocking, so these
// are the poll interval in whole seconds (1 is the library's minimum) and
// the number of retries after the first attempt — about five minutes.
// Production always uses these; tests shrink them through
// WithLockTimeoutForTest to make the timeout path reachable in a second.
var (
	lockPollPeriodSeconds uint64 = 1
	lockMaxRetries        uint64 = 300
)

// Applied describes one migration's state as goose's bookkeeping table knows
// it, for an operator-facing status command to print.
type Applied struct {
	// Version is the migration's leading version number, e.g. 1 for
	// 00001_audit.sql.
	Version int64
	// Name is the migration's filename, e.g. "00001_audit.sql".
	Name string
	// Applied reports whether this migration has been applied. AppliedAt is
	// the zero time when it has not.
	Applied   bool
	AppliedAt time.Time
}

// Up applies this module's schema to pool: the fixed migrations, then the
// partitions, then the privileges. See the package doc comment for why those
// are three layers rather than one.
//
// pool must connect as a role that can create objects in — and ideally
// owns — schema "audit", and that can GRANT to and REVOKE from
// cfg.AppRole. That is the owner identity, and it is deliberately not the
// identity the application runs as: the whole of this module's append-only
// guarantee is that the application cannot UPDATE or DELETE what the owner
// created. A deployment may keep that as two DSNs, or as one owner DSN that
// the runtime narrows with SET ROLE; this module does not care which, and
// pglog.Open reports loudly if the result is that no separation exists.
//
// Up is safe to call concurrently, from goroutines or from separate
// processes against the same database: goose's migrations are serialized by
// the advisory lock on lockKey, and the two reconciliation layers take the
// same lock for their own transaction. Calling Up against an already-current
// database applies nothing new, extends the partition window if time has
// moved on, re-asserts the privileges, and returns nil.
func Up(ctx context.Context, pool *pgxpool.Pool, cfg Config) error {
	resolved, err := cfg.resolve()
	if err != nil {
		return err
	}

	if err := ensureSchema(ctx, pool); err != nil {
		return err
	}

	provider, closeDB, err := newProvider(pool)
	if err != nil {
		return err
	}
	defer closeDB()

	if _, err := provider.Up(ctx); err != nil {
		return classify("apply migrations", err)
	}

	return reconcile(ctx, pool, resolved)
}

// Status reports the state of every embedded migration: applied ones with
// the time they were applied, and pending ones not yet run. It takes the
// same advisory lock as Up for the duration of the call, so a status read
// reflects a consistent view rather than racing a concurrent Up.
//
// It reports only layer 1, the versioned migrations. Layers 2 and 3 have no
// "pending" state to report: they are reconciled on every Up, so the
// question "are the privileges applied" is answered by
// pglog.CheckEnforcement against the running configuration, not by a version
// number.
func Status(ctx context.Context, pool *pgxpool.Pool) ([]Applied, error) {
	if err := ensureSchema(ctx, pool); err != nil {
		return nil, err
	}

	provider, closeDB, err := newProvider(pool)
	if err != nil {
		return nil, err
	}
	defer closeDB()

	statuses, err := provider.Status(ctx)
	if err != nil {
		return nil, classify("status", err)
	}

	applied := make([]Applied, 0, len(statuses))
	for _, s := range statuses {
		applied = append(applied, Applied{
			Version:   s.Source.Version,
			Name:      path.Base(s.Source.Path),
			Applied:   s.State == goose.StateApplied,
			AppliedAt: s.AppliedAt,
		})
	}
	return applied, nil
}

// reconcile applies layers 2 and 3 inside one transaction holding the same
// advisory lock goose used for layer 1, so the whole of Up is serialized
// against another process doing the same thing. DDL is transactional in
// Postgres, so a failure anywhere in here leaves the database exactly as the
// migrations left it rather than half-partitioned.
//
// pg_advisory_xact_lock blocks rather than polling, and is released by the
// commit or rollback; that is the right shape here because this transaction
// is short and there is nothing useful to do while waiting.
func reconcile(ctx context.Context, pool *pgxpool.Pool, cfg resolvedConfig) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("%w: migrate: begin reconciliation: %w", domain.ErrUnavailable, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", lockKey); err != nil {
		return fmt.Errorf("%w: migrate: take reconciliation lock: %w", domain.ErrUnavailable, err)
	}

	if err := ensurePartitions(ctx, tx, cfg); err != nil {
		return err
	}
	if err := reconcilePrivileges(ctx, tx, cfg); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("%w: migrate: commit reconciliation: %w", domain.ErrUnavailable, err)
	}
	return nil
}

// ensureSchema creates this module's schema if it is not there yet, because
// goose's version table lives inside it and goose has to create that table
// before it can run the migration that would otherwise create the schema.
//
// CREATE SCHEMA IF NOT EXISTS still loses a race against a concurrent
// identical statement — both sessions can see "not there" before either
// commits — so duplicate_schema is caught and treated as success. That is
// the same hazard CAS documented for its cluster-wide CREATE ROLE, in a
// different catalog.
func ensureSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+pgx.Identifier{Schema}.Sanitize())
	if err == nil {
		return nil
	}
	if isDuplicateObject(err) {
		return nil
	}
	return classify("create schema "+Schema, err)
}

// newProvider builds a goose Provider wrapping pool, configured with the
// session-level advisory lock described on lockKey, plus a cleanup function
// that closes the *sql.DB wrapper it created — not pool itself, which pgx
// documents stdlib.OpenDBFromPool as never closing.
//
// goose checks out exactly one *sql.Conn from db for any one call to Up or
// Status and runs the session lock, the bookkeeping check and every
// migration statement on that same connection. That is what makes a
// session-scoped advisory lock actually serialize the work it is held
// around; taking the lock on a connection of our own and letting goose use a
// different one would not.
func newProvider(pool *pgxpool.Pool) (*goose.Provider, func(), error) {
	db := stdlib.OpenDBFromPool(pool)
	closeDB := func() { _ = db.Close() }

	provider, err := buildProvider(db)
	if err != nil {
		closeDB()
		return nil, nil, err
	}
	return provider, closeDB, nil
}

func buildProvider(db *sql.DB) (*goose.Provider, error) {
	locker, err := lock.NewPostgresSessionLocker(
		lock.WithLockID(lockKey),
		lock.WithLockTimeout(lockPollPeriodSeconds, lockMaxRetries),
	)
	if err != nil {
		// Only reachable if the fixed arguments above were invalid, which
		// is a defect in this binary rather than a runtime condition.
		return nil, fmt.Errorf("%w: migrate: build session locker: %w", domain.ErrInvalidConfig, err)
	}

	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS,
		goose.WithSessionLocker(locker),
		goose.WithTableName(versionTableName),
	)
	if err != nil {
		// Reachable if the embedded migration set is malformed — again a
		// defect in the binary, not in the database.
		return nil, fmt.Errorf("%w: migrate: build goose provider: %w", domain.ErrInvalidConfig, err)
	}
	return provider, nil
}

// classify maps an error out of goose or pgx onto this module's taxonomy, so
// nothing in this package returns a bare driver error across its boundary.
//
// Two failure modes are "reachable in principle, just not right now", and
// therefore domain.ErrUnavailable — worth a caller retrying:
//
//   - the database could not be reached at all, which pgx reports as a
//     *pgconn.ConnectError anywhere in the chain;
//   - the advisory lock could not be acquired within its budget, meaning
//     another process is still migrating. goose exports no sentinel for
//     this: its exhausted-retries error is the fixed, unexported string
//     "failed to acquire lock", which is what is matched below. That is
//     pinned to the goose version in go.mod, and
//     TestUp_LockTimeout_IsUnavailable exercises it through real contention
//     so an upgrade that reworded it fails a test instead of silently
//     misclassifying a contended lock as a permanent defect.
//
// Everything else means the binary's embedded schema does not fit this
// database — a rejected statement, a version mismatch between the embedded
// set and the version table — which is a deployment defect, so
// domain.ErrInvalidConfig. The underlying error stays wrapped either way:
// unlike the adapter's row paths, nothing here has seen an event, so an
// operator gets to read what Postgres actually said.
func classify(op string, err error) error {
	var connectErr *pgconn.ConnectError
	switch {
	case errors.As(err, &connectErr):
		return fmt.Errorf("%w: migrate: %s: could not reach the database: %w", domain.ErrUnavailable, op, err)
	case strings.Contains(err.Error(), "failed to acquire lock"):
		return fmt.Errorf("%w: migrate: %s: timed out waiting for another migration to finish: %w", domain.ErrUnavailable, op, err)
	default:
		return fmt.Errorf("%w: migrate: %s: %w", domain.ErrInvalidConfig, op, err)
	}
}

// isDuplicateObject reports whether err is Postgres complaining that
// something we asked it to create already exists. Every CREATE in the two
// reconciliation layers is idempotent by intent, and the IF NOT EXISTS form
// still loses a race against a concurrent identical statement, so these
// codes are success rather than failure.
func isDuplicateObject(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	switch pgErr.Code {
	case "42P06", // duplicate_schema
		"42P07", // duplicate_table
		"42710", // duplicate_object (a role, a policy)
		"23505": // unique_violation, which is how a lost CREATE ROLE race surfaces
		return true
	default:
		return false
	}
}
