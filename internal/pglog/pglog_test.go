package pglog_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/laenen-ai/audit"
	"github.com/laenen-ai/audit/audittest"
	"github.com/laenen-ai/audit/internal/domain"
	"github.com/laenen-ai/audit/internal/migrate"
	"github.com/laenen-ai/audit/internal/pglog"
	"github.com/laenen-ai/audit/internal/testdb"
)

// quietLogger discards what Open reports. Most tests here run as the
// container's superuser, which is exactly the condition Open shouts about,
// and a test's output should be about the test. The shouting itself has its
// own test: TestOpen_ReportsLoudlyWhenPrivilegeSeparationIsAbsent.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// chainFor returns a chain identifier unique to t, so that two tests sharing
// one database — which they do not here, but which a future harness change
// could make true — still cannot see each other's entries.
func chainFor(t *testing.T) domain.ChainID {
	t.Helper()

	id, err := domain.NewEventID(domain.SystemClock{})
	if err != nil {
		t.Fatalf("mint a chain id: %v", err)
	}
	return domain.ChainID{Tenant: domain.TenantID("tenant-" + string(id)), Pool: "pool-main"}
}

// openLog opens a log on pool for chain, as the application role, failing
// the test rather than returning an error.
func openLog(ctx context.Context, t *testing.T, pool *pgxpool.Pool, chain domain.ChainID) audit.Log {
	t.Helper()

	log, err := pglog.Open(ctx, pglog.Config{
		DB:      pool,
		Chain:   chain,
		AppRole: testdb.AppRole,
		Logger:  quietLogger(),
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return log
}

// TestPostgres_PassesLogSuite is the test of whether the port's shape was
// right: the conformance suite, unchanged, against a real database.
//
// The factory starts a fresh isolated database per subtest, which is what
// the suite's contract requires — each subtest is handed an empty log — and
// is why this is the slowest test in the module. It opens the log with
// AppRole set, so every assertion in the suite is made by the application
// role under row-level security, not by the owner: the suite therefore also
// proves the role has exactly enough privilege to do everything the port
// promises.
func TestPostgres_PassesLogSuite(t *testing.T) {
	audittest.RunLogSuite(t, func(t *testing.T) audit.Log {
		t.Helper()
		db := testdb.Start(t)
		return openLog(context.Background(), t, db.Pool(), chainFor(t))
	})
}

// The suite covers the contract. What follows is what the suite cannot
// express, because it is about this database rather than about any
// append-only store.

// A chain serializes writes by construction, and the head row lock is what
// makes that true under real contention rather than under a process-local
// mutex. The generic suite has a concurrency subtest; this one is the same
// property under separate connections, separate transactions, and Postgres
// row locks, which is a different mechanism entirely.
func TestPostgres_ConcurrentAppendsToOneChainProduceOneWellOrderedChain(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t)
	ctx := context.Background()
	chain := chainFor(t)
	log := openLog(ctx, t, db.Pool(), chain)

	const (
		workers          = 8
		appendsPerWorker = 12
		total            = workers * appendsPerWorker
	)

	var wg sync.WaitGroup
	errs := make([]error, workers)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range appendsPerWorker {
				_, err := log.Append(ctx, audit.Record{
					Actor:   audit.ActorID(fmt.Sprintf("worker-%d", w)),
					Subject: audit.SubjectRef{Kind: "document", ID: fmt.Sprintf("doc-%d-%d", w, i)},
					Action:  "content.read",
					Outcome: "allowed",
				})
				if err != nil {
					errs[w] = fmt.Errorf("worker %d append %d: %w", w, i, err)
					return
				}
			}
		}()
	}
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			t.Fatalf("concurrent append failed: %v", err)
		}
	}

	head, err := audit.Verify(ctx, log, audit.VerifyOptions{PageSize: 10})
	if err != nil {
		t.Fatalf("Verify after %d concurrent appends: %v", total, err)
	}
	if head.Sequence != total {
		t.Fatalf("head sequence = %d after %d concurrent appends, want %d", head.Sequence, total, total)
	}

	// Every submitted record present exactly once: no append lost to a
	// rolled-back transaction, none applied twice by a retry.
	var distinctSubjects, rowCount int
	err = db.Pool().QueryRow(ctx, `
		SELECT count(DISTINCT subject_id), count(*) FROM audit.event
		WHERE tenant_id = $1 AND pool_id = $2
	`, string(chain.Tenant), string(chain.Pool)).Scan(&distinctSubjects, &rowCount)
	if err != nil {
		t.Fatalf("count stored entries: %v", err)
	}
	if rowCount != total || distinctSubjects != total {
		t.Fatalf("stored %d rows with %d distinct subjects, want %d of each", rowCount, distinctSubjects, total)
	}
}

// The chain is per (tenant, pool) precisely so that one tenant's append rate
// is not another tenant's problem. A single deployment-wide chain would be a
// single lock, and this test is the difference: an append holding chain A's
// head lock must not delay an append to chain B at all.
//
// It is asserted with a lock_timeout rather than with wall-clock timing,
// which makes it a statement about the lock rather than about how fast the
// machine is. Chain A's head is locked by an open transaction; chain B's
// append is then given a 2-second lock timeout and must succeed, while chain
// A's append under the same timeout must fail — the second half being what
// makes the first half meaningful.
func TestPostgres_AppendsToDifferentChainsDoNotSerialize(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t)
	ctx := context.Background()

	tenant := chainFor(t).Tenant
	chainA := domain.ChainID{Tenant: tenant, Pool: "pool-a"}
	chainB := domain.ChainID{Tenant: tenant, Pool: "pool-b"}

	logA := openLog(ctx, t, db.Pool(), chainA)
	logB := openLog(ctx, t, db.Pool(), chainB)

	// Both chains need a head row before one can be locked while the other
	// is written, so that the test is about the row lock and not about two
	// appenders racing to create the same row.
	if _, err := logA.Append(ctx, testRecord()); err != nil {
		t.Fatalf("seed chain A: %v", err)
	}
	if _, err := logB.Append(ctx, testRecord()); err != nil {
		t.Fatalf("seed chain B: %v", err)
	}

	// Hold chain A's head row on a connection of our own, uncommitted.
	holder, err := db.Pool().Begin(ctx)
	if err != nil {
		t.Fatalf("begin the holding transaction: %v", err)
	}
	defer func() { _ = holder.Rollback(ctx) }()

	var locked int64
	err = holder.QueryRow(ctx,
		`SELECT sequence FROM audit.chain_head WHERE tenant_id = $1 AND pool_id = $2 FOR UPDATE`,
		string(chainA.Tenant), string(chainA.Pool),
	).Scan(&locked)
	if err != nil {
		t.Fatalf("lock chain A's head: %v", err)
	}

	// Chain B is untouched by that lock.
	appendWithLockTimeout(ctx, t, db.Pool(), chainB, func(err error) {
		if err != nil {
			t.Fatalf("appending to chain B while chain A's head is locked: %v\n"+
				"appends to different chains must not serialize against each other", err)
		}
	})

	// And chain A genuinely is blocked, which is what makes the assertion
	// above a result rather than a coincidence.
	appendWithLockTimeout(ctx, t, db.Pool(), chainA, func(err error) {
		if err == nil {
			t.Fatal("appending to chain A succeeded while its own head row was locked elsewhere: " +
				"the append is not taking the head lock, so nothing serializes appends to one chain")
		}
		// The adapter deliberately does not wrap the driver error — it maps
		// a SQLSTATE onto a sentinel and drops the database's message text,
		// because that text can carry row values and one of the columns
		// here is an opaque detail payload. So the assertion is on the
		// sentinel and on the SQLSTATE the adapter chose to surface.
		if !errors.Is(err, domain.ErrUnavailable) {
			t.Fatalf("appending to chain A failed with %v, want ErrUnavailable", err)
		}
		if !strings.Contains(err.Error(), "55P03") {
			t.Fatalf("appending to chain A failed with %v, want it to name the lock_not_available SQLSTATE 55P03", err)
		}
	})
}

// appendWithLockTimeout appends to chain inside a transaction with a short
// lock_timeout, and hands the outcome to check. The log is enlisted in that
// transaction, which is how the timeout reaches the statement the adapter
// runs: a timeout set on our transaction applies to every lock taken in it,
// including the adapter's.
func appendWithLockTimeout(ctx context.Context, t *testing.T, pool *pgxpool.Pool, chain domain.ChainID, check func(error)) {
	t.Helper()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout = '2s'"); err != nil {
		t.Fatalf("set lock_timeout: %v", err)
	}

	log, err := pglog.Open(ctx, pglog.Config{DB: pool, Chain: chain, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	_, appendErr := log.Append(pglog.WithTx(ctx, tx), testRecord())
	check(appendErr)
}

// An append that joins the caller's transaction commits with the thing it
// audits, or with nothing. Both halves are asserted, because only the
// rollback half distinguishes a real enlistment from an append that happened
// to work.
func TestPostgres_AppendJoinsACallerSuppliedTransaction(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t)
	ctx := context.Background()

	t.Run("commit", func(t *testing.T) {
		log := openLog(ctx, t, db.Pool(), chainFor(t))

		tx, err := db.Pool().Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()

		txCtx := pglog.WithTx(ctx, tx)
		appended, err := log.Append(txCtx, testRecord())
		if err != nil {
			t.Fatalf("enlisted Append: %v", err)
		}

		// Visible inside the transaction that wrote it, and not outside it.
		inside, err := log.Entries(txCtx, domain.FirstSequence, 10)
		if err != nil {
			t.Fatalf("read inside the transaction: %v", err)
		}
		if len(inside) != 1 {
			t.Fatalf("read %d entries inside the transaction, want 1", len(inside))
		}
		outside, err := log.Head(ctx)
		if err != nil {
			t.Fatalf("Head outside the transaction: %v", err)
		}
		if !outside.IsZero() {
			t.Fatalf("Head outside the uncommitted transaction = %s, want the zero checkpoint", outside)
		}

		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}

		head, err := log.Head(ctx)
		if err != nil {
			t.Fatalf("Head after commit: %v", err)
		}
		want := audit.Checkpoint{Sequence: appended.Event.Sequence, Digest: appended.Link.Self}
		if head != want {
			t.Fatalf("Head after commit = %s, want %s", head, want)
		}
		if _, err := audit.Verify(ctx, log, audit.VerifyOptions{}); err != nil {
			t.Fatalf("Verify after a committed enlisted append: %v", err)
		}
	})

	// This is the half that matters: an operation that rolled back must
	// leave no audit record claiming it happened, and must leave the chain
	// exactly where it was — including the head row, which is the one thing
	// in this schema an append updates rather than inserts.
	t.Run("rollback", func(t *testing.T) {
		log := openLog(ctx, t, db.Pool(), chainFor(t))

		if _, err := log.Append(ctx, testRecord()); err != nil {
			t.Fatalf("seed: %v", err)
		}
		before, err := log.Head(ctx)
		if err != nil {
			t.Fatalf("Head: %v", err)
		}

		tx, err := db.Pool().Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if _, err := log.Append(pglog.WithTx(ctx, tx), testRecord()); err != nil {
			t.Fatalf("enlisted Append: %v", err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatalf("rollback: %v", err)
		}

		after, err := log.Head(ctx)
		if err != nil {
			t.Fatalf("Head after rollback: %v", err)
		}
		if after != before {
			t.Fatalf("Head moved from %s to %s across a rolled-back transaction", before, after)
		}

		entries, err := log.Entries(ctx, domain.FirstSequence, 10)
		if err != nil {
			t.Fatalf("Entries after rollback: %v", err)
		}
		if len(entries) != 1 {
			t.Fatalf("read %d entries after a rolled-back append, want 1", len(entries))
		}

		// And the chain still verifies, and the next append continues it
		// rather than claiming the sequence the rolled-back one took.
		next, err := log.Append(ctx, testRecord())
		if err != nil {
			t.Fatalf("Append after rollback: %v", err)
		}
		if next.Event.Sequence != before.Sequence+1 {
			t.Fatalf("the append after a rollback took sequence %d, want %d: a rolled-back append consumed a sequence number",
				next.Event.Sequence, before.Sequence+1)
		}
		if _, err := audit.Verify(ctx, log, audit.VerifyOptions{}); err != nil {
			t.Fatalf("Verify after a rolled-back enlisted append: %v", err)
		}
	})
}

// A denial has no transaction, because nothing happened — and the record of
// it must survive regardless. This is the standalone path, asserted
// alongside the fact that it is durable even when the caller's surrounding
// transaction (the one that was about to do the thing, and did not) rolls
// back.
func TestPostgres_ADenialIsRecordedOutsideAnyTransaction(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t)
	ctx := context.Background()
	chain := chainFor(t)
	log := openLog(ctx, t, db.Pool(), chain)

	// The shape of the real call site: a transaction was open, the
	// authorization check denied the operation, the transaction is
	// abandoned, and the denial is audited on a context that carries no
	// transaction at all.
	tx, err := db.Pool().Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}

	denial := audit.Record{
		Actor:   "principal-1",
		Subject: audit.SubjectRef{Kind: "document", ID: "doc-secret"},
		Action:  "content.read",
		Outcome: "denied",
		Detail:  []byte(`{"rule":"no-such-grant"}`),
	}
	appended, err := log.Append(ctx, denial)
	if err != nil {
		t.Fatalf("Append a denial: %v", err)
	}

	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback the abandoned transaction: %v", err)
	}

	// The denial is still there, on a connection that knows nothing about
	// either transaction.
	fresh := openLog(ctx, t, db.Pool(), chain)
	head, err := fresh.Head(ctx)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	want := audit.Checkpoint{Sequence: appended.Event.Sequence, Digest: appended.Link.Self}
	if head != want {
		t.Fatalf("Head = %s, want %s: a denial recorded outside a transaction did not survive", head, want)
	}

	entries, err := fresh.Entries(ctx, domain.FirstSequence, 10)
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 1 || entries[0].Event.Outcome != "denied" {
		t.Fatalf("read back %v, want exactly the denial", entries)
	}
	if _, err := audit.Verify(ctx, fresh, audit.VerifyOptions{}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// Two chains in one table must be entirely independent sequences, because
// each is its own hash chain. A shared counter would make one tenant's
// entries renumber another's.
func TestPostgres_ChainsAreIndependentSequences(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t)
	ctx := context.Background()

	first := chainFor(t)
	second := domain.ChainID{Tenant: first.Tenant, Pool: "pool-second"}
	third := chainFor(t)

	logs := map[string]audit.Log{
		"first":  openLog(ctx, t, db.Pool(), first),
		"second": openLog(ctx, t, db.Pool(), second),
		"third":  openLog(ctx, t, db.Pool(), third),
	}

	for name, log := range logs {
		for i := range 3 {
			appended, err := log.Append(ctx, testRecord())
			if err != nil {
				t.Fatalf("%s append %d: %v", name, i, err)
			}
			if want := uint64(i) + domain.FirstSequence; appended.Event.Sequence != want {
				t.Fatalf("%s append %d got sequence %d, want %d: the chains share a counter",
					name, i, appended.Event.Sequence, want)
			}
		}
	}

	// Each chain verifies on its own, and sees only its own entries.
	for name, log := range logs {
		head, err := audit.Verify(ctx, log, audit.VerifyOptions{})
		if err != nil {
			t.Fatalf("Verify %s: %v", name, err)
		}
		if head.Sequence != 3 {
			t.Fatalf("%s head sequence = %d, want 3", name, head.Sequence)
		}
	}

	// Two chains of the same tenant, one pool apart, must not share a
	// digest either: the chain identifier is in the entry digest precisely
	// so an entry cannot be moved between them.
	a, err := logs["first"].Entries(ctx, domain.FirstSequence, 1)
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	b, err := logs["second"].Entries(ctx, domain.FirstSequence, 1)
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if a[0].Link.Self == b[0].Link.Self {
		t.Fatal("the genesis entries of two chains hash identically: the digest does not commit to the chain")
	}
}

func testRecord() audit.Record {
	return audit.Record{
		Actor:   "principal-1",
		Subject: audit.SubjectRef{Kind: "document", ID: "doc-1"},
		Action:  "content.read",
		Outcome: "allowed",
	}
}

func TestOpen_RejectsAnUnusableConfiguration(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t)
	ctx := context.Background()
	valid := chainFor(t)

	cases := map[string]pglog.Config{
		"no_db":              {Chain: valid},
		"no_chain":           {DB: db.Pool()},
		"chain_without_pool": {DB: db.Pool(), Chain: domain.ChainID{Tenant: "t"}},
		"chain_without_tenant": {
			DB: db.Pool(), Chain: domain.ChainID{Pool: "p"},
		},
		"app_role_is_not_an_identifier": {
			DB: db.Pool(), Chain: valid, AppRole: "role; DROP SCHEMA audit CASCADE",
		},
		"app_role_does_not_exist": {
			DB: db.Pool(), Chain: valid, AppRole: "no_such_role_here",
		},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			cfg.Logger = quietLogger()
			if _, err := pglog.Open(ctx, cfg); !errors.Is(err, domain.ErrInvalidConfig) {
				t.Fatalf("Open error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

// Opening against a database that was never migrated must say so, rather
// than failing later inside the first append with a SQLSTATE.
func TestOpen_AgainstAnUnmigratedDatabaseSaysSo(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t, testdb.WithMigrator(testdb.NoMigrations))

	_, err := pglog.Open(context.Background(), pglog.Config{
		DB:     db.Pool(),
		Chain:  chainFor(t),
		Logger: quietLogger(),
	})
	if !errors.Is(err, domain.ErrInvalidConfig) {
		t.Fatalf("Open against an unmigrated database error = %v, want ErrInvalidConfig", err)
	}
	if !strings.Contains(err.Error(), "migrate.Up") {
		t.Fatalf("Open error = %v, want it to point at migrate.Up", err)
	}
}

// The clock is injected, and the entry's timestamp must be exactly the
// canonical form of what the clock returned — before and after a storage
// round trip. A timestamp that survived in memory and not through the
// database would report every persisted entry as tampered, which is the
// worst possible way for a precision mismatch to present itself.
func TestPostgres_TimestampSurvivesTheStorageRoundTripExactly(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t)
	ctx := context.Background()

	// A time with nanosecond precision and a non-UTC zone: both of the
	// things that could be lost.
	wall := time.Date(2026, time.October, 23, 15, 4, 5, 123456789, time.FixedZone("UTC+7", 7*3600))
	clock := domain.NewFixedClock(wall)

	log, err := pglog.Open(ctx, pglog.Config{
		DB:      db.Pool(),
		Chain:   chainFor(t),
		AppRole: testdb.AppRole,
		Clock:   clock,
		Logger:  quietLogger(),
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	appended, err := log.Append(ctx, testRecord())
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	want := domain.CanonicalTime(wall)
	if !appended.Event.Timestamp.Equal(want) {
		t.Fatalf("appended timestamp = %v, want the canonical form of the clock's %v (%v)", appended.Event.Timestamp, wall, want)
	}

	read, err := log.Entries(ctx, domain.FirstSequence, 1)
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if !read[0].Event.Timestamp.Equal(want) {
		t.Fatalf("stored timestamp read back as %v, want %v", read[0].Event.Timestamp, want)
	}
	if read[0].Event.Timestamp.Location() != time.UTC {
		t.Fatalf("stored timestamp read back in %v, want UTC", read[0].Event.Timestamp.Location())
	}
	// And the digest the chain committed to still matches, which is the
	// property the precision rule exists to protect.
	if got := read[0].ComputeDigest(); !got.Equal(read[0].Link.Self) {
		t.Fatalf("the entry read back hashes to %s, but its stored link is %s", got, read[0].Link.Self)
	}
}

// The entry the adapter wrote must be byte-identical to the entry it read
// back, field by field, because the digest commits to all of them. This is
// the round trip the suite asserts for submitted fields, extended to the
// ones the log assigns.
func TestPostgres_EveryAssignedFieldRoundTrips(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t)
	ctx := context.Background()
	chain := chainFor(t)
	log := openLog(ctx, t, db.Pool(), chain)

	appended, err := log.Append(ctx, audit.Record{
		Actor:   "principal-1",
		Subject: audit.SubjectRef{Kind: "link", ID: "lnk-7"},
		Action:  "link.redeem",
		Outcome: "allowed",
		Detail:  []byte{0x00, 0xff, 0x7f, 0x80},
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	read, err := log.Entries(ctx, domain.FirstSequence, 1)
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	got, want := read[0], appended
	if got.Event.Chain != chain {
		t.Errorf("read back chain %s, want %s", got.Event.Chain, chain)
	}
	if got.Event.ID != want.Event.ID {
		t.Errorf("read back event id %q, want %q", got.Event.ID, want.Event.ID)
	}
	if got.Event.Sequence != want.Event.Sequence {
		t.Errorf("read back sequence %d, want %d", got.Event.Sequence, want.Event.Sequence)
	}
	if got.Event.Subject != want.Event.Subject {
		t.Errorf("read back subject %+v, want %+v", got.Event.Subject, want.Event.Subject)
	}
	if !bytes.Equal(got.Event.Detail, want.Event.Detail) {
		t.Errorf("read back %d detail bytes, want %d", len(got.Event.Detail), len(want.Event.Detail))
	}
	if got.Link != want.Link {
		t.Errorf("read back link %+v, want %+v", got.Link, want.Link)
	}
	// The one assertion that subsumes the rest: the entry read back hashes
	// to the link it was stored with, so every field the digest commits to
	// survived.
	if d := got.ComputeDigest(); !d.Equal(want.Link.Self) {
		t.Errorf("the entry read back hashes to %s, want the stored %s", d, want.Link.Self)
	}
}

// The table names this adapter hardcodes are the ones internal/migrate
// creates. They are duplicated on purpose — importing migrate would pull
// goose into every consumer that opens a log — so the duplication is checked
// here rather than trusted.
func TestTableNamesMatchTheMigratedSchema(t *testing.T) {
	t.Parallel()

	if pglog.Schema != migrate.Schema {
		t.Fatalf("pglog.Schema = %q but migrate.Schema = %q: the adapter is reading a schema the migration does not create",
			pglog.Schema, migrate.Schema)
	}

	db := testdb.Start(t)
	for _, table := range []string{"event", "chain_head"} {
		var exists bool
		err := db.Pool().QueryRow(context.Background(),
			`SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = $1 AND tablename = $2)`,
			pglog.Schema, table,
		).Scan(&exists)
		if err != nil {
			t.Fatalf("look for %s.%s: %v", pglog.Schema, table, err)
		}
		if !exists {
			t.Fatalf("the adapter reads %s.%s, which the migration did not create", pglog.Schema, table)
		}
	}
}

// A canceled context must not leave a transaction open, and the adapter must
// still work afterwards. The suite asserts the error; this asserts that the
// pool was not poisoned, which is a property of this adapter's transaction
// handling rather than of the port.
func TestPostgres_ACanceledAppendLeavesNoOpenTransaction(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t)
	ctx := context.Background()
	log := openLog(ctx, t, db.Pool(), chainFor(t))

	for range 5 {
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := log.Append(canceled, testRecord()); !errors.Is(err, context.Canceled) {
			t.Fatalf("Append with a canceled context error = %v, want context.Canceled", err)
		}
	}

	if _, err := log.Append(ctx, testRecord()); err != nil {
		t.Fatalf("Append after canceled attempts: %v", err)
	}

	var idle int
	err := db.Pool().QueryRow(ctx, `
		SELECT count(*) FROM pg_stat_activity
		WHERE datname = current_database() AND state = 'idle in transaction'
	`).Scan(&idle)
	if err != nil {
		t.Fatalf("count idle transactions: %v", err)
	}
	if idle != 0 {
		t.Fatalf("%d connections are idle in transaction after canceled appends", idle)
	}
}

// Both a pool and a transaction satisfy the narrow handle the adapter
// declares, which is what lets one code path run standalone and enlisted.
var (
	_ pglog.DB = (*pgxpool.Pool)(nil)
	_ pglog.DB = (pgx.Tx)(nil)
)

// Verification pages through the chain and then asks for the head, and each
// unenlisted read is its own transaction — so a pass over a chain that is
// still being appended to can see a head that is ahead of the entries it
// walked, which Verify correctly calls a head mismatch and which is not
// tampering.
//
// Enlistment is the answer, and this is the test of it: a REPEATABLE READ
// transaction in the context makes every read in the pass come from one
// snapshot, so the verdict is about a consistent chain even while appends
// land. The unenlisted half is deliberately not asserted to fail — it is a
// race, and asserting that a race goes the bad way is how a test becomes
// flaky — but the enlisted half must never fail.
func TestPostgres_VerifyUnderConcurrentAppendsIsStableInOneSnapshot(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t)
	ctx := context.Background()
	log := openLog(ctx, t, db.Pool(), chainFor(t))

	for range 20 {
		if _, err := log.Append(ctx, testRecord()); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := log.Append(ctx, testRecord()); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		close(stop)
		<-done
	})

	for pass := range 5 {
		tx, err := db.Pool().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			t.Fatalf("begin the verification snapshot: %v", err)
		}

		head, err := audit.Verify(pglog.WithTx(ctx, tx), log, audit.VerifyOptions{PageSize: 4})
		_ = tx.Rollback(ctx)
		if err != nil {
			t.Fatalf("pass %d: Verify in a repeatable-read snapshot while appends are landing: %v\n"+
				"a verification pass enlisted in one snapshot must see a consistent chain", pass, err)
		}
		if head.Sequence < 20 {
			t.Fatalf("pass %d: verified head %s, want at least the 20 seeded entries", pass, head)
		}
	}
}
