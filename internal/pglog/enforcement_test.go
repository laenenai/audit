package pglog_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/laenen-ai/audit"
	"github.com/laenen-ai/audit/internal/domain"
	"github.com/laenen-ai/audit/internal/migrate"
	"github.com/laenen-ai/audit/internal/pglog"
	"github.com/laenen-ai/audit/internal/testdb"
)

// asAppRole runs fn inside a transaction that has switched into the
// application role and set the chain's tenant, which is how a real
// deployment's runtime statements execute.
//
// Switching roles explicitly is the whole point. The harness connects as the
// container's superuser, and a superuser bypasses privilege checks and row
// security unconditionally — so a test that issued an UPDATE on the pool
// directly would succeed and prove nothing at all. SET LOCAL ROLE is what
// puts the assertion on the privileges the migration actually granted.
func asAppRole(ctx context.Context, t *testing.T, pool *pgxpool.Pool, chain domain.ChainID, fn func(tx pgx.Tx)) {
	t.Helper()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{testdb.AppRole}.Sanitize()); err != nil {
		t.Fatalf("SET LOCAL ROLE %s: %v", testdb.AppRole, err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", string(chain.Tenant)); err != nil {
		t.Fatalf("set app.tenant_id: %v", err)
	}
	fn(tx)
}

// This is the test that the append-only claim is Postgres's and not Go's: an
// UPDATE and a DELETE issued as the application role, directly in SQL,
// bypassing this module's API entirely. The Log port having no Update method
// is irrelevant to it — a compromised application writes SQL.
//
// Both must fail with insufficient_privilege (42501), and the revoke must be
// what fails them. That last part is why the test also reads the privilege
// back: an UPDATE can fail for several reasons, and "the trigger caught it"
// would mean the mechanism is the defence-in-depth layer rather than the
// privileges.
func TestAppendOnly_UpdateAndDeleteAsTheAppRoleBothFail(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t)
	ctx := context.Background()
	chain := chainFor(t)
	log := openLog(ctx, t, db.Pool(), chain)

	appended, err := log.Append(ctx, testRecord())
	if err != nil {
		t.Fatalf("Append: %v", err)
	}

	statements := map[string]string{
		"update_a_field":        `UPDATE audit.event SET outcome = 'denied' WHERE tenant_id = $1`,
		"update_the_detail":     `UPDATE audit.event SET detail = '\x00'::bytea WHERE tenant_id = $1`,
		"update_the_link":       `UPDATE audit.event SET link_self = link_prev WHERE tenant_id = $1`,
		"delete_an_entry":       `DELETE FROM audit.event WHERE tenant_id = $1`,
		"delete_everything":     `DELETE FROM audit.event`,
		"truncate_the_history":  `TRUNCATE audit.event`,
		"delete_the_chain_head": `DELETE FROM audit.chain_head WHERE tenant_id = $1`,
	}

	for name, stmt := range statements {
		t.Run(name, func(t *testing.T) {
			asAppRole(ctx, t, db.Pool(), chain, func(tx pgx.Tx) {
				var execErr error
				if strings.Contains(stmt, "$1") {
					_, execErr = tx.Exec(ctx, stmt, string(chain.Tenant))
				} else {
					_, execErr = tx.Exec(ctx, stmt)
				}
				if execErr == nil {
					t.Fatalf("the application role was able to run %q: the audit history is not append-only", stmt)
				}

				var pgErr *pgconn.PgError
				if !errors.As(execErr, &pgErr) {
					t.Fatalf("%q failed with %v, want a Postgres error", stmt, execErr)
				}
				if pgErr.Code != "42501" {
					t.Fatalf("%q failed with SQLSTATE %s (%s), want 42501 insufficient_privilege", stmt, pgErr.Code, pgErr.Message)
				}
				// The privileges, not the trigger, are the mechanism. A
				// message from the trigger here would mean the revoke did
				// not bite and the defence-in-depth layer caught it.
				if strings.Contains(pgErr.Message, "append-only") {
					t.Fatalf("%q was refused by the trigger rather than by the revoke: %s\n"+
						"the trigger is defence in depth; the privileges are supposed to be the mechanism", stmt, pgErr.Message)
				}
			})
		})
	}

	// Nothing above changed anything, and the chain still verifies.
	entries, err := log.Entries(ctx, domain.FirstSequence, 10)
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("read %d entries after the attempted mutations, want 1", len(entries))
	}
	if !bytes.Equal(entries[0].Event.Detail, appended.Event.Detail) ||
		entries[0].Event.Outcome != appended.Event.Outcome ||
		entries[0].Link != appended.Link {
		t.Fatal("an attempted mutation changed the stored entry")
	}
	if _, err := audit.Verify(ctx, log, audit.VerifyOptions{}); err != nil {
		t.Fatalf("Verify after the attempted mutations: %v", err)
	}
}

// The trigger is the layer behind the privileges, so it has to be tested
// where the privileges are not in the way: as the owner, who holds UPDATE
// and DELETE and would otherwise succeed. This is the case that matters when
// a privilege is granted by mistake, or when a careless session runs as the
// owner.
func TestAppendOnly_TheTriggerRefusesTheOwnerToo(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t)
	ctx := context.Background()
	chain := chainFor(t)

	// Opened without AppRole, so the appends run as the owner — which is
	// exactly the deployment shape Open warns about, and the one this test
	// is about.
	log, err := pglog.Open(ctx, pglog.Config{DB: db.Pool(), Chain: chain, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := log.Append(ctx, testRecord()); err != nil {
		t.Fatalf("Append: %v", err)
	}

	// The owner really does hold the privileges, so the refusal below can
	// only be the trigger.
	var canUpdate, canDelete bool
	err = db.Pool().QueryRow(ctx, `
		SELECT has_table_privilege(current_user, 'audit.event', 'UPDATE'),
		       has_table_privilege(current_user, 'audit.event', 'DELETE')
	`).Scan(&canUpdate, &canDelete)
	if err != nil {
		t.Fatalf("read the owner's privileges: %v", err)
	}
	if !canUpdate || !canDelete {
		t.Skip("the connected role does not hold UPDATE and DELETE on audit.event, so the trigger cannot be isolated from the privileges")
	}

	for name, stmt := range map[string]string{
		"update": `UPDATE audit.event SET outcome = 'denied' WHERE tenant_id = $1`,
		"delete": `DELETE FROM audit.event WHERE tenant_id = $1`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := db.Pool().Exec(ctx, stmt, string(chain.Tenant))
			if err == nil {
				t.Fatalf("the owner was able to run %q: the BEFORE UPDATE OR DELETE trigger is not refusing it", stmt)
			}
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) {
				t.Fatalf("%q failed with %v, want a Postgres error", stmt, err)
			}
			if !strings.Contains(pgErr.Message, "append-only") {
				t.Fatalf("%q failed with %q, want the trigger's append-only refusal", stmt, pgErr.Message)
			}
		})
	}
}

// A row trigger on a partitioned table is cloned to its partitions, so a
// mutation aimed straight at a leaf partition — the obvious way to try to
// dodge a policy or a trigger on the parent — hits it as well.
func TestAppendOnly_TheTriggerAlsoCoversAMutationAimedAtALeafPartition(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t)
	ctx := context.Background()
	chain := chainFor(t)

	log, err := pglog.Open(ctx, pglog.Config{DB: db.Pool(), Chain: chain, Logger: quietLogger()})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := log.Append(ctx, testRecord()); err != nil {
		t.Fatalf("Append: %v", err)
	}

	leaf := leafPartitionHolding(ctx, t, db.Pool(), chain)

	for _, stmt := range []string{
		`UPDATE ` + leaf + ` SET outcome = 'denied'`,
		`DELETE FROM ` + leaf,
	} {
		_, err := db.Pool().Exec(ctx, stmt)
		if err == nil {
			t.Fatalf("%q succeeded: a mutation aimed at a leaf partition escaped the trigger", stmt)
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || !strings.Contains(pgErr.Message, "append-only") {
			t.Fatalf("%q failed with %v, want the trigger's append-only refusal", stmt, err)
		}
	}
}

// leafPartitionHolding returns the quoted name of the leaf partition that
// actually holds chain's rows, found from the catalog rather than computed,
// so the test does not depend on this module's own hashing being right.
func leafPartitionHolding(ctx context.Context, t *testing.T, pool *pgxpool.Pool, chain domain.ChainID) string {
	t.Helper()

	var name string
	err := pool.QueryRow(ctx, `
		SELECT c.relname
		FROM audit.event e
		JOIN pg_class c ON c.oid = e.tableoid
		WHERE e.tenant_id = $1
		LIMIT 1
	`, string(chain.Tenant)).Scan(&name)
	if err != nil {
		t.Fatalf("find the leaf partition holding the chain's rows: %v", err)
	}
	return pgx.Identifier{pglog.Schema, name}.Sanitize()
}

// Row-level security has to be fail-closed: a session with no tenant context
// sees nothing, and raises nothing. Raising would be worse than returning
// nothing, because the predicate would then have to be reached by every
// caller including ones that have no business raising.
func TestRLS_AppRoleSeesOnlyItsOwnTenantAndNothingWithoutAContext(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t)
	ctx := context.Background()

	mine := chainFor(t)
	theirs := chainFor(t)

	for _, chain := range []domain.ChainID{mine, theirs} {
		log := openLog(ctx, t, db.Pool(), chain)
		if _, err := log.Append(ctx, testRecord()); err != nil {
			t.Fatalf("seed %s: %v", chain, err)
		}
	}

	// Scoped to one tenant: exactly that tenant's rows, whatever the
	// predicate says.
	asAppRole(ctx, t, db.Pool(), mine, func(tx pgx.Tx) {
		var all, others int
		err := tx.QueryRow(ctx, `
			SELECT count(*), count(*) FILTER (WHERE tenant_id <> $1) FROM audit.event
		`, string(mine.Tenant)).Scan(&all, &others)
		if err != nil {
			t.Fatalf("count visible entries: %v", err)
		}
		if others != 0 {
			t.Fatalf("%d entries of another tenant are visible to a session scoped to %s", others, mine.Tenant)
		}
		if all != 1 {
			t.Fatalf("%d entries visible, want 1", all)
		}
	})

	// No tenant context at all: nothing visible, and no error.
	tx, err := db.Pool().Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{testdb.AppRole}.Sanitize()); err != nil {
		t.Fatalf("SET LOCAL ROLE: %v", err)
	}
	var visible int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM audit.event`).Scan(&visible); err != nil {
		t.Fatalf("a session with no tenant context must see nothing and raise nothing, but raised: %v", err)
	}
	if visible != 0 {
		t.Fatalf("%d entries are visible to a session with no tenant context", visible)
	}
}

// An enlisted append inherits the caller's tenant scoping, which the adapter
// deliberately does not override. So a caller whose transaction is scoped to
// a different tenant than the log's chain must be refused by the policy's
// WITH CHECK rather than quietly writing a row into the wrong tenant.
func TestRLS_AnEnlistedAppendCannotCrossTenants(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t)
	ctx := context.Background()

	logChain := chainFor(t)
	otherTenant := chainFor(t).Tenant

	log, err := pglog.Open(ctx, pglog.Config{
		DB:      db.Pool(),
		Chain:   logChain,
		AppRole: testdb.AppRole,
		Logger:  quietLogger(),
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	tx, err := db.Pool().Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// The caller's transaction: the application role, scoped to a tenant
	// that is not the log's.
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{testdb.AppRole}.Sanitize()); err != nil {
		t.Fatalf("SET LOCAL ROLE: %v", err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", string(otherTenant)); err != nil {
		t.Fatalf("set app.tenant_id: %v", err)
	}

	_, err = log.Append(pglog.WithTx(ctx, tx), testRecord())
	if err == nil {
		t.Fatal("an append enlisted in a transaction scoped to another tenant succeeded: " +
			"the row-level security WITH CHECK is not fail-closed")
	}
	if !errors.Is(err, domain.ErrStorage) {
		t.Fatalf("cross-tenant enlisted append error = %v, want ErrStorage", err)
	}
}

// CheckEnforcement is the mechanism behind Open's report, and it has to be
// right about both answers — a check that said "not enforced" always would
// be useless, and one that said "enforced" always would be dangerous.
func TestCheckEnforcement_DistinguishesTheOwnerFromTheAppRole(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t)
	ctx := context.Background()

	t.Run("the_app_role_is_enforced", func(t *testing.T) {
		e, err := pglog.CheckEnforcement(ctx, db.Pool(), testdb.AppRole)
		if err != nil {
			t.Fatalf("CheckEnforcement: %v", err)
		}
		if !e.AppendOnly {
			t.Fatalf("append-only is not enforced for %s: %v", testdb.AppRole, e.Findings)
		}
		if e.CanUpdate || e.CanDelete || e.CanTruncate {
			t.Fatalf("%s holds update=%v delete=%v truncate=%v on the history", testdb.AppRole, e.CanUpdate, e.CanDelete, e.CanTruncate)
		}
		if e.Superuser || e.BypassRLS || e.OwnsHistory {
			t.Fatalf("%s is superuser=%v bypassrls=%v owner=%v", testdb.AppRole, e.Superuser, e.BypassRLS, e.OwnsHistory)
		}
		if !e.TriggerPresent {
			t.Error("the append-only trigger is reported missing")
		}
		if !e.RowSecurityForced {
			t.Error("row-level security is reported as not FORCEd")
		}
		if len(e.Findings) != 0 {
			t.Errorf("findings for a correctly separated deployment: %v", e.Findings)
		}
	})

	// The harness connects as the container's superuser, which also owns the
	// tables, so this is the "no privilege separation" deployment exactly.
	t.Run("the_connected_owner_is_not", func(t *testing.T) {
		e, err := pglog.CheckEnforcement(ctx, db.Pool(), "")
		if err != nil {
			t.Fatalf("CheckEnforcement: %v", err)
		}
		if e.AppendOnly {
			t.Fatal("append-only is reported as enforced for the role that owns the tables and is a superuser")
		}
		if e.Role == "" {
			t.Error("the report does not name the role it checked")
		}
		if len(e.Findings) == 0 {
			t.Fatal("no findings were reported for a deployment with no privilege separation at all")
		}
		if !e.Superuser && !e.OwnsHistory {
			t.Errorf("neither superuser nor ownership was detected for the connecting role: %+v", e)
		}
	})
}

// The condition has to be said out loud, because it is otherwise invisible
// from inside the application and permanent until someone acts on it.
func TestOpen_ReportsLoudlyWhenPrivilegeSeparationIsAbsent(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t)
	ctx := context.Background()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// No AppRole: the appends would run as the owning superuser.
	if _, err := pglog.Open(ctx, pglog.Config{DB: db.Pool(), Chain: chainFor(t), Logger: logger}); err != nil {
		t.Fatalf("Open: %v", err)
	}

	logged := buf.String()
	if !strings.Contains(logged, "level=ERROR") {
		t.Fatalf("Open logged %q, want an ERROR-level line: a deployment with no enforcement must be told, not left to assume", logged)
	}
	for _, want := range []string{"APPEND-ONLY IS NOT ENFORCED", "findings", "remedy", "RequireAppendOnlyEnforcement"} {
		if !strings.Contains(logged, want) {
			t.Errorf("Open's report does not mention %q:\n%s", want, logged)
		}
	}
}

// And a deployment that treats the guarantee as load-bearing can have the
// condition be fatal rather than a log line.
func TestOpen_CanRefuseToStartWithoutEnforcement(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t)
	ctx := context.Background()

	_, err := pglog.Open(ctx, pglog.Config{
		DB:                           db.Pool(),
		Chain:                        chainFor(t),
		Logger:                       quietLogger(),
		RequireAppendOnlyEnforcement: true,
	})
	if !errors.Is(err, domain.ErrNoAppendOnlyEnforcement) {
		t.Fatalf("Open with RequireAppendOnlyEnforcement error = %v, want ErrNoAppendOnlyEnforcement", err)
	}

	// And with separation in place, the same configuration opens.
	log, err := pglog.Open(ctx, pglog.Config{
		DB:                           db.Pool(),
		Chain:                        chainFor(t),
		AppRole:                      testdb.AppRole,
		Logger:                       quietLogger(),
		RequireAppendOnlyEnforcement: true,
	})
	if err != nil {
		t.Fatalf("Open with RequireAppendOnlyEnforcement and an app role: %v", err)
	}
	if _, err := log.Append(ctx, testRecord()); err != nil {
		t.Fatalf("Append through a log that required enforcement: %v", err)
	}
}

// Retention is a partition drop at a checkpoint boundary, which is the only
// form of deletion a hash chain tolerates — and the point of it is that what
// remains is still verifiable, from that checkpoint as its new root.
//
// The chain is written across two months with an injected clock, the
// checkpoint is taken at the boundary, the older month's partition is
// dropped, and the remainder must verify from the checkpoint. The negative
// half is asserted too: verifying from the genesis must now fail, because
// the prefix really is gone and a verifier that accepted it would be
// accepting a hole.
func TestRetention_APartitionDropAtACheckpointBoundaryLeavesTheChainVerifiable(t *testing.T) {
	t.Parallel()

	// A window that covers both months the chain is written into, so the
	// rows land in real monthly partitions rather than in the default one.
	march := time.Date(2026, time.March, 10, 9, 0, 0, 0, time.UTC)
	april := time.Date(2026, time.April, 10, 9, 0, 0, 0, time.UTC)

	cfg := migrate.Config{
		AppRole:        testdb.AppRole,
		HashPartitions: 4,
		MonthsBehind:   0,
		MonthsAhead:    2,
		Clock:          domain.NewFixedClock(march),
	}
	db := testdb.Start(t, testdb.WithMigrateConfig(cfg))
	ctx := context.Background()
	chain := chainFor(t)

	clock := domain.NewFixedClock(march)
	log, err := pglog.Open(ctx, pglog.Config{
		DB:      db.Pool(),
		Chain:   chain,
		AppRole: testdb.AppRole,
		Clock:   clock,
		Logger:  quietLogger(),
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Three entries in March, then the checkpoint, then three in April.
	for i := range 3 {
		if _, err := log.Append(ctx, testRecord()); err != nil {
			t.Fatalf("march append %d: %v", i, err)
		}
		clock.Advance(time.Hour)
	}

	checkpoint, err := log.Head(ctx)
	if err != nil {
		t.Fatalf("Head at the retention boundary: %v", err)
	}
	if checkpoint.Sequence != 3 {
		t.Fatalf("the checkpoint is at sequence %d, want 3", checkpoint.Sequence)
	}

	clock.Advance(april.Sub(clock.Now()))
	for i := range 3 {
		if _, err := log.Append(ctx, testRecord()); err != nil {
			t.Fatalf("april append %d: %v", i, err)
		}
		clock.Advance(time.Hour)
	}

	if _, err := audit.Verify(ctx, log, audit.VerifyOptions{}); err != nil {
		t.Fatalf("Verify before the drop: %v", err)
	}

	// The entries really are in two different partitions, or the drop below
	// would prove nothing.
	marchPartition := partitionOf(ctx, t, db.Pool(), chain, 1)
	aprilPartition := partitionOf(ctx, t, db.Pool(), chain, 4)
	if marchPartition == aprilPartition {
		t.Fatalf("both months landed in %s: the range partitioning is not separating them, so this test cannot drop one", marchPartition)
	}

	// Retention: drop the whole partition. As the owner, because dropping a
	// partition is emphatically not something the application role may do.
	if _, err := db.Pool().Exec(ctx, "DROP TABLE "+marchPartition); err != nil {
		t.Fatalf("drop the partition at the checkpoint boundary: %v", err)
	}

	// From the genesis, the chain is now broken, and it must say so: the
	// prefix is gone, and a verifier that accepted the hole would be
	// accepting exactly the tampering it exists to detect.
	_, err = audit.Verify(ctx, log, audit.VerifyOptions{})
	if !errors.Is(err, audit.ErrChainBroken) {
		t.Fatalf("Verify from the genesis after a partition drop error = %v, want ErrChainBroken", err)
	}

	// From the checkpoint, it verifies.
	head, err := audit.Verify(ctx, log, audit.VerifyOptions{Root: checkpoint})
	if err != nil {
		t.Fatalf("Verify from the checkpoint %s after the partition drop: %v", checkpoint, err)
	}
	if head.Sequence != 6 {
		t.Fatalf("head after the drop = %s, want sequence 6", head)
	}

	// And appending continues the chain from where it is, so retention does
	// not stop the log working.
	next, err := log.Append(ctx, testRecord())
	if err != nil {
		t.Fatalf("Append after the partition drop: %v", err)
	}
	if next.Event.Sequence != 7 {
		t.Fatalf("the append after the drop took sequence %d, want 7", next.Event.Sequence)
	}
	if _, err := audit.Verify(ctx, log, audit.VerifyOptions{Root: checkpoint}); err != nil {
		t.Fatalf("Verify from the checkpoint after appending again: %v", err)
	}
}

// partitionOf returns the quoted name of the leaf partition holding the
// chain's entry at the given sequence, read from the catalog.
func partitionOf(ctx context.Context, t *testing.T, pool *pgxpool.Pool, chain domain.ChainID, sequence int64) string {
	t.Helper()

	var name string
	err := pool.QueryRow(ctx, `
		SELECT c.relname
		FROM audit.event e
		JOIN pg_class c ON c.oid = e.tableoid
		WHERE e.tenant_id = $1 AND e.pool_id = $2 AND e.sequence = $3
	`, string(chain.Tenant), string(chain.Pool), sequence).Scan(&name)
	if err != nil {
		t.Fatalf("find the partition holding sequence %d: %v", sequence, err)
	}
	return pgx.Identifier{pglog.Schema, name}.Sanitize()
}
