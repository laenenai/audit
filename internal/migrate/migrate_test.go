package migrate_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/laenenai/audit/internal/domain"
	"github.com/laenenai/audit/internal/migrate"
	"github.com/laenenai/audit/internal/testdb"
)

// testConfig is the configuration these tests migrate with: the harness's
// own app role, and four hash partitions rather than the production 64, so a
// per-test database is 56 tables instead of 896. The production count has
// its own test below.
func testConfig() migrate.Config {
	return migrate.Config{AppRole: testdb.AppRole, HashPartitions: 4}
}

func TestUp_AppliesEveryMigrationAndIsIdempotent(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t, testdb.WithMigrator(testdb.NoMigrations))
	ctx := context.Background()

	if err := migrate.Up(ctx, db.Pool(), testConfig()); err != nil {
		t.Fatalf("first Up: %v", err)
	}

	applied, err := migrate.Status(ctx, db.Pool())
	if err != nil {
		t.Fatalf("Status after the first Up: %v", err)
	}
	assertAllApplied(t, applied)

	// A second Up against an already-current database must apply nothing
	// new and still return nil: the two reconciliation layers run again by
	// design, so "idempotent" here means the whole of Up, not only goose.
	if err := migrate.Up(ctx, db.Pool(), testConfig()); err != nil {
		t.Fatalf("second Up: %v", err)
	}

	again, err := migrate.Status(ctx, db.Pool())
	if err != nil {
		t.Fatalf("Status after the second Up: %v", err)
	}
	if len(again) != len(applied) {
		t.Fatalf("the second Up changed the migration count: %d, want %d", len(again), len(applied))
	}
	for i := range applied {
		if !again[i].AppliedAt.Equal(applied[i].AppliedAt) {
			t.Errorf("migration %d AppliedAt moved on an idempotent second Up: %v -> %v",
				applied[i].Version, applied[i].AppliedAt, again[i].AppliedAt)
		}
	}
}

// The version table lives inside this module's own schema. That is the whole
// cross-module decision: two migration owners writing one database must not
// collide on goose's single version table, so audit's is audit.goose_db_version
// and nothing of this module's is recorded in public.
func TestUp_RecordsItsVersionsInItsOwnSchema(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t, testdb.WithMigrateConfig(testConfig()))
	ctx := context.Background()

	var inAudit int
	err := db.Pool().QueryRow(ctx, `
		SELECT count(*) FROM pg_tables
		WHERE schemaname = 'audit' AND tablename = 'goose_db_version'
	`).Scan(&inAudit)
	if err != nil {
		t.Fatalf("look for audit.goose_db_version: %v", err)
	}
	if inAudit != 1 {
		t.Fatalf("audit.goose_db_version exists %d times, want exactly 1", inAudit)
	}

	var inPublic int
	err = db.Pool().QueryRow(ctx, `
		SELECT count(*) FROM pg_tables
		WHERE schemaname = 'public' AND tablename = 'goose_db_version'
	`).Scan(&inPublic)
	if err != nil {
		t.Fatalf("look for public.goose_db_version: %v", err)
	}
	if inPublic != 0 {
		t.Fatal("this module recorded migration state in public.goose_db_version: " +
			"a consumer's own goose sequence lives there, and sharing it is the collision a schema per module exists to prevent")
	}

	// Nor anything else of this module's, outside its own schema.
	rows, err := db.Pool().Query(ctx, `
		SELECT schemaname || '.' || tablename FROM pg_tables
		WHERE schemaname NOT IN ('audit', 'pg_catalog', 'information_schema')
		ORDER BY 1
	`)
	if err != nil {
		t.Fatalf("list tables outside the audit schema: %v", err)
	}
	defer rows.Close()

	var strays []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan table name: %v", err)
		}
		strays = append(strays, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read table names: %v", err)
	}
	if len(strays) != 0 {
		t.Fatalf("migrating left tables outside schema audit: %v", strays)
	}
}

func TestUp_ConcurrentCallersDoNotDoubleApply(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t, testdb.WithMigrator(testdb.NoMigrations))
	ctx := context.Background()

	const callers = 8
	var wg sync.WaitGroup
	errs := make([]error, callers)
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = migrate.Up(ctx, db.Pool(), testConfig())
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("caller %d: Up returned %v", i, err)
		}
	}

	applied, err := migrate.Status(ctx, db.Pool())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	assertAllApplied(t, applied)

	// Belt and braces: the DDL itself ran exactly once, not merely that
	// goose's bookkeeping agrees with itself. A double-applied 00001 would
	// have failed outright (CREATE FUNCTION and CREATE POLICY have no
	// IF NOT EXISTS guard), so this also checks that no caller swallowed
	// such a failure.
	var triggers int
	err = db.Pool().QueryRow(ctx, `
		SELECT count(*) FROM pg_trigger
		WHERE tgrelid = 'audit.event'::regclass AND NOT tgisinternal
	`).Scan(&triggers)
	if err != nil {
		t.Fatalf("count triggers on audit.event: %v", err)
	}
	if triggers != 1 {
		t.Fatalf("audit.event has %d user triggers, want exactly 1", triggers)
	}

	if got := countHashPartitions(t, db.Pool()); got != 4 {
		t.Fatalf("audit.event has %d hash partitions after concurrent Up, want 4", got)
	}
}

// The partitioning strategy is the decision 00001 cannot revisit, so it is
// asserted directly rather than inferred from inserts working: hash on
// tenant_id at the top, range on recorded_at within each hash partition.
func TestUp_PartitionsHashByTenantThenRangeByTime(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t, testdb.WithMigrateConfig(testConfig()))
	ctx := context.Background()

	var strategy, key string
	err := db.Pool().QueryRow(ctx, `
		SELECT p.partstrat, pg_get_partkeydef('audit.event'::regclass)
		FROM pg_partitioned_table p
		WHERE p.partrelid = 'audit.event'::regclass
	`).Scan(&strategy, &key)
	if err != nil {
		t.Fatalf("read the partitioning of audit.event: %v", err)
	}
	if strategy != "h" {
		t.Fatalf("audit.event partition strategy = %q, want %q (hash)", strategy, "h")
	}
	if key != "HASH (tenant_id)" {
		t.Fatalf("audit.event partition key = %q, want HASH (tenant_id)", key)
	}

	if got := countHashPartitions(t, db.Pool()); got != 4 {
		t.Fatalf("audit.event has %d hash partitions, want 4", got)
	}

	for i := range 4 {
		name := "audit." + migrate.HashPartitionName(i)
		var subStrategy, subKey string
		err := db.Pool().QueryRow(ctx, `
			SELECT p.partstrat, pg_get_partkeydef($1::regclass)
			FROM pg_partitioned_table p
			WHERE p.partrelid = $1::regclass
		`, name).Scan(&subStrategy, &subKey)
		if err != nil {
			t.Fatalf("read the partitioning of %s: %v", name, err)
		}
		if subStrategy != "r" {
			t.Fatalf("%s partition strategy = %q, want %q (range)", name, subStrategy, "r")
		}
		if subKey != "RANGE (recorded_at)" {
			t.Fatalf("%s partition key = %q, want RANGE (recorded_at)", name, subKey)
		}

		// A monthly partition for this month, and a default to catch a row
		// whose month has none.
		for _, want := range []string{
			migrate.RangePartitionName(i, time.Now()),
			migrate.HashPartitionName(i) + "_default",
		} {
			var exists bool
			err := db.Pool().QueryRow(ctx,
				`SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = $1 AND relnamespace = 'audit'::regnamespace)`,
				want,
			).Scan(&exists)
			if err != nil {
				t.Fatalf("look for partition %s: %v", want, err)
			}
			if !exists {
				t.Fatalf("range partition audit.%s does not exist", want)
			}
		}
	}
}

// The modulus is fixed at creation because changing it redistributes every
// tenant's rows. A deployment that edits the number must be told, not
// quietly left with the old shape while believing it has the new one.
func TestUp_RefusesToChangeTheHashPartitionCount(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t, testdb.WithMigrateConfig(testConfig()))
	ctx := context.Background()

	changed := testConfig()
	changed.HashPartitions = 8

	err := migrate.Up(ctx, db.Pool(), changed)
	if !errors.Is(err, domain.ErrInvalidConfig) {
		t.Fatalf("Up with a changed modulus error = %v, want ErrInvalidConfig", err)
	}
	if got := countHashPartitions(t, db.Pool()); got != 4 {
		t.Fatalf("a refused Up changed the partition count to %d, want 4 untouched", got)
	}
}

// The number nobody configures is still the number that ships, so it gets a
// test of its own even though it is the slow one.
func TestUp_AppliesTheDefaultHashPartitionCount(t *testing.T) {
	t.Parallel()

	cfg := migrate.Config{AppRole: testdb.AppRole}
	db := testdb.Start(t, testdb.WithMigrateConfig(cfg))

	if got := countHashPartitions(t, db.Pool()); got != migrate.DefaultHashPartitions {
		t.Fatalf("audit.event has %d hash partitions, want the default %d", got, migrate.DefaultHashPartitions)
	}

	// 13 months of window (one behind, twelve ahead, inclusive) plus the
	// default partition, in every hash partition.
	const wantPerHash = migrate.DefaultMonthsBehind + migrate.DefaultMonthsAhead + 1 + 1
	var leaves int
	err := db.Pool().QueryRow(context.Background(), `
		SELECT count(*)
		FROM pg_inherits i
		JOIN pg_inherits h ON h.inhrelid = i.inhparent
		WHERE h.inhparent = 'audit.event'::regclass
	`).Scan(&leaves)
	if err != nil {
		t.Fatalf("count leaf partitions: %v", err)
	}
	if want := migrate.DefaultHashPartitions * wantPerHash; leaves != want {
		t.Fatalf("audit.event has %d leaf partitions, want %d (%d hash x %d range)",
			leaves, want, migrate.DefaultHashPartitions, wantPerHash)
	}
}

// Re-running Up as time moves forward is how the partition window stays
// ahead of the present, because that is the only partition maintenance a
// library-applied migration model has.
func TestUp_ExtendsTheRangeWindowOnALaterRun(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, time.March, 15, 12, 0, 0, 0, time.UTC)
	cfg := testConfig()
	cfg.MonthsAhead = 1
	cfg.MonthsBehind = 0
	cfg.Clock = domain.NewFixedClock(start)

	db := testdb.Start(t, testdb.WithMigrateConfig(cfg))
	ctx := context.Background()

	// March and April exist; May does not yet.
	assertPartitionExists(t, db.Pool(), migrate.RangePartitionName(0, start), true)
	assertPartitionExists(t, db.Pool(), migrate.RangePartitionName(0, start.AddDate(0, 1, 0)), true)
	assertPartitionExists(t, db.Pool(), migrate.RangePartitionName(0, start.AddDate(0, 2, 0)), false)

	later := testConfig()
	later.MonthsAhead = 1
	later.MonthsBehind = 0
	later.Clock = domain.NewFixedClock(start.AddDate(0, 1, 0))
	if err := migrate.Up(ctx, db.Pool(), later); err != nil {
		t.Fatalf("Up a month later: %v", err)
	}

	assertPartitionExists(t, db.Pool(), migrate.RangePartitionName(0, start.AddDate(0, 2, 0)), true)
	// And the month that rolled out of the window is still there: Up
	// extends, it never drops. Dropping is retention's decision and it has
	// to happen at a checkpoint boundary.
	assertPartitionExists(t, db.Pool(), migrate.RangePartitionName(0, start), true)
}

// Row-level security on every table, enabled and FORCEd. FORCE matters on
// its own: without it a policy shows up in pg_policies while protecting
// nothing from any query running as the table's owner.
func TestUp_EnablesAndForcesRowLevelSecurityOnEveryTable(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t, testdb.WithMigrateConfig(testConfig()))
	ctx := context.Background()

	for _, table := range []string{"event", "chain_head"} {
		var enabled, forced bool
		err := db.Pool().QueryRow(ctx,
			`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = $1::regclass`,
			"audit."+table,
		).Scan(&enabled, &forced)
		if err != nil {
			t.Fatalf("read row security flags of audit.%s: %v", table, err)
		}
		if !enabled {
			t.Fatalf("audit.%s does not have row-level security enabled", table)
		}
		if !forced {
			t.Fatalf("audit.%s does not have row-level security FORCEd, so the owner is exempt from its own policy", table)
		}

		var policies int
		err = db.Pool().QueryRow(ctx,
			`SELECT count(*) FROM pg_policies WHERE schemaname = 'audit' AND tablename = $1`,
			table,
		).Scan(&policies)
		if err != nil {
			t.Fatalf("count policies on audit.%s: %v", table, err)
		}
		if policies != 2 {
			t.Fatalf("audit.%s has %d policies, want exactly 2 "+
				"(the restrictive tenant policy and its permissive companion)", table, policies)
		}

		// The kinds, not just the count. A permissive tenant predicate is
		// OR-ed away by any policy a consumer adds, which is a
		// cross-tenant disclosure; the restriction is what filters and the
		// companion exists only so the restriction has something to AND
		// against. See TestRLS_AnAddedPermissivePolicyCannotWidenPastTheTenant.
		var tenantKind, accessKind string
		if err := db.Pool().QueryRow(ctx,
			`SELECT permissive FROM pg_policies WHERE schemaname = 'audit' AND tablename = $1
			 AND policyname = 'tenant_isolation'`, table).Scan(&tenantKind); err != nil {
			t.Fatalf("read the tenant policy's kind on audit.%s: %v", table, err)
		}
		if tenantKind != "RESTRICTIVE" {
			t.Fatalf("audit.%s's tenant policy is %s, want RESTRICTIVE", table, tenantKind)
		}
		if err := db.Pool().QueryRow(ctx,
			`SELECT permissive FROM pg_policies WHERE schemaname = 'audit' AND tablename = $1
			 AND policyname = 'tenant_access'`, table).Scan(&accessKind); err != nil {
			t.Fatalf("read the companion policy's kind on audit.%s: %v", table, err)
		}
		if accessKind != "PERMISSIVE" {
			t.Fatalf("audit.%s's companion policy is %s, want PERMISSIVE: with no permissive "+
				"policy the restrictive one denies every row", table, accessKind)
		}
	}
}

// The indexes the design asks of an audit log: principal, resource, time,
// and the link id a read receipt is looked up by — which is a subject, not a
// column of its own, because naming a link would be this module taking a
// position on what an event means.
func TestUp_CreatesTheIndexesAuditQueriesNeed(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t, testdb.WithMigrateConfig(testConfig()))
	ctx := context.Background()

	want := map[string]string{
		"event_by_actor":    "(tenant_id, actor_id, recorded_at DESC)",
		"event_by_subject":  "(tenant_id, subject_kind, subject_id, recorded_at DESC)",
		"event_by_time":     "(tenant_id, recorded_at DESC)",
		"event_by_event_id": "(tenant_id, event_id)",
	}
	for name, columns := range want {
		var def string
		err := db.Pool().QueryRow(ctx,
			`SELECT pg_get_indexdef(oid) FROM pg_class WHERE relname = $1 AND relnamespace = 'audit'::regnamespace`,
			name,
		).Scan(&def)
		if err != nil {
			t.Fatalf("read the definition of index audit.%s: %v", name, err)
		}
		if !strings.Contains(def, columns) {
			t.Fatalf("index audit.%s is %q, want it over %s", name, def, columns)
		}
	}

	// A partitioned index is propagated to partitions, including ones
	// attached later, which is what stops next year's partition coming up
	// unindexed. Each of the four indexes must have one child per leaf.
	for name := range want {
		var children int
		err := db.Pool().QueryRow(ctx,
			`SELECT count(*) FROM pg_inherits WHERE inhparent = ('audit.' || $1)::regclass`,
			name,
		).Scan(&children)
		if err != nil {
			t.Fatalf("count the children of index audit.%s: %v", name, err)
		}
		if children != 4 {
			t.Fatalf("index audit.%s has %d partition-level children, want one per hash partition (4)", name, children)
		}
	}
}

// The primary key has to carry both partition key columns, because Postgres
// requires it. That is a constraint on the design rather than a choice, so
// it is pinned: a later edit that dropped recorded_at from the key would not
// fail until someone tried to create a partitioned index, and a later edit
// that dropped pool_id would silently stop separating two chains in one
// tenant.
func TestUp_PrimaryKeyCarriesTheChainAndBothPartitionKeys(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t, testdb.WithMigrateConfig(testConfig()))

	var def string
	err := db.Pool().QueryRow(context.Background(), `
		SELECT pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conrelid = 'audit.event'::regclass AND contype = 'p'
	`).Scan(&def)
	if err != nil {
		t.Fatalf("read the primary key of audit.event: %v", err)
	}
	if want := "PRIMARY KEY (tenant_id, pool_id, sequence, recorded_at)"; def != want {
		t.Fatalf("audit.event primary key is %q, want %q", def, want)
	}
}

func TestUp_RequiresAnAppRole(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t, testdb.WithMigrator(testdb.NoMigrations))
	ctx := context.Background()

	invalid := map[string]migrate.Config{
		"missing":           {},
		"not_an_identifier": {AppRole: "audit app; DROP SCHEMA audit"},
		"leading_digit":     {AppRole: "1role"},
		"negative_window":   {AppRole: testdb.AppRole, MonthsAhead: -1},
		"zero_partitions":   {AppRole: testdb.AppRole, HashPartitions: -3},
	}
	for name, cfg := range invalid {
		t.Run(name, func(t *testing.T) {
			if err := migrate.Up(ctx, db.Pool(), cfg); !errors.Is(err, domain.ErrInvalidConfig) {
				t.Fatalf("Up error = %v, want ErrInvalidConfig", err)
			}
		})
	}

	// A rejected configuration must not have half-migrated anything.
	var schemas int
	err := db.Pool().QueryRow(ctx,
		`SELECT count(*) FROM pg_tables WHERE schemaname = 'audit'`).Scan(&schemas)
	if err != nil {
		t.Fatalf("count tables in schema audit: %v", err)
	}
	if schemas != 0 {
		t.Fatalf("a rejected configuration created %d tables in schema audit", schemas)
	}
}

func TestStatus_ReportsPendingBeforeUp(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t, testdb.WithMigrator(testdb.NoMigrations))

	applied, err := migrate.Status(context.Background(), db.Pool())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(applied) == 0 {
		t.Fatal("Status reported no migrations at all: the embedded set is empty")
	}
	for _, m := range applied {
		if m.Applied {
			t.Errorf("migration %d (%s) reported applied before Up ran", m.Version, m.Name)
		}
		if !m.AppliedAt.IsZero() {
			t.Errorf("migration %d (%s) has a non-zero AppliedAt before Up ran", m.Version, m.Name)
		}
	}
}

// An unreachable database is "reachable in principle, just not now", which
// is the one condition in this module worth retrying — so it must not arrive
// as the same sentinel as a schema that does not fit.
func TestUp_UnreachableDatabaseIsUnavailable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// A port nothing listens on, so this is a refused connection rather
	// than a hang, and it does not depend on any real server being down.
	ln, err := new(net.ListenConfig).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find an unused port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	cfg, err := pgxpool.ParseConfig(fmt.Sprintf("postgres://nobody@127.0.0.1:%d/nope?sslmode=disable", port))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	cfg.ConnConfig.ConnectTimeout = 2 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("build pool: %v", err)
	}
	defer pool.Close()

	err = migrate.Up(ctx, pool, testConfig())
	if !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("Up against an unreachable database error = %v, want ErrUnavailable", err)
	}
}

func assertAllApplied(t *testing.T, applied []migrate.Applied) {
	t.Helper()

	if len(applied) == 0 {
		t.Fatal("no migrations reported at all: the embedded set is empty")
	}
	for _, m := range applied {
		if !m.Applied {
			t.Errorf("migration %d (%s) is not applied", m.Version, m.Name)
		}
		if m.AppliedAt.IsZero() {
			t.Errorf("migration %d (%s) is applied but has a zero AppliedAt", m.Version, m.Name)
		}
	}
}

func countHashPartitions(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()

	var n int
	err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM pg_inherits WHERE inhparent = 'audit.event'::regclass`).Scan(&n)
	if err != nil {
		t.Fatalf("count hash partitions of audit.event: %v", err)
	}
	return n
}

func assertPartitionExists(t *testing.T, pool *pgxpool.Pool, name string, want bool) {
	t.Helper()

	var got bool
	err := pool.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = $1 AND relnamespace = 'audit'::regnamespace)`,
		name,
	).Scan(&got)
	if err != nil {
		t.Fatalf("look for partition audit.%s: %v", name, err)
	}
	if got != want {
		t.Fatalf("partition audit.%s exists = %v, want %v", name, got, want)
	}
}

// The privileges are the actual append-only mechanism; the trigger in
// 00001_audit.sql is defence in depth behind them. This asserts the grant
// table directly, which is the only way to see that a privilege is *absent*
// rather than merely unused — a test that only tried an UPDATE and saw it
// fail could not tell the revoke from the trigger.
func TestUp_GrantsTheAppRoleAppendAndReadAndNothingElse(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t, testdb.WithMigrateConfig(testConfig()))
	ctx := context.Background()

	type want struct {
		table      string
		privileges map[string]bool
	}
	cases := []want{
		{"audit.event", map[string]bool{
			"SELECT": true, "INSERT": true,
			"UPDATE": false, "DELETE": false, "TRUNCATE": false,
			"REFERENCES": false, "TRIGGER": false,
		}},
		// The head row is the exception that needs care: it must be
		// updatable, so it is the one writable surface. DELETE stays
		// revoked — deleting a head row would let an appender restart the
		// chain at sequence one, and a chain that can be restarted is not
		// a chain.
		{"audit.chain_head", map[string]bool{
			"SELECT": true, "INSERT": true, "UPDATE": true,
			"DELETE": false, "TRUNCATE": false,
			"REFERENCES": false, "TRIGGER": false,
		}},
	}

	for _, c := range cases {
		for privilege, expected := range c.privileges {
			var held bool
			err := db.Pool().QueryRow(ctx,
				`SELECT has_table_privilege($1, $2, $3)`, testdb.AppRole, c.table, privilege,
			).Scan(&held)
			if err != nil {
				t.Fatalf("has_table_privilege(%s, %s, %s): %v", testdb.AppRole, c.table, privilege, err)
			}
			if held != expected {
				t.Errorf("role %s holds %s on %s = %v, want %v", testdb.AppRole, privilege, c.table, held, expected)
			}
		}
	}

	// Nothing on any leaf partition, ever. Privileges on a partitioned
	// table are checked against the table the statement names, so an
	// INSERT through the parent needs none on the leaf — which lets the
	// leaves stay completely inaccessible and closes the direct-to-partition
	// path around the parent's row-security policy.
	for i := range 4 {
		leaf := "audit." + migrate.RangePartitionName(i, time.Now())
		for _, privilege := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE"} {
			var held bool
			err := db.Pool().QueryRow(ctx,
				`SELECT has_table_privilege($1, $2, $3)`, testdb.AppRole, leaf, privilege,
			).Scan(&held)
			if err != nil {
				t.Fatalf("has_table_privilege(%s, %s, %s): %v", testdb.AppRole, leaf, privilege, err)
			}
			if held {
				t.Errorf("role %s holds %s directly on leaf partition %s: a mutation aimed at the leaf would bypass the parent's policy", testdb.AppRole, privilege, leaf)
			}
		}
	}

	// And the role itself carries nothing cluster-wide that would make all
	// of the above decorative.
	var superuser, bypassRLS, canLogin bool
	err := db.Pool().QueryRow(ctx,
		`SELECT rolsuper, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname = $1`, testdb.AppRole,
	).Scan(&superuser, &bypassRLS, &canLogin)
	if err != nil {
		t.Fatalf("read role attributes of %s: %v", testdb.AppRole, err)
	}
	if superuser {
		t.Errorf("role %s is a superuser, which bypasses both privileges and row security unconditionally", testdb.AppRole)
	}
	if bypassRLS {
		t.Errorf("role %s has BYPASSRLS, which makes every policy decorative", testdb.AppRole)
	}
	if canLogin {
		t.Errorf("role %s can log in: the default deployment reaches it through SET ROLE, so it needs no login of its own", testdb.AppRole)
	}
}

// The role name is configuration precisely because the migration names it in
// its REVOKE, so a second role name must produce a second, independently
// correct set of privileges — not a no-op because goose already recorded the
// privilege step as applied.
func TestUp_ReappliesPrivilegesForAChangedAppRole(t *testing.T) {
	t.Parallel()

	db := testdb.Start(t, testdb.WithMigrateConfig(testConfig()))
	ctx := context.Background()

	second := testConfig()
	second.AppRole = "audit_app_second"
	if err := migrate.Up(ctx, db.Pool(), second); err != nil {
		t.Fatalf("Up with a second app role: %v", err)
	}

	for _, role := range []string{testdb.AppRole, second.AppRole} {
		var insert, update bool
		err := db.Pool().QueryRow(ctx,
			`SELECT has_table_privilege($1, 'audit.event', 'INSERT'), has_table_privilege($1, 'audit.event', 'UPDATE')`,
			role,
		).Scan(&insert, &update)
		if err != nil {
			t.Fatalf("read privileges of %s: %v", role, err)
		}
		if !insert {
			t.Errorf("role %s cannot INSERT into audit.event", role)
		}
		if update {
			t.Errorf("role %s can UPDATE audit.event: the revoke did not reach it", role)
		}
	}
}
