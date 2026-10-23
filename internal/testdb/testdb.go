// Package testdb is the harness every database-backed test in this module
// runs on: Start gives a test its own uniquely-named, isolated Postgres
// database, migrated fresh, so tests run in parallel with no shared state
// and nothing to truncate between them.
//
// # This is staged duplication, not divergence
//
// The shared harness belongs in `tenancy`, because tenant scoping and
// row-level security are what it exists to test. `tenancy` does not exist
// yet, and `cas/internal/testdb` is keeping its own copy until the
// post-alpha swap for the same reason. This package is the third copy of the
// same agreed pattern — same image, same per-test database, same
// TEST_DATABASE_URL override, same testing.Short() gate — and it converges
// on `tenancy`'s harness the moment that module lands. It is deliberately
// shaped to make that swap mechanical: Start's signature is the whole of the
// contract, and only the default Migrator is specific to this module.
//
// Duplicating *test* code for one release is a cost worth paying to avoid
// creating a module before a second consumer needs it. Duplicating
// production code would not be.
package testdb

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/laenen-ai/audit/internal/domain"
	"github.com/laenen-ai/audit/internal/migrate"
)

// postgresImage is the container image used when TEST_DATABASE_URL is not
// set. It is pgvector/pgvector:pg18, not stock postgres:18 — vector columns
// exist elsewhere in this system and the stock image lacks the extension, so
// a harness built on it passes locally and fails where it matters. This
// module has no vector columns of its own; matching the image is about every
// module's tests running on the same Postgres as the deployment.
const postgresImage = "pgvector/pgvector:pg18"

// AppRole is the application role name this module's tests migrate with. It
// is a fixed, test-only name rather than a per-test one because roles are
// cluster-wide and one shared container serves the whole run: a role per test
// would leave hundreds behind on a long-lived TEST_DATABASE_URL server, and
// there is nothing a test can learn from a unique role name that it cannot
// learn from a unique database.
const AppRole = "audit_app_test"

// adminConnectTimeout bounds every administrative connection Start makes: to
// create or drop a database, and to open the per-test pool.
const adminConnectTimeout = 10 * time.Second

// Migrator applies this module's schema to pool. Start calls it exactly once
// against a freshly created, empty database before handing the pool back.
// The default migrates with DefaultMigrateConfig, so every test using Start
// runs against a fully migrated database unless WithMigrator overrides it.
type Migrator func(ctx context.Context, pool *pgxpool.Pool) error

// DefaultMigrateConfig is the configuration Start migrates with.
//
// HashPartitions is 4 rather than migrate.DefaultHashPartitions (64), and
// that is a speed decision with a cost worth naming. Each hash partition
// carries one range partition per month in the window plus a default, so the
// production default is 64 x 14 = 896 tables, created in every one of these
// per-test databases. Four keeps a test database at 56 tables and the suite
// in the tens of seconds. The production default is exercised by its own
// test (TestUp_AppliesTheDefaultHashPartitionCount), so the number nobody
// configures is still the number something checks.
func DefaultMigrateConfig() migrate.Config {
	return migrate.Config{AppRole: AppRole, HashPartitions: 4}
}

// DB is an isolated database created for a single test by Start.
type DB struct {
	pool *pgxpool.Pool
	name string
}

// Pool returns the connection pool opened against this test's database. It
// connects as the container's superuser, which matters and is the reason
// several tests in this module explicitly SET LOCAL ROLE before asserting
// anything about privileges or row-level security: a superuser bypasses both
// unconditionally, so a test that did not switch roles would be proving
// nothing while appearing to pass.
func (d *DB) Pool() *pgxpool.Pool { return d.pool }

// Name returns this test database's name.
func (d *DB) Name() string { return d.name }

var (
	containerOnce sync.Once
	containerDSN  string
	containerErr  error
)

// Option configures Start.
type Option func(*options)

type options struct {
	migrator Migrator
}

// WithMigrator overrides the Migrator Start runs against the freshly created
// database. Passing one that does nothing is how a test gets a database that
// exists but is not yet migrated, which is the only way to test migrating.
func WithMigrator(m Migrator) Option {
	return func(o *options) { o.migrator = m }
}

// WithMigrateConfig runs the standard migrator with a different
// migrate.Config — the usual reason being a test that needs the production
// hash-partition count, or a clock pointed at a month in the past so it can
// create a partition and then drop it.
func WithMigrateConfig(cfg migrate.Config) Option {
	return WithMigrator(func(ctx context.Context, pool *pgxpool.Pool) error {
		return migrate.Up(ctx, pool, cfg)
	})
}

// NoMigrations is a Migrator that leaves the database untouched.
func NoMigrations(context.Context, *pgxpool.Pool) error { return nil }

// Start creates a uniquely-named Postgres database, runs the configured
// Migrator against it, and registers a t.Cleanup that closes the pool and
// drops the database. Each call gets its own database, so tests using Start
// may run in parallel without interfering; there is no shared database and
// no truncation step because there is nothing shared to reset.
//
// When TEST_DATABASE_URL is set, Start connects to that server and still
// creates a unique database on it rather than reusing a shared one.
// Otherwise it starts a pgvector/pgvector:pg18 container through
// testcontainers-go once per test binary run — not once per test — and
// shares that container across every Start in the run.
//
// Start skips the test under testing.Short(). This is the module's single
// chokepoint for that convention, so every database test inherits it without
// its author remembering a gate of their own, and -short wins even when
// TEST_DATABASE_URL is set: "no databases in the inner loop" is the rule,
// and a reachable server is not an exception to it. The skip happens before
// any container or database work, so a skipped test pays no setup cost.
func Start(t *testing.T, opts ...Option) *DB {
	t.Helper()

	if testing.Short() {
		t.Skip("testdb: skipping database-backed test in -short mode; run `mise run test-all` for the full suite")
	}

	cfg := options{migrator: func(ctx context.Context, pool *pgxpool.Pool) error {
		return migrate.Up(ctx, pool, DefaultMigrateConfig())
	}}
	for _, opt := range opts {
		opt(&cfg)
	}

	ctx := context.Background()
	serverDSN := adminDSN(ctx, t)
	dbName := newDatabaseName(t)

	adminConn, err := pgx.Connect(ctx, serverDSN)
	if err != nil {
		t.Fatalf("testdb: connect to admin database: %v", err)
	}
	defer func() { _ = adminConn.Close(ctx) }()

	if _, err := adminConn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
		t.Fatalf("testdb: create database %s: %v", dbName, err)
	}

	// The drop is registered now, immediately after the database exists,
	// rather than after the pool and migrator steps below: both of those
	// can fail via t.Fatalf, which never returns, so a Cleanup registered
	// after them would never run on that path — orphaning the database
	// permanently, which is especially damaging against a long-lived
	// TEST_DATABASE_URL server where nothing else ever drops it. The
	// closure closes over the variable rather than a snapshot, so by the
	// time it runs it sees whatever pool holds: nil if the open never got
	// that far, open if it did, and it closes it first so the drop does not
	// find the database still in use.
	var pool *pgxpool.Pool
	t.Cleanup(func() {
		if pool != nil {
			pool.Close()
		}
		dropDatabase(t, serverDSN, dbName)
	})

	testDSN, err := withDatabaseName(serverDSN, dbName)
	if err != nil {
		t.Fatalf("testdb: build dsn for database %s: %v", dbName, err)
	}

	pool, err = openPool(ctx, testDSN)
	if err != nil {
		t.Fatalf("testdb: open pool for database %s: %v", dbName, err)
	}

	if err := cfg.migrator(ctx, pool); err != nil {
		t.Fatalf("testdb: run migrator against database %s: %v", dbName, err)
	}

	return &DB{pool: pool, name: dbName}
}

// openPool opens a pool against dsn and verifies it with one ping, so a
// failure to connect is reported where it happened rather than inside the
// first test assertion.
func openPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		// The DSN here is the harness's own, built from the container's or
		// TEST_DATABASE_URL's; it is not forwarded, because pgx's parse
		// error can carry an embedded credential verbatim.
		return nil, fmt.Errorf("parse dsn")
	}
	poolCfg.ConnConfig.ConnectTimeout = adminConnectTimeout

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("build pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, adminConnectTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return pool, nil
}

// dropDatabase connects to serverDSN and drops name, forcibly disconnecting
// any session still attached — Start's pool was just closed, but pgxpool's
// close does not guarantee every socket is already torn down server-side. It
// logs rather than fails: best-effort cleanup is preferable to masking the
// test's real result.
func dropDatabase(t *testing.T, serverDSN, name string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), adminConnectTimeout)
	defer cancel()

	conn, err := pgx.Connect(ctx, serverDSN)
	if err != nil {
		t.Logf("testdb: cleanup: connect to drop database %s: %v", name, err)
		return
	}
	defer func() { _ = conn.Close(ctx) }()

	if _, err := conn.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
		t.Logf("testdb: cleanup: drop database %s: %v", name, err)
	}
}

// adminDSN returns the DSN of a Postgres server to create test databases on:
// TEST_DATABASE_URL when set, otherwise a container started once per test
// binary run through testcontainers-go.
func adminDSN(ctx context.Context, t *testing.T) string {
	t.Helper()

	if dsn := os.Getenv("TEST_DATABASE_URL"); dsn != "" {
		return dsn
	}

	containerOnce.Do(func() {
		containerDSN, containerErr = startContainer(ctx)
	})
	if containerErr != nil {
		t.Fatalf("testdb: start postgres container: %v", containerErr)
	}
	return containerDSN
}

func startContainer(ctx context.Context) (string, error) {
	const (
		user     = "postgres"
		password = "postgres"
		database = "postgres"
	)

	container, err := tcpostgres.Run(ctx, postgresImage,
		tcpostgres.WithDatabase(database),
		tcpostgres.WithUsername(user),
		tcpostgres.WithPassword(password),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		return "", fmt.Errorf("run postgres container: %w", err)
	}

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return "", fmt.Errorf("container connection string: %w", err)
	}
	return dsn, nil
}

// newDatabaseName returns a database name unique enough to run in parallel
// across the whole test binary.
//
// It uses this module's own event id, which is a ULID rendered in hex — a
// millisecond timestamp plus 80 bits of entropy, already lowercase, which
// suits Postgres folding unquoted identifiers to lowercase. Minting it with
// the module's own id generator rather than taking a dependency on a ULID
// library is the cheaper of the two, and it means the harness exercises the
// generator the adapter under test depends on.
func newDatabaseName(t *testing.T) string {
	t.Helper()

	id, err := domain.NewEventID(domain.SystemClock{})
	if err != nil {
		t.Fatalf("testdb: mint a unique database name: %v", err)
	}
	return "audittestdb_" + string(id)
}

// withDatabaseName returns dsn with its path replaced by name, so the
// returned DSN points at the newly created per-test database on the same
// server dsn names.
func withDatabaseName(dsn, name string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", fmt.Errorf("parse dsn")
	}
	u.Path = "/" + name
	return u.String(), nil
}
