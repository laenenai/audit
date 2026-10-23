// Package pglog is the Postgres adapter for the audit Log port: the
// durable, append-only, hash-chained store this module exists to provide.
// It passes audittest.RunLogSuite unchanged, which is the test of whether
// the port's shape survived contact with a real database, and it adds the
// guarantees a generic suite cannot express.
//
// # What Postgres enforces that Go cannot
//
// The port has no Update, no Delete and no Truncate. That is necessary and
// nowhere near sufficient: a compromised application holding DELETE on the
// history table can truncate the log, and the Go type system has nothing to
// say about it. So append-only is enforced by the database — the tables are
// owned by a role the application is not, the application role holds INSERT
// and SELECT on the history, UPDATE, DELETE and TRUNCATE are revoked from
// it, and a BEFORE UPDATE OR DELETE trigger refuses a mutation that gets
// past the privileges anyway. internal/migrate applies all of that.
//
// A deployment is free to decline privilege separation and run as the owner.
// What it must not do is believe it has a guarantee it does not have, so
// Open checks and says so: see CheckEnforcement and
// Config.RequireAppendOnlyEnforcement.
//
// # One chain per (tenant, pool), and why appends serialize
//
// A Log opened here is bound to one chain, because a chain is a
// (tenant, pool) and that is what the entry digest commits to. An append
// reads the chain's head row FOR UPDATE and writes the entry and the new
// head in one transaction, so appends to one chain are serialized — which a
// hash chain requires, since each entry commits to its predecessor — while
// appends to *different* chains touch different head rows and do not
// serialize against each other at all. That difference is the whole reason
// the chain is per tenant and pool rather than per deployment.
//
// # Joining a caller's transaction
//
// An audit record and the thing it audits should commit together or not at
// all, so Append joins a transaction the caller put in the context with
// WithTx. When there is none it opens its own, because the case that most
// needs auditing has no transaction to join: a denial means nothing
// happened, and the record of it must survive regardless.
//
// # Where the SQL is
//
// Every statement that reads or writes this module's own tables is in
// db/queries/*.sql and reaches Go through internal/pglog/gen, which sqlc
// generates against db/migrations. The reasoning that belongs to a statement
// lives beside it there, as SQL, checked against the schema at generation
// time; this package holds the transaction shape and the conversions into
// domain types, and nothing else.
//
// What is left hand-written is three statements, none of which touch this
// module's tables, and each of which is a case CONVENTIONS.md's sqlc rule
// names rather than a departure from it:
//
//   - SET LOCAL ROLE, in scopeTransaction. It takes no bound parameter, so
//     the role name has to reach Postgres as SQL text: the statement is
//     composed at run time from configuration by definition, which is the
//     one genuine exception. The value is validated as a plain identifier at
//     Open and quoted with pgx.Identifier.Sanitize at every use.
//   - The two catalog probes — canAssumeRole below, and CheckEnforcement's
//     query in enforcement.go. Both are static, and sqlc still cannot
//     generate either: they read pg_roles, pg_class and pg_trigger and call
//     pg_has_role and has_table_privilege, while sqlc resolves every
//     relation against the migrations in db/migrations, which do not contain
//     the system catalogs. Declaring fake pg_catalog tables to satisfy the
//     generator would make generated code agree with a fiction, so these
//     stay in Go, each in one place, with its reasoning on it.
package pglog

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/laenen-ai/audit/internal/domain"
	"github.com/laenen-ai/audit/internal/eventlog"
)

// Schema is this adapter's copy of the schema name internal/migrate
// creates. It is duplicated rather than imported because internal/migrate
// imports goose, and a consumer that opens a log without applying migrations
// itself should not link a migration engine.
//
// The duplication is checked rather than hoped for:
// TestTableNamesMatchTheMigratedSchema reads both and fails if they drift.
//
// eventTable is the only qualified table name still written in Go, and it is
// here for the enforcement probe alone — the probe asks the catalog about
// audit.event by name, and it is the one query in this package sqlc cannot
// generate (see the package doc comment). Every statement against this
// module's tables names them in db/queries/*.sql instead, where sqlc checks
// the name against db/migrations at generation time, which is a stronger
// guarantee than this constant ever was.
const (
	Schema     = "audit"
	eventTable = Schema + ".event"
)

// DB is the narrow database handle this adapter needs: enough to run a
// query and to open a transaction, and nothing more.
//
// It is declared here, as an interface, rather than taken as a
// *pgxpool.Pool, so that the data-plane handle a tenancy module hands out
// satisfies it without this module depending on that module. *pgxpool.Pool
// satisfies it, and so does pgx.Tx — which is what lets the same code path
// run enlisted in a caller's transaction and standalone.
type DB interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Config configures Open.
type Config struct {
	// DB is the handle the adapter reads and writes through. Required.
	DB DB

	// Chain is the chain this log appends to: one per (tenant, pool).
	// Required, and both halves must be set — unlike the in-memory
	// adapter, this one shares storage with every other chain in the
	// database, so an unnamed chain would be an unnamed row.
	Chain domain.ChainID

	// AppRole, when set, is a Postgres role the adapter switches into with
	// SET LOCAL ROLE for the duration of every transaction it opens itself.
	//
	// It is how the single-connection-string deployment model keeps
	// privilege separation: the process connects as the owner, which is the
	// identity that migrated the schema, and narrows itself to the
	// application role for runtime work. SET LOCAL is scoped to one
	// transaction, so it cannot leak across a reused pooled connection.
	//
	// It is deliberately not applied to a transaction the caller supplied.
	// That transaction's role is the caller's choice, and changing it
	// underneath them would change it for every statement they run after
	// the append returns.
	//
	// Empty means "whatever role the handle already connects as", which is
	// a valid configuration for a deployment that separates the two
	// identities with two connection strings instead.
	AppRole string

	// RequireAppendOnlyEnforcement makes Open fail with
	// domain.ErrNoAppendOnlyEnforcement when the role that will run the
	// appends could in fact update, delete or truncate the history.
	//
	// The default is false, and the default still reports the condition —
	// loudly, at error level, through Logger. False rather than true
	// because a developer running against a throwaway database as its owner
	// has a working audit log and no reason to be blocked; what they must
	// not have is the impression that the database is stopping them from
	// rewriting it. A deployment that treats the guarantee as load-bearing
	// sets this and gets a refusal to start instead of a log line.
	RequireAppendOnlyEnforcement bool

	// Logger is where Open reports what it found about enforcement. Nil
	// means slog.Default().
	Logger *slog.Logger

	// Clock supplies the instant each appended entry records. Nil means
	// domain.SystemClock.
	Clock domain.Clock
}

// pgLog is the Postgres Log adapter. It holds no chain state at all — no
// cached head, no sequence counter — which is what lets an append run inside
// a transaction that may be rolled back: there is nothing in memory for a
// rollback to invalidate.
type pgLog struct {
	db      DB
	chain   domain.ChainID
	appRole string
	clock   domain.Clock
}

var _ eventlog.Log = (*pgLog)(nil)

// Open validates cfg, checks what the database actually enforces, and
// returns a Log bound to cfg.Chain.
//
// It does not create or migrate anything: the schema is applied by
// migrate.Up, as a separate identity with privileges this one is not meant
// to have. Open against an unmigrated database fails on the enforcement
// check, which is the earliest honest place to find out.
//
// The enforcement check is the part worth knowing about. A deployment
// running as the owner role gets no protection against a compromised
// application, and the difference between "we have an append-only audit log"
// and "we have a log the application could rewrite" is exactly the kind of
// thing that is assumed rather than verified. So Open verifies it, every
// time, and either refuses to start or logs at error level with the specific
// privileges it found. See CheckEnforcement.
func Open(ctx context.Context, cfg Config) (eventlog.Log, error) {
	if cfg.DB == nil {
		return nil, fmt.Errorf("%w: pglog: DB is required", domain.ErrInvalidConfig)
	}
	if err := cfg.Chain.Validate(); err != nil {
		return nil, fmt.Errorf("%w: pglog: Chain is not usable: %w", domain.ErrInvalidConfig, err)
	}
	if cfg.AppRole != "" && !isPlainIdentifier(cfg.AppRole) {
		return nil, fmt.Errorf("%w: pglog: AppRole %q is not a plain identifier: letters, digits and underscore, not starting with a digit", domain.ErrInvalidConfig, cfg.AppRole)
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	clock := cfg.Clock
	if clock == nil {
		clock = domain.SystemClock{}
	}

	if cfg.AppRole != "" {
		member, err := canAssumeRole(ctx, cfg.DB, cfg.AppRole)
		if err != nil {
			return nil, err
		}
		if !member {
			return nil, fmt.Errorf("%w: pglog: the connected role cannot SET ROLE to AppRole %q: grant it membership, or leave AppRole empty and connect as the application role directly",
				domain.ErrInvalidConfig, cfg.AppRole)
		}
	}

	enforcement, err := CheckEnforcement(ctx, cfg.DB, cfg.AppRole)
	if err != nil {
		return nil, err
	}
	if err := enforcement.report(ctx, logger, cfg.RequireAppendOnlyEnforcement); err != nil {
		return nil, err
	}

	return &pgLog{
		db:      cfg.DB,
		chain:   cfg.Chain,
		appRole: cfg.AppRole,
		clock:   clock,
	}, nil
}

// txKey is the context key WithTx stores a transaction under. It is an
// unexported empty struct type, so nothing outside this package can put a
// value under it or read one out by accident.
type txKey struct{}

// WithTx returns a context carrying tx, so that an Append made with it joins
// the caller's transaction rather than committing on its own. The audit
// record and the thing it audits then commit together or not at all —
// otherwise the system produces audited-but-not-done and done-but-not-audited
// pairs under failure, and the second of those is the failure mode the log
// exists to prevent.
//
// The honest cost of a context-carried transaction is that enlistment is
// invisible to the type system: a caller who forgets this gets a
// correct-looking append that commits independently. It is still the right
// mechanism here, because the alternative — a WithTx method on the port —
// would put a database handle in the signature of a port that an in-memory
// adapter also implements.
//
// A denial must be audited outside any transaction, because there is no
// transaction: nothing happened, and the record has to survive regardless.
// That is simply an Append with a context this was never called on.
func WithTx(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, txKey{}, tx)
}

// txFromContext returns the transaction a caller enlisted, if any.
func txFromContext(ctx context.Context) pgx.Tx {
	tx, _ := ctx.Value(txKey{}).(pgx.Tx)
	return tx
}

// canAssumeRole reports whether the connected role may SET ROLE to role.
//
// It is one of the two catalog probes this package keeps in Go rather than
// in db/queries: sqlc has no pg_roles to resolve it against. See the package
// doc comment.
func canAssumeRole(ctx context.Context, db DB, role string) (bool, error) {
	var ok bool
	err := db.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname = $1) AND pg_has_role(current_user, $1, 'MEMBER')`,
		role,
	).Scan(&ok)
	if err != nil {
		return false, mapErr("check role membership", err)
	}
	return ok, nil
}

// mapErr maps a pgx or pgconn error onto this module's taxonomy.
//
// It never includes the database's own message text, and that is a security
// rule rather than tidiness. Postgres echoes offending values into some of
// its messages, one of the columns here holds an event's opaque detail
// payload, and an error string is one of the few things from a failed
// operation that reliably ends up in a log file someone else can read. What
// a caller gets instead is the operation, a sentinel, and the five-character
// SQLSTATE — enough for an operator to look up what Postgres objected to,
// and incapable of carrying a payload. The suite's NoEventDetailLeaksInErrors
// subtest is this rule as a test.
//
// Four conditions are "reachable in principle, just not now", and therefore
// domain.ErrUnavailable: an unreachable database, a serialization failure, a
// detected deadlock, and a lock that could not be taken within the session's
// lock_timeout. The last three are worth a retry precisely because an append
// serializes on a head row, so contention is the normal cost of the design
// rather than a sign that anything is wrong.
func mapErr(op string, err error) error {
	if err == nil {
		return nil
	}

	// A context that was already done is the caller's own condition, and it
	// must stay matchable with errors.Is(err, context.Canceled) rather than
	// being flattened into a storage error.
	if ctxErr := contextCause(err); ctxErr != nil {
		return fmt.Errorf("audit: %s: %w", op, ctxErr)
	}

	var connectErr *pgconn.ConnectError
	if errors.As(err, &connectErr) {
		return fmt.Errorf("%w: audit: %s: could not reach the database", domain.ErrUnavailable, op)
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "40001", "40P01", "55P03": // serialization_failure, deadlock_detected, lock_not_available
			return fmt.Errorf("%w: audit: %s: postgres asked for a retry (SQLSTATE %s)", domain.ErrUnavailable, op, pgErr.Code)
		case "42501": // insufficient_privilege
			return fmt.Errorf("%w: audit: %s: refused by the database (SQLSTATE %s): the audit history is append-only and this role may only insert and read",
				domain.ErrStorage, op, pgErr.Code)
		default:
			return fmt.Errorf("%w: audit: %s: refused by the database (SQLSTATE %s)", domain.ErrStorage, op, pgErr.Code)
		}
	}

	return fmt.Errorf("%w: audit: %s", domain.ErrStorage, op)
}

// contextCause returns the context error in err's chain, if any, so that a
// cancellation stays matchable as one.
func contextCause(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	default:
		return nil
	}
}

// isPlainIdentifier reports whether s is safe to use as a SQL identifier:
// ASCII letters, digits and underscore, not starting with a digit, not
// empty. It is the same gate internal/migrate applies to the same
// configuration value, duplicated for the same reason the table names are
// (see Schema): to keep goose out of this package's import graph.
//
// Every use also goes through pgx.Identifier.Sanitize, which quotes and
// escapes. This is the second of two reasons, applied because SET LOCAL ROLE
// cannot take a bound parameter, so the role name is the one value in this
// package that has to reach Postgres as SQL text.
func isPlainIdentifier(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case c >= '0' && c <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return len(s) > 0
}
