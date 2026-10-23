// This file answers one question at startup: is append-only actually
// enforced by Postgres for the role that will be running the appends, or is
// it only enforced by a Go interface that happens not to have a Delete
// method?
//
// The question matters because the two are indistinguishable from inside the
// application and very different from outside it. A deployment that migrated
// and then ran as the owner role has an audit log it can rewrite at will,
// and nothing about its behaviour says so. Leaving that to be assumed is how
// a tamper-evident log quietly becomes an ordinary table with a hash column.

package pglog

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/laenenai/audit/internal/domain"
)

// Enforcement is what the database actually enforces about append-only, for
// one role, at one moment. It is a report rather than a boolean because the
// reasons are what an operator needs: "not enforced" is not actionable,
// "this role is a member of a superuser role" is.
type Enforcement struct {
	// Role is the role whose privileges were checked: Config.AppRole when
	// one is configured, otherwise the role the handle connects as.
	Role string

	// AppendOnly reports whether the database would stop this role
	// rewriting the history. It is true only when the role is not a
	// superuser, does not bypass row-level security, cannot reach the
	// tables' owner, and holds none of UPDATE, DELETE or TRUNCATE on the
	// history table.
	AppendOnly bool

	// Superuser reports whether the role is, or can reach, a superuser. A
	// superuser bypasses privilege checks and row security unconditionally,
	// so nothing below it matters when this is true.
	Superuser bool
	// BypassRLS reports whether the role is, or can reach, a role with
	// BYPASSRLS, which makes every policy decorative.
	BypassRLS bool
	// OwnsHistory reports whether the role is, or can reach, the owner of
	// the history table. An owner can grant itself anything, so owning the
	// table is equivalent to holding every privilege on it.
	OwnsHistory bool

	// CanUpdate, CanDelete and CanTruncate report the privileges the role
	// holds on the history table — the three the migration revokes.
	CanUpdate   bool
	CanDelete   bool
	CanTruncate bool

	// TriggerPresent reports whether the BEFORE UPDATE OR DELETE trigger is
	// in place. It is defence in depth rather than the mechanism, so its
	// absence does not by itself make AppendOnly false — but a deployment
	// missing it has lost the layer that catches a privilege granted by
	// mistake.
	TriggerPresent bool
	// RowSecurityForced reports whether the history table has row-level
	// security both enabled and FORCEd. Without FORCE, the policy does not
	// apply to the table's owner, so it protects nothing in exactly the
	// deployment that needs it most.
	RowSecurityForced bool

	// Findings is the human-readable list of reasons AppendOnly is false,
	// or of weaknesses found even when it is true. Empty means the
	// deployment is in the shape this module is designed for.
	Findings []string
}

// CheckEnforcement reads what the database enforces for role — or for the
// role the handle connects as, when role is empty.
//
// It is exported because the answer is worth asking outside Open: a
// deployment's own health check, or a test that wants to assert the
// migration's revoke actually bites, should be able to ask the same question
// the adapter asks rather than reimplement it.
//
// Every check accounts for role membership rather than only direct
// attributes, through pg_has_role and has_table_privilege. A role that is a
// member of a superuser role is a superuser for this purpose, and a role
// that inherits UPDATE from a group holds UPDATE; a check that read
// pg_roles.rolsuper alone would report a deployment as safe because the
// dangerous privilege arrived one indirection away.
func CheckEnforcement(ctx context.Context, db DB, role string) (Enforcement, error) {
	if db == nil {
		return Enforcement{}, fmt.Errorf("%w: pglog: DB is required", domain.ErrInvalidConfig)
	}

	e := Enforcement{Role: role}
	err := db.QueryRow(ctx, `
		WITH subject AS (
			SELECT coalesce(nullif($1, ''), current_user) AS name
		)
		SELECT
			s.name,
			EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolsuper     AND pg_has_role(s.name, r.oid, 'USAGE')),
			EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolbypassrls AND pg_has_role(s.name, r.oid, 'USAGE')),
			pg_has_role(s.name, c.relowner, 'USAGE'),
			has_table_privilege(s.name, c.oid, 'UPDATE'),
			has_table_privilege(s.name, c.oid, 'DELETE'),
			has_table_privilege(s.name, c.oid, 'TRUNCATE'),
			EXISTS (
				SELECT 1 FROM pg_trigger t
				WHERE t.tgrelid = c.oid AND NOT t.tgisinternal
				  AND t.tgname = 'reject_history_mutation'
			),
			c.relrowsecurity AND c.relforcerowsecurity
		FROM subject s, pg_class c
		WHERE c.oid = $2::regclass
	`, role, eventTable).Scan(
		&e.Role,
		&e.Superuser,
		&e.BypassRLS,
		&e.OwnsHistory,
		&e.CanUpdate,
		&e.CanDelete,
		&e.CanTruncate,
		&e.TriggerPresent,
		&e.RowSecurityForced,
	)
	if err != nil {
		// The most likely cause by far is that the schema has not been
		// migrated, so the table in the predicate does not exist. That is a
		// deployment-ordering mistake rather than a transient fault, and
		// saying which one it is here saves an operator reading a SQLSTATE.
		return Enforcement{}, fmt.Errorf("%w: pglog: cannot read what the database enforces on %s: has migrate.Up been run against this database? (%w)",
			domain.ErrInvalidConfig, eventTable, mapErr("check enforcement", err))
	}

	e.Findings = e.findings()
	e.AppendOnly = !e.Superuser && !e.BypassRLS && !e.OwnsHistory &&
		!e.CanUpdate && !e.CanDelete && !e.CanTruncate
	return e, nil
}

// findings renders the reasons, in the order they matter: the ones that make
// everything else irrelevant first.
func (e Enforcement) findings() []string {
	var out []string

	if e.Superuser {
		out = append(out, "the role is, or is a member of, a superuser role, which bypasses every privilege check and all row security unconditionally")
	}
	if e.BypassRLS {
		out = append(out, "the role can reach a role with BYPASSRLS, so the tenant isolation policies do not apply to it")
	}
	if e.OwnsHistory {
		out = append(out, "the role can reach the owner of "+eventTable+", and an owner can grant itself any privilege on its own table")
	}
	if e.CanUpdate {
		out = append(out, "the role holds UPDATE on "+eventTable+", so it can rewrite history")
	}
	if e.CanDelete {
		out = append(out, "the role holds DELETE on "+eventTable+", so it can remove entries")
	}
	if e.CanTruncate {
		out = append(out, "the role holds TRUNCATE on "+eventTable+", so it can discard the whole log")
	}
	if !e.TriggerPresent {
		out = append(out, "the BEFORE UPDATE OR DELETE trigger on "+eventTable+" is missing, so the defence-in-depth layer behind the privileges is absent")
	}
	if !e.RowSecurityForced {
		out = append(out, "row-level security on "+eventTable+" is not both enabled and FORCEd, so its tenant isolation policy does not bind the table's owner")
	}
	return out
}

// report logs what was found and, when required, refuses to go on.
//
// The log line is at error level deliberately, and that is a judgement worth
// defending: this is not an error in the run, nothing has failed, and
// warning level is where such a message would normally go. But the whole
// point of the check is that the condition is invisible otherwise and
// permanent until someone acts, and a warning in a deployment that emits
// warnings routinely is indistinguishable from noise. A deployment that has
// decided to run without privilege separation can set
// RequireAppendOnlyEnforcement to false — which it is by default — and
// silence this by fixing it, which is the only kind of silencing worth
// offering.
func (e Enforcement) report(ctx context.Context, logger *slog.Logger, required bool) error {
	if e.AppendOnly && len(e.Findings) == 0 {
		logger.DebugContext(ctx, "audit: postgres enforces append-only on the history table",
			slog.String("role", e.Role),
			slog.String("table", eventTable),
		)
		return nil
	}

	if !e.AppendOnly && required {
		return fmt.Errorf("%w: pglog: role %q could rewrite %s: %s",
			domain.ErrNoAppendOnlyEnforcement, e.Role, eventTable, strings.Join(e.Findings, "; "))
	}

	level := slog.LevelError
	message := "audit: APPEND-ONLY IS NOT ENFORCED BY THE DATABASE: this deployment's audit log can be rewritten by the application role"
	if e.AppendOnly {
		// The privileges are right but a layer behind them is missing. Still
		// worth saying out loud, but it is not the headline condition.
		level = slog.LevelWarn
		message = "audit: append-only is enforced by privileges, but a defence-in-depth layer is missing"
	}

	logger.Log(ctx, level, message,
		slog.String("role", e.Role),
		slog.String("table", eventTable),
		slog.Bool("append_only_enforced", e.AppendOnly),
		slog.Any("findings", e.Findings),
		slog.String("remedy", "migrate as an owner role and run the application as a separate role (pglog.Config.AppRole, or a second connection string); set pglog.Config.RequireAppendOnlyEnforcement to make this fatal"),
	)
	return nil
}
