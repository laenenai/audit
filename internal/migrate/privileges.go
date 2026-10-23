// This file is layer 3 of Up: the privilege separation that is the actual
// mechanism behind "append-only", as opposed to the trigger in
// 00001_audit.sql, which is defence in depth behind it.
//
// The claim being enforced is narrow and worth stating precisely. The Log
// port has no Update, no Delete and no Truncate — necessary, and nowhere
// near sufficient, because a compromised application holding DELETE on the
// history table can truncate the log and the Go type system has nothing to
// say about it. So the tables are owned by a role the application is not,
// the application role holds INSERT and SELECT on the history and nothing
// else, and UPDATE, DELETE and TRUNCATE are revoked from it explicitly.
//
// The head row is the exception that needs care: it *must* be updatable, so
// it is the one writable surface in the schema. It holds no history, so
// rewriting it cannot rewrite the chain — only make verification fail, which
// is the log doing its job.

package migrate

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/laenenai/audit/internal/domain"
)

// reconcilePrivileges creates the application role if it is missing and then
// asserts exactly the privileges it should hold, every time Up runs.
//
// Asserting rather than migrating is the decision explained in the package
// doc comment: a versioned migration would record itself as applied, and a
// deployment that later renamed its application role would come up with no
// privilege separation while goose reported everything in order. GRANT and
// REVOKE are idempotent, so there is nothing to gain from running them once.
func reconcilePrivileges(ctx context.Context, tx pgx.Tx, cfg resolvedConfig) error {
	if err := ensureRole(ctx, tx, cfg.appRole); err != nil {
		return err
	}

	role := pgx.Identifier{cfg.appRole}.Sanitize()
	for _, stmt := range privilegeStatements(role) {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("%w: migrate: apply privileges for role %s: %w", domain.ErrInvalidConfig, cfg.appRole, err)
		}
	}
	return nil
}

// privilegeStatements is the complete, ordered set of grants and revokes
// that define what the application role may do in this schema. It is one
// list, in one place, so that "what can the application do to the audit log"
// is answerable by reading eleven lines rather than by auditing a schema.
//
// Note what is *not* granted: nothing on any partition of audit.event, and
// nothing on audit.goose_db_version. Privileges on a partitioned table are
// checked against the table the statement names, so an INSERT through the
// parent needs none on the leaf it routes to — which means the leaves can be
// left completely inaccessible, and a mutation aimed straight at a leaf to
// dodge the parent's row-level security policy never gets a foothold. The
// version table is the owner's bookkeeping and the application has no
// business reading it.
func privilegeStatements(role string) []string {
	event := qualified("event")
	head := qualified("chain_head")

	return []string{
		// Without USAGE on the schema, every grant below is unreachable.
		"GRANT USAGE ON SCHEMA " + pgx.Identifier{Schema}.Sanitize() + " TO " + role,

		// The history: append and read, and nothing else. The REVOKE is
		// not redundant with "never granted" — it is what makes the
		// intent explicit, what overrides a privilege granted by hand or
		// by an earlier configuration, and what pglog.Open's check reads
		// back to decide whether this deployment has any enforcement at
		// all.
		"GRANT SELECT, INSERT ON " + event + " TO " + role,
		"REVOKE UPDATE, DELETE, TRUNCATE ON " + event + " FROM " + role,
		"REVOKE REFERENCES, TRIGGER ON " + event + " FROM " + role,

		// The head row is the single writable surface. UPDATE is granted
		// because an append has to move the head; DELETE is not, because
		// deleting a head row would let an appender restart a chain at
		// sequence one, and a chain that can be restarted is not a chain.
		// TRUNCATE likewise.
		"GRANT SELECT, INSERT, UPDATE ON " + head + " TO " + role,
		"REVOKE DELETE, TRUNCATE ON " + head + " FROM " + role,
		"REVOKE REFERENCES, TRIGGER ON " + head + " FROM " + role,

		// PUBLIC holds no table privileges by default, but "by default" is
		// a property of how the table was created rather than a guarantee
		// about how it is now, and a privilege held by PUBLIC would make
		// every revoke above decorative.
		"REVOKE ALL ON " + event + " FROM PUBLIC",
		"REVOKE ALL ON " + head + " FROM PUBLIC",
		"REVOKE ALL ON SCHEMA " + pgx.Identifier{Schema}.Sanitize() + " FROM PUBLIC",
	}
}

// ensureRole creates the application role if it does not already exist, as
// NOLOGIN and with nothing cluster-wide: no superuser, no createdb, no
// createrole, and explicitly NOBYPASSRLS, since a role that bypasses
// row-level security would make the policies in 00001_audit.sql decorative.
//
// NOLOGIN is the default because the deployment model this module is built
// for keeps one connection string: the process connects as the owner and
// narrows itself with SET ROLE for runtime work. A deployment that would
// rather separate the two operationally gives the role LOGIN and a password
// out of band; nothing here depends on which it chose.
//
// Roles are cluster-wide rather than per-database, and this module's
// advisory lock is per-database, so two test databases on one cluster can
// race to create the same role at the same moment. A guard that checks
// pg_roles first still loses that race — both sessions can see "not there"
// before either commits — so the duplicate is caught instead of prevented.
// CAS hit precisely this, as a 23505 on pg_authid's name index, with
// parallel tests.
func ensureRole(ctx context.Context, tx pgx.Tx, role string) error {
	stmt := "CREATE ROLE " + pgx.Identifier{role}.Sanitize() +
		" NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOLOGIN NOBYPASSRLS"

	if err := execIdempotent(ctx, tx, stmt); err != nil {
		return fmt.Errorf("%w: migrate: create role %s: %w", domain.ErrInvalidConfig, role, err)
	}
	return nil
}
