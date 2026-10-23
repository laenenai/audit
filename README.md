# audit

An append-only hash-chained event log that can be independently verified.

**Not in scope:** Event semantics. Who may read it — that is an iam permission.

See [CHARTER.md](CHARTER.md) for the boundary and how it is enforced, and
`api.txt` for the public surface.

## The two identities

This is the one thing about deploying this module that is not obvious from the
API, so it is here rather than only in a doc comment.

Append-only is enforced by Postgres, not by Go. The port has no `Update`, no
`Delete` and no `Truncate`, and that is necessary and nowhere near sufficient:
a compromised application holding `DELETE` on the history table can truncate
the log. So the audit tables are owned by a role the application is not, the
application role holds `INSERT` and `SELECT` on the history, and `UPDATE`,
`DELETE` and `TRUNCATE` are revoked from it. A `BEFORE UPDATE OR DELETE`
trigger refuses a mutation that gets past the privileges anyway, as defence in
depth rather than as the mechanism.

That means a deployment needs **two identities**:

- an **owner** role, which runs `audit.Migrate` and owns everything in schema
  `audit`;
- an **application** role, which inserts and reads and can do nothing else.
  Its name is configuration, because the migration has to name it in its
  `REVOKE`.

Either keep them as two connection strings, or — the default — connect as the
owner and name the application role in `Config.AppRole`, which the adapter
switches into with `SET LOCAL ROLE` for every transaction it opens.

```go
// Deployment time, as the owner.
if err := audit.Migrate(ctx, ownerPool, audit.MigrateConfig{AppRole: "myapp_audit"}); err != nil {
    return err
}

// Runtime. One Log per (tenant, pool) chain.
log, err := audit.Open(ctx, audit.Config{
    DB:      pool,
    Chain:   audit.ChainID{Tenant: "tenant-1", Pool: "main"},
    AppRole: "myapp_audit",
    // Fail to start rather than run without the guarantee.
    RequireAppendOnlyEnforcement: true,
})
```

A deployment that declines privilege separation gets a working audit log with
**no enforcement of append-only** beyond the Go API — which is to say, none
against a compromised application. `Open` detects that at startup and reports
it at error level with the specific privileges it found; set
`RequireAppendOnlyEnforcement` to make it fatal instead, or call
`audit.CheckEnforcement` from a health check to ask the same question.

## Committing an audit record with the thing it audits

```go
// A granted operation: the audit row commits with the work, or neither does.
tx, _ := pool.Begin(ctx)
_, err := log.Append(audit.WithTx(ctx, tx), rec)

// A denial has no transaction — nothing happened — and must still be
// recorded. That is an Append on a context WithTx was never called on.
_, err = log.Append(ctx, denial)
```

## Verification

`audit.Verify` walks the chain and re-derives it. Two options matter:

- `Witness` is a checkpoint obtained earlier and kept somewhere the log's
  operator does not control. Without one, a **truncated tail is undetectable**:
  a prefix of a valid chain is a valid chain, and the log cannot bear witness
  to its own completeness.
- `Root` is where verification begins. Retention drops whole range partitions
  at a checkpoint boundary — the only deletion a hash chain tolerates — so the
  checkpoint becomes the chain's new verification root. Everything at or
  before a `Root` is accepted on that root's authority, so a root is worth
  exactly what its provenance is worth.

Verifying a chain that is still being appended to should be done inside one
snapshot, since a pass that pages across several transactions can see a head
that is ahead of the entries it walked. Open a `REPEATABLE READ` transaction,
put it in the context with `audit.WithTx`, and verify through that.
