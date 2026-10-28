# audit

[![ci](https://github.com/laenenai/audit/actions/workflows/ci.yml/badge.svg)](https://github.com/laenenai/audit/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/laenenai/audit.svg)](https://pkg.go.dev/github.com/laenenai/audit)

An append-only, hash-chained event log that can be independently verified —
with append-only enforced by Postgres privileges rather than by the absence of
an `Update` method.

> **Status: pre-1.0.** The domain model, the chain, verification, an in-memory
> adapter and a Postgres adapter with its migrations are implemented and
> tested, the latter against a real Postgres container. Checkpoint signing and
> publication, retention scheduling and the query API are not built yet. The
> API may change before v1.

## Install

```
go get github.com/laenenai/audit
```

Requires Go 1.25.6, and Postgres 17+ for the Postgres adapter. No cgo.

## Example

```go
if err := audit.Migrate(ctx, migrationPool, audit.MigrateConfig{AppRole: "myapp"}); err != nil {
	return err
}

log, err := audit.Open(ctx, audit.Config{
	DB:    runtimePool, // the app role: INSERT and SELECT, nothing else
	Chain: audit.ChainID{Tenant: "tenant-42", Pool: "eu-1"},
})
if err != nil {
	return err
}

entry, err := log.Append(ctx, audit.Record{
	Actor:   "principal-7",
	Subject: audit.SubjectRef{Kind: "document", ID: "doc-9"},
	Action:  "content.read",
	Outcome: "allowed",
})
```

To make the audit row commit with the thing it records, put your transaction in
the context — `audit.WithTx(ctx, tx)` — and the append joins it. A **denial**
has no transaction, and is recorded standalone.

## Four things worth knowing before you rely on it

**Append-only is enforced by Postgres, not by this API.** The `Log` interface
has no `Update`, `Delete` or `Truncate` — necessary, and nowhere near
sufficient, because a compromised application holding `DELETE` can truncate the
log and Go has nothing to say about it. So the tables are owned by a role the
application is not, the application role holds `INSERT` and `SELECT` and
nothing else, and the trigger is defence in depth *behind* the privilege rather
than the mechanism. `audit.CheckEnforcement` reports whether that separation is
actually in effect, and `Open` says so loudly when it is not — a deployment
running as the owner gets a working log with no enforcement, and must be told
rather than left to assume.

**A hash chain cannot bear witness to its own completeness.** A prefix of a
valid chain is a valid chain, so truncation of the tail is undetectable from
the log alone. `VerifyOptions` therefore takes a witness or a root: everything
at or before it is accepted on *its* authority, which means a root read back out
of the same storage that holds the chain proves nothing. The window of
deniability is everything since the last published checkpoint, so **checkpoint
frequency and publication is the real security parameter** — and publishing
them is not yet built.

**One chain per `(tenant, pool)`, because a chain serializes writes.** Each
entry commits to its predecessor, so an append must read the head, so appends
to one chain cannot be concurrent. The chain is a write bottleneck and its
granularity is the only lever. Appends to *different* chains do not serialize.

**Audit records cannot be erased.** Nothing can be removed from an append-only
chain after the fact, which makes one call-site rule load-bearing: **never put
content in `Detail`.** If content lands there, no later erasure reaches it.

## What it does not do

Event semantics — what an action means, and which fields a given event carries
— are the caller's. So is who may read the log: that is an authorization
question, not this module's. Retention scheduling, checkpoint publication and
the query API are not yet built.

## Documentation

- [`CHARTER.md`](CHARTER.md) — the boundary and the two mechanisms that enforce it
- [`SECURITY.md`](SECURITY.md)
- `docs/superpowers/specs/` — the Postgres backend's design decisions, including why the privilege grants are *reconciled on every run* rather than applied by a versioned migration
- [`CHANGELOG.md`](CHANGELOG.md) and [`UPGRADING.md`](UPGRADING.md) — release notes and migration steps

API compatibility is compared with the last root tag by `mise run api-diff`
(apidiff; `internal/...` packages are ignored) and validated on a clean release
by `mise run release-check` (gorelease). Pre-1.0 incompatible changes are
reported and documented, not fatal.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
