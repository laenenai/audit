# Notes: the Postgres backend for `audit`

Date: 2026-10-23
Status: decisions for the next increment, not yet implemented

Current state: **in-memory only.** `internal/eventlog/memory.go` is the only
adapter. The port, the CASF-style canonical encoding, the chain and `Verify`
exist and are green; nothing is durable.

Postgres is the backend, in the consumer's instance via `tenancy`. Five
decisions, three of which CAS §8.5 does not address.

## 1. Chain granularity is a throughput decision, not only a security one

**A hash chain serializes writes by construction.** Each entry commits to its
predecessor, so an append must read the head; appends to one chain therefore
cannot be concurrent. The chain is a write bottleneck, and its granularity is
the only lever.

Set against CAS §8.5's own volume numbers — "millions of agent-memory
retrievals per tenant", and the observation that without aggregation "one agent
doing semantic retrieval would generate tens of thousands of audit rows an
hour" — a single deployment-wide chain is dead on arrival.

**Decision: one chain per `(tenant, pool)`.** Tenant because §8.5 says audit
records are tenant-scoped and that is the granularity every audit question is
asked at; pool because pools may be separate databases (CAS §14.1) and a chain
cannot span databases. Cross-chain ordering does not exist and is not needed.

The envelope therefore gains a chain identifier, which the first increment
deliberately left out (it treated one `Log` as one chain). A per-chain head row
carries the current sequence and digest, and an append is an update of that row
plus an insert, in one transaction.

## 2. Append-only must be enforced by Postgres, not by the Go API

The port has no `Update`, `Delete` or `Truncate` — necessary, and nowhere near
sufficient. **A compromised application with `DELETE` on the table can truncate
the log**, and the Go type system has nothing to say about it.

So: the audit tables are owned by a role the application is not, the
application role holds `INSERT` and `SELECT` only, and `UPDATE`, `DELETE` and
`TRUNCATE` are revoked. A `BEFORE UPDATE OR DELETE` trigger that raises is
added as defence in depth, not as the mechanism. RLS applies as everywhere else,
since rows are tenant-scoped.

The head row is the exception that needs care: it *must* be updatable, so it is
the one writable surface, and it holds no history — only the latest sequence and
digest. Rewriting it cannot rewrite the chain, only make verification fail.

## 3. Retention and tamper-evidence are only compatible through checkpoints

Audit grows without bound, and CAS wants retention. But **you cannot delete
from a hash chain without breaking verification from genesis.**

**Decision: retention drops whole partitions at a checkpoint boundary, and the
published checkpoint becomes the new verification root.** Verification starts
from the most recent published checkpoint rather than from entry zero.

This is the consequence worth noticing: checkpoint publication stops being a
security nicety and becomes a *functional* prerequisite for retention. Two
independent requirements now rest on it — truncation detection (the first
increment's finding: a prefix of a valid chain is a valid chain, so the log
cannot witness its own completeness) and retention.

Partitioning follows CAS §12.2's decision: declarative hash partitioning on
tenant, range-partitioned by time within it, so retention is a partition drop
rather than a delete.

## 4. Checkpoint publication — the piece that was unowned

It now has an owner: this module publishes, and the deployment chooses where.
Cheapest-first, and the first two are already in the stack:

1. **Signed with a key the application cannot read.** OpenBao transit `sign`
   over a checkpoint, with the application granted `sign` and nothing else. It
   can produce today's signature and cannot forge last month's. `keyring`
   already speaks transit.
2. **Written to write-once storage.** An S3-compatible bucket with object lock
   in compliance mode; CAS already has an S3 blob adapter and SeaweedFS in its
   dev stack.
3. A separate database under a different credential — weakest, but strictly
   better than nothing and the only option with no dependencies.
4. An external transparency log — out of scope until someone asks.

**The security parameter is checkpoint frequency**, because the window of
deniability is everything since the last one. It is configuration with a
conservative default, and the default is stated rather than implied.

## 5. Transactional participation, and the one case that must stay outside

`Append` is a single adapter-owned read-modify-write with no cached head, so it
fits inside a caller's transaction, taken from the context. That is what makes
"the audit record commits with the thing it audits" true rather than aspirational
— otherwise the system produces audited-but-not-done and done-but-not-audited
pairs under failure.

**But a denial must be audited outside any transaction**, because there is no
transaction: nothing happened, and the record must survive regardless. So the
adapter supports both — enlisted when a caller supplies a unit of work, and
standalone when it does not. CAS §8.5 and the kgs design both require denied
access to be audited; this is the mechanism.

## What this backend is not

CAS §8.6 separates audit from observability, and the separation holds here:
**the authoritative record is Postgres.** Shipping a derived copy to a log or
search system for querying is fine; that copy is never the record, is never
verified, and must not be what a compliance question is answered from.

Queryability (§8.5's read receipts, tenant-facing audit queries by principal,
resource and time) is ordinary indexing over the same table. The rule is that
verification walks the chain and queries use indexes — an index is never
allowed to become the record.
