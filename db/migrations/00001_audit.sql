-- 00001_audit.sql is the whole of this module's fixed schema. Everything
-- here is chosen once: the partitioning strategy, the append-only
-- enforcement, the shape of the head row, and the indexes. The things that
-- are *not* here are the ones a later deployment may legitimately change —
-- the number of hash partitions is fixed at first migration but supplied as
-- configuration, the range partitions extend forward over time, and the
-- application role's name is configuration — so those are applied by
-- internal/migrate's Up around this file rather than written into it. See
-- that package's doc comment for why.
--
-- Two decisions in here cannot be undone later and are the reason this file
-- is read before it is edited.
--
-- # Partitioning, chosen at creation
--
-- audit.event is PARTITION BY HASH (tenant_id), and each hash partition is
-- in turn PARTITION BY RANGE (recorded_at). CAS's design settled this and
-- said why: "converting a populated table to a partitioned one is an
-- outage". Hash on tenant because every audit question is asked per tenant,
-- so it buys partition pruning on every query and independent vacuum and
-- index maintenance per tenant group. Range by time within, because that is
-- what makes retention a partition drop.
--
-- Retention has to be a partition drop and nothing else, because **you
-- cannot delete from a hash chain without breaking verification from the
-- genesis.** Dropping a whole range partition at a checkpoint boundary is
-- the only form of deletion a hash chain tolerates: what remains still
-- verifies, from that checkpoint as its new root
-- (eventlog.VerifyOptions.Root). A DELETE of individual rows would leave a
-- chain that reports itself as tampered forever, which is why the revoke
-- and the trigger below forbid one.
--
-- # The primary key, and the uniqueness it does not give us
--
-- PRIMARY KEY (tenant_id, pool_id, sequence, recorded_at).
--
-- Postgres requires every column of a partition key to appear in a unique
-- constraint on a partitioned table, so recorded_at is in the key whether
-- the chain wants it there or not. The consequence, stated rather than
-- discovered later: this key does **not** enforce that (tenant_id, pool_id,
-- sequence) is unique — two rows with one sequence and two recorded_at
-- values would satisfy it.
--
-- What enforces one entry per sequence is the head row: an append takes a
-- row lock on audit.chain_head for its chain, so appends to one chain are
-- serialized and no second appender can observe the same head. The index is
-- defence in depth that declarative partitioning cannot make absolute, and
-- a duplicate sequence that somehow arrived anyway is detectable by
-- verification, which is the property that actually matters. The column
-- order is also the chain-walk order — (tenant_id, pool_id, sequence) is
-- exactly the prefix Entries pages on — so the key is the read path too.

-- +goose Up
CREATE SCHEMA IF NOT EXISTS audit;

-- audit.chain_head is the single writable surface in this schema: one row
-- per (tenant_id, pool_id) chain, carrying only the latest sequence and
-- digest. It must be updatable, which is exactly why it holds no history —
-- rewriting it cannot rewrite the chain, only make verification fail, and a
-- verification that fails is the outcome the log exists to produce.
--
-- It is deliberately not partitioned. It is one row per chain, it is the row
-- every append locks, and partition pruning on a table that size would buy
-- nothing while making the lock harder to reason about.
CREATE TABLE audit.chain_head (
    tenant_id  text        NOT NULL,
    pool_id    text        NOT NULL,
    sequence   bigint      NOT NULL DEFAULT 0 CHECK (sequence >= 0),
    digest     bytea       NOT NULL CHECK (octet_length(digest) = 32),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, pool_id)
);

COMMENT ON TABLE audit.chain_head IS
    'One row per (tenant, pool) chain: the latest sequence and digest. The only '
    'updatable table in this schema, and the lock every append serializes on. '
    'Holds no history, so rewriting it cannot rewrite the chain.';

-- audit.event is the history. Every column is a field the entry digest
-- commits to, so every column is immutable by construction: a change to any
-- of them makes the entry stop hashing to its stored link_self.
--
-- recorded_at is timestamptz and the Go side canonicalizes every timestamp
-- to UTC at microsecond precision before hashing it, because timestamptz
-- holds microseconds and a chain committing to nanoseconds would verify in
-- memory and then report every persisted entry as tampered.
--
-- detail is bytea and opaque: this module never parses it, and no error
-- raised anywhere in this schema or in the adapter may reproduce it.
CREATE TABLE audit.event (
    tenant_id    text        NOT NULL,
    pool_id      text        NOT NULL,
    sequence     bigint      NOT NULL CHECK (sequence >= 1),
    event_id     text        NOT NULL CHECK (event_id ~ '^[0-9a-f]{32}$'),
    recorded_at  timestamptz NOT NULL,
    actor_id     text        NOT NULL,
    subject_kind text        NOT NULL,
    subject_id   text        NOT NULL,
    action       text        NOT NULL,
    outcome      text        NOT NULL,
    detail       bytea       NOT NULL,
    link_prev    bytea       NOT NULL CHECK (octet_length(link_prev) = 32),
    link_self    bytea       NOT NULL CHECK (octet_length(link_self) = 32),
    PRIMARY KEY (tenant_id, pool_id, sequence, recorded_at)
) PARTITION BY HASH (tenant_id);

COMMENT ON TABLE audit.event IS
    'The append-only hash-chained audit history. UPDATE, DELETE and TRUNCATE are '
    'revoked from the application role and refused by a trigger; the only '
    'sanctioned deletion is dropping a whole range partition at a published '
    'checkpoint boundary.';

-- Indexes for the queries the design actually asks of an audit log:
-- principal, resource, and time. The standing rule is that verification
-- walks the chain and queries use indexes — an index is never the record.
--
-- There is no link_id column, and that is on purpose: "has the recipient
-- opened this link, when, and from where" is answered by auditing a link
-- redemption with subject_kind = 'link' and subject_id = the link id, so
-- event_by_subject *is* the read-receipt index. A dedicated column would be
-- this module taking a position on what an event means, which its charter
-- places outside it.
--
-- Each of these is a partitioned index: Postgres propagates it to every
-- partition, including ones attached later, so a partition created next year
-- cannot come up unindexed.
CREATE INDEX event_by_actor ON audit.event (tenant_id, actor_id, recorded_at DESC);

CREATE INDEX event_by_subject ON audit.event (tenant_id, subject_kind, subject_id, recorded_at DESC);

CREATE INDEX event_by_time ON audit.event (tenant_id, recorded_at DESC);

CREATE INDEX event_by_event_id ON audit.event (tenant_id, event_id);

-- The append-only trigger is defence in depth, not the mechanism. The
-- mechanism is the privilege separation internal/migrate applies: the
-- application role holds INSERT and SELECT and has UPDATE, DELETE and
-- TRUNCATE revoked. This trigger is what still refuses a mutation issued by
-- a role that was granted one by mistake, or by the owner itself in a
-- careless session.
--
-- It raises 42501 (insufficient_privilege) so that a caller sees the same
-- class of failure whichever layer refused, and names the operation and the
-- table so an operator can tell the two apart in the log. TRUNCATE is not
-- covered here — truncate triggers must be statement-level and Postgres does
-- not allow them on a partitioned table — so TRUNCATE is held by the revoke
-- alone, which is noted here rather than left for someone to discover.
--
-- The trigger is created on the partitioned parent. Postgres clones a
-- row-level trigger on a partitioned table to every partition, so a mutation
-- aimed straight at a leaf partition hits it too.
-- +goose StatementBegin
CREATE FUNCTION audit.reject_history_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION
        'audit: % on %.% is forbidden: the audit history is append-only',
        TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = '42501',
              HINT = 'retention drops a whole range partition at a published checkpoint boundary; it never rewrites or deletes rows';
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER reject_history_mutation
    BEFORE UPDATE OR DELETE ON audit.event
    FOR EACH ROW
    EXECUTE FUNCTION audit.reject_history_mutation();

-- Row-level security, on every table, keyed on the same app.tenant_id
-- session setting every other module in this system uses. Audit rows are
-- tenant-scoped, so a query that forgets its tenant predicate must return
-- nothing rather than another tenant's history.
--
-- The predicate takes no cast and uses nullif, for a reason worth repeating
-- because it is found the hard way: current_setting('app.tenant_id', true)
-- returns the empty string, not NULL, once any transaction on the connection
-- has set it with set_config(..., true) and then ended, so a session with no
-- tenant context can observe ''. A cast would make the predicate *raise* for
-- that caller instead of evaluating to false. nullif collapses both "never
-- set" and "set earlier, now ended" to NULL; tenant_id = NULL is NULL, which
-- Postgres treats as false for USING and WITH CHECK, so the row is filtered
-- with nothing raised.
--
-- FORCE is included because RLS does not apply to a table's owner by
-- default: without it the policy would appear in pg_policies while protecting
-- nothing for any query running as the owning role. It does not help against
-- a superuser, which bypasses row security unconditionally — which is one of
-- the conditions pglog.Open reports loudly at startup.
--
-- A policy on the partitioned parent is applied to its partitions, and the
-- application role is granted privileges on the parent only (never on a
-- partition), so there is no direct-to-partition path around it.
-- The tenant predicate is AS RESTRICTIVE, and that is load-bearing.
--
-- Postgres ORs permissive policies together and ANDs restrictive ones over
-- the result. A tenant predicate written as a single permissive policy —
-- which is what this migration shipped first — is therefore OR-ed away by
-- any additional permissive policy on the same table. Measured on Postgres
-- 18.6: a tenant seeing its own single row saw two the moment a second
-- permissive policy existed, and the second row belonged to another tenant.
-- Adding a policy weakened isolation, which any table owner can do and no
-- consumer would expect.
--
-- The permissive companion is required rather than decorative: a table whose
-- only policies are restrictive has an empty permissive set, and Postgres
-- then denies every row. tenant_access grants nothing on its own — the
-- restriction is what filters — it exists so the restriction has something
-- to AND against. A consumer adding its own permissive policies ORs them
-- with this one and still cannot escape the AND.
ALTER TABLE audit.event ENABLE ROW LEVEL SECURITY;

ALTER TABLE audit.event FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON audit.event AS RESTRICTIVE
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), ''))
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), ''));

CREATE POLICY tenant_access ON audit.event AS PERMISSIVE
    USING (true) WITH CHECK (true);

ALTER TABLE audit.chain_head ENABLE ROW LEVEL SECURITY;

ALTER TABLE audit.chain_head FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON audit.chain_head AS RESTRICTIVE
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), ''))
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), ''));

CREATE POLICY tenant_access ON audit.chain_head AS PERMISSIVE
    USING (true) WITH CHECK (true);

-- +goose Down
DROP POLICY IF EXISTS tenant_access ON audit.chain_head;

DROP POLICY IF EXISTS tenant_isolation ON audit.chain_head;

DROP POLICY IF EXISTS tenant_access ON audit.event;

DROP POLICY IF EXISTS tenant_isolation ON audit.event;

DROP TRIGGER IF EXISTS reject_history_mutation ON audit.event;

DROP TABLE IF EXISTS audit.event;

DROP FUNCTION IF EXISTS audit.reject_history_mutation();

DROP TABLE IF EXISTS audit.chain_head;

-- The schema itself is not dropped: goose's own version table for this
-- module lives in it (audit.goose_db_version), so dropping the schema here
-- would delete the bookkeeping recording that this very migration was rolled
-- back. The application role is not dropped either — roles are cluster-wide,
-- not per-database, so dropping one would break every other database on the
-- same cluster that still uses it.
