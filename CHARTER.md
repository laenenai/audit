# Charter: `audit`

**It does this one thing:** An append-only hash-chained event log that can be independently verified.

**It must not contain:** Event semantics. Who may read it — that is an iam permission.

## Why this file exists

A shared module with no stated boundary accretes until it is the dependency
every project has and nobody can reason about. This charter is the boundary.
Two mechanisms enforce it rather than merely stating it:

1. **The importable API is diffed against the last root release tag** by
   `mise run api-diff` (apidiff; `internal/...` is outside the compatibility
   contract), and a clean release is validated by `mise run release-check`
   (gorelease). Growing the public surface requires a reviewed diff, so a new
   responsibility cannot slip in quietly. Pre-1.0 incompatible changes are
   reported and recorded in `CHANGELOG.md` and `UPGRADING.md`; from 1.0 they
   fail the gate.
2. **The conformance suite** (`suite.go`, following the pattern of
   `cas/internal/blob/suite.go`) is the contract. A consumer counts as
   *adopted* when this module's suite runs green in that consumer's CI against
   its own wiring — not when someone says it is adopted.

A change that does not fit the charter belongs in a different module. A module
is created when a **second** consumer needs it, not in anticipation.

## Adoption

| Consumer | State |
|---|---|
| cas | greenfield (nothing built) |
| kgs | pending (phase 0) |
| acre | pending (no code yet; adopts from birth) |

## Provenance

Extracted per `kgs/docs/superpowers/specs/2026-10-23-knowledge-graph-store-design.md`
§6.1 (the six-module decomposition) and §6.2 (authority and projections).
