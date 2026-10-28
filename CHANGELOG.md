# Changelog

All notable changes to `github.com/laenenai/audit` are recorded here. The file
is human-readable; versions follow SemVer with the pre-1.0 rule that a minor
release may break the API. See `UPGRADING.md` for migration steps.

## Unreleased — API compatibility tooling

### Tooling and documentation

- Removed the hand-maintained AST-generated API snapshot, its root-package
  test, and the task that rewrote it. The snapshot captured implementation
  declarations, including internal packages, and could not prove consumer
  compatibility.
- Public API compatibility is now checked by `mise run api-diff` against the
  last root release tag using apidiff
  `v0.0.0-20261014143641-f0251eb4aa3e`; `internal/...` packages are ignored.
  Pre-1.0 incompatible changes are reported and must be documented here and in
  `UPGRADING.md`. Set `API_DIFF_STRICT=1` after 1.0 to make them fail.
- Added `mise run release-check` using gorelease
  `v0.0.0-20261014143641-f0251eb4aa3e` for a clean release tree. The new
  tag-triggered release workflow runs the check gate, gorelease, and creates
  the GitHub release from this file.
- Added `mise run generate-check` (`sqlc diff`) and `mise run vuln`
  (govulncheck `v1.9.0`). `mise run check` now includes both plus
  `mise run api-diff`.
- CI installs the toolchain from `mise.toml`, checks out full tags
  (`fetch-depth: 0`), and runs `mise run check` instead of duplicating tool
  versions in workflow YAML.
- Updated `README.md`, `CHARTER.md`, `CONVENTIONS.md`, and the 2026-10-28
  review to describe the new compatibility gate.

### Security

- Updated `golang.org/x/text` to v0.41.0, `golang.org/x/crypto` to v0.56.0,
  and `github.com/moby/go-archive` to v0.3.0, with the transitive updates
  required by those fixes. `mise run vuln` now reports no reachable
  vulnerabilities.

### Compatibility

- apidiff reports no incompatible changes against `v0.2.0`; no importable API
  change is required by this tooling migration.

## v0.2.0 — 2026-10-23

- Changed the entry digest format: one v1 canonical format with domain tag
  `audit:entry:v1` replaces the former v1/v2 pair. Digests computed under
  v0.1.0 do not reproduce; nothing was persisted with v0.1.0.
- Made the tenant isolation policy `AS RESTRICTIVE`, paired with a permissive
  companion. A later permissive policy can no longer OR the tenant predicate
  away.

## v0.1.0 — 2026-10-23

- First published version: the domain model, canonical hash chain,
  verification, in-memory adapter, and Postgres adapter with migrations.
- Fixed the module path to `github.com/laenenai/audit`; no earlier repository
  state was fetchable and none was tagged.
