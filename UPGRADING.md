# Upgrading

`audit` is pre-1.0: a minor release may break the API. This file records the
steps for breaking changes and for changes to the compatibility tooling.

## From v0.2.x to the unreleased API

No importable Go API changes are required by this release. apidiff reports no
incompatible changes against `v0.2.0`.

### 1. Replace the local API snapshot workflow

The hand-maintained AST-generated API snapshot, its root-package test, and the
task that rewrote it were removed. They captured implementation declarations,
including internal packages, and did not prove consumer compatibility.

Use the replacement commands:

```bash
mise run api-diff       # apidiff against the last root tag; internal ignored
mise run release-check  # gorelease; requires a clean tree, run at release time
mise run check          # the full local/CI gate
```

`api-diff` reports pre-1.0 incompatible changes but exits 0. Record any such
change in `CHANGELOG.md` and this file. After 1.0, set `API_DIFF_STRICT=1` so an
incompatible change fails the gate.

### 2. Update CI and release automation

CI now installs the pinned toolchain from `mise.toml`, checks out full tags so
apidiff can resolve the previous release, and runs `mise run check`. The check
task now includes `generate-check` (`sqlc diff`), `vuln` (govulncheck), and
`api-diff`.

A tag push runs the release workflow: the same check gate, then gorelease with
the tag as `-version`, then a GitHub release whose body is `CHANGELOG.md`.
gorelease requires a clean tree, so `release-check` is intentionally not part
of the normal dirty-branch gate.

### 3. Update development dependencies

The vulnerability gate required fixed versions of three transitive
dependencies: `golang.org/x/text` v0.41.0, `golang.org/x/crypto` v0.56.0, and
`github.com/moby/go-archive` v0.3.0. Run `go mod tidy` after updating your
local fork or replacement.

## From v0.1.x to v0.2.0

- **Entry digests changed.** The single v1 canonical format and domain tag
  `audit:entry:v1` replace the former v1/v2 pair. Digests computed under
  v0.1.0 do not reproduce under v0.2.0. Nothing was persisted with v0.1.0; if
  you exported entries or checkpoints from a v0.1.0 build, re-ingest or
  re-compute them before relying on verification.
- **The tenant RLS policy became restrictive.** `tenant_isolation` is now
  `AS RESTRICTIVE`, with `tenant_access` as the permissive companion. A
  consumer that adds its own permissive policy is still constrained by the
  tenant predicate; remove any policy that assumed it could widen access.

## Release policy

- `v0.x.0` may break; `v0.x.y` is a fix.
- Every breaking change gets an entry in `CHANGELOG.md` and a section here.
- `main` is tagged only after `mise run check` passes.
- The release workflow runs gorelease on the tagged, clean tree.
- Only the root module is published; test-only and spike modules are never
  tagged.
