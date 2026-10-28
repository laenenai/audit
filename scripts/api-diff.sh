#!/usr/bin/env bash
# Compare the current module's exported API with the last root release tag.
#
# apidiff is the Go team's export-data comparison tool. It compares the
# importable packages (internal packages are ignored unless -allow-internal is
# set), which is the surface Go's compatibility promise and a module's SemVer
# contract actually cover. It works from a dirty tree, unlike gorelease, so it
# can run in the ordinary check.
#
# Breaking changes are allowed before 1.0. This task reports them and exits 0;
# set API_DIFF_STRICT=1 to make an incompatible change fail the gate instead.
set -euo pipefail

base="$(git describe --tags --abbrev=0 --match 'v[0-9]*' 2>/dev/null || true)"
if [[ -z "${base}" ]]; then
  echo "api-diff: no root tag yet; skipping comparison"
  exit 0
fi

apidiff_version="v0.0.0-20261014143641-f0251eb4aa3e"
tool="golang.org/x/exp/cmd/apidiff@${apidiff_version}"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

git archive "${base}" | tar -x -C "${work}"
base_export="${work}/base.export"
new_export="${work}/new.export"

(
  cd "${work}"
  GOFLAGS=-mod=mod go run "${tool}" -m -w "${base_export}" github.com/laenenai/audit
)
go run "${tool}" -m -w "${new_export}" github.com/laenenai/audit

set +e
report="$(go run "${tool}" -m "${base_export}" "${new_export}" 2>&1)"
status=$?
set -e
printf '%s\n' "${report}"
if [[ ${status} -ne 0 ]]; then
  echo "api-diff: apidiff failed (exit ${status})" >&2
  exit "${status}"
fi

if grep -q '^Incompatible changes:' <<<"${report}"; then
  echo "api-diff: incompatible changes detected against ${base}."
  echo "api-diff: pre-1.0 allows this; record it in CHANGELOG.md and UPGRADING.md."
  if [[ "${API_DIFF_STRICT:-0}" == "1" ]]; then
    exit 1
  fi
fi
