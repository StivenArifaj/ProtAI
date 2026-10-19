#!/usr/bin/env bash
# Phase 0a local quality gate (blueprint section 20.3, initial checks only).
#
# Remaining section 20.3 steps are added in later phases: Gitleaks secret scanning
# (Phase 0b) and the signature tests, audit-chain tests, policy self-checks, and
# evaluation regression suite (Phases 1-9). This script exits non-zero on any failure
# and prints a clear summary.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

fail() {
    echo ""
    echo "CHECK FAILED: $1" >&2
    exit 1
}

step() {
    echo ""
    echo "==> $1"
}

command -v uv >/dev/null 2>&1 || fail "uv is not installed or not on PATH"

step "[1/6] lockfile/dependency consistency (uv lock --check)"
uv lock --check || fail "lockfile is not consistent with pyproject.toml"

step "[2/6] ruff format check"
uv run --frozen ruff format --check . || fail "formatting check reported changes"

step "[3/6] ruff lint"
uv run --frozen ruff check . || fail "lint errors reported"

step "[4/6] static type checks (mypy, src/)"
uv run --frozen mypy || fail "type errors reported"

step "[5/6] test suite (pytest)"
uv run --frozen pytest || fail "test failures reported"

step "[6/6] invariant greps (prohibited patterns in src/)"
PROHIBITED='(os\.system\(|subprocess|shell=True|(^|[^A-Za-z_])eval\(|(^|[^A-Za-z_])exec\(|pickle|yaml\.load\()'
matches=$(grep -rnE "$PROHIBITED" src/)
grep_rc=$?
if [ "$grep_rc" -eq 0 ]; then
    echo "$matches"
    fail "prohibited pattern(s) found in src/ (see matches above)"
elif [ "$grep_rc" -ne 1 ]; then
    fail "invariant grep could not run (grep exit $grep_rc)"
fi
echo "no prohibited patterns found"

echo ""
echo "All Phase 0a checks passed."
