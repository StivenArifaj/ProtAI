#!/usr/bin/env bash
# Local quality gate (blueprint section 20.3). Phase 0b adds the Gitleaks secret scan and
# the constant-time confinement invariant. Remaining section 20.3 steps arrive in later
# phases (signature/audit-chain tests already run inside pytest; evaluation regression
# suite in Phases 1-9). This script exits non-zero on any failure and prints a summary.
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

step "[1/8] lockfile/dependency consistency (uv lock --check)"
uv lock --check || fail "lockfile is not consistent with pyproject.toml"

step "[2/8] ruff format check"
uv run --frozen ruff format --check . || fail "formatting check reported changes"

step "[3/8] ruff lint"
uv run --frozen ruff check . || fail "lint errors reported"

step "[4/8] static type checks (mypy, src/)"
uv run --frozen mypy || fail "type errors reported"

step "[5/8] test suite (pytest)"
uv run --frozen pytest || fail "test failures reported"

step "[6/8] secret scanning (Gitleaks, pinned)"
GITLEAKS_REQUIRED="8.30.1"
command -v gitleaks >/dev/null 2>&1 \
    || fail "gitleaks $GITLEAKS_REQUIRED is not installed (e.g. brew install gitleaks)"
gitleaks_installed=$(gitleaks version 2>/dev/null || true)
[ "$gitleaks_installed" = "$GITLEAKS_REQUIRED" ] \
    || fail "gitleaks version mismatch (required $GITLEAKS_REQUIRED, found '${gitleaks_installed:-unknown}')"
gitleaks dir --redact --exit-code 1 . \
    || fail "gitleaks found potential secret(s) in the working tree"
gitleaks git --redact --exit-code 1 . \
    || fail "gitleaks found potential secret(s) in git history"

step "[7/8] invariant greps (prohibited patterns in src/)"
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

step "[8/8] constant-time confinement (compare_digest only in security/constant_time.py)"
matches=$(grep -rnE 'compare_digest' src/ --include='*.py' | grep -vE '^src/ai_security/security/constant_time\.py:')
grep_rc=$?
if [ "$grep_rc" -eq 0 ]; then
    echo "$matches"
    fail "compare_digest used outside src/ai_security/security/constant_time.py"
elif [ "$grep_rc" -ne 1 ]; then
    fail "constant-time grep could not run (exit $grep_rc)"
fi
echo "compare_digest usage confined to the constant-time helper"

echo ""
echo "All checks passed."
