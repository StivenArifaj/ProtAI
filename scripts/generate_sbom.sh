#!/usr/bin/env bash
# Generate CycloneDX SBOM from uv.lock (Phase 10).
# This script is run manually to (re)generate the SBOM; it is validated by
# scripts/check.sh (step [11/11]) which checks presence and validity.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

command -v uv >/dev/null 2>&1 || { echo "uv is not installed" >&2; exit 1; }

mkdir -p releases/sbom

uv export --frozen --no-hashes --format requirements-txt -o requirements.txt \
    || { echo "uv export failed" >&2; exit 1; }

if command -v cyclonedx-py >/dev/null 2>&1; then
    cyclonedx-py requirements --pyproject pyproject.toml --of JSON \
        -o releases/sbom/cyclonedx-sbom.json --validate \
        || { echo "cyclonedx-py failed" >&2; exit 1; }
else
    uv run --with cyclonedx-bom==7.6.0 cyclonedx-py requirements \
        --pyproject pyproject.toml --of JSON \
        -o releases/sbom/cyclonedx-sbom.json --validate \
        || { echo "cyclonedx-py (via --with) failed" >&2; exit 1; }
fi

rm -f requirements.txt

sha256sum releases/sbom/cyclonedx-sbom.json > releases/sbom/SHA256SUMS.new
# Prepend the reproduction header to SHA256SUMS
{
    echo "# CycloneDX SBOM SHA256 checksums (Phase 10)"
    echo "# Generated from uv.lock via cyclonedx-py"
    echo "# Tool: cyclonedx-bom==7.6.0, CycloneDX spec version 1.6"
    echo "#"
    echo "# Reproduction:"
    echo "#   uv export --frozen --no-hashes --format requirements-txt -o requirements.txt"
    echo "#   uv run --with cyclonedx-bom==7.6.0 cyclonedx-py requirements"
    echo "#     --pyproject pyproject.toml --of JSON -o releases/sbom/cyclonedx-sbom.json --validate"
    echo "#   sha256sum releases/sbom/cyclonedx-sbom.json"
    echo "#"
    cat releases/sbom/SHA256SUMS.new
} > releases/sbom/SHA256SUMS
rm -f releases/sbom/SHA256SUMS.new

echo "SBOM generated: releases/sbom/cyclonedx-sbom.json"
echo "Checksums: releases/sbom/SHA256SUMS"
