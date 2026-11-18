#!/usr/bin/env bash
# Frontend checks for the post-v1 console. Runs only when dependencies are installed
# so the v1 release gate stays runnable on machines without Node/npm.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

if [ ! -d web/node_modules ]; then
    echo "console: web/node_modules missing — skipping frontend checks"
    echo "  install with: cd web && npm install"
    exit 0
fi

command -v npm >/dev/null 2>&1 || { echo "console: npm not found" >&2; exit 1; }

(cd web && npm run typecheck) || { echo "console: TypeScript check failed" >&2; exit 1; }
(cd web && npm test) || { echo "console: frontend tests failed" >&2; exit 1; }
(cd web && npm run build) || { echo "console: frontend build failed" >&2; exit 1; }

echo "console: TypeScript, tests, and production build passed"
