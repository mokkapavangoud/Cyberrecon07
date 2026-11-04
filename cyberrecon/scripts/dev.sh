#!/usr/bin/env bash
# Usage: scripts/dev.sh setup | api | web | test | build | serve
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
case "${1:-}" in
  setup)
    python3 -m venv "$ROOT/backend/.venv"
    "$ROOT/backend/.venv/bin/pip" install -r "$ROOT/backend/requirements-dev.txt"
    (cd "$ROOT/frontend" && npm install)
    echo "Optional: $ROOT/backend/.venv/bin/playwright install chromium   (enables website screenshots)"
    ;;
  api)   cd "$ROOT/backend" && exec .venv/bin/uvicorn app.main:app_factory --factory --reload --port 8000 ;;
  web)   cd "$ROOT/frontend" && exec npm run dev ;;
  test)  (cd "$ROOT/backend" && .venv/bin/pytest -q) && (cd "$ROOT/frontend" && npm run typecheck && npm test) ;;
  build) cd "$ROOT/frontend" && npm run build ;;
  serve) cd "$ROOT/backend" && exec .venv/bin/uvicorn app.main:app_factory --factory --port 8000 ;;
  *) sed -n 2p "$0"; exit 1 ;;
esac
