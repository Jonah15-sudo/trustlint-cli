#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
HOST="${SPL_V7_DASHBOARD_HOST:-0.0.0.0}"
PORT="${SPL_V7_DASHBOARD_PORT:-8000}"
PYTHONPATH=. uvicorn spl_v7.dashboard:app --host "$HOST" --port "$PORT"
