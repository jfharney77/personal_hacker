#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

mkdir -p logs

echo "Starting backend in the background (logs/backend.log) ..."
bash "$SCRIPT_DIR/start_backend.sh" > logs/backend.log 2>&1 &
BACKEND_PID=$!

echo "Starting frontend in the background ..."
bash "$SCRIPT_DIR/start_frontend.sh" &
FRONTEND_PID=$!

# Record PIDs so scripts/stop_all.sh can stop both (backend line 1, frontend line 2).
printf '%s\n%s\n' "$BACKEND_PID" "$FRONTEND_PID" > logs/pids

cleanup() {
  echo
  echo "Stopping ..."
  for pid in "$FRONTEND_PID" "$BACKEND_PID"; do
    kill "$pid" 2>/dev/null || true
    pkill -P "$pid" 2>/dev/null || true   # uvicorn --reload / vite spawn children
  done
  rm -f logs/pids
}
trap cleanup INT TERM EXIT

echo "Both starting — backend http://localhost:8000, frontend http://localhost:5173"
echo "Press Ctrl-C to stop both."
wait
