#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

PIDFILE="logs/pids"
stopped=0

# 1. Prefer the recorded PIDs (backend on line 1, frontend on line 2).
if [ -f "$PIDFILE" ]; then
  while read -r pid; do
    [ -n "$pid" ] || continue
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true       # SIGTERM only — graceful shutdown
      pkill -P "$pid" 2>/dev/null || true    # children (reloader / vite)
      echo "Stopped pid $pid"
      stopped=1
    fi
  done < "$PIDFILE"
  rm -f "$PIDFILE"
fi

# 2. Fallback: kill whatever is listening on the known ports (stale/missing PID file).
if command -v lsof >/dev/null 2>&1; then
  for entry in "8000:FastAPI/uvicorn" "5173:Vite dev server"; do
    port="${entry%%:*}"; label="${entry#*:}"
    for pid in $(lsof -ti tcp:"$port" 2>/dev/null || true); do
      kill "$pid" 2>/dev/null || true
      echo "Stopped $label on port $port (pid $pid)"
      stopped=1
    done
  done
fi

[ "$stopped" -eq 0 ] && echo "No running processes found."
exit 0
