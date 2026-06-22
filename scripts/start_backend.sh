#!/usr/bin/env bash
set -euo pipefail

# Resolve the project root from this script's location.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT"

# The backend shares the engine's virtualenv at the repo root (.venv).
if [ ! -d ".venv" ]; then
  echo "Creating virtualenv at .venv ..."
  python3 -m venv .venv
fi

# Activate (Windows vs POSIX layout).
if [ -f ".venv/Scripts/activate" ]; then
  # shellcheck disable=SC1091
  source ".venv/Scripts/activate"
else
  # shellcheck disable=SC1091
  source ".venv/bin/activate"
fi

# Install deps.
if [ -f "requirements.txt" ]; then
  pip install -q -r requirements.txt
elif [ -f "pyproject.toml" ]; then
  pip install -q -e .
fi

# Seed .env from an example if one is provided.
if [ -f ".env.example" ] && [ ! -f ".env" ]; then
  cp ".env.example" ".env"
  echo "Created .env from .env.example — review it before relying on it."
fi

# The backend package uses relative imports, so run it as a module from the repo root.
echo "Starting FastAPI on http://localhost:8000 ..."
exec python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
