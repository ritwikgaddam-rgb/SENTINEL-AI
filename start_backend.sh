#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

# 1. Locate the best Python interpreter on the system (prefer Python 3.11-3.13)
find_base_python() {
  if [ -n "${SENTINELAI_PYTHON:-}" ] && command -v "$SENTINELAI_PYTHON" >/dev/null 2>&1; then
    echo "$SENTINELAI_PYTHON"
    return
  fi
  for py in "$HOME/.local/bin/python3.13" python3.13 python3.12 python3.11 python3 python; do
    if command -v "$py" >/dev/null 2>&1; then
      echo "$py"
      return
    fi
  done
  echo "python3"
}

VENV_DIR=".venv"
BASE_PY=$(find_base_python)

# 2. Check if .venv exists and is valid on this machine
REBUILD_VENV=0
if [ -d "$VENV_DIR" ]; then
  # Test if the virtualenv interpreter runs and isn't pointing to a non-existent foreign path
  if ! "$VENV_DIR/bin/python" -c "import sys" >/dev/null 2>&1; then
    echo "[Sentinel AI] Existing virtual environment is invalid or from another machine. Rebuilding..."
    rm -rf "$VENV_DIR"
    REBUILD_VENV=1
  fi
else
  REBUILD_VENV=1
fi

if [ "$REBUILD_VENV" -eq 1 ]; then
  echo "[Sentinel AI] Creating virtual environment using $BASE_PY..."
  "$BASE_PY" -m venv "$VENV_DIR"
fi

# 3. Ensure required packages are installed
if ! "$VENV_DIR/bin/python" -c "import tldextract, bs4, joblib, sklearn, pandas" >/dev/null 2>&1; then
  echo "[Sentinel AI] Installing dependencies from requirements.txt..."
  "$VENV_DIR/bin/pip" install -q -r requirements.txt
fi

# 4. Start the Sentinel AI backend server
PORT="${SENTINELAI_PORT:-8000}"
echo "[Sentinel AI] Starting server on http://127.0.0.1:$PORT..."
exec "$VENV_DIR/bin/python" backend/server.py "$PORT"
