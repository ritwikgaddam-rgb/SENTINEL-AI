#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [ -z "${SENTINELAI_PYTHON:-}" ]; then
  for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1 &&
       "$candidate" -c 'import sys; raise SystemExit(not ((3, 11) <= sys.version_info[:2] <= (3, 13)))'; then
      SENTINELAI_PYTHON="$candidate"
      break
    fi
  done
fi
if [ -z "${SENTINELAI_PYTHON:-}" ]; then
  echo "Install Python 3.11, 3.12 or 3.13 and run this script again." >&2
  exit 1
fi

# Keep the app's environment separate from any existing development environment.
VENV_DIR=".runtime/app-venv"
if [ ! -x "$VENV_DIR/bin/python" ]; then
  "$SENTINELAI_PYTHON" -m venv "$VENV_DIR"
fi
PYTHON="$VENV_DIR/bin/python"
if ! cmp -s requirements.txt "$VENV_DIR/installed-requirements.txt"; then
  "$PYTHON" -m pip install -r requirements.txt
  cp requirements.txt "$VENV_DIR/installed-requirements.txt"
fi

exec "$PYTHON" -m backend.server "${SENTINELAI_PORT:-8000}"
