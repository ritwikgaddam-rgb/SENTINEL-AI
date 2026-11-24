#!/usr/bin/env bash
set -eu
cd "$(dirname "$0")"
exec "${SENTINELAI_PYTHON:-python3}" backend/server.py "${SENTINELAI_PORT:-8000}"
