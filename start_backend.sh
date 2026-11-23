#!/usr/bin/env bash
# Sentinel AI - Backend Startup Script

cd "$(dirname "$0")"

echo "====================================================="
echo "  Starting Sentinel AI Backend & SQLite Service      "
echo "====================================================="

# Check which python is available
if command -v python3 &>/dev/null; then
    PY_CMD="python3"
elif command -v python &>/dev/null; then
    PY_CMD="python"
else
    echo "Error: Python is not found on your system PATH."
    exit 1
fi

echo "Using Python: $($PY_CMD --version)"

# Check if port 8000 is already occupied by a stray process
OCCUPIED_PID=$(lsof -ti :8000 2>/dev/null)
if [ -n "$OCCUPIED_PID" ]; then
    echo "Notice: Port 8000 is currently occupied by PID $OCCUPIED_PID."
    echo "Freeing port 8000..."
    kill -9 $OCCUPIED_PID 2>/dev/null
    sleep 0.5
fi

# Run backend server
exec $PY_CMD backend/server.py 8000
