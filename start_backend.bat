@echo off
setlocal
cd /d "%~dp0"

set "VENV_DIR=.venv"

if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo [Sentinel AI] Creating virtual environment...
    python -m venv "%VENV_DIR%"
)

"%VENV_DIR%\Scripts\python.exe" -c "import tldextract, bs4, joblib, sklearn, pandas" >nul 2>&1
if errorlevel 1 (
    echo [Sentinel AI] Installing dependencies from requirements.txt...
    "%VENV_DIR%\Scripts\pip.exe" install -r requirements.txt
)

set "PORT=%SENTINELAI_PORT%"
if "%PORT%"=="" set "PORT=8000"

echo [Sentinel AI] Starting server on http://127.0.0.1:%PORT%...
"%VENV_DIR%\Scripts\python.exe" backend\server.py %PORT%
