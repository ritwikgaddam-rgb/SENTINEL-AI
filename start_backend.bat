@echo off
setlocal
cd /d "%~dp0" || exit /b 1

if not defined SENTINELAI_PYTHON set "SENTINELAI_PYTHON=python"
"%SENTINELAI_PYTHON%" -c "import sys; raise SystemExit(not ((3,11) <= sys.version_info[:2] <= (3,13)))"
if errorlevel 1 (
    echo Install Python 3.11, 3.12 or 3.13, or set SENTINELAI_PYTHON to its full path.
    exit /b 1
)

set "VENV_DIR=.runtime\app-venv"
set "VENV_PYTHON=%VENV_DIR%\Scripts\python.exe"
if not exist "%VENV_PYTHON%" (
    "%SENTINELAI_PYTHON%" -m venv "%VENV_DIR%" || exit /b 1
)
fc /b requirements.txt "%VENV_DIR%\installed-requirements.txt" >nul 2>&1
if errorlevel 1 (
    "%VENV_PYTHON%" -m pip install -r requirements.txt || exit /b 1
    copy /y requirements.txt "%VENV_DIR%\installed-requirements.txt" >nul || exit /b 1
)
if not defined SENTINELAI_PORT set "SENTINELAI_PORT=8000"
"%VENV_PYTHON%" -m backend.server "%SENTINELAI_PORT%"
exit /b %errorlevel%
