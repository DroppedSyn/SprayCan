@echo off
setlocal enabledelayedexpansion

set "ROOT_DIR=%~dp0"
if "%ROOT_DIR:~-1%"=="\" set "ROOT_DIR=%ROOT_DIR:~0,-1%"
set "VENV_DIR=%ROOT_DIR%\.venv"
if "%PYTHON_BIN%"=="" set "PYTHON_BIN=python"

cd /d "%ROOT_DIR%"

where %PYTHON_BIN% >nul 2>nul
if errorlevel 1 (
    echo [!] Python not found: %PYTHON_BIN%
    echo     Install Python 3 and ensure it is on PATH.
    echo     Download from https://python.org/downloads/
    echo     ^(during setup, check "Add python.exe to PATH"^)
    exit /b 1
)

where npm >nul 2>nul
if errorlevel 1 (
    echo [!] npm not found
    echo     Install Node.js ^(includes npm^) and rerun this script.
    echo     Download from https://nodejs.org/
    exit /b 1
)

if not exist "%VENV_DIR%" (
    echo [i] Creating virtual environment
    %PYTHON_BIN% -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo [!] Failed to create virtual environment.
        exit /b 1
    )
)

echo [i] Installing Python dependencies
"%VENV_DIR%\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 exit /b 1
"%VENV_DIR%\Scripts\pip.exe" install -r requirements.txt
if errorlevel 1 exit /b 1

echo [i] Installing frontend dependencies and building UI
call npm --prefix frontend install
if errorlevel 1 exit /b 1
call npm --prefix frontend run build
if errorlevel 1 exit /b 1

echo [i] Ensuring output directory exists
if not exist "output" mkdir "output"

echo.
echo [OK] Install complete
echo     Run: python SprayCan.py

endlocal
