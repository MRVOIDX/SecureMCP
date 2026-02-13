@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "ROOT=%~dp0"
set "VENV=%ROOT%.venv"
set "APP=%ROOT%app.py"
set "REQ=%ROOT%requirements.txt"

if /I "%~1"=="--help" goto :help
if /I "%~1"=="help" goto :help

echo ============================================
echo   SecureMCP - Security Analysis Tool
echo ============================================
echo.

where /q python
if errorlevel 1 (
    echo [ERROR] Python 3.10+ is required but was not found in PATH.
    echo Install it from https://www.python.org/downloads/ and rerun this script.
    pause
    exit /b 1
)

python -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python 3.10+ is required. Please upgrade your Python installation.
    pause
    exit /b 1
)

if not exist "%VENV%\Scripts\python.exe" (
    echo [INFO] Creating virtual environment at %VENV% ...
    python -m venv "%VENV%"
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
) else (
    echo [OK] Using existing virtual environment at %VENV%
)

echo [INFO] Activating virtual environment...
call "%VENV%\Scripts\activate.bat" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Could not activate virtual environment.
    pause
    exit /b 1
)

if /I "%~1"=="--skip-install" goto :skip_install
if /I "%~1"=="skip-install" goto :skip_install

echo [INFO] Installing/updating dependencies...
python -m pip install --upgrade pip
if errorlevel 1 (
    echo [ERROR] Failed to upgrade pip.
    goto :fail
)
python -m pip install -r "%REQ%"
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies.
    goto :fail
)

:skip_install
if "%GROQ_API_KEY%"=="" (
    echo [WARN] GROQ_API_KEY not set. AI-powered fixes will be disabled.
    echo        Set it in your environment or add GROQ_API_KEY=your_key to a .env file.
) else (
    echo [OK] GROQ_API_KEY detected.
)

echo.
echo [INFO] Starting SecureMCP on http://localhost:5000
echo Press Ctrl+C to stop the server.
echo.

python "%APP%"
set "EXIT_CODE=%ERRORLEVEL%"

call "%VENV%\Scripts\deactivate.bat" >nul 2>&1
exit /b %EXIT_CODE%

:fail
call "%VENV%\Scripts\deactivate.bat" >nul 2>&1
pause
exit /b 1

:help
echo Usage: run.bat [--skip-install ^| --help]
echo.
echo --skip-install   Use existing venv and dependencies without reinstalling.
echo --help           Show this help message.
echo.
echo The script will create and reuse %VENV% automatically.
exit /b 0
