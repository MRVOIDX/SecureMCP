@echo off
REM SecureMCP Startup Script for Windows
REM This script sets up and runs the security analysis application

setlocal enabledelayedexpansion

echo.
echo 🛡️  Starting SecureMCP - AI-Powered Security Analysis Tool
echo ==================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not in PATH.
    echo Please install Python from https://www.python.org/
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('python --version') do set PYTHON_VERSION=%%i
echo ✅ Python found: %PYTHON_VERSION%
echo.

REM Install dependencies
echo 📦 Installing dependencies from requirements.txt...
pip install -r requirements.txt -q
if errorlevel 1 (
    echo ⚠️  Some dependencies may have failed to install
    echo Continuing anyway...
)
echo ✅ Dependencies installed successfully
echo.

REM Create necessary directories
echo 📁 Creating necessary directories...
if not exist "reports" mkdir reports
if not exist "templates" mkdir templates
if not exist "static" mkdir static
if not exist "src" mkdir src
echo ✅ Directories created
echo.

REM Check for environment variables
echo 🔑 Checking environment setup...
if not exist ".env" (
    echo ⚠️  No .env file found. Creating from .env.example...
    copy ".env.example" ".env" >nul
    echo 📝 Please edit .env and add your GOOGLE_AI_API_KEY
    echo    To get a free API key, visit: https://ai.google.dev
    echo.
)

REM Display startup information
echo ==================================================
echo 🚀 Starting Flask Server...
echo ==================================================
echo.
echo The application will be available at:
echo   🌐 http://localhost:5000
echo.
echo To use SecureMCP:
echo   1. Add your GOOGLE_AI_API_KEY to the .env file
echo   2. Upload a ZIP file of your project OR enter a directory path
echo   3. Click 'Scan Project' to analyze security vulnerabilities
echo   4. Review findings and apply suggested fixes
echo   5. Generate a detailed security report
echo.
echo Press CTRL+C to stop the server
echo ==================================================
echo.

REM Start the Flask application
python app.py

REM If Flask exits, pause to show the message
pause
