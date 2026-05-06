@echo off
title SecReport Generator - Desktop

echo ============================================================
echo   SecReport Generator - Desktop Launcher
echo ============================================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.8+
    echo Download: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

:: Check Node.js
node --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js not found. Please install Node.js 18+
    echo Download: https://nodejs.org/
    echo.
    pause
    exit /b 1
)

:: Check and install Python dependencies
echo [1/3] Checking Python dependencies...
pip show flask >nul 2>&1
if errorlevel 1 (
    echo Installing Python dependencies...
    pip install -r requirements.txt
)

:: Check and install Electron dependencies
echo [2/3] Checking Electron dependencies...
if not exist "node_modules\electron" (
    echo Installing Electron dependencies (may take a few minutes)...
    npm install
)

:: Launch
echo [3/3] Starting desktop app...
echo.
npx electron .

if errorlevel 1 (
    echo.
    echo [ERROR] Launch failed
    pause
)
