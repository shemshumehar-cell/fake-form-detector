@echo off
title Fake Form Detector - BUILD SECURE 2026
echo ============================================================
echo   FAKE FORM DETECTOR - BUILD SECURE 2026
echo   "Is This Website Safe?" - Passive Web Security Inspector
echo ============================================================
echo.
echo Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not found in your system PATH.
    echo Please install Python 3.8+ from python.org and check "Add Python to PATH".
    pause
    exit /b 1
)

echo Installing / verifying dependencies...
python -m pip install -r requirements.txt --quiet

echo.
echo Starting Fake Form Detector on http://127.0.0.1:5000 ...
echo Press Ctrl+C in this terminal window to stop the server.
echo.

start http://127.0.0.1:5000
python app.py

pause
