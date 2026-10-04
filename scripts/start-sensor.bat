@echo off
title ARGUS Endpoint Security Sensor
cls
echo ================================================================
echo           ARGUS Real-Time Windows Endpoint Sensor
echo ================================================================
echo.
echo [1/3] Verifying Python runtime...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python 3.10+ is required to sample Windows telemetry.
    echo Please download and install Python from https://www.python.org/
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo [2/3] Checking required libraries (psutil)...
python -m pip install -q psutil

echo [3/3] Launching live Windows security sensor...
echo ----------------------------------------------------------------
echo Streaming live CPU, RAM, Disk, Sockets, and Process telemetry
echo to your ARGUS dashboard tab at http://localhost:5000
echo.
echo Keep this window open while monitoring your computer.
echo Press Ctrl+C to stop the sensor anytime.
echo ----------------------------------------------------------------
echo.

python artifacts/security-engine/main.py --api --snapshot
pause
