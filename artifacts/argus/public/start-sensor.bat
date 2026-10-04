@echo off
setlocal enabledelayedexpansion
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
    echo CRITICAL: Ensure you check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo [2/3] Checking required libraries (psutil, requests)...
python -m pip install -q psutil requests >nul 2>&1

set TARGET_URL=%1
if "%TARGET_URL%"=="" set TARGET_URL=http://localhost:5000
set ARGUS_API_BASE_URL=%TARGET_URL%

echo [3/3] Preparing live Windows sensor agent...

cd /d "%~dp0"

if exist "argus_sensor.py" (
    python argus_sensor.py %TARGET_URL%
    goto done
)

if exist "artifacts\security-engine\main.py" (
    python artifacts\security-engine\main.py --api --snapshot
    goto done
)

if exist "..\artifacts\security-engine\main.py" (
    cd ..
    python artifacts\security-engine\main.py --api --snapshot
    goto done
)

echo [*] Downloading latest sensor module...
powershell -Command "try { Invoke-WebRequest -Uri '%TARGET_URL%/argus_sensor.py' -OutFile 'argus_sensor.py' } catch { try { Invoke-WebRequest -Uri 'http://localhost:5173/argus_sensor.py' -OutFile 'argus_sensor.py' } catch {} }"

if exist "argus_sensor.py" (
    python argus_sensor.py %TARGET_URL%
    goto done
)

echo [*] Running inline sensor script...
powershell -Command "irm '%TARGET_URL%/argus_sensor.py' | python -"

:done
pause
