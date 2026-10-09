@echo off
setlocal enabledelayedexpansion
title ARGUS Endpoint Security Sensor

set TARGET_URL=
set MODE=
set SCRIPT_DIR=%~dp0

:: Parse arguments
:parse_args
if "%~1"=="" goto done_args
if /i "%~1"=="--stop" (set MODE=STOP& shift& goto parse_args)
if /i "%~1"=="-stop" (set MODE=STOP& shift& goto parse_args)
if /i "%~1"=="/stop" (set MODE=STOP& shift& goto parse_args)
if /i "%~1"=="--status" (set MODE=STATUS& shift& goto parse_args)
if /i "%~1"=="-status" (set MODE=STATUS& shift& goto parse_args)
if /i "%~1"=="/status" (set MODE=STATUS& shift& goto parse_args)
if /i "%~1"=="--background" (set MODE=BACKGROUND& shift& goto parse_args)
if /i "%~1"=="-background" (set MODE=BACKGROUND& shift& goto parse_args)
if /i "%~1"=="/background" (set MODE=BACKGROUND& shift& goto parse_args)
if /i "%~1"=="--install" (set MODE=BACKGROUND& shift& goto parse_args)
if /i "%~1"=="-install" (set MODE=BACKGROUND& shift& goto parse_args)
if /i "%~1"=="/install" (set MODE=BACKGROUND& shift& goto parse_args)
if /i "%~1"=="--foreground" (set MODE=FOREGROUND& shift& goto parse_args)
if /i "%~1"=="-foreground" (set MODE=FOREGROUND& shift& goto parse_args)
if "%TARGET_URL%"=="" (set TARGET_URL=%~1& shift& goto parse_args)
shift
goto parse_args
:done_args

if "%TARGET_URL%"=="" (
    if defined ARGUS_API_BASE_URL (
        set TARGET_URL=%ARGUS_API_BASE_URL%
    ) else (
        set TARGET_URL=http://localhost:5000
    )
)
set ARGUS_API_BASE_URL=%TARGET_URL%

echo ================================================================
echo           ARGUS Real-Time Windows Endpoint Sensor
echo ================================================================
echo Target Dashboard : %TARGET_URL%
echo.

:: 1. Verify Python & pythonw
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python 3.10+ was not found in PATH.
    echo Please install Python 3.10+ from https://www.python.org/
    echo Be sure to check "Add Python to PATH" during installation.
    echo.
    if "%MODE%"=="" pause
    exit /b 1
)

:: 2. Ensure dependencies
python -m pip install -q psutil requests >nul 2>&1

:: 3. Prepare persistent AppData directory
set SENSOR_DIR=%APPDATA%\Argus
if not exist "%SENSOR_DIR%" mkdir "%SENSOR_DIR%"

:: Locate local or download argus_sensor.py
if exist "%SCRIPT_DIR%argus_sensor.py" (
    copy /y "%SCRIPT_DIR%argus_sensor.py" "%SENSOR_DIR%\argus_sensor.py" >nul 2>&1
) else if exist "artifacts\argus\public\argus_sensor.py" (
    copy /y "artifacts\argus\public\argus_sensor.py" "%SENSOR_DIR%\argus_sensor.py" >nul 2>&1
) else (
    if not exist "%SENSOR_DIR%\argus_sensor.py" (
        echo [*] Fetching sensor script from %TARGET_URL%...
        powershell -Command "try { Invoke-WebRequest -Uri '%TARGET_URL%/argus_sensor.py' -OutFile '%SENSOR_DIR%\argus_sensor.py' } catch {}"
    )
)

:: Handle explicit stop/status flags
if "%MODE%"=="STOP" goto do_stop
if "%MODE%"=="STATUS" goto do_status
if "%MODE%"=="BACKGROUND" goto do_background
if "%MODE%"=="FOREGROUND" goto do_foreground

:: Interactive Menu when double-clicked without flags
echo Select operational mode:
echo   [1] Install ^& Run Silently in Background (Windows Auto-Start) [RECOMMENDED]
echo   [2] Run in Foreground Console (Monitor live output in this window)
echo   [3] Check Background Sensor Status
echo   [4] Stop Background Sensor Service
echo   [5] Exit
echo.
set /p USER_CHOICE="Enter selection [1-5] (Default: 1): "
if "%USER_CHOICE%"=="" set USER_CHOICE=1
if "%USER_CHOICE%"=="1" goto do_background
if "%USER_CHOICE%"=="2" goto do_foreground
if "%USER_CHOICE%"=="3" goto do_status_interactive
if "%USER_CHOICE%"=="4" goto do_stop_interactive
if "%USER_CHOICE%"=="5" exit /b 0

:do_background
echo.
echo [*] Configuring silent Windows background service...
python "%SENSOR_DIR%\argus_sensor.py" --stop >nul 2>&1

schtasks /create /tn "ARGUS_Endpoint_Sensor" /tr "pythonw.exe \"%SENSOR_DIR%\argus_sensor.py\" %TARGET_URL% --daemon" /sc onlogon /f >nul 2>&1
if %errorlevel% neq 0 (
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "ARGUS_Endpoint_Sensor" /t REG_SZ /d "pythonw.exe \"%SENSOR_DIR%\argus_sensor.py\" %TARGET_URL% --daemon" /f >nul 2>&1
)

powershell -Command "Start-Process 'pythonw.exe' -ArgumentList '\"%SENSOR_DIR%\argus_sensor.py\" \"%TARGET_URL%\" --daemon' -WindowStyle Hidden"

ping -n 3 127.0.0.1 >nul 2>&1
echo ================================================================
echo  [+] ARGUS Sensor is now RUNNING SILENTLY in the background!
echo ================================================================
echo  * Process Subsystem : pythonw.exe (0 visible windows)
echo  * Auto-Start        : Enabled (Windows Logon)
echo  * Target Dashboard : %TARGET_URL%
echo  * Sensor Directory : %SENSOR_DIR%
echo  * Log File         : %SENSOR_DIR%\sensor.log
echo.
python "%SENSOR_DIR%\argus_sensor.py" --status
echo.
echo Telemetry is streaming live. You may safely close this window.
ping -n 5 127.0.0.1 >nul 2>&1
exit /b 0

:do_foreground
echo.
echo [*] Launching interactive foreground sensor (Press Ctrl+C to stop)...
python "%SENSOR_DIR%\argus_sensor.py" %TARGET_URL%
pause
exit /b 0

:do_status_interactive
echo.
echo [*] Querying ARGUS Sensor state...
python "%SENSOR_DIR%\argus_sensor.py" --status
echo.
pause
exit /b 0

:do_status
python "%SENSOR_DIR%\argus_sensor.py" --status
exit /b 0

:do_stop_interactive
echo.
echo [*] Stopping ARGUS Sensor background service...
python "%SENSOR_DIR%\argus_sensor.py" --stop
schtasks /delete /tn "ARGUS_Endpoint_Sensor" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "ARGUS_Endpoint_Sensor" /f >nul 2>&1
echo [+] Auto-start task removed.
echo.
pause
exit /b 0

:do_stop
python "%SENSOR_DIR%\argus_sensor.py" --stop
schtasks /delete /tn "ARGUS_Endpoint_Sensor" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "ARGUS_Endpoint_Sensor" /f >nul 2>&1
exit /b 0
