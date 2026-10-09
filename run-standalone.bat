@echo off
setlocal
title ARGUS Standalone Server (Port 5000)
cd /d "%~dp0"

echo ========================================================
echo   ARGUS Standalone Server
echo   Activation Key: ARGUS-DEV-2026
echo ========================================================
echo.

:: Ensure public dashboard is copied to api-server dist
if not exist "artifacts\api-server\dist\public" (
    echo Copying pre-built UI dashboard to api-server...
    xcopy /E /I /Y /Q "artifacts\argus\dist\public" "artifacts\api-server\dist\public" >nul
)

set "ARGUS_DEV_ACCESS_KEY=ARGUS-DEV-2026"
set "PORT=5000"

echo Starting server on http://localhost:5000...
cd /d "%~dp0artifacts\api-server"

start "" http://localhost:5000
node dist\index.mjs

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Server exited with code %ERRORLEVEL%.
    pause
)
