# ARGUS Live Windows Endpoint Sensor Launcher (PowerShell)
param(
    [string]$TargetUrl = "http://localhost:5000"
)

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "          ARGUS Real-Time Windows Endpoint Sensor               " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check Python
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "[!] Python 3.10+ was not found in your PATH." -ForegroundColor Red
    Write-Host "    Please install Python from https://www.python.org/ (check 'Add Python to PATH')" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "[1/3] Python detected: $(python --version)" -ForegroundColor Green

# 2. Check dependencies
Write-Host "[2/3] Checking required libraries (psutil, requests)..." -ForegroundColor Yellow
python -m pip install -q psutil requests

# 3. Target setup
$env:ARGUS_API_BASE_URL = $TargetUrl
Write-Host "[3/3] Target dashboard configured: $TargetUrl" -ForegroundColor Green

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if (Test-Path "$ScriptDir\argus_sensor.py") {
    python "$ScriptDir\argus_sensor.py" $TargetUrl
    exit 0
}

if (Test-Path "artifacts\security-engine\main.py") {
    python artifacts\security-engine\main.py --api --snapshot
    exit 0
}

# Download argus_sensor.py if not local
try {
    Write-Host "[*] Fetching latest sensor agent..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri "$TargetUrl/argus_sensor.py" -OutFile "$env:TEMP\argus_sensor.py"
    python "$env:TEMP\argus_sensor.py" $TargetUrl
} catch {
    Write-Host "[!] Fallback: streaming directly via python..." -ForegroundColor Yellow
    irm "$TargetUrl/argus_sensor.py" | python -
}
