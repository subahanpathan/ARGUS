# ARGUS Endpoint Security Sensor Launcher for PowerShell
param(
    [string]$TargetUrl = "",
    [string]$Mode = "BACKGROUND"
)

$ErrorActionPreference = "SilentlyContinue"

if (-not $TargetUrl) {
    if ($env:ARGUS_API_BASE_URL) {
        $TargetUrl = $env:ARGUS_API_BASE_URL
    } else {
        $TargetUrl = "http://localhost:5000"
    }
}

$SensorDir = Join-Path $env:APPDATA "Argus"
if (-not (Test-Path $SensorDir)) {
    New-Item -ItemType Directory -Path $SensorDir -Force | Out-Null
}

$SensorScript = Join-Path $SensorDir "argus_sensor.py"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "         ARGUS Real-Time Windows Endpoint Sensor               " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Target Dashboard : $TargetUrl" -ForegroundColor Green

# Fetch latest sensor script from backend if missing or outdated
try {
    Invoke-WebRequest -Uri "$TargetUrl/argus_sensor.py" -OutFile $SensorScript -UseBasicParsing
} catch {
    Write-Host "[*] Could not reach $TargetUrl/argus_sensor.py directly, checking local workspace..." -ForegroundColor Yellow
}

if (-not (Test-Path $SensorScript)) {
    Write-Error "Could not locate or download argus_sensor.py script!"
    exit 1
}

# Verify Python runtime
$PythonExe = (Get-Command pythonw -ErrorAction SilentlyContinue).Source
if (-not $PythonExe) {
    $PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
}

if (-not $PythonExe) {
    Write-Error "Python runtime not found in PATH! Please install Python 3.10+ from python.org"
    exit 1
}

# Ensure psutil and requests
Start-Process -FilePath $PythonExe -ArgumentList "-m pip install -q psutil requests" -Wait -WindowStyle Hidden

if ($Mode -eq "STOP") {
    Get-Process -Name "python", "pythonw" | Where-Object { $_.CommandLine -like "*argus_sensor.py*" } | Stop-Process -Force
    Write-Host "[+] ARGUS Sensor background service stopped successfully." -ForegroundColor Yellow
    exit 0
}

# Launch sensor process
if ($Mode -eq "BACKGROUND") {
    Start-Process -FilePath $PythonExe -ArgumentList "`"$SensorScript`" --api `"$TargetUrl`"" -WindowStyle Hidden
    Write-Host "[+] ARGUS Real-Time Windows Sensor launched in silent background mode!" -ForegroundColor Green
    Write-Host "[+] Endpoint telemetry streaming live to $TargetUrl" -ForegroundColor Green
} else {
    Write-Host "[*] Launching ARGUS Sensor in foreground console..." -ForegroundColor Cyan
    & $PythonExe "$SensorScript" --api "$TargetUrl"
}
