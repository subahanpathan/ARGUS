# ARGUS Live Windows Endpoint Sensor Launcher (PowerShell)
param(
    [string]$TargetUrl = "",
    [switch]$Background,
    [switch]$Install,
    [switch]$Stop,
    [switch]$Status,
    [switch]$Foreground
)

if (-not $TargetUrl) {
    if ($env:ARGUS_API_BASE_URL) {
        $TargetUrl = $env:ARGUS_API_BASE_URL
    } else {
        $TargetUrl = "http://localhost:5000"
    }
}
$env:ARGUS_API_BASE_URL = $TargetUrl

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "          ARGUS Real-Time Windows Endpoint Sensor               " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Target Dashboard : $TargetUrl" -ForegroundColor Yellow
Write-Host ""

# 1. Verify Python
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Host "[!] Python 3.10+ was not found in your PATH." -ForegroundColor Red
    Write-Host "    Please install Python from https://www.python.org/ (check 'Add Python to PATH')" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

$pythonwCmd = Get-Command pythonw -ErrorAction SilentlyContinue
$pythonwPath = if ($pythonwCmd) { $pythonwCmd.Source } else { "pythonw.exe" }

# 2. Check dependencies
Write-Host "[*] Checking required libraries (psutil, requests)..." -ForegroundColor DarkGray
python -m pip install -q psutil requests

# 3. Setup persistent directory
$SensorDir = "$env:APPDATA\Argus"
if (-not (Test-Path $SensorDir)) {
    New-Item -ItemType Directory -Path $SensorDir -Force | Out-Null
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($ScriptDir -and (Test-Path "$ScriptDir\argus_sensor.py")) {
    Copy-Item "$ScriptDir\argus_sensor.py" "$SensorDir\argus_sensor.py" -Force
} elseif (Test-Path "artifacts\argus\public\argus_sensor.py") {
    Copy-Item "artifacts\argus\public\argus_sensor.py" "$SensorDir\argus_sensor.py" -Force
} else {
    try {
        Invoke-WebRequest -Uri "$TargetUrl/argus_sensor.py" -OutFile "$SensorDir\argus_sensor.py"
    } catch {
        try {
            Invoke-WebRequest -Uri "http://localhost:5173/argus_sensor.py" -OutFile "$SensorDir\argus_sensor.py"
        } catch {}
    }
}

# Handle actions
if ($Stop) {
    Write-Host "[*] Stopping ARGUS Sensor..." -ForegroundColor Yellow
    python "$SensorDir\argus_sensor.py" --stop
    try { Unregister-ScheduledTask -TaskName "ARGUS_Endpoint_Sensor" -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "ARGUS_Endpoint_Sensor" /f 2>$null | Out-Null
    Write-Host "[+] ARGUS Sensor background task stopped and removed." -ForegroundColor Green
    exit 0
}

if ($Status) {
    python "$SensorDir\argus_sensor.py" --status
    exit 0
}

# If not explicitly background or foreground, prompt user or default
if (-not $Background -and -not $Install -and -not $Foreground) {
    Write-Host "Select execution mode:" -ForegroundColor White
    Write-Host "  [1] Install & Run Silently in Background (Windows Auto-Start) [RECOMMENDED]" -ForegroundColor Green
    Write-Host "  [2] Run in Foreground Console (Monitor live output)" -ForegroundColor White
    Write-Host "  [3] Check Sensor Status" -ForegroundColor White
    Write-Host "  [4] Stop Background Sensor Service" -ForegroundColor White
    $choice = Read-Host "Enter selection [1-4] (Default: 1)"
    if (-not $choice) { $choice = "1" }
    
    if ($choice -eq "2") { $Foreground = $true }
    elseif ($choice -eq "3") { python "$SensorDir\argus_sensor.py" --status; exit 0 }
    elseif ($choice -eq "4") {
        python "$SensorDir\argus_sensor.py" --stop
        try { Unregister-ScheduledTask -TaskName "ARGUS_Endpoint_Sensor" -Confirm:$false -ErrorAction SilentlyContinue } catch {}
        reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "ARGUS_Endpoint_Sensor" /f 2>$null | Out-Null
        exit 0
    }
    else { $Background = $true }
}

if ($Background -or $Install) {
    Write-Host "[*] Configuring silent background service..." -ForegroundColor Cyan
    # Stop existing
    python "$SensorDir\argus_sensor.py" --stop 2>$null | Out-Null

    # 1. Register Task Scheduler for auto boot
    try {
        $action = New-ScheduledTaskAction -Execute $pythonwPath -Argument "`"$SensorDir\argus_sensor.py`" $TargetUrl --daemon"
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0
        Register-ScheduledTask -TaskName "ARGUS_Endpoint_Sensor" -Action $action -Trigger $trigger -Settings $settings -Force -ErrorAction SilentlyContinue | Out-Null
    } catch {
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "ARGUS_Endpoint_Sensor" /t REG_SZ /d "`"$pythonwPath`" `"$SensorDir\argus_sensor.py`" $TargetUrl --daemon" /f 2>$null | Out-Null
    }

    # 2. Launch detached silent background process (lives independently of terminal)
    try {
        $wscript = New-Object -ComObject WScript.Shell
        $wscript.Run("pythonw.exe `"$SensorDir\argus_sensor.py`" $TargetUrl --daemon", 0, $false)
    } catch {
        Start-Process -FilePath $pythonwPath -ArgumentList "`"$SensorDir\argus_sensor.py`" $TargetUrl --daemon" -WindowStyle Hidden
    }
    Start-Sleep -Seconds 2

    Write-Host "================================================================" -ForegroundColor Green
    Write-Host " [+] ARGUS Sensor is now RUNNING SILENTLY in the background!     " -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host " * Process Subsystem : pythonw.exe (0 visible windows)" -ForegroundColor White
    Write-Host " * Auto-Start        : Enabled on Windows Logon" -ForegroundColor White
    Write-Host " * Dashboard Target : $TargetUrl" -ForegroundColor Cyan
    Write-Host " * Sensor Directory : $SensorDir" -ForegroundColor DarkGray
    Write-Host " * Log File         : $SensorDir\sensor.log" -ForegroundColor DarkGray
    Write-Host ""
    python "$SensorDir\argus_sensor.py" --status
    exit 0
}

# Foreground mode
Write-Host "[*] Running foreground sensor (Press Ctrl+C to stop)..." -ForegroundColor Green
python "$SensorDir\argus_sensor.py" $TargetUrl
