<#
.SYNOPSIS
    Endpoint Guard - Host Detection and Response (EDR / HIDS) Automated Installer.
.DESCRIPTION
    Configures secure directories in C:\ProgramData\EndpointGuard, locks ACL permissions to
    Administrators and SYSTEM, creates firewall rule groups, deploys honeypot canaries, and
    registers a Windows auto-start task with highest administrative privileges.
#>

[CmdletBinding()]
param(
    [switch]$SkipTask
)

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "         ENDPOINT GUARD - DEFENSIVE EDR INSTALLER          " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Administrator Check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error @"
[!] ELEVATION REQUIRED:
This installer requires Administrator privileges to:
  1. Configure Windows Firewall rules to block attacker IPs
  2. Terminate malicious process trees and inspect low-level sockets
  3. Secure C:\ProgramData\EndpointGuard with SYSTEM/Admin ACLs
  4. Register auto-start services in Task Scheduler

Please right-click PowerShell and select 'Run as Administrator', then rerun this script.
"@
    exit 1
}

Write-Host "[+] Administrator privileges verified." -ForegroundColor Green

# 2. Directory Creation
$DataDir = "C:\ProgramData\EndpointGuard"
$QuarantineDir = "$DataDir\quarantine"
$IncidentDir = "$DataDir\incidents"
$CanaryDir = "$DataDir\canaries"

foreach ($dir in @($DataDir, $QuarantineDir, $IncidentDir, $CanaryDir)) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "[+] Created directory: $dir" -ForegroundColor Gray
    }
}

# 3. Secure NTFS Permissions (SYSTEM & Administrators only)
Write-Host "[*] Restricting directory ACLs to SYSTEM and Administrators..." -ForegroundColor Yellow
try {
    & icacls "$DataDir" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
    Write-Host "[+] ACL permissions locked successfully." -ForegroundColor Green
} catch {
    Write-Warning "[-] Note: Could not set strict ACLs: $_"
}

# 4. Check Python & Dependencies
Write-Host "[*] Checking Python environment..." -ForegroundColor Yellow
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) {
    Write-Error "[-] Python was not found on PATH. Please install Python 3.11+ and try again."
    exit 1
}

$pyVersion = & python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
Write-Host "[+] Detected Python $pyVersion at $($py.Source)" -ForegroundColor Green

$reqFile = Join-Path $PSScriptRoot "..\requirements.txt"
if (Test-Path $reqFile) {
    Write-Host "[*] Installing/verifying dependencies from requirements.txt..." -ForegroundColor Yellow
    & python -m pip install -r "$reqFile" --quiet
    Write-Host "[+] Python packages ready." -ForegroundColor Green
}

# 5. Initialize Database & Honeypots
Write-Host "[*] Initializing database and deploying decoy canary files..." -ForegroundColor Yellow
$setupScript = Join-Path $PSScriptRoot "..\endpoint_guard\config.py"
& python -c "from endpoint_guard.config import Config; from endpoint_guard.database.manager import DatabaseManager; from endpoint_guard.response.canary_manager import CanaryManager; c = Config(); db = DatabaseManager(c.db_path); cm = CanaryManager(c); print('[+] Database and canaries deployed.');"

# 6. Register Windows Auto-Start Task (Boot with Highest Privileges)
if (-not $SkipTask) {
    Write-Host "[*] Registering Endpoint Guard auto-start scheduled task..." -ForegroundColor Yellow
    $taskName = "EndpointGuardDefenseService"
    $serviceScript = (Resolve-Path (Join-Path $PSScriptRoot "..\endpoint_guard\service\windows_service.py")).Path
    $pyExe = (Get-Command python).Source

    $action = New-ScheduledTaskAction -Execute $pyExe -Argument "`"$serviceScript`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
        Write-Host "[+] Scheduled task '$taskName' registered to auto-start on boot as SYSTEM." -ForegroundColor Green
    } catch {
        Write-Warning "[-] Note: Could not register scheduled task: $_. You can still run Endpoint Guard via CLI."
    }
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "        ENDPOINT GUARD INSTALLATION COMPLETE!               " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "To run interactive SOC Console & Tray Icon:" -ForegroundColor White
Write-Host "  python endpoint_guard\main.py" -ForegroundColor Yellow
Write-Host "To access local Web Console:" -ForegroundColor White
Write-Host "  http://127.0.0.1:8443" -ForegroundColor Cyan
Write-Host ""
