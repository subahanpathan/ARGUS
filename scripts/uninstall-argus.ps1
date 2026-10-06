# ARGUS Security Intelligence — PowerShell Application Uninstaller
param(
    [string]$TargetDir = "C:\Program Files\ARGUS",
    [string]$DataDir = "C:\ProgramData\ARGUS",
    [switch]$KeepData = $false
)

$ErrorActionPreference = "Continue"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Uninstalling ARGUS Security Intelligence                  " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Stop Background Services
$ServiceScript = Join-Path $TargetDir "argus-service.ps1"
if (Test-Path $ServiceScript) {
    Write-Host "[1/3] Stopping background services..." -ForegroundColor Yellow
    & powershell.exe -ExecutionPolicy Bypass -File $ServiceScript stop -InstallDir $TargetDir -DataDir $DataDir
}

# 2. Remove Desktop & Start Menu Shortcuts
Write-Host "[2/3] Removing shortcuts..." -ForegroundColor Yellow
$DesktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
$ShortcutDesktop = Join-Path $DesktopPath "ARGUS Security Intelligence.url"
if (Test-Path $ShortcutDesktop) { Remove-Item $ShortcutDesktop -Force }

$StartMenuPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Programs)
$ArgusMenuDir = Join-Path $StartMenuPath "ARGUS Security"
if (Test-Path $ArgusMenuDir) { Remove-Item $ArgusMenuDir -Recurse -Force }

# 3. Remove Program Files and (Optionally) ProgramData
Write-Host "[3/3] Cleaning up application binaries..." -ForegroundColor Yellow
if (Test-Path $TargetDir) {
    Remove-Item $TargetDir -Recurse -Force -ErrorAction SilentlyContinue
}

if (-not $KeepData -and (Test-Path $DataDir)) {
    Write-Host "  Removing application data and logs ($DataDir)..." -ForegroundColor Yellow
    Remove-Item $DataDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "============================================================" -ForegroundColor Green
Write-Host " ARGUS Security Intelligence Uninstalled Cleanly.          " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
