# ARGUS Security Intelligence — PowerShell Application Installer
param(
    [string]$TargetDir = "C:\Program Files\ARGUS",
    [string]$DataDir = "C:\ProgramData\ARGUS",
    [int]$Port = 5000,
    [string]$AccessKey = "ARGUS-DEV-2026"
)

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Installing ARGUS Security Intelligence Application        " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$WorkspaceRoot = Split-Path -Parent $PSScriptRoot
$SourceDist = Join-Path $WorkspaceRoot "dist\production"

# Ensure production build exists
if (-not (Test-Path $SourceDist)) {
    Write-Host "Production payload not found. Running build..." -ForegroundColor Yellow
    & "$PSScriptRoot\build-production.ps1"
}

# 1. Prepare Target Directory Structure
Write-Host "[1/5] Creating application directories..." -ForegroundColor Yellow
New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $DataDir "logs") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $DataDir "db") -Force | Out-Null

# 2. Deploy Application Binaries to Program Files
Write-Host "[2/5] Deploying binaries to $TargetDir..." -ForegroundColor Yellow
Copy-Item -Path "$SourceDist\*" -Destination $TargetDir -Recurse -Force
Copy-Item -Path "$PSScriptRoot\argus-service.ps1" -Destination $TargetDir -Force

# 3. Create Default Environment Configuration
Write-Host "[3/5] Initializing ProgramData configuration..." -ForegroundColor Yellow
$ConfigFile = Join-Path $DataDir "argus.env"
@"
PORT=$Port
ARGUS_DEV_ACCESS_KEY=$AccessKey
ARGUS_DATA_DIR=$DataDir
ARGUS_API_BASE_URL=http://localhost:$Port
NODE_ENV=production
"@ | Out-File -FilePath $ConfigFile -Encoding utf8 -Force

# 4. Create Desktop & Start Menu Shortcuts
Write-Host "[4/5] Creating Shortcuts..." -ForegroundColor Yellow
$WshShell = New-Object -ComObject WScript.Shell

$DesktopPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
$ShortcutDesktop = $WshShell.CreateShortcut((Join-Path $DesktopPath "ARGUS Security Intelligence.url"))
$ShortcutDesktop.TargetPath = "http://localhost:$Port"
$ShortcutDesktop.Save()

$StartMenuPath = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Programs)
$ArgusMenuDir = Join-Path $StartMenuPath "ARGUS Security"
New-Item -ItemType Directory -Path $ArgusMenuDir -Force | Out-Null
$ShortcutStartMenu = $WshShell.CreateShortcut((Join-Path $ArgusMenuDir "ARGUS Dashboard.url"))
$ShortcutStartMenu.TargetPath = "http://localhost:$Port"
$ShortcutStartMenu.Save()

# 5. Start Background Services
Write-Host "[5/5] Launching ARGUS Background Services..." -ForegroundColor Yellow
$ServiceScript = Join-Path $TargetDir "argus-service.ps1"
& powershell.exe -ExecutionPolicy Bypass -File $ServiceScript start -InstallDir $TargetDir -DataDir $DataDir -Port $Port -AccessKey $AccessKey

Write-Host "============================================================" -ForegroundColor Green
Write-Host " ARGUS Security Intelligence Installed Successfully!       " -ForegroundColor Green
Write-Host " Application Root: $TargetDir                             " -ForegroundColor Green
Write-Host " Data & Logs:     $DataDir                               " -ForegroundColor Green
Write-Host " Access Dashboard: http://localhost:$Port                  " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
