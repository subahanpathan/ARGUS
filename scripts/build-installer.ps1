# ARGUS Security Intelligence — Reproducible Desktop App & Installer Builder
$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Building ARGUS Desktop Application & Windows Installer    " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$WorkspaceRoot = Split-Path -Parent $PSScriptRoot
Set-Location $WorkspaceRoot

$PnpmCmd = Join-Path $WorkspaceRoot "pnpm.cmd"
if (-not (Test-Path $PnpmCmd)) { $PnpmCmd = "pnpm" }

# Step 1: Typecheck workspace
Write-Host "[1/7] Running TypeScript Workspace Check..." -ForegroundColor Yellow
& $PnpmCmd run typecheck
if ($LASTEXITCODE -ne 0) {
    Write-Error "Typecheck failed!"
    exit 1
}

# Step 2: Build API Server
Write-Host "[2/7] Compiling API Server..." -ForegroundColor Yellow
& $PnpmCmd --filter @workspace/api-server run build
if ($LASTEXITCODE -ne 0) {
    Write-Error "API server build failed!"
    exit 1
}

# Step 3: Build React Frontend
Write-Host "[3/7] Building React Dashboard Frontend..." -ForegroundColor Yellow
& $PnpmCmd --filter @workspace/argus run build
if ($LASTEXITCODE -ne 0) {
    Write-Error "Frontend build failed!"
    exit 1
}

# Step 4: Stage Frontend into API Server public directory
Write-Host "[4/7] Staging compiled UI into API Server static output..." -ForegroundColor Yellow
$ApiPublic = Join-Path $WorkspaceRoot "artifacts\api-server\dist\public"
if (Test-Path $ApiPublic) { Remove-Item $ApiPublic -Recurse -Force }
New-Item -ItemType Directory -Path $ApiPublic -Force | Out-Null
Copy-Item -Path "$WorkspaceRoot\artifacts\argus\dist\public\*" -Destination $ApiPublic -Recurse -Force

# Step 5: Assemble Production Payload Directory Structure
Write-Host "[5/7] Assembling Launcher Payload..." -ForegroundColor Yellow
$PayloadDir = Join-Path $PSScriptRoot "_launcher_payload"
$PayloadApi = Join-Path $PayloadDir "api-server"
$PayloadEngine = Join-Path $PayloadDir "engine"
$PayloadRuntime = Join-Path $PayloadDir "runtime"

New-Item -ItemType Directory -Path $PayloadApi -Force | Out-Null
New-Item -ItemType Directory -Path $PayloadEngine -Force | Out-Null
New-Item -ItemType Directory -Path $PayloadRuntime -Force | Out-Null

# Copy API server compiled output
Copy-Item -Path "$WorkspaceRoot\artifacts\api-server\dist\*" -Destination $PayloadApi -Recurse -Force

# Copy Security Engine output
Copy-Item -Path "$WorkspaceRoot\artifacts\security-engine\*" -Destination $PayloadEngine -Recurse -Force
if (Test-Path "$WorkspaceRoot\artifacts\security-engine\dist\argus-agent.exe") {
    Copy-Item -Path "$WorkspaceRoot\artifacts\security-engine\dist\argus-agent.exe" -Destination (Join-Path $PayloadEngine "argus-agent.exe") -Force
}

# Locate Node binary for runtime payload
$NodeSystemPath = (Get-Command node -ErrorAction SilentlyContinue).Source
if ($NodeSystemPath -and (Test-Path $NodeSystemPath)) {
    Copy-Item -Path $NodeSystemPath -Destination (Join-Path $PayloadRuntime "node.exe") -Force
}

# Step 6: Build Standalone Installer Executable via PyInstaller
Write-Host "[6/7] Compiling Windows Installer via PyInstaller..." -ForegroundColor Yellow
$DistInstaller = Join-Path $WorkspaceRoot "dist\installer"
$BuildWork = Join-Path $PSScriptRoot "build"
if (-not (Test-Path $DistInstaller)) { New-Item -ItemType Directory -Path $DistInstaller -Force | Out-Null }

python -m PyInstaller --noconfirm "$PSScriptRoot\ARGUS.spec" --distpath $DistInstaller --workpath $BuildWork
if ($LASTEXITCODE -ne 0) {
    Write-Error "PyInstaller build failed!"
    exit 1
}

# Step 7: Sync Installer Executable to Frontend Assets
Write-Host "[7/7] Syncing Installer to Distribution Directory..." -ForegroundColor Yellow
node "$PSScriptRoot\copy-installer.mjs"

$InstallerPath = Join-Path $DistInstaller "ARGUS-Setup.exe"
if (Test-Path $InstallerPath) {
    $SizeMB = [math]::Round((Get-Item $InstallerPath).Length / 1MB, 2)
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host " ARGUS Windows Installer Build Successful!                  " -ForegroundColor Green
    Write-Host " Output Installer: $InstallerPath ($SizeMB MB)             " -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
} else {
    Write-Error "Installer binary not found at $InstallerPath"
    exit 1
}
