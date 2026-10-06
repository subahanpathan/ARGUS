# ARGUS Security Intelligence — Production Build Script
# Compiles API server bundle and static frontend dashboard for production distribution.

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Building ARGUS Security Intelligence Production Package   " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$WorkspaceRoot = Split-Path -Parent $PSScriptRoot
Set-Location $WorkspaceRoot

# Step 1: Build API Server Bundle
Write-Host "[1/3] Compiling API Server..." -ForegroundColor Yellow
pnpm --filter @workspace/api-server run build
if ($LASTEXITCODE -ne 0) {
    Write-Error "API server build failed!"
    exit 1
}

# Step 2: Build Frontend Web Assets
Write-Host "[2/3] Building React Frontend Dashboard..." -ForegroundColor Yellow
pnpm --filter @workspace/argus run build
if ($LASTEXITCODE -ne 0) {
    Write-Error "Frontend build failed!"
    exit 1
}

# Step 3: Assemble Production Distribution Directory
$DistDir = Join-Path $WorkspaceRoot "dist\production"
Write-Host "[3/3] Assembling production payload into $DistDir..." -ForegroundColor Yellow

if (Test-Path $DistDir) {
    Remove-Item $DistDir -Recurse -Force
}

New-Item -ItemType Directory -Path $DistDir | Out-Null
New-Item -ItemType Directory -Path (Join-Path $DistDir "api-server") | Out-Null
New-Item -ItemType Directory -Path (Join-Path $DistDir "security-engine") | Out-Null
New-Item -ItemType Directory -Path (Join-Path $DistDir "public") | Out-Null

# Copy API Server compiled artifacts
Copy-Item -Path "$WorkspaceRoot\artifacts\api-server\dist\*" -Destination "$DistDir\api-server" -Recurse -Force

# Copy Static Frontend compiled assets
Copy-Item -Path "$WorkspaceRoot\artifacts\argus\dist\public\*" -Destination "$DistDir\public" -Recurse -Force

# Copy Python Security Engine
Copy-Item -Path "$WorkspaceRoot\artifacts\security-engine\*" -Destination "$DistDir\security-engine" -Recurse -Force

Write-Host "============================================================" -ForegroundColor Green
Write-Host " ARGUS Production Build Successful!                        " -ForegroundColor Green
Write-Host " Package location: $DistDir                                " -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
