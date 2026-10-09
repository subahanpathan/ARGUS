# ARGUS Desktop Application & Windows Installer Build Pipeline
param(
    [switch]$SkipFrontend = $false,
    [switch]$SkipBackend = $false,
    [switch]$SkipAgent = $false
)

$ErrorActionPreference = "Stop"
$WorkspaceRoot = Split-Path -Parent $PSScriptRoot

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  ARGUS Desktop Application & Windows Installer Build       " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 0. Locate Tools
$nodeExe = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $nodeExe -and (Test-Path "D:\node.exe")) { $nodeExe = "D:\node.exe" }
if (-not $nodeExe -and (Test-Path "C:\Program Files\nodejs\node.exe")) { $nodeExe = "C:\Program Files\nodejs\node.exe" }
if (-not $nodeExe) { Write-Error "Node.js not found on system PATH." }

$isccCandidates = @(
    (Get-Command iscc.exe -ErrorAction SilentlyContinue).Source,
    "C:\Users\HP\AppData\Local\Programs\Inno Setup 6\ISCC.exe",
    "${env:LOCALAPPDATA}\Programs\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles}\Inno Setup 6\ISCC.exe",
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe"
)
$isccExe = $isccCandidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

if (-not $isccExe) {
    Write-Warning "Inno Setup compiler (ISCC.exe) was not found. Installer step will be skipped."
}

Write-Host "[*] Node runtime:      $nodeExe" -ForegroundColor Gray
Write-Host "[*] Inno compiler:     $isccExe" -ForegroundColor Gray

# 1. Build Backend API Server
if (-not $SkipBackend) {
    Write-Host "`n[1/6] Building Express API Server..." -ForegroundColor Yellow
    Push-Location (Join-Path $WorkspaceRoot "artifacts\api-server")
    pnpm run build
    Pop-Location
}

# 2. Build Frontend Dashboard
if (-not $SkipFrontend) {
    Write-Host "`n[2/6] Building React Frontend Dashboard..." -ForegroundColor Yellow
    Push-Location (Join-Path $WorkspaceRoot "artifacts\argus")
    pnpm run build
    Pop-Location
}

# 3. Build Security Engine Executable
if (-not $SkipAgent) {
    Write-Host "`n[3/6] Building Python Security Engine (argus-agent.exe)..." -ForegroundColor Yellow
    Push-Location (Join-Path $WorkspaceRoot "artifacts\security-engine")
    python -m PyInstaller --distpath dist --workpath build -y argus-agent.spec
    Pop-Location
}

$AgentExe = Join-Path $WorkspaceRoot "artifacts\security-engine\dist\argus-agent.exe"
if (-not (Test-Path $AgentExe)) {
    Write-Error "Security Engine executable not found at $AgentExe"
}

# 4. Assemble Application Directory (dist\app)
Write-Host "`n[4/6] Assembling application directory (dist\app)..." -ForegroundColor Yellow
$DistApp = Join-Path $WorkspaceRoot "dist\app"
$RuntimeDir = Join-Path $DistApp "runtime"
$ApiServerDir = Join-Path $DistApp "api-server"
$PublicDir = Join-Path $ApiServerDir "public"
$EngineDir = Join-Path $DistApp "engine"

# Clean previous app staging
if (Test-Path $DistApp) {
    Remove-Item -Path $DistApp -Recurse -Force -ErrorAction SilentlyContinue
}

New-Item -ItemType Directory -Path $RuntimeDir -Force | Out-Null
New-Item -ItemType Directory -Path $PublicDir -Force | Out-Null
New-Item -ItemType Directory -Path $EngineDir -Force | Out-Null

# Copy Node runtime
Copy-Item -Path $nodeExe -Destination (Join-Path $RuntimeDir "node.exe") -Force

# Copy API server compiled bundle
Copy-Item -Path (Join-Path $WorkspaceRoot "artifacts\api-server\dist\*") -Destination $ApiServerDir -Recurse -Force

# Copy React dashboard assets to api-server\public
$WebDistDir = Join-Path $WorkspaceRoot "artifacts\argus\dist\public"
if (Test-Path $WebDistDir) {
    Get-ChildItem -Path $WebDistDir | ForEach-Object {
        if ($_.Name -ne "ARGUS-Setup.exe") {
            Copy-Item -Path $_.FullName -Destination (Join-Path $PublicDir $_.Name) -Recurse -Force
        }
    }
}

# Copy Security Engine executable
Copy-Item -Path $AgentExe -Destination (Join-Path $EngineDir "argus-agent.exe") -Force

# Copy application icon
Copy-Item -Path (Join-Path $WorkspaceRoot "scripts\icon\argus.ico") -Destination (Join-Path $DistApp "argus.ico") -Force

# 5. Build Desktop Launcher (dist\app\ARGUS.exe)
Write-Host "`n[5/6] Compiling Native Desktop Shell (ARGUS.exe)..." -ForegroundColor Yellow
Push-Location (Join-Path $WorkspaceRoot "scripts")
# NOTE: We DO NOT embed node, server, or agent in the EXE anymore! They are copied alongside it.
python -m PyInstaller --noconfirm --onefile --windowed `
    --name ARGUS `
    --icon "icon\argus.ico" `
    --hidden-import webview.platforms.winforms `
    --hidden-import webview.platforms.edgechromium `
    --collect-all webview `
    --distpath $DistApp `
    --workpath "build" `
    argus-launcher.py
Pop-Location

$TargetAppExe = Join-Path $DistApp "ARGUS.exe"
if (-not (Test-Path $TargetAppExe)) {
    Write-Error "Failed to build ARGUS.exe"
}

# 6. Compile Inno Setup Installer
Write-Host "`n[6/6] Compiling Windows Installer (ARGUS-Setup.exe)..." -ForegroundColor Yellow
$DistInstaller = Join-Path $WorkspaceRoot "dist\installer"
New-Item -ItemType Directory -Path $DistInstaller -Force | Out-Null

if ($isccExe) {
    Push-Location (Join-Path $WorkspaceRoot "installer")
    & $isccExe "argus-installer.iss"
    Pop-Location

    $TargetInstaller = Join-Path $DistInstaller "ARGUS-Setup.exe"
    if (Test-Path $TargetInstaller) {
        # Synchronize installer to web distribution points
        $ArgusPublicDir = Join-Path $WorkspaceRoot "artifacts\argus\dist\public"
        $ArgusPublicDevDir = Join-Path $WorkspaceRoot "artifacts\argus\public"
        New-Item -ItemType Directory -Path $ArgusPublicDir -Force | Out-Null
        New-Item -ItemType Directory -Path $ArgusPublicDevDir -Force | Out-Null

        Copy-Item -Path $TargetInstaller -Destination (Join-Path $ArgusPublicDir "ARGUS-Setup.exe") -Force
        Copy-Item -Path $TargetInstaller -Destination (Join-Path $ArgusPublicDevDir "ARGUS-Setup.exe") -Force

        $mb = [math]::Round((Get-Item $TargetInstaller).Length / 1MB, 2)
        Write-Host "`nARGUS Windows Installer created successfully ($mb MB)" -ForegroundColor Green
    } else {
        Write-Error "Inno Setup failed to produce $TargetInstaller"
    }
} else {
    Write-Host "`nSkipped Inno Setup installer compilation (ISCC.exe not found)." -ForegroundColor Yellow
}
