# Build ARGUS.exe - standalone launcher bundling Node runtime + API server + dashboard + engine agent
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot   # workspace root
$Scripts = $PSScriptRoot
$ApiDist = Join-Path $Root "artifacts\api-server\dist"
$WebDist = Join-Path $Root "artifacts\argus\dist\public"
$AgentExe = Join-Path $Root "artifacts\security-engine\dist\argus-agent.exe"
$Stage = Join-Path $Scripts "_launcher_payload"
$OutDir = Join-Path $Root "dist\app"

Write-Host "[1/6] Checking prerequisites..." -ForegroundColor Cyan
if (!(Test-Path $ApiDist)) { Write-Error "api-server not built. Run: pnpm --filter @workspace/api-server run build" }
if (!(Test-Path $WebDist)) { Write-Error "frontend not built. Run: pnpm --filter @workspace/argus run build" }
if (!(Test-Path $AgentExe)) { Write-Error "agent exe missing. Build argus-agent first." }
$nodeSrc = (Get-Command node).Source
if (!$nodeSrc) { Write-Error "Node.js not found on PATH" }

Write-Host "[2/6] Staging runtime payload..." -ForegroundColor Cyan
if (Test-Path $Stage) { Remove-Item $Stage -Recurse -Force }
New-Item -ItemType Directory -Path "$Stage\runtime" -Force | Out-Null
New-Item -ItemType Directory -Path "$Stage\api-server" -Force | Out-Null
New-Item -ItemType Directory -Path "$Stage\engine" -Force | Out-Null

# Portable Node runtime (just node.exe is enough for the bundled ESM server)
Copy-Item $nodeSrc "$Stage\runtime\node.exe" -Force
# Compiled API server bundle
Copy-Item "$ApiDist\*" "$Stage\api-server\" -Recurse -Force
# React dashboard is served by the API server from ./public next to index.mjs
Copy-Item $WebDist "$Stage\api-server\public" -Recurse -Force
# Standalone Python agent
Copy-Item $AgentExe "$Stage\engine\argus-agent.exe" -Force
# Desktop installer offered via /api/desktop/download after activation
$SetupExe = Join-Path $Root "dist\installer\ARGUS-Setup.exe"
if (Test-Path $SetupExe) {
  New-Item -ItemType Directory -Path "$Stage\api-server\downloads" -Force | Out-Null
  Copy-Item $SetupExe "$Stage\api-server\downloads\ARGUS-Setup.exe" -Force
  Write-Host "  Bundling desktop installer for the download endpoint." -ForegroundColor DarkCyan
}

Write-Host "[3/6] Building ARGUS.exe with PyInstaller (one-file, windowed)..." -ForegroundColor Cyan
Set-Location $Scripts
# PyInstaller onefile unpacks to _MEIPASS at runtime; base_dir() falls back
# to it when runtime\ is not next to the exe. --windowed hides the console.
python -m PyInstaller --noconfirm --onefile --name ARGUS --windowed --icon icon\argus.ico `
  --add-data "$Stage\runtime;runtime" `
  --add-data "$Stage\api-server;api-server" `
  --add-data "$Stage\engine;engine" `
  --hidden-import webview.platforms.winforms `
  --hidden-import webview.platforms.edgechromium `
  --collect-all webview `
  argus-launcher.py
if ($LASTEXITCODE -ne 0) { Write-Error "PyInstaller failed" }

Write-Host "[4/6] Verifying exe..." -ForegroundColor Cyan
$exe = Join-Path $Scripts "dist\ARGUS.exe"
if (!(Test-Path $exe)) { Write-Error "ARGUS.exe not produced" }

Write-Host "[5/6] Finalizing single-file package..." -ForegroundColor Cyan
if (Test-Path $OutDir) { Remove-Item $OutDir -Recurse -Force }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
Copy-Item (Join-Path $Scripts "dist\ARGUS.exe") "$OutDir\ARGUS.exe" -Force
Copy-Item (Join-Path $Scripts "icon\argus.ico") "$OutDir\argus.ico" -Force

$size = [math]::Round((Get-Item (Join-Path $Scripts "dist\ARGUS.exe")).Length / 1MB, 1)
Write-Host "[6/6] Done." -ForegroundColor Green
Write-Host "Single-file app: $OutDir\ARGUS.exe  ($size MB)"
Write-Host "Distribute the whole 'ARGUS' folder - or build the installer with Inno Setup."
