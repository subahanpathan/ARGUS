# ARGUS Security Intelligence — Quick Launcher Script
$WorkspaceRoot = $PSScriptRoot
Set-Location $WorkspaceRoot

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Starting ARGUS Security Intelligence                     " -ForegroundColor Cyan
Write-Host "  Activation Key: ARGUS-DEV-2026                            " -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Sync React dashboard assets into API server
$WebDist = Join-Path $WorkspaceRoot "artifacts\argus\dist\public"
$ApiPublic = Join-Path $WorkspaceRoot "artifacts\api-server\dist\public"
if (Test-Path $WebDist) {
    New-Item -ItemType Directory -Path "$ApiPublic\assets" -Force | Out-Null
    Copy-Item -Path "$WebDist\*" -Destination $ApiPublic -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path "$WebDist\assets") {
        Copy-Item -Path "$WebDist\assets\*" -Destination "$ApiPublic\assets" -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# 2. Check and start API server
$healthUrl = "http://localhost:5000/api/healthz"
$running = $false
try {
    $res = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
    if ($res.StatusCode -eq 200) { $running = $true }
} catch {}

if (-not $running) {
    Write-Host "[*] Launching API server on port 5000..." -ForegroundColor Gray
    $nodeExe = "D:\node.exe"
    if (-not (Test-Path $nodeExe)) { $nodeExe = (Get-Command node -ErrorAction SilentlyContinue).Source }
    
    $nodeExeEsc = $nodeExe.Replace('\', '/')
    $wsEsc = $WorkspaceRoot.Replace('\', '/')
    
    python -c "import subprocess, os; env = os.environ.copy(); env['PORT']='5000'; env['NODE_ENV']='production'; env['ARGUS_DEV_ACCESS_KEY']='ARGUS-DEV-2026'; subprocess.Popen(['$nodeExeEsc', '--enable-source-maps', 'artifacts/api-server/dist/index.mjs'], env=env, cwd=r'$wsEsc', creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)"
    Start-Sleep -Seconds 2
}

# 3. Check and start Security Engine
Write-Host "[*] Launching Python Security Engine..." -ForegroundColor Gray
$wsEsc = $WorkspaceRoot.Replace('\', '/')
python -c "import subprocess, os; env = os.environ.copy(); env['ARGUS_API_BASE_URL']='http://127.0.0.1:5000'; subprocess.Popen(['python', 'artifacts/security-engine/main.py', '--api', '--snapshot'], env=env, cwd=r'$wsEsc', creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)"

# 4. Open browser
Write-Host "[+] ARGUS is live! Opening dashboard..." -ForegroundColor Green
Start-Process "http://localhost:5000"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Dashboard URL:  http://localhost:5000                     " -ForegroundColor Green
Write-Host "  Activation Key: ARGUS-DEV-2026                            " -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan
