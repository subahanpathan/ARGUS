param(
    [string]$ApiUrl = "http://localhost:5000"
)
$env:ARGUS_API_BASE_URL = $ApiUrl

# Check Python
try {
    $pythonVersion = & python --version 2>&1
    Write-Host "[1/3] Python detected: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Python 3.10+ is required to sample Windows telemetry." -ForegroundColor Red
    Write-Host "Please download Python from https://www.python.org/downloads/ (check 'Add Python to PATH')"
    exit 1
}

# Install psutil
Write-Host "[2/3] Verifying psutil telemetry library..." -ForegroundColor Yellow
& python -m pip install -q psutil

# Run engine
Write-Host "[3/3] Starting ARGUS Windows Host Sensor..." -ForegroundColor Green
Write-Host "Streaming live CPU, RAM, Disk, Sockets, and Process telemetry to $ApiUrl" -ForegroundColor Cyan
Write-Host "Keep this window open while monitoring your computer." -ForegroundColor Gray
Write-Host "Press Ctrl+C to stop." -ForegroundColor Gray
Write-Host ""

& python artifacts/security-engine/main.py --api --snapshot
