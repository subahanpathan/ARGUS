# ARGUS Security Intelligence — Windows Runtime & Service Controller
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("start", "stop", "restart", "status", "install", "uninstall")]
    [string]$Action,

    [string]$InstallDir = "C:\Program Files\ARGUS",
    [string]$DataDir = "C:\ProgramData\ARGUS",
    [int]$Port = 5000,
    [string]$AccessKey = "ARGUS-DEV-2026"
)

$ErrorActionPreference = "Continue"

$ApiPidFile = Join-Path $DataDir "api-server.pid"
$AgentSupervisorScript = Join-Path $InstallDir "security-engine\agent_supervisor.py"
$ApiServerBundle = Join-Path $InstallDir "api-server\index.mjs"

# Ensure Data and Log Directories exist
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $DataDir "logs") -Force | Out-Null

function Get-ApiPid {
    if (Test-Path $ApiPidFile) {
        $raw = Get-Content $ApiPidFile -ErrorAction SilentlyContinue
        if ($raw -match '^\d+$') {
            $pidVal = [int]$raw
            $proc = Get-Process -Id $pidVal -ErrorAction SilentlyContinue
            if ($proc -and -not $proc.HasExited) {
                return $pidVal
            }
        }
        Remove-Item $ApiPidFile -Force -ErrorAction SilentlyContinue
    }
    return $null
}

function Start-ArgusServices {
    Write-Host "[ARGUS Service] Starting ARGUS Background Services..." -ForegroundColor Cyan

    # 1. Start API Server if not running
    $apiPid = Get-ApiPid
    if ($apiPid) {
        Write-Host "  API Server is already running (PID: $apiPid)" -ForegroundColor Yellow
    } else {
        Write-Host "  Launching ARGUS API Server..." -ForegroundColor Yellow
        $apiLog = Join-Path $DataDir "logs\api-server.log"
        
        $env:PORT = $Port.ToString()
        $env:ARGUS_DEV_ACCESS_KEY = $AccessKey
        $env:ARGUS_DATA_DIR = $DataDir
        $env:NODE_ENV = "production"

        # Find Node binary
        $nodeExe = (Get-Command node -ErrorAction SilentlyContinue).Source
        if (-not $nodeExe) {
            $nodeExe = "node"
        }

        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $nodeExe
        $psi.Arguments = "`"$ApiServerBundle`""
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $psi.EnvironmentVariables["PORT"] = $Port.ToString()
        $psi.EnvironmentVariables["ARGUS_DEV_ACCESS_KEY"] = $AccessKey
        $psi.EnvironmentVariables["ARGUS_DATA_DIR"] = $DataDir
        $psi.EnvironmentVariables["NODE_ENV"] = "production"

        $proc = [System.Diagnostics.Process]::Start($psi)
        if ($proc) {
            $proc.Id | Out-File -FilePath $ApiPidFile -Encoding utf8
            Write-Host "  API Server started (PID: $($proc.Id))" -ForegroundColor Green
        } else {
            Write-Error "  Failed to start API Server process."
        }
    }

    # 2. Start Python Agent Supervisor
    Write-Host "  Launching Security Engine Supervisor..." -ForegroundColor Yellow
    $env:ARGUS_DATA_DIR = $DataDir
    $env:ARGUS_API_BASE_URL = "http://localhost:$Port"
    python $AgentSupervisorScript start
}

function Stop-ArgusServices {
    Write-Host "[ARGUS Service] Stopping ARGUS Background Services..." -ForegroundColor Cyan

    # Stop Security Engine Supervisor
    if (Test-Path $AgentSupervisorScript) {
        python $AgentSupervisorScript stop
    }

    # Stop API Server Process
    $apiPid = Get-ApiPid
    if ($apiPid) {
        Write-Host "  Stopping API Server (PID: $apiPid)..." -ForegroundColor Yellow
        Stop-Process -Id $apiPid -Force -ErrorAction SilentlyContinue
        Remove-Item $ApiPidFile -Force -ErrorAction SilentlyContinue
        Write-Host "  API Server stopped." -ForegroundColor Green
    } else {
        Write-Host "  API Server is not running." -ForegroundColor Yellow
    }
}

function Get-ArgusStatus {
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " ARGUS Background Service Status                           " -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    $apiPid = Get-ApiPid
    if ($apiPid) {
        Write-Host " API Server:     [RUNNING] (PID: $apiPid, Port: $Port)" -ForegroundColor Green
    } else {
        Write-Host " API Server:     [STOPPED]" -ForegroundColor Red
    }

    if (Test-Path $AgentSupervisorScript) {
        python $AgentSupervisorScript status
    } else {
        Write-Host " Security Engine Supervisor script not found at $AgentSupervisorScript" -ForegroundColor Red
    }
}

switch ($Action.ToLower()) {
    "start"   { Start-ArgusServices }
    "stop"    { Stop-ArgusServices }
    "restart" { Stop-ArgusServices; Start-Sleep -Seconds 2; Start-ArgusServices }
    "status"  { Get-ArgusStatus }
    "install" {
        Write-Host "[ARGUS Service] Installing Scheduled Task for Auto-Start on Boot..." -ForegroundColor Cyan
        $taskName = "ARGUS_Background_Security_Agent"
        $scriptPath = $PSCommandPath
        $actionObj = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`" start -InstallDir `"$InstallDir`" -DataDir `"$DataDir`""
        $triggerObj = New-ScheduledTaskTrigger -AtStartup
        $principalObj = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $taskName -Action $actionObj -Trigger $triggerObj -Principal $principalObj -Force | Out-Null
        Write-Host "  Task '$taskName' registered to run on system boot." -ForegroundColor Green
    }
    "uninstall" {
        Write-Host "[ARGUS Service] Removing Scheduled Task..." -ForegroundColor Cyan
        Unregister-ScheduledTask -TaskName "ARGUS_Background_Security_Agent" -Confirm:$false -ErrorAction SilentlyContinue
        Stop-ArgusServices
        Write-Host "  ARGUS Background Task removed." -ForegroundColor Green
    }
}
