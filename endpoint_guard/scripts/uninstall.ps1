<#
.SYNOPSIS
    Endpoint Guard - Clean Uninstaller.
.DESCRIPTION
    Removes scheduled task, unblocks any remaining firewall rules created by Endpoint Guard,
    and provides the option to keep or purge the incident audit log.
#>

[CmdletBinding()]
param(
    [switch]$PurgeData
)

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "         ENDPOINT GUARD - UNINSTALLER                      " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Remove Scheduled Task
Write-Host "[*] Removing scheduled task..." -ForegroundColor Yellow
Unregister-ScheduledTask -TaskName "EndpointGuardDefenseService" -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
Write-Host "[+] Scheduled task removed." -ForegroundColor Green

# Remove Firewall Rules created by Endpoint Guard
Write-Host "[*] Removing Endpoint Guard firewall block rules..." -ForegroundColor Yellow
try {
    Get-NetFirewallRule -DisplayName "EndpointGuard_*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    Write-Host "[+] All Endpoint Guard firewall rules cleaned." -ForegroundColor Green
} catch {
    Write-Warning "[-] Error cleaning firewall rules: $_"
}

# Data purge if requested
if ($PurgeData) {
    Write-Host "[*] Purging C:\ProgramData\EndpointGuard..." -ForegroundColor Yellow
    Remove-Item "C:\ProgramData\EndpointGuard" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Data purged." -ForegroundColor Green
} else {
    Write-Host "[i] Preserved forensic records in C:\ProgramData\EndpointGuard (use -PurgeData to delete)." -ForegroundColor Gray
}

Write-Host "[+] Endpoint Guard uninstalled." -ForegroundColor Green
