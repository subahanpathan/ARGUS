# Fix Windows ACL permissions for the ARGUS workspace
#
# Root cause of EPERM on pnpm install / vite build:
# Files under D:\Mini were inherited with Users:(RX) only while
# Administrators:(F) requires an elevated token. Non-elevated PowerShell
# (UAC filtered admin) therefore cannot rewrite node_modules\.modules.yaml,
# .bin shims, or artifacts/*/dist.
#
# Run ONCE in an elevated PowerShell:
#   Right-click PowerShell → Run as administrator
#   Set-Location D:\Mini
#   .\scripts\fix-windows-permissions.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $root "pnpm-workspace.yaml"))) {
  throw "Run this script from the ARGUS repo (expected pnpm-workspace.yaml beside scripts\)."
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Elevation required. Relaunching with UAC..."
  Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Wait
  exit $LASTEXITCODE
}

Write-Host "Granting Modify to BUILTIN\Users and Authenticated Users on $root"
icacls $root /grant "BUILTIN\Users:(OI)(CI)M" /T /C /Q | Out-Null
icacls $root /grant "NT AUTHORITY\Authenticated Users:(OI)(CI)M" /T /C /Q | Out-Null
attrib -R "$root\*" /S /D | Out-Null

$status = Join-Path $PSScriptRoot ".acl-fix-status.txt"
"ACL_FIX_DONE $(Get-Date -Format o)" | Set-Content -Path $status -Encoding utf8
Write-Host "Done. Re-run: pnpm install ; pnpm run typecheck ; pnpm run build"
exit 0
