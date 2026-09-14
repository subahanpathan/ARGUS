# Windows-friendly post-merge hook (PowerShell)
# Replit still references post-merge.sh; on Windows use this script instead:
#   .\scripts\post-merge.ps1

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

pnpm install --frozen-lockfile

# Database push is optional and NOT required for the local-first ARGUS demo.
if ($env:DATABASE_URL) {
  pnpm --filter @workspace/db run push
} else {
  Write-Host "Skipping db push (DATABASE_URL not set). ARGUS demo uses synthetic local data."
}
