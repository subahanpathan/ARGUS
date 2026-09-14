#!/usr/bin/env bash
# Replit / Unix post-merge hook.
# On Windows PowerShell use: .\scripts\post-merge.ps1
set -e
pnpm install --frozen-lockfile
# DATABASE_URL is optional for the local-first ARGUS demo (synthetic data).
if [ -n "${DATABASE_URL:-}" ]; then
  pnpm --filter db push
else
  echo "Skipping db push (DATABASE_URL not set). ARGUS demo uses synthetic local data."
fi
