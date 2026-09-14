# ARGUS Security Intelligence

ARGUS is a safe, synthetic-data cybersecurity and digital-forensics prototype that helps an analyst detect, investigate, assess exposure, contain, remediate, and report an endpoint incident.

## Run & Operate

### Windows PowerShell

```powershell
pnpm install
pnpm run typecheck
pnpm run build

# Frontend (ARGUS)
$env:PORT = "5173"
$env:BASE_PATH = "/"
pnpm --filter @workspace/argus run dev

# Optional API scaffold (not required by ARGUS UI)
$env:PORT = "5000"
$env:BASE_PATH = "/"
$env:NODE_ENV = "development"
pnpm --filter @workspace/api-server run dev
```

### Unix / Replit

- `pnpm --filter @workspace/argus run dev` — ARGUS frontend (set `PORT` / `BASE_PATH`)
- `pnpm --filter @workspace/api-server run dev` — API server scaffold (port 5000)
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (**optional**, only if using Postgres)

### Environment notes

- **ARGUS is local-first** and uses **synthetic/mock data** in React state. It does **not** require PostgreSQL or `DATABASE_URL`.
- `DATABASE_URL` is only needed if you intentionally use the Drizzle/`@workspace/db` scaffold.
- **Node.js:** 20.x or newer (LTS). Replit may provision Node 24; local Windows development commonly uses Node 20/22.

If Windows install/build hits `EPERM` on `node_modules` or `dist`, run `.\scripts\fix-windows-permissions.ps1` once as Administrator (see `artifacts/argus/README.md`).

## Stack

- pnpm workspaces, Node.js 20+, TypeScript 5.9
- Frontend: Vite + React 19 + wouter
- API scaffold: Express 5
- DB scaffold: PostgreSQL + Drizzle ORM (optional for ARGUS demo)
- Validation: Zod, `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- Build: Vite (frontend), esbuild (API)

## Where things live

- `artifacts/argus/src/App.tsx` — complete ARGUS frontend, synthetic data model, shared incident state, routes, and working interactions
- `artifacts/argus/src/index.css` — ARGUS charcoal/navy interface theme, evidence states, responsive layout, and motion
- `artifacts/argus/README.md` — standalone setup and demo instructions (includes Windows PowerShell)
- `artifacts/api-server/` — shared API scaffold retained for future server-backed prototype work
- `lib/api-spec/openapi.yaml` — shared API contract scaffold; ARGUS first build intentionally uses local mock data
- `scripts/post-merge.ps1` — Windows post-merge helper; `scripts/post-merge.sh` for Unix/Replit

## Architecture decisions

- ARGUS is intentionally local-first in the prototype: synthetic data and shared React state make the full incident demonstration reliable without external services or real endpoint access.
- The visual language treats observed evidence and potential/inferred activity as separate concepts so the demo does not overclaim certainty.
- The central demo is stateful rather than a slide show: detection, exposure risk, containment, quarantine, and reporting update the same incident record.
- Destructive actions are confirmation-gated and reversible where appropriate; cyber incident submission is consent-gated (two checkboxes) and local-only.

## Product

ARGUS includes login/demo entry, a SOC dashboard, threat detection, live monitoring, process/file/network forensics, exposure analysis, an exposure-window view, clickable incident timeline, quarantine, threat intelligence, incident reports, report history, consent-gated Cyber Cell reporting, settings, and an About page.

## User preferences

- Keep this project safe for demonstrations: synthetic data only and never expose real passwords, banking details, identity numbers, or endpoint telemetry.

## Gotchas

- Run the ARGUS artifact workflow rather than a root-level dev command so `PORT`, `BASE_PATH`, and preview routing are supplied correctly.
- Do not describe the ARGUS risk score as proof of actual data theft; it is a clearly labeled demonstration assessment.
- On Windows, prefer PowerShell `$env:VAR = "..."` syntax; Unix `VAR=value cmd` does not work in PowerShell.

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
