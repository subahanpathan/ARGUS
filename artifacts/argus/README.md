# ARGUS Security Intelligence

ARGUS is a safe, local cybersecurity and digital-forensics prototype for demonstrating the path from endpoint detection to investigation, exposure assessment, remediation, reporting, and user-controlled cyber incident submission.

All records are synthetic demonstration data. The interface deliberately separates **Observed Evidence** from **Potential / Inferred Activity** and does not claim that an IP address identifies an attacker or that a risk score proves data theft.

## Requirements

- **Node.js** 20.x or 22.x (Node 24 also works). The workspace is developed against the current LTS line.
- **pnpm** 10.x
- **PostgreSQL / `DATABASE_URL` is NOT required** for the current local-first ARGUS demo. ARGUS runs entirely on synthetic React state.

## Run locally (Windows PowerShell)

From the workspace root (`D:\Mini`):

```powershell
pnpm install
$env:PORT = "5173"
$env:BASE_PATH = "/"
pnpm --filter @workspace/argus run dev
```

Open [http://localhost:5173](http://localhost:5173).

### Optional API scaffold

The Express API is a health-check scaffold for future server-backed work. ARGUS does not call it today.

```powershell
$env:PORT = "5000"
$env:BASE_PATH = "/"
$env:NODE_ENV = "development"
pnpm --filter @workspace/api-server run dev
```

Health check: [http://localhost:5000/api/healthz](http://localhost:5000/api/healthz)

### Unix / macOS

```bash
pnpm install
PORT=5173 BASE_PATH=/ pnpm --filter @workspace/argus run dev
```

## Build and typecheck

```powershell
pnpm install
pnpm run typecheck
pnpm run build
```

## Windows EPERM / Access Denied on install or build

**Root cause:** folder ACLs under `D:\Mini` often grant `Users:(RX)` only while full control sits on elevated Administrators. A normal (UAC-filtered) PowerShell session therefore cannot rewrite `node_modules\.modules.yaml`, `.bin` shims, or `artifacts/*/dist`. Lingering Vite/Node processes can also lock open files.

**Fix once** (Run as administrator):

```powershell
Set-Location D:\Mini
.\scripts\fix-windows-permissions.ps1
```

Then stop any running Vite/API processes and re-run in a normal PowerShell window:

```powershell
pnpm install
pnpm run typecheck
pnpm run build
```

Vite caches live under `artifacts/.vite-cache/` (not inside package `node_modules`) to reduce Windows lock contention on `.vite-temp`.

## Demo flow

1. Open the app and choose **Enter Demo Mode**.
2. Use **Start Demo** on the dashboard. Use **Pause** / **Resume** to control automatic progression.
3. Watch the shared incident state progress through appearance, collection, staging, network activity, detection, containment, quarantine, and report generation.
4. Open investigation pages from the left navigation. **Investigate** on a detection routes to the related evidence view.
5. Use **Cyber Cell** only after reviewing the evidence and granting **both** explicit consent checkboxes. Submission is recorded locally and is not sent externally.

## Project structure

- `src/App.tsx` — shared app state, synthetic records, routing, pages, and interactions
- `src/index.css` — ARGUS visual system and responsive layout
- `public/` — favicon and crawler metadata
- `package.json` — Vite scripts and frontend dependencies

This prototype uses local React state and does not transmit login values or telemetry.
