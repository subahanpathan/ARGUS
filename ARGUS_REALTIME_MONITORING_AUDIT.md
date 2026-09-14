# ARGUS REALTIME MONITORING AUDIT

**Scope:** Audit-only review of the existing ARGUS Security Intelligence Platform prototype.
**Date:** 2026-09-08
**Rule:** No source code was modified; no packages installed; this report is derived exclusively from the inspected files.

---

## FILES INSPECTED

| File | Purpose | Notes |
|---|---|---|
| `package.json` (root) | Workspace root manifest | engines, scripts, dependency policy |
| `pnpm-workspace.yaml` | Workspace/catalog config | catalog versions, supply-chain policy |
| `.npmrc`, `tsconfig.base.json`, `.replit` | Tooling config | pnpm enforcement, TS base |
| `artifacts/argus/src/App.tsx` | Entire ARGUS UI (594 lines) | All pages, state, mock data, demo engine |
| `artifacts/argus/src/main.tsx` | React entry | Verifies no extra wiring |
| `artifacts/argus/vite.config.ts` | Vite config | Alias, base path, output |
| `artifacts/argus/package.json` | Frontend manifest | deps |
| `artifacts/api-server/src/app.ts` | Express app | Middleware stack |
| `artifacts/api-server/src/index.ts` | Server bootstrap | Port handling |
| `artifacts/api-server/src/lib/logger.ts` | Pino logger | Redaction config |
| `artifacts/api-server/src/routes/index.ts` | Router index | Only health mounted |
| `artifacts/api-server/src/routes/health.ts` | healthz handler | Zod-validated response |
| `artifacts/api-server/package.json` | Backend manifest | deps |
| `artifacts/api-server/build.mjs` | esbuild bundler | Build mechanics |
| `lib/api-spec/openapi.yaml` | API specification | 1 endpoint |
| `lib/api-spec/orval.config.ts` | Codegen config | orval → zod + react-query |
| `lib/api-zod/src/index.ts` | Zod export barrel | |
| `lib/api-zod/src/generated/api.ts` | Generated zod schema | Health only |
| `lib/api-zod/src/generated/types/*` | Generated TS types | Health only |
| `lib/api-client-react/src/index.ts` | Client export barrel | |
| `lib/api-client-react/src/generated/api.ts` | Generated react-query hooks | Health only |
| `lib/api-client-react/src/custom-fetch.ts` | Fetch wrapper | base URL + bearer support |
| `lib/db/src/index.ts` | Drizzle DB layer | Lazy pool, requires DATABASE_URL |
| `lib/db/src/schema/index.ts` | DB schema | **EMPTY** (`export {}`) |
| `lib/db/drizzle.config.ts` | Drizzle config | postgres dialect |
| `lib/api-spec/package.json`, `lib/api-zod/package.json`, `lib/db/package.json`, `lib/api-client-react/package.json` | Shared lib manifests | |
| `scripts/package.json` | Scripts pkg | hello only |
| `app-output.log`, `app-error.log` | Runtime logs | Vite dev server only |

**Search-based verification (no assumptions):**
- `grep fetch|axios|WebSocket|EventSource|api-client|useHealthCheck` in `artifacts/argus/src` → **no matches**. The frontend makes **zero network calls**.
- `grep @workspace` in `src/App.tsx` → **no imports** of any shared library.
- `grep ws|socket|WebSocket|EventSource|text/event-stream|child_process|spawn|exec` in `artifacts/api-server/src` → **no matches**.
- `grep powershell|ETW|WMI|ps-list|child_process` in `artifacts/argus/src` → matches are **string literals** inside mock data only (e.g. `powershell.exe` as a seeded process name, App.tsx:39, 51, 64). Nothing executes anything.
- `grep api_key|secret|token|password|Authorization` in API/Argus source → only a hardcoded **demo password default** `argus-demo` (App.tsx:394).

---

# PHASE 1 — PROJECT STRUCTURE

| Item | Finding | Evidence |
|---|---|---|
| Frontend framework | React 19.1.0 + TypeScript + Vite 7 + Tailwind CSS v4 + wouter router | `pnpm-workspace.yaml:59-61` (react/react-dom 19.1.0), `artifacts/argus/package.json:7-75`, `App.tsx:6,591` |
| Backend framework | Express 5.2.1 + TypeScript, bundled with esbuild | `artifacts/api-server/package.json:18`, `build.mjs`, `src/app.ts:1` |
| Language(s) | TypeScript throughout (frontend, backend, all shared libs) | `tsconfig.base.json`, package types |
| Package manager | pnpm 10.34.4 (workspaces + catalog); forced by preinstall script | `package.json:10-21`, `.npmrc`, `pnpm-workspace.yaml:37-67` |
| Node version requirement | `>=20` (installed: v20.20.2) | `package.json:5` (`engines.node`); `.replit:1` targets nodejs-24 |
| Existing scripts | `build`, `typecheck:libs`, `typecheck` at root; `dev/build/serve/typecheck` in argus; `dev/build/start/typecheck` in api-server | `package.json:6-19`, `artifacts/argus/package.json:6-11`, `artifacts/api-server/package.json:6-11` |
| Existing API architecture | Single REST endpoint `GET /api/healthz`; Express 5 + cors + pino-http + JSON body parsers; no controllers/services/WS/SSE | `api-server/src/app.ts:9-32`, `src/routes/index.ts:1-8`, `src/routes/health.ts:1-9` |
| Shared libraries | `@workspace/api-zod` (zod schemas), `@workspace/api-client-react` (react-query hooks + custom fetch), `@workspace/api-spec` (OpenAPI + orval codegen), `@workspace/db` (drizzle/postgres layer) | `artifacts/*/package.json`, `lib/*/package.json` |
| Existing database architecture | PostgreSQL via drizzle-orm + `pg`. Connection pool is lazy and requires `DATABASE_URL`. **Schema file is empty — zero tables exist.** | `lib/db/src/index.ts:1-42`, `lib/db/src/schema/index.ts:20` (`export {}`), `lib/db/drizzle.config.ts:8-13` |
| Does ARGUS use the API server? | **NO.** The UI never imports the API client, never calls `fetch`, and renders entirely from local React state/constants. The About page even states "No API calls". | grep results above; `App.tsx:358` (`Data source … No API calls`); `App.tsx:20` (QueryClient created but no queries registered) |
| Does ARGUS use the database? | **NO.** Neither the frontend nor the API server imports `@workspace/db`. No table schema exists to use even if it did. | grep of `@workspace` in `api-server/src` (only `api-zod` at `health.ts:2`); `App.tsx` grep (no shared imports) |

**Summary:** This is a single-page React mockup. The API server, database, and shared API libraries are scaffolding that currently serve exactly one purpose: a `healthz` check. None of the security UI is wired to them.

---

# PHASE 2 — App.tsx AUDIT

## A. Routing

Router: `wouter` (`Router as WouterRouter`, `useLocation`, `Link`). Base URL from Vite. `App.tsx:6,591`.

Routes dispatched by a single `useMemo` switch (`App.tsx:547-565`):

| Route | Page component | Implemented? |
|---|---|---|
| `/login` (implicit) | `AuthScreen` (`App.tsx:569-585`) | Yes — simulated auth UI |
| `/dashboard` | `Dashboard` | Yes — mock data |
| `/threats` | `ThreatsPage` | Yes — mock data |
| `/monitoring` | `MonitoringPage` | Yes — mock data |
| `/processes` | `ProcessesPage` | Yes — mock data |
| `/files` | `FilesPage` | Yes — mock data |
| `/network` | `NetworkPage` | Yes — mock data |
| `/exposure` | `ExposurePage` | Yes — mock data |
| `/exposure-window` | `ExposureWindowPage` | Yes — mock data |
| `/timeline` | `TimelinePage` | Yes — mock data |
| `/quarantine` | `QuarantinePage` | Yes — mock data |
| `/intelligence` | `IntelligencePage` | Yes — mock data |
| `/reports` | `ReportsPage` | Yes — mock data |
| `/history` | `HistoryPage` | Yes — mock data |
| `/cyber-cell` | `CyberCellPage` | Yes — mock data |
| `/settings` | `SettingsPage` | Yes — mock data |
| `/about` | `AboutPage` | Yes |
| anything else | `NotFound` | Yes |

Navigation works correctly (wouter `<Link>`, `setLocation` used in investigate/containment flows). No route is a "placeholder" — but **every route renders simulated data**.

## B. State management

- `useState` (`App.tsx`): top-level in `AppContent` — `session`, `userName`, `authMode`, `mobileOpen`, `phase` (demo step 0–8), `demoState` (`idle/running/paused/completed`), `threats`, `quarantine`, `cyberCellSubmitted`, `modal`, `toasts`. Page-local states — search/severity filters, selected PID, selected timeline event, report format, Cyber Cell consents, dark-contrast toggle, etc.
- `useEffect` (`App.tsx`): auth-phase advancement (`:407-412`), demo progression timer (`:524-538`), redirect-to-login when unauthenticated (`:540-542`).
- Timers: demo advance `setTimeout` 1550 ms (`:526`), toast auto-dismiss 3800 ms (`:456`), fake scan 1800 ms (`:199`), auth phase 3000 ms (`:403`).
- **No context, no reducers, no WebSocket, no SSE, no polling, no `setInterval`.**
- Event/incident/threat/quarantine/network/process/file "state": only `threats` and `quarantine` are actual React state (`App.tsx:447-448`); process/file/connection/timeline data are **module-level constants** (`App.tsx:38-88`).

## C. Data source per major feature

| Feature | Data source | Evidence |
|---|---|---|
| Dashboard metrics/charts | HARDCODED + derived from `phase` | `App.tsx:179-191` (SVG polyline points math, static `94.8%`, `24/24`) |
| Dashboard live event stream | MOCK (`timelineSeed`) | `App.tsx:188` |
| Threats/incidents | MOCK (`threatsSeed`) dipped in React state | `App.tsx:38-44,447` |
| Process tree / inventory | MOCK (`processSeed`) | `App.tsx:47-53`, `ProcessesPage:222-230` |
| File activity | MOCK (`fileSeed`) | `App.tsx:55-61`, `FilesPage:232-239` |
| Network connections | MOCK (`connectionSeed`) | `App.tsx:63-68`, `NetworkPage:242-250` |
| Exposure assessment | HARDCODED score formula on `phase` | `App.tsx:253-254` (`phase >= 5 ? 86 : phase >= 3 ? 61 : 38`) |
| Forensic timeline | MOCK (`timelineSeed`) | `App.tsx:70-79`, `TimelinePage:269-273` |
| Quarantine | MOCK (`quarantineSeed` + `containmentQuarantineItems`) | `App.tsx:81-88,448` |
| Threat intelligence | HARDCODED | `IntelligencePage:285-288` |
| Incident reports | HARDCODED local text/JSON generation | `ReportsPage:290-335` |
| Report history | HARDCODED 3-row array | `HistoryPage:337-339` |
| Cyber Cell | LOCAL simulated submission | `CyberCellPage:341-350` |
| **Any API/DB data** | **NONE** | grep (no fetch/imports) |

## D. Real-time behavior

**NONE.** There is no reception of real Windows process, filesystem, network, Event Log, Defender, ETW, WMI, PowerShell, Python, or native API data. No WebSocket, no SSE, no polling, no `setInterval`. The only timers are:

1. Demo sequence advance (`App.tsx:524-538`) — increments an integer and fires a toast. Cosmetic.
2. Login animation (`:407-412`), toast expiry (`:456`), fake scan (`:199`) — cosmetic.

The "AUTO-REFRESH 12s" and "LIVE · LAST 5 MIN" labels (`App.tsx:188,205`) are **decorative text** with no backing timer. The Settings "Stream refresh interval" dropdown has no effect (`App.tsx:354`).

## E. Monitoring page classification

| Page | Classification | Why |
|---|---|---|
| Live Monitoring | MOCK/SIMULATED | Static metrics + `timelineSeed` slice; hardcoded endpoints table (`App.tsx:203-206`) |
| Process Analysis | MOCK/SIMULATED | `processSeed` constants; tree render is real React but data fixed (`App.tsx:208-230`) |
| File Activity | MOCK/SIMULATED | `fileSeed` constants; CSV export of mock rows (`App.tsx:232-239`) |
| Network Forensics | MOCK/SIMULATED | `connectionSeed`; graph is fixed positioned DOM nodes (`App.tsx:242-250`) |
| Threat Detection | MOCK/SIMULATED | `threatsSeed`; scans are a 1.8 s spinner (`App.tsx:199`) |
| Data Exposure | MOCK/SIMULATED | Score derived from `phase`, static stages (`App.tsx:252-266`) |
| Exposure Window | MOCK/SIMULATED | Static window visualization + `timelineSeed` (`App.tsx:434-436`) |
| Incident Timeline | MOCK/SIMULATED | `timelineSeed`, static confidence values (`App.tsx:269-273`) |
| Quarantine | MOCK/SIMULATED | Local React list only; no real file movement (`App.tsx:275-283`) |
| Threat Intelligence | MOCK/SIMULATED | Hardcoded dossier/kpis (`App.tsx:285-288`) |
| Incident Reports | MOCK/SIMULATED | Locally generated TXT/JSON of mock data (`App.tsx:290-335`) |
| Cyber Cell Reporting | MOCK/SIMULATED | Confirmed local-only submission (`App.tsx:341-350`) |

**There is no page classified REAL.**

---

# PHASE 3 — API SERVER AUDIT

Source tree (`artifacts/api-server/src`):
- `app.ts` — Express app
- `index.ts` — bootstrap
- `lib/logger.ts` — pino (redacts auth/cookie headers)
- `middlewares/` — **empty** (only `.gitkeep`)
- `lib/` — **empty** (only `.gitkeep`)
- `routes/index.ts`, `routes/health.ts`

| Capability | Status | Evidence |
|---|---|---|
| Routes | 1: `GET /api/healthz` | `routes/index.ts:6`, `routes/health.ts:6` |
| Controllers | NONE | — |
| Middleware | `pino-http` logging, `cors` (unrestricted), `express.json`, `express.urlencoded` | `app.ts:9-30` |
| Services | NONE | — |
| WebSocket | NONE (no `ws`/socket.io dep) | grep; `package.json:12-21` |
| SSE | NONE | — |
| Polling endpoints | NONE | — |
| Authentication | NONE | — |
| Authorization | NONE | — |
| Error handling | No error-handling middleware; unhandled errors hit Express default | `app.ts` (none registered) |
| Logging | pino + pino-http with redaction | `lib/logger.ts:5-20`, `app.ts:9-27` |
| Validation | Only response-side zod parse on healthz | `routes/health.ts:7` |
| Security middleware | NONE (no helmet, no rate limit) | `app.ts` |
| CORS | **Unrestricted** (`cors()` with defaults) | `app.ts:28` |
| Rate limiting | NONE | — |
| Database connectivity | Not connected in code (driver lib present but unimported) | grep `@workspace` in api-server |
| Event ingestion | NONE | — |
| Event broadcasting | NONE | — |

### CAN CURRENT API RECEIVE REAL SECURITY EVENTS?
### **NO**

Exactly why: the API exposes a single, read-only health endpoint. There is no event-ingestion route, no POST body handling for telemetry, no event model/schema, no queue, no WebSocket/SSE channel, and no persistence. A Windows monitoring engine has nowhere to send data and the UI has no channel to receive it. Everything required for ingestion (schema, route, validation, storage, broadcast) is missing.

---

# PHASE 4 — ROOT package.json

| Item | Value | Evidence |
|---|---|---|
| scripts | `preinstall` (forces pnpm), `build` (typecheck + recursive build), `typecheck:libs` (`tsc --build`), `typecheck` | `package.json:6-19` |
| dependencies | `@replit/connectors-sdk ^0.4.1` (unrelated to monitoring) | `package.json:23-27` |
| devDependencies | `prettier`, `typescript ~5.9.3` | `package.json:29-33` |
| workspace config | pnpm workspaces (`artifacts/*`, `lib/*`, `scripts`) + version catalog; supply-chain `minimumReleaseAge: 1440` | `pnpm-workspace.yaml:37-42,28` |
| build config | esbuild for API server; Vite for UI; root build orchestrates both | `package.json:7`, `build.mjs`, `vite.config.ts` |
| typecheck config | `tsc --build` for libs then recursive per-package `tsc --noEmit` | `package.json:16-19` |
| test config | **NONE** (no test runner anywhere) | grep `package.json` files |
| dev commands | `pnpm --filter @workspace/argus dev`, `pnpm --filter @workspace/api-server dev` | `artifacts/*/package.json` |
| security-related packages | none directly; supply-chain age policy only | `pnpm-workspace.yaml:28` |
| networking packages | none (Vite dev server only) | — |
| WebSocket packages | **NONE** | — |
| database packages | `drizzle-orm`, `pg`, `drizzle-kit` via `@workspace/db` | `lib/db/package.json:14-23`; but no schema |

**Useful for the future architecture:** pnpm workspace + catalog (single-version management), `@workspace/db` driver layer (just needs schema), `@workspace/api-zod` codegen pipeline (extend openapi.yaml → zod + react-query regenerated automatically), the pino logging stack already in the API server, and the esbuild production bundler.

---

# PHASE 5 — API package.json

| Item | Value |
|---|---|
| Express | `^5.2.1` |
| Middleware available | `cors ^2.8.6`, `pino-http ^10.5.0`, `cookie-parser ^1.4.7` (declared, **not mounted** in `app.ts`) |
| WebSocket capability | **None** (`ws`/socket.io absent) |
| Database capability | `drizzle-orm` + `@workspace/db` (dcapable once schema exists) |
| Validation capability | `zod` transitively via `@workspace/api-zod` (workspace schema), no dedicated validation dependency for incoming bodies |
| Logging capability | `pino ^9.14.0` + `pino-http` + `pino-pretty` dev transport |
| Security middleware | **None** (no helmet, no rate-limit, no auth libs) |
| Testing tools | **None** |
| Missing for production event-ingestion API | WebSocket/SSE transport, Zod validation for high-volume telemetry bodies, authentication/authorization, rate limiting, security headers (helmet), a queuing/backpressure mechanism, event persistence (DB schema/migrations), structural logging config for telemetry (event ingestion), test runner, and an error-handling middleware contract. |

---

# PHASE 6 — OPENAPI AUDIT

`lib/api-spec/openapi.yaml` (36 lines) defines exactly one path & one schema:

- **Endpoints:** `GET /healthz` (operationId `healthCheck`, tag `health`) — `openapi.yaml:14-26`
- **Schemas:** `HealthStatus { status: string }` — `openapi.yaml:29-35`

Security-related endpoints: **none**. Incident endpoints: **none**. Monitoring endpoints: **none**. Event endpoints: **none**. Threat endpoints: **none**. Process endpoints: **none**. File endpoints: **none**. Network endpoints: **none**. Report endpoints: **none**. WebSocket/SSE: **not expressible**.

**Classification: NOT READY.** The spec supports neither a real-time monitoring model nor any security domain objects. It must be extended with process/file/network/event/threat/incident/report schemas and an events ingestion contract (or an `asyncapi`/documented SSE stream) before codegen can produce usable client/server artifacts.

---

# PHASE 7 — ZOD SCHEMA AUDIT

`lib/api-zod/src/generated/` (orval-generated from the OpenAPI above) contains **one** schema:

- `HealthCheckResponse = z.object({ status: z.string() })` — `api-zod/src/generated/api.ts:14`
- `HealthStatus` interface — `generated/types/healthStatus.ts:9`

Request validation: **none** (no request schemas generated). Response validation: healthz only (used at `routes/health.ts:7`).

Event/threat/incident/process/network/file/report schemas: **none exist**.

Can current schemas represent real Windows security telemetry? **No.** They model a single string. The runtime types in `App.tsx` (`Threat`, `ProcessRecord`, `FileRecord`, `Connection`, `TimelineEvent`, `QuarantineItem`, `App.tsx:28-36`) are UI-local TypeScript interfaces only — not validated schemas, not shared with the API. Useful: the orval pipeline already generates both zod validators and react-query clients from the OpenAPI spec, so extending the spec regenerates the whole contract.

---

# PHASE 8 — REAL-TIME MONITORING READINESS

| Capability | STATUS | EVIDENCE |
|---|---|---|
| Real process monitoring | **MISSING** | No process API; `App.tsx:47-53` hardcodes `processSeed` |
| Real process creation/termination detection | **MISSING** | No event source for process lifecycle |
| Parent-child process tree | **MOCK** | `App.tsx:208-220` renders a static `parent` field from `processSeed` |
| Real file monitoring | **MISSING** | `App.tsx:55-61` hardcodes `fileSeed` |
| Real network monitoring | **MISSING** | `App.tsx:63-68` hardcodes `connectionSeed` |
| Process-to-network correlation | **MOCK** | Only a hardcoded `network: N` count on processes (`App.tsx:32,51`) |
| Real threat detection | **MISSING** | `threatsSeed` (`App.tsx:38-44`) is static |
| Malware hash detection | **MISSING** | Hashes are literal strings; no lookup/computation (`App.tsx:39-44`) |
| Suspicious behavior detection | **MISSING** | `reason` fields are literals; no rule engine |
| Sensitive-file monitoring | **MOCK** | `classification` strings hardcoded in `fileSeed` (`App.tsx:55-61`) |
| Data exposure analysis | **MOCK** | Score is an arithmetic function of demo `phase` (`App.tsx:253-254`) |
| Event correlation | **MOCK** | `App.tsx:77` labels "ARGUS correlated…" but correlation is a pre-written timeline entry |
| Incident timeline | **MOCK** | `timelineSeed` (`App.tsx:70-79`) |
| Evidence preservation | **MISSING** | No storage; exports are pure text/JSON blobs from mock (`App.tsx:112-123,234-238,244-248`) |
| Real-time dashboard updates | **MISSING** | Only the 1550 ms demo `setTimeout` (`App.tsx:526`); no live data |
| Containment | **MOCK** | `applyContainment` mutates local arrays only (`App.tsx:459-472`) |
| Quarantine | **MOCK** | Local list add/remove (`App.tsx:275-283`; delete is `items.filter(...)` on in-memory state, `App.tsx:276`) |
| Reporting | **MOCK** | Locally generated TXT/JSON from constants (`App.tsx:290-335`) |

**Verdict:** Every capability is MOCK or MISSING. The prototype proves the information design (evidence model, confidence labeling, UI) but none of the sensor/data/processing layers.

---

# PHASE 9 — ARCHITECTURE GAP ANALYSIS

## CURRENT ARCHITECTURE (as proven by source)

```
Browser (React SPA — artifacts/argus/src/App.tsx)
   │  all data is module-level constants + React state
   │  only timers: demo phase advance (1550ms), toasts, fake scan, login animation
   ▼
Monolithic single-file UI
   ├── threatsSeed / processSeed / fileSeed / connectionSeed / timelineSeed / quarantineSeed
   ├── Demo Mode: increments `phase` 0→8, flips derived statuses/banners
   └── Local Blob downloads (CSV/TXT/JSON) — no persistence

   └ (disconnected scaffold) api-server (Express 5) → GET /api/healthz → zod → JSON
        └ lib/db exists but has NO schema and is imported by nothing
        └ @workspace/api-zod / api-client-react generated from spec = healthz only
```

## REQUIRED REAL-TIME ARCHITECTURE

```
Windows
  ↓
ARGUS Security Engine (MISSING — to be built)
  ├── Process Monitor        (MISSING)
  ├── File Monitor           (MISSING)
  ├── Network Monitor        (MISSING)
  ├── Threat Detection       (MISSING)
  ├── Event Correlation      (MISSING)
  ├── Data Exposure Analyzer (MISSING)
  └── Evidence Collector     (MISSING)
  ↓
ARGUS API (exists as scaffold only — Express 5 + pino; needs ingestion, auth, validation, storage)
  ↓
WebSocket / SSE            (MISSING — no ws/socket.io, no EventSource handling anywhere)
  ↓
ARGUS React UI (exists as UI shell; needs a real data layer replacing seeds)
```

**Component existence map:** UI presentation layer exists (all pages). Everything below the UI is missing — security engine, event pipeline, ingestion API, real-time transport, schema/model layer, persistence. The only true backend assets are Express 5, pino, cors, the esbuild bundler, and drizzle-orm + pg (driver present, no tables).

---

# PHASE 10 — EXACT FILE CHANGES REQUIRED (PLAN ONLY — NOT APPLIED)

For each future change: `FILE`, `STATUS`, `PURPOSE`, `CURRENT STATUS`, `CHANGE REQUIRED`, `DEPENDENCIES`, `RISK`.

| FILE | STATUS | PURPOSE | CURRENT | CHANGE REQUIRED | DEPENDENCIES | RISK |
|---|---|---|---|---|---|---|
| `artifacts/argus/src/App.tsx` | Existing | UI / state owner | Consumes mock constants + demo `phase` for every page (`App.tsx:38-88,547-565`) | Replace seeded data consumption with a real event store/hook layer feeding the same page components; keep component props stable | New API client hooks; WebSocket/SSE hook | High — largest file (594 lines), every page wired to seeds; must be incremental |
| `artifacts/api-server/src/routes/` | Existing | HTTP routing | Only `health.ts` mounted (`routes/index.ts:6`) | Add event ingestion routes (process/file/network/event/threat/incident/report) with zod body validation | `@workspace/api-zod` schemas; auth middleware; DB | Medium — new routes don't touch existing healthz |
| `artifacts/api-server/src/middlewares/` | Existing (empty) | Auth, rate-limit, error handler, security headers | Only `.gitkeep` | Add `authenticate`, `authorize`, `rateLimit`, `errorHandler`, `helmet`-style headers middleware | New deps (helmet, express-rate-limit, sessions/JWT) | Low–Medium |
| `artifacts/api-server/src/services/` | NEW | Business logic: event store, correlation, quarantine actions | N/A | Implement event persistence, correlation, containment services | DB schema, engine emit contract | Medium |
| `artifacts/api-server/src/real-time/` | NEW | WebSocket/SSE broadcasting | N/A | Implement WS or SSE hub pushing ingested events to UI | ws or sse lib; auth handshake | Medium — backpressure/heartbeat handling |
| `lib/api-spec/openapi.yaml` | Existing | API contract | healthz only (`openapi.yaml:14-26`) | Add schemas + endpoints for events, processes, files, network, threats, incidents, reports | none | Low — additive; regenerate with orval |
| `lib/api-zod/src/generated/*` | Existing (generated) | Shared validation | healthz only | Regenerate via `pnpm -w run typecheck:libs`/orval after spec change | orval | Low — do not hand-edit |
| `lib/api-client-react/src/generated/*` | Existing (generated) | Frontend API client | healthz only | Regenerate; add hooks for ingestion + streaming | orval | Low |
| `lib/db/src/schema/index.ts` | Existing (empty) | DB model | `export {}` (`schema/index.ts:20`) | Define tables: processes, files, connections, events, threats, incidents, quarantine, evidence, reports | drizzle-zod | Low-Medium — sets foundation; migration discipline required |
| `lib/db/src/*` (new tables) | NEW | Per-entity schemas + migrations | N/A | Create typed Drizzle tables + `drizzle-kit generate` migrations | drizzle-kit | Low |
| NEW: `artifacts/security-engine/` (e.g. `monitor-process.ts`, `monitor-file.ts`, `monitor-network.ts`, `detection.ts`, `correlation.ts`, `exposure.ts`, `evidence.ts`) | NEW | Windows monitoring engine | N/A | Use Node/PowerShell/ETW (e.g. `process` snapshot via PowerShell, filesystem watchers, network via `Get-NetTCPConnection`, ETW via `wintrust`/native or ETW consumer) emitting normalized events to API | Windows-only tooling; elevated privileges | High — the entire "real" layer; privilege and performance sensitive |
| `artifacts/argus/src/hooks/*` (new) | NEW | Real-time data hooks (events, threats, network…) | N/A | Subscribe to SSE/WS, map to existing page props | api-client-react generated hooks, SSE/WS client | Medium — must preserve UI contract |
| `artifacts/argus/src/lib/` (new) | NEW | Client-side event/type model matching API zod schemas | `lib/utils.ts` only | Export shared types; map API DTOs to page props | api-zod | Low |
| `artifacts/argus/package.json` | Existing | Deps | No WS/SSE client, no API client wired | Add SSE/WS dependency; wire `@workspace/api-client-react` | pnpm catalog entry | Low |
| `artifacts/api-server/package.json` | Existing | Deps | No WS, no auth, no rate-limit | Add `ws` or SSE (no dep), auth lib, rate-limit, helmet, validation helper | pnpm catalog | Low |
| `scripts/*` | Existing | One-off tasks | hello+QA scripts | Add engine install/start script, migration runner | none | Low |
| `package.json` (root) | Existing | Workspace scripts | build/typecheck only | Add `dev:engine` / `dev:api` orchestration | pnpm workspace | Low |

---

# PHASE 11 — DO NOT BREAK CURRENT WORKING FEATURES

These are working (client-side) behaviors that must be preserved during any real-time conversion:

- **Routing + navigation** — all 17 routes, sidebar groups, `investigateRouteForThreat` deep links (`App.tsx:90-102,125-131,547-565`).
- **Login/logout flow** — gate on `session`, auth phases, register validation (min 8-char key, email regex), demo-mode entry (`App.tsx:361-432,569-585,515-522`).
- **Dashboard** — metrics, risk, chart, event stream, recent incidents, intel, sensor health (`App.tsx:178-194`).
- **Threat detection page** — filter/search, scan simulation, contain w/ confirmation modal, hash shortening (`App.tsx:196-201`).
- **Investigation navigation** — threat → process/network/file/timeline routing (`App.tsx:125-131`).
- **Process tree** — interactive parent/child selection; detail panel; sorted inventory (`App.tsx:208-230`).
- **Network page** — connection graph, destination evidence panel, contained-state visuals (`App.tsx:242-250`).
- **Quarantine state** — inventory add/remove via containment; investigate/restore/delete with confirmation modal (`App.tsx:275-283`).
- **Incident timeline** — selectable event detail with observed-vs-inferred labeling (`App.tsx:269-273`).
- **Exposure analysis** — stage chain, risk breakdown, linked evidence (`App.tsx:252-266`).
- **Report generation & local download** — TXT/JSON blob downloads (`App.tsx:112-123,290-335`).
- **Cyber Cell consent** — dual-consent gated submission, local-only acknowledgment, reset flow (`App.tsx:341-350`).
- **Demo pause/resume/reset** — `demoState` machine and phase progression (`App.tsx:482-538`).

These depend on the current component prop contracts and the seed-shaped data types (`App.tsx:28-36`). Preserve those contracts while swapping the data source.

---

# PHASE 12 — SECURITY REVIEW (findings only — NOT exploited)

| SEVERITY | FILE | DESCRIPTION | EVIDENCE | RECOMMENDATION |
|---|---|---|---|---|
| MEDIUM | `artifacts/api-server/src/app.ts:28` | Unrestricted CORS (`cors()` used with default `origin: *`), meaning any origin can call the future API | `app.ts:28` | Configure an explicit allowlist before adding any real endpoints |
| MEDIUM | `artifacts/api-server/src/app.ts` | No authentication/authorization on the API; only a public healthz exists today, but any added route would inherit this gap | `app.ts:9-32` | Add auth + authorization middleware as part of the ingestion pipeline |
| MEDIUM | `artifacts/argus/src/App.tsx:394` | Hardcoded demo credential default `argus-demo` is present in source and auto-filled into the password field | `App.tsx:394` (`useState(… 'argus-demo')`) | Acceptable for demo; must not leak into production — gate behind a build flag or remove |
| MEDIUM | `artifacts/argus/src/App.tsx:112-123` | Client-side "evidence" reports/CSV/JSON/assessment are generated from unsaved mock state; labeled synthetic (good), but if wired to real telemetry this pattern could expose raw sensitive path/host data in downloads without authority checks | `App.tsx:234-248,255-265,277-281,294-331` | When real data lands, wrap exports in authorization and redaction policies |
| LOW | `artifacts/api-server/src/lib/logger.ts:7-11` | Logging redaction config exists for auth headers/cookies (good); but no request-body redaction whitelist — future telemetry bodies (paths, usernames, tokens) could be logged verbatim | `logger.ts:7-11` | Extend `redact` list with telemetry-sensitive fields before ingestion routes exist |
| LOW | `artifacts/api-server/src/app.ts` | No global error-handling middleware; errors bubble to Express default which can leak stack traces | `app.ts` (no 4-arg handler) | Add central error handler returning `application/problem+json` |
| INFORMATIONAL | `lib/db/src/index.ts:12-18` | Throws if `DATABASE_URL` unset; no secret in source. DB layer unused — no accidental exposure | `db/src/index.ts:12-18` | N/A |
| INFORMATIONAL | `artifacts/argus/src/App.tsx:364-388` | Login UI simulates "TLS 1.3 handshake / RSA-4096 / Argon2id" steps that do not occur; cosmetic only, but could mislead | `App.tsx:364-388,431` | Label these explicitly as simulated (already partly the case on page copy) |
| POSITIVE | `artifacts/argus/src/App.tsx:276` | Quarantine "delete" only filters an in-memory array — no real file deletion or path traversal risk | `App.tsx:276` | N/A (this will change when real quarantine is implemented — enforce path allowlists then) |
| POSITIVE | Root | No command-injection, unsafe shell exec, child_process, path traversal, arbitrary file deletion, or secrets in source across inspected files | grep results (no `exec`/`spawn`; no secret patterns) | N/A |
| POSITIVE | `pnpm-workspace.yaml:28` | 24-hour minimum npm release-age policy (supply-chain defense) | `pnpm-workspace.yaml:28` | Keep enabled |

---

# PHASE 13 — FINAL SCORES

| Dimension | Score | Rationale |
|---|---|---|
| Frontend readiness | **5/10** | Polished, working single-page UI with complete information design; zero data-layer integration |
| Backend readiness | **1/10** | Express 5 + logging scaffold; no endpoints except healthz, no services, no auth |
| API readiness | **1/10** | One `GET /healthz`; no ingestion, no streaming, no validation pipeline |
| Real-time readiness | **0/10** | No WebSocket, no SSE, no polling, no event source |
| Windows monitoring readiness | **0/10** | Nothing reads Windows processes/files/network/events |
| Security architecture | **2/10** | Logging redaction + supply-chain policy only; no auth, no CORS policy, no rate limiting, no hardening |
| Forensic readiness | **1/10** | Excellent evidence-model UI, but no evidence capture, storage, or chain-of-custody |
| Industrial readiness | **0/10** | Prototype/demo only; cannot run unattended against real endpoints |

### CURRENT ARGUS OVERALL READINESS: **1/10**

Scored on implemented functionality, not appearance. The UI layer of a security-console prototype exists; all monitoring intelligence, data acquisition, real-time transport, and persistence are absent.

---

# PHASE 14 — FINAL SUMMARY

## WHAT ARGUS ALREADY HAS
- Complete React 19 + TypeScript + Vite + Tailwind UI prototype with 17 routes.
- Coherent security-domain information design: observed-vs-inferred evidence model, severity/status taxonomy, process-tree rendering, quarantine inventory, timeline, exposure window, local report/CSV/JSON generation, Cyber Cell consent flow.
- Working client-side interactions: search/filter, drill-down, modals, toasts, demo pause/resume/reset, local downloads.
- Scaffolded backend: Express 5, pino logging with redaction, unrestricted-cors, JSON body parsing, esbuild bundling.
- Shared-library pipeline: OpenAPI → orval → zod validators + react-query client; drizzle + pg driver layer.
- Configured pnpm workspace/catalog with supply-chain release-age policy.

## WHAT IS ONLY MOCK/SIMULATED
- All process, file, network, incident, threat, timeline, quarantine, intelligence, and report data (module constants in `App.tsx:38-88`).
- Demo progression engine (`App.tsx:524-538`) and the derived risk/status/banner state.
- Threat "scans", endpoint "containment", quarantine restore/delete, Cyber Cell "submission", report "sharing", notification bell, sensor-health metrics.
- The API's sole purpose (healthz) and all generated schemas/hooks (health only).

## WHAT IS COMPLETELY MISSING
- Windows data acquisition: process, file, network, Event Log, Defender, ETW, WMI, PowerShell-based,
  or native-API monitoring.
- Event ingestion endpoints and event schema/model (process/file/network/threat/incident).
- Real-time transport: WebSocket or SSE (server and client).
- Event persistence and database schema (zero tables).
- Threat detection rules, hash reputation lookup, behavior analysis.
- Event correlation / incident timeline builder.
- Data-exposure analysis on real telemetry.
- Evidence capture/storage with integrity guarantees.
- Containment/quarantine that affects real endpoints.
- Authentication, authorization, rate limiting, CORS policy, error-handling middleware, security headers.
- Testing (unit/integration/e2e) and linting.

## WHAT MUST BE MODIFIED
- `artifacts/api-server/src/app.ts` (middleware: auth, CORS policy, error handler).
- `artifacts/api-server/src/routes/index.ts` (+ new route modules).
- `artifacts/argus/src/App.tsx` (swap mock data sources for real/hook-driven data; preserve page contracts).
- `lib/api-spec/openapi.yaml` (full API contract), then regenerate `lib/api-zod/*` and `lib/api-client-react/*`.
- `lib/db/src/schema/index.ts` (real tables).
- `artifacts/api-server/package.json` and `artifacts/argus/package.json` (new deps: WS/SSE, auth, rate-limit, helmet).
- `pnpm-workspace.yaml` (catalog entries for new packages).

## WHAT NEW FILES MUST BE CREATED
- `artifacts/security-engine/` — Process Monitor, File Monitor, Network Monitor, Threat Detection, Event Correlation, Data Exposure Analyzer, Evidence Collector (orchestrated by a Windows agent).
- `artifacts/api-server/src/middlewares/auth.ts`, `rateLimit.ts`, `errorHandler.ts`.
- `artifacts/api-server/src/services/events.ts`, `correlation.ts`, `containment.ts`.
- `artifacts/api-server/src/real-time/hub.ts` (WebSocket/SSE broadcaster).
- `lib/db/src/schema/events.ts|processes.ts|files.ts|connections.ts|threats.ts|incidents.ts|evidence.ts` (+ drizzle migrations).
- `artifacts/argus/src/hooks/useRealtimeEvents.ts` (+ stream topic hooks).
- `artifacts/argus/src/lib/types.ts` (shared telemetry types).
- Test suites + a `scripts/run-agent.ps1` style dev orchestration.

## RECOMMENDED IMPLEMENTATION ORDER
(baseline; each phase gated on UI-contract preservation per Phase 11)

1. **PHASE 1 — Real Process Monitoring:** Build process snapshot + creation/termination monitor in the engine; add `/events/process` ingestion + persistence; feed the existing `/processes` page.
2. **PHASE 2 — Real File Monitoring:** filesystem watcher (create/read/write/delete/rename) + sensitive-path classifier; ingest + persist; feed `/files`.
3. **PHASE 3 — Real Network Monitoring:** per-process TCP/UDP connection capture; ingest + persist; feed `/network`.
4. **PHASE 4 — Real-Time Event Pipeline:** WebSocket/SSE hub on API + UI stream hook; replace dashboard "live stream" with real events.
5. **PHASE 5 — Event Correlation:** correlate process→parent→file→network; generate timeline entries.
6. **PHASE 6 — Real Threat Detection:** rules + hash reputation checks on ingested events; feed `/threats`.
7. **PHASE 7 — Data Exposure Analysis:** scoring on real telemetry; feed `/exposure` + `/exposure-window`.
8. **PHASE 8 — Containment and Quarantine:** real process termination / network isolation / file quarantine; wire confirmations.
9. **PHASE 9 — Forensic Evidence:** evidence store with hashes, chain-of-custody timestamps, integrity checks; wired exports.
10. **PHASE 10 — Incident Reporting:** generate reports from persisted incident state; history page backed by DB.

---

### FINAL NOTE

No files were created, modified, or deleted other than this report. No packages were installed. **Do not start Phase 1 until approved.**