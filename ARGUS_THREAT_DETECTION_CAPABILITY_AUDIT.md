# ARGUS — THREAT DETECTION CAPABILITY AUDIT

**Scope:** Read-only audit of the existing ARGUS Security Intelligence Platform as it stands today.
**Date:** 2026-09-13
**Rule:** No source code modified; no packages installed; no process terminated. This report is derived exclusively from inspected files.

---

## 1. PROJECT STRUCTURE

```
D:\Mini
├── artifacts\
│   ├── argus\            React 19 + TS + Vite frontend (single-file app in src/App.tsx + hooks + components + motion + pages)
│   ├── api-server\       Express 5 + TS backend (routes/, lib/event-hub.ts)
│   ├── security-engine\  Python 3 + psutil engine (process/system/network/topology/ports/file collectors)
│   └── mockup-sandbox\   shadcn-style UI component library (no threat logic)
├── lib\
│   ├── api-spec\         OpenAPI 3.1 spec + orval config
│   ├── api-zod\          Generated zod validators + TS types
│   ├── api-client-react\ Generated react-query hooks + custom fetch (NOT used at runtime)
│   └── db\               Drizzle + postgres schema (dormant — no runtime use)
├── scripts\              fix-windows-permissions.ps1, post-merge.*, argus-browser-qa.mjs
├── ARGUS_PHASE1_PROCESS_MONITOR.md     (prior phase doc)
└── ARGUS_REALTIME_MONITORING_AUDIT.md  (prior audit of the initial scaffold)
```

**Important:** the older `ARGUS_REALTIME_MONITORING_AUDIT.md` (2026-09-08) audited the *initial scaffold* when the whole platform was a mock single-page demo and there was no real telemetry. Since then Phases 1–4 have been built (real process/system/network/topology/ports/file capture, SSE pipeline, live threat hook). **This report documents the CURRENT state**, and its findings supersede the older document where they disagree.

---

## 2. ARCHITECTURE (AS BUILT)

```
Windows OS
   │  psutil / net_connections / shell tools (read-only)
   ▼
security-engine (Python, daemon threads, polling)
   ├─ ProcessWatcher         (2s)          → POST /api/events/process
   ├─ SystemMonitorWatcher   (1s)          → POST /api/system/telemetry
   ├─ NetworkMonitorWatcher  (3s)          → POST /api/network/connections
   ├─ NetworkTopologyWatcher (3s)          → POST /api/network/topology
   ├─ PortIntelligenceWatcher(3s)          → POST /api/network/ports
   └─ FileMonitorWatcher     (15s)         → POST /api/files/scan
   ▼
api-server (Express 5, in-memory EventHub + SSE topic broadcast)
   ▼
argus React frontend (fetch ESP / EventSource + polling fallback hooks)
   ├─ useProcessMonitor / useNetworkMonitor / useNetworkTopology /
   ├─ usePortIntelligence / useTelemetryStream / useFileScan
   └─ useThreatAnalysis   ← client-side detection rules over live telemetry
```

Flagship fact for the whole audit: **the "threat detection engine" is a pure client-side rule evaluator in `artifacts/argus/src/hooks/use-threat-analysis.ts`. There is no detection/ML/signature engine anywhere in Python, Node, or the spec.**

---

## 3. FRONTEND / UI AUDIT (`artifacts/argus/src/App.tsx`, 1052 lines single file)

### 3.1 Routes (dispatched by one `useMemo` switch, `App.tsx:1005-1023`)

| Route | Component | Data source today |
|---|---|---|
| `/dashboard` | Dashboard | Real telemetry cards (if online) + **hardcoded demo** metrics/incidents |
| `/threats` | ThreatsPage | **Live client-side detections** when engine online; demo seeds otherwise |
| `/monitoring` | MonitoringPage | Real system telemetry streaming (psutil) |
| `/processes` | ProcessesPage | Real process snapshot + events (psutil); demo `processSeed` offline |
| `/files` | FilesPage | `fileSeed` **demo constant only** — NOT the real file scanner output |
| `/network` | NetworkPage | Real topology/ports/events via hooked universe; `useSimulatedNetwork` offline |
| `/exposure` | ExposurePage | **Formulistic**: score derived from demo `phase` (`App.tsx:705`) |
| `/exposure-window` | ExposureWindowPage | Demo `phase`-driven static visualization |
| `/timeline` | TimelinePage | `timelineSeed` demo constant |
| `/quarantine` | QuarantinePage | Local React state only (no real file movement) |
| `/intelligence` | IntelligencePage | Hardcoded synthetic feed |
| `/reports` | ReportsPage | Locally generated TXT/JSON from demo state |
| `/history` | HistoryPage | Hardcoded 3-row array |
| `/cyber-cell` | CyberCellPage | Local simulated submission |
| `/settings` | SettingsPage | Session-local only |
| `/about` | AboutPage | Static |

### 3.2 Data-source classification per feature

| Feature | REAL | MOCK/SIMULATED |
|---|---|---|
| Process tree / inventory | ✅ psutil (offline → `processSeed`) | — |
| Process lifecycle events | ✅ SSE | — |
| Network connections & topology | ✅ psutil + shell | offline → `useSimulatedNetwork` (labeled **SIMULATED PREVIEW**) |
| Port intelligence | ✅ psutil | offline → synthetic |
| System telemetry | ✅ psutil (1s) | — |
| Filesystem threat scan | ✅ real walk + SHA-256 | — |
| Threat detections | ✅ client-side rules on live data | demo threats still **merged in** when live |
| Dashboard metrics | `Protection score 94.8%` is **hardcoded** (`App.tsx:234`) | risk = f(phase) |
| Exposure / risk scores | ✗ | score is `phase>=5?86:phase>=3?61:38` (`App.tsx:705`) |
| Incident timeline | ✗ | `timelineSeed`+phase |
| Quarantine | ✗ | local array |
| Containment | ✗ | status flip on local arrays (`App.tsx:917-930`) |
| Intelligence / reports / history / Cyber Cell | ✗ | static / local |

---

## 4. REAL-TIME THREAT DETECTION ENGINE (`artifacts/argus/src/hooks/use-threat-analysis.ts`)

### 4.1 Concept
`useThreatAnalysis(processMonitor, networkMonitor, fileMonitor, demoThreats)` — the demo threat seeds are passed in and **merged** with live detections via `mergeThreats` when live (`use-threat-analysis.ts:329-340, 452`). When live, `allThreats = mergeThreats(demoAsLive, liveThreats)` — so on `/threats` while the engine is running you see **both** real detections and the seeded demo threat card (`thr-1…thr-5`) unless a live one happens to match by `process + className`.

### 4.2 Actual live rules (all hardcoded regex / static lists)

| Rule | Trigger | Severity | Notes / gaps |
|---|---|---|---|
| Encoded PowerShell (`isEncodedPowerShell`) | name matches `/powershell/i` **and** `executable_path` matches enc/IEX/base64 patterns (`:75`) | critical | Checks the **exe path string**, not command-line → effectively detects a PowerShell binary *named* with enc patterns; real `powershell.exe` never matches. Weak. |
| Running from user-writable dir | `exePath` under Temp/Downloads/AppData, excl. explorer/svchost (`:76,88-91`) | medium | Labels it "Unsigned binary …" **without any signature verification**. High FP potential (any dev tool in Downloads). |
| Credential access | name/`CREDENTIAL_PROCS` (lsass/sam/ntds) or rundll32/mimikatz/procdump + lsass path (`:77-78,93-97`) | high | Static name matching → flags **any** `lsass.exe`/`sam` process regardless of handles. |
| Persistence via Run key | `proc.name === 'reg.exe'` and path contains `currentversion\run` (`:179`) | medium | Heuristic on path string. |
| PowerShell spawned | any recent `PROCESS_STARTED` with `/powershell/i` (`:200`) | low | No parent/args analysis. |
| Suspicious network | remote port in `[4444,5555,6666,7777,8888,9999,31337,1234,4321]`, **or** remote not matching safe domains while port ∉ {80,443,53} (`:79,99-107`) | critical/high | Rare ports / "everything non-80/443/53 against non-safelisted host". Safe-domain regexes (`microsoft.com$`…) applied to **IP address strings** → they effectively never match remote IPs, inflating FPs. |
| High-port outbound | remote port 8000-9000, ESTABLISHED (`:249`) | medium | Overlaps rule above; double-counting. |
| File artifacts | maps scanner categories to threat names (`:304-327`) | per finding | Real scan data. |

**Scan UX (`runScan`)**: purely cosmetic UI timer (`:394-438`) — progress bar, random `itemsChecked` via `Math.random`, `findings` = length of existing live set. **No new scan is invoked.**

### 4.3 Status taxonomy
`detected / contained / quarantined / resolved` (`:17`). Live threats always enter `detected`; only the demo `thr-1`/`thr-2` flow toggles to **quarantined/contained** via `applyContainment`.

### 4.4 Containment & quarantine reality check
- `containThreat` → `applyContainment([id])` (`App.tsx:968-971, 917-930`) updates in-memory `threats` statuses and prepends **demo** `containmentQuarantineItems` to the quarantine list. **No process killed, no socket closed, no file moved, no API call.**
- Quarantine Restore/Delete filters a local array (`App.tsx:727-735`). **No filesystem effect.**

---

## 5. FILE MONITORING & SCANNING (`artifacts/security-engine/file_monitor/scanner.py`)

**REAL, read-only, polished.**

- Roots: `TEMP/TMP`, `LOCALAPPDATA\Temp`, `Downloads`, `APPDATA`, `PROGRAMDATA`, + `FILE_SCAN_ROOTS` (`scanner.py:109-134`).
- Target extensions: `.exe .scr .pif .msi .cpl .com .jar .dll .bat .cmd .ps1 .psm1 .vbs .vbe .js .jse .wsf .hta .sh .py .zip .rar .7z` (`:31-35`).
- Window: files modified within last 48h (`config.py:53-55`), cap 2000 candidates (`config.py:65-67`), hash prefix up to 8 MB / read up to 512 KB (`config.py:57-63`).
- Heuristics: misleading filenames (invoice.pdf.exe, double-extensions, `:44-49`), script content markers (encoded-PS, download cradles, lsass/mimikatz, scheduled-task, startup-copy, archive-stager, recon commands, obfuscated strings `:52-93`), Startup-folder presence, Temp context. Severity ladder in `_severity_for` (`:229-262`).
- Produces real **SHA-256** of file contents (`:183-197`) and links `is_running` via current process snapshot. **Never modifies/quarantines/deletes** (docstring + code confirm).
- Gaps: **no signature verification (Authenticode), no hash-lookup (VT/Reputation), no YARA/signatures, no scan of `System32`/Program Files, no registry/scheduled-task/Event Log collection, no read of protected files, single session policy (48h) — old-dropped artifacts on disk from >48h are invisible.**

---

## 6. PROCESS MONITORING (`process_monitor/`)

- `snapshot.py`: real psutil enumeration (pid, name, exe, parent_pid, creation_time, cpu%, mem, username, status, `access_error` handling) — read-only.
- `watcher.py`: detects PROCESS_STARTED / PROCESS_TERMINATED / SNAPSHUT between poll cycles (2 s default).
- Gaps: **no command-line capture, no parent-args correlation, no integrity level consumed from engine metadata (`integrity` field exists in spec but not captured), no ETW/WMI event-driven start**.

---

## 7. NETWORK MONITORING (`network_monitor/`)

### 7.1 Connections (`collector.py`, `connections.py`, `watcher.py`)
- Real `psutil.net_connections(kind="inet")`; classifies LOCAL/LOOPBACK/PRIVATE/LINK_LOCAL/REMOTE; TCP state normalization; stable connection IDs; process-info cache. 3 s poll.
- **Gaps:** listing captures TCP/UDP local+remote sockets — **no packet capture, no payload, no per-flow bytes**, no DNS query logging, no TLS/metadata.

### 7.2 Topology (`topology_collector.py`, `topology_watcher.py`)
- Interfaces, gateway, DNS (`route print`, `ipconfig /all`), neighbors (`arp -a`, `Get-NetNeighbor`, `Get-NetAdapter`), public IP via `api.ipify.org` (every ~40 cycles), reverse-DNS cache.
- Event types: NEW/CLOSED/STATE_CHANGE + GATEWAY_CHANGE/DNS_CHANGE/INTERFACE_UP/DOWN/… with bounded history (200).

### 7.3 Port intelligence (`port_collector.py`, `port_models.py`, watcher)
- TCP LISTEN + UDP endpoints from socket table; stable `port_id` (SHA-1 digest); binding classification (LOOPBACK/WILDCARD/INTERFACE); process resolution; associations to active connection IDs. Read-only. 3 s poll.

**All network components are observation-only: nothing drops/limits/firewalls.**

---

## 8. SYSTEM TELEMETRY (`system_monitor/collector.py`)
- psutil CPU/memory/disk/uptime/network interfaces, `_safe()` error guard. 1 s poll. Real.

---

## 9. EVENT PIPELINE & API SERVER (`artifact/api-server`)

#### 9.1 EventHub (`lib/event-hub.ts`)
- **In-memory only**: process events buffer 500 (`:344`), topology event history 1000 (`:346`), port history 1000, latest snapshots for each type, SSE clients ≤ 50 (`:345`).
- Topic-based broadcast: `process`, `telemetry`, `network.connections`, `network.topology`, `network.connection_events`, `network.ports`, `network.port_events`, `files.scan` (`:289-297`).

#### 9.2 Endpoints (`routes/`)
| Route | Method | Verified |
|---|---|---|
| `/healthz` | GET | zod-validated response (`health.ts:7`) |
| `/events/process` | POST/GET | hand-written validator, ≤100/batch, 413 guard (`process.ts:10-61`) |
| `/events/process/stream` | GET SSE | heartbeat 15 s |
| `/processes` | POST/GET | ≤10000 processes, 413 guard |
| `/system/telemetry` | POST/GET | source check (`telemetry.ts:22-28`) |
| `/system/telemetry/stream` | GET SSE | — |
| `/network/connections` | POST/GET | ≤5000 conns (`network.ts:30`) |
| `/network/connections/stream` | GET SSE | — |
| `/network/topology` | POST/GET | ≤10000 conns |
| `/network/topology/stream` | GET SSE | — |
| `/network/events` | GET | limit ≤1000 |
| `/network/ports` | POST/GET | ≤10000 ports |
| `/network/ports/events` | GET | limit ≤1000 |
| `/network/ports/stream` | GET SSE | — |
| `/files/scan` | POST/GET | ≤1000 findings (`file.ts:49`) |
| `/files/scan/stream` | GET SSE | — |
| `/processes/icon` | GET | PowerShell icon extraction, path-validated (see §13) |

#### 9.3 Pipeline gaps
- **Ingestion validation is hand-written in the route layer, not the generated `@workspace/api-zod` schemas** (those are only used at `/healthz`). Spec drift risk exists (see §10).
- **No persistence**: every event/snapshot lives in process memory; restart = data loss. `@workspace/db` is installed in the api-server manifest but **imported nowhere in `api-server/src`** (grep confirmed only `package.json`).
- No queue/backpressure (engine buffers locally on API failure: `main.py:210-213`).

---

## 10. OPENAPI SPEC & CODE-GEN (`lib/api-spec`, `lib/api-zod`, `lib/api-client-react`)

- `openapi.yaml` defines: healthz, processes, events/process (+stream), system/telemetry (+stream), network/connections (+stream), network/topology (+stream), network/events, network/ports (+stream, +events). **Missing from spec: `/files/scan*` and `/processes/icon`** — the spec lags the implemented routes (drift: server has them, spec/client types don't).
- `api-zod` generated only up to spec; `api-client-react` (react-query hooks) exists but **frontend does NOT import `@workspace/api-client-react` or `@workspace/api-zod`** — hooks use raw `fetch` + `EventSource` directly (confirmed by grep: no workspace imports in `argus/src`). Generated client is dormant.

---

## 11. DATABASE (`lib/db`)
- `schema/index.ts` re-exports only `./processEvents`; `processEvents.ts` defines a single table `process_events` (uuid, event_type, timestamp, pid, process_name, executable_path, parent_pid, parent_process_name, source, observed, metadata jsonb, created_at).
- Comment notes it is "prepared for future PostgreSQL persistence… events stored in-memory via EventHub". **Dormant**: no runtime import, requires `DATABASE_URL`, zero migrations applied (drizzle config exists).

---

## 12. REAL vs MOCK — DEFINITIVE TABLE

| Data set | Real | Mock/Synthetic | Where |
|---|---|---|---|
| Process inventory/events | ✅ | offline fallback `processSeed` | `/processes`, dashboard stream |
| System telemetry | ✅ | — | `/monitoring`, dashboard host card |
| Network topology/connections/ports | ✅ | offline `useSimulatedNetwork` (labeled SIMULATED, RFC 5737 test nets) | `/network` |
| File scan findings/hashes | ✅ | — | only surfaced via `/threats`; **not** `/files` |
| Threat detections | ✅ client-side rules | **demo `thr-1..5` merged in even when live** | `/threats`, dashboard |
| Incident timeline | ✗ | `timelineSeed` + phase | `/timeline`, `/exposure-window` |
| Risk/exposure scores | ✗ | formula of phase | `/exposure` |
| Quarantine/containment | ✗ | local state only | `/quarantine`, `/threats` |
| Intelligence/reports/history/Cyber Cell | ✗ | static | various |
| Protection score "94.8%" | ✗ | hardcoded | dashboard |

---

## 13. SECURITY-RELEVANT FINDINGS (current code, not exploited)

| # | Severity | Finding | Evidence | Note |
|---|---|---|---|---|
| 1 | 🔴 HIGH | API has **no authentication/authorization**; any local process can POST/read all telemetry and alter event-hub state | `app.ts:28-32` (no auth), every route open | Future real deployment risk |
| 2 | 🔴 HIGH | **No persistence** → forensic evidence vanishes on restart; audit trail impossible today | EventHub in-memory buffers; `@workspace/db` unimported | Blocks forensic/reporting goals |
| 3 | 🟠 MED | Unrestricted CORS (`cors()`), no rate limiting, no security headers (helmet), no centralized error handler | `app.ts:28`; middleware list | Real-time ingestion abuse in a networked deployment |
| 4 | 🟠 MED | Client-side detection uses unresolvable/mis-scaled heuristics → FP-heavy and partly inert (encoded-PS rule never fires on real `powershell.exe` because it tests the path string; safe-domain regexes test IPs not hostnames) | `use-threat-analysis.ts:75-107,179` | Tuning/pruning needed before trust |
| 5 | 🟠 MED | `/processes/icon` shells to `powershell.exe` w/ encoded command (read-only icon extract, 8 s timeout, path validated `^[A-Za-z]:` + ≤320 chars) | `icon.ts:35-101` | Acceptable risk now; re-audit when API is exposed |
| 6 | 🟡 LOW | File scan "Unsigned binary" label has no Authenticode check; severity ladder can label benign scripts | `use-threat-analysis.ts:144-147` | Label accuracy |
| 7 | 🟡 LOW | `FileScanRoots` reads `PROGRAMDATA` + env-based roots; path-traversal surface minimal (os.walk on fixed roots) | `scanner.py:109-134` | Watch if roots user-configurable |
| 8 | 🟡 LOW | Frontend hardcodes demo credential default `argus-demo` (`App.tsx:846`) — cosmetic auth, no server session | `App.tsx` AuthScreen | demo-only, remove before prod |
| 9 | ⚪ INFO | Python engine uses only stdlib + psutil; no command shell exec for data collection except read-only tools (route print, ipconfig, arp, Get-Net*) | topology_collector | safe pattern |

**Positive findings:** No command-injection, no arbitrary file deletion, no packet capture, no process termination anywhere in engine or API; all collectors are read-only; SHA-256 hashing and content heuristics are genuinely implemented; SSE heartbeat + reconnect logic present; per-endpoint payload caps present.

---

## 14. CAPABILITY SCORECARD (what exists today)

| Capability | Status | Evidence |
|---|---|---|
| Real process monitoring | ✅ | `snapshot.py`, SSE |
| Process lifecycle detection | ✅ (polling, not ETW) | `watcher.py` |
| Real file scanning w/ hashes | ✅ (limited roots+window) | `scanner.py` |
| Real network connections | ✅ | `collector.py` |
| Topology/ports/neighbors/gateway/DNS | ✅ | topology + port collectors |
| System telemetry | ✅ | `system_monitor` |
| Live rule-based detection | ✅ (client-side, heuristic) | `use-threat-analysis.ts` |
| Scan UX | 🟡 cosmetic progress, no real engine scan |
| Incident timeline / correlation | ❌ demo only |
| Exposure/risk scoring | ❌ phase formula |
| Quarantine (real file movement) | ❌ local array |
| Containment (real process/network action) | ❌ status flip only |
| Alerts / notification engine | ❌ hardcoded "No new alerts" toast (`App.tsx` Bell button) |
| Threat intel / reputation / hash lookup | ❌ static text |
| Evidence store / chain-of-custody | ❌ none |
| DB persistence / migrations | ❌ dormant schema |
| AuthZ / authN / rate limit / headers | ❌ |
| Tests / CI | ❌ none (only browser QA script) |

---

## 15. WHAT CAN ARGUS THREAT DETECTION ACTUALLY DO RIGHT NOW?

Honest summary: **It observes the local Windows host in real time (process, network topology/ports, system health, and a bounded heuristic filesystem scan) and computes a curated list of candidate detections directly in the browser.** That part is genuinely live and read-only. Everything downstream that a security analyst relies on — named incident lifecycle, correlation timeline, exposure scores, quarantine, containment, alerting, persistence across restarts — is **simulated on the client** and does not touch the endpoint.

Therefore the current threat-detection capability is best characterized as: a **live telemetry dashboard with browser-side heuristics and a clearly-labeled synthetic incident scenario**, not a deployable detection/response product.

---

## 16. TOP-LEVEL GAPS TO CLOSE (for the planned Threat Detection upgrade)

1. **Detection moved server-side** — rules currently live in `use-threat-analysis.ts`; a real detection service (Python or Node) should own rules and events; keep the UI as presentation only.
2. **Signature & reputation layer** — no YARA, no Authenticode, no hash lookup (VT/reputation). File hashes exist but nothing consults them.
3. **Wider capture** — command-line/args for processes; DNS query events; Event Log/ETW; scheduled tasks/startup registry; all are currently absent.
4. **Persistence** — activate `@workspace/db` (`process_events` table exists), add schema for connections/files/ports/threats/incidents, real ingestion writes.
5. **API hardening** — authN/Z, rate limit, CORS policy, error middleware; regenerate api-zod/client from a spec that includes `/files/scan` and `/processes/icon`.
6. **Remote-control safety rail** — if containment/quarantine becomes real, gate behind strict allowlists + confirmation; engine currently has zero destructive primitives (good baseline).
7. **Reduce FP noise** — rework encoded-PS rule, safe-domain matching against hostnames not IPs, dedupe high-port rule.

---

## 17. VERIFICATION NOTES

- `rg` unavailable on this host; searches used the grep tool / PowerShell `Select-String`.
- Typecheck/build/test were **not** run (audit read-only); `App.tsx` is a 1052-line single file (large refactor target).
- Reports outside the code dirs (`ARGUS_REALTIME_MONITORING_AUDIT.md`, `ARGUS_PHASE1_PROCESS_MONITOR.md`) read; they describe scaffold and Phase 1 respectively and are partially superseded.

**No files were created, modified, or deleted in source directories. No packages installed. Engine never run.**