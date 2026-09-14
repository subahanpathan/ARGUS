# ARGUS Phase 2 — Process & Behavioral Detection

Deterministic, explainable process detection built on top of the Phase 1
real Windows process monitor. Every detection is produced by pure rules that
reason over real telemetry — no fabricated incidents, no opaque scoring.

## Architecture

```
ARGUS React UI (port 5173)
    ↓ fetch + EventSource (SSE)
ARGUS API Server (port 5000)
    ↓ detection module (normalize → rules → score → dedup → correlate)
    ↓ in-memory event hub (events, snapshot, detections)
Windows Process Monitor (Python)
    ↓ psutil (read-only), incl. command_line capture
Windows OS
```

New process events and snapshots pushed by the engine are normalized by the
API server, evaluated against the PROC rule set, and stored in the event hub
with a bounded, SSE-visible detection buffer.

## Detection Module (New)

| File | Purpose |
|------|---------|
| `artifacts/api-server/src/detection/types.ts` | `Detection`, `SecurityEvent`, `RuleMatch`, `DetectionRuleId`, lifecycle/evidence/ancestry types |
| `artifacts/api-server/src/detection/normalize.ts` | Raw process telemetry → `SecurityEvent` (hostname-stamped, origin spared) |
| `artifacts/api-server/src/detection/rules.ts` | The 7 PROC rules + ordered `RULES` list + `RULE_CATALOG` |
| `artifacts/api-server/src/detection/lists.ts` | Lookups: script interpreters, LOLBins, productivity apps, user-writable path detection |
| `artifacts/api-server/src/detection/engine.ts` | `DetectionEngine` — scoring, dedup, correlation, ancestry, context memory |
| `artifacts/api-server/src/detection/__tests__/*.test.ts` | normalize / rules / engine / api test suites |

## Rule Set (PROC-001 … PROC-007)

| Rule | Name | Fires when | Severity |
|------|------|-----------|----------|
| PROC-001 | Suspicious parent-child relationship | Productivity/browser/mail app or script interpreter spawned a script interpreter or LOLBin (spawn events only) | medium/high |
| PROC-002 | Encoded or obfuscated command line | EncodedCommand / Base64 decode / hex escapes / hidden window / execution-policy bypass | medium/high |
| PROC-003 | Interpreter script in user-writable dir | Script argument under Temp/Downloads/AppData/Desktop/Documents | high |
| PROC-004 | Execution from user-writable location | Script interpreter or LOLBin binary runs outside Windows directories | medium/high |
| PROC-005 | Interpreter chain | Script interpreter spawned another script interpreter (spawn events only) | medium |
| PROC-006 | Download-and-execute behaviour | bitsadmin, certutil urlcache, Invoke-WebRequest -OutFile, curl/wget markers | high |
| PROC-007 | LOLBin abuse | regsvr32 /runobj, rundll32 javascript:, mshta, schtasks /create, etc. | high |

Key properties:

- **Every rule is a pure function** `(SecurityEvent) => RuleMatch | null`. No
  randomness; confidence/severity derive from the rule, its evidence count and
  explicit modifiers.
- **Explanation + recommended action + evidence** accompany every match, so any
  detection can be audited end-to-end.
- **Double-marked**: `process_monitor` events are truncated (snippet) into
  bounded `evidence.detail`; the command line is never echoed raw.

## Files Modified in this Session

| File | Change |
|------|--------|
| `lib/api-zod/src/generated/api.ts` | Regenerated, then Zod-3 compatibility layer restored per repo precedent |
| `lib/api-zod/src/generated/types/index.ts` | Removed `updateDetectionStatusBody` barrel export (resolved TS2308 ambiguity) |
| `lib/api-client-react/src/generated/api.ts`, `api.schemas.ts` | Regenerated; detection schemas + hooks now present (useGetDetections, useStreamDetections, useGetDetectionRules, getDetection, updateDetectionStatus) |
| `artifacts/argus/src/App.tsx` | Added `RuleCatalogPage` + `/detections/rules` route (fixes the previously broken "Rule catalog" link) |

### Contract synchronization (codegen + compat layer)

- The OpenAPI spec in `lib/api-spec/openapi.yaml` already declared the full
  detection surface (`GET /detections`, `GET /detections/rules`, `GET
  /detections/:id`, `PATCH /detections/:id`, `GET /detections/stream`).
- Running `pnpm --filter @workspace/api-spec run codegen` (orval v8.23.0)
  regenerated both clients. Orval v8.23.0 emits Zod-4-style `zod.int()` /
  `zod.uuid()` helpers that do not exist in the pinned Zod 3.25.76, so the
  regenerated `api-zod` broke typecheck.
- The repo already documents this as a **manually maintained compatibility
  layer** (see the header of the prior compiled `lib/api-zod/dist/generated/api.d.ts`).
  Applied per repo precedent: `zod.int(x)` → `zod.number().int()` (211×) and
  `zod.uuid` → `zod.string().uuid` (3×).
- Restored the 10 deprecated backward-compatible aliases the previous
  checked-in output exposed (`HealthCheckResponseSchema`, `ProcessSnapshotSchema`,
  `SnapshotIngestResponseSchema`, `ProcessEventListSchema`,
  `EventIngestResponseSchema`, `SystemTelemetrySchema`, `NetworkTopologySchema`,
  `NetworkSnapshotIngestResponseSchema`, `DetectionListSchema`,
  `DetectionDetailSchema`). Note: new Orval output inlines component schemas
  instead of emitting standalone `ProcessEventSchema`/`PortInfoSchema`/... consts;
  those dormant names were not preserved.
- `@workspace/api-zod` is imported only by `health.ts` (`HealthCheckResponse`);
  `@workspace/api-client-react` is never imported at runtime. Both libraries
  typecheck cleanly and remain available for future consumers.

## Detection Engine Behaviour

- **Lifecycle**: `observed → detected → investigated → contained → resolved`
  (PATCH only; explicit lifecycle, **no auto-resolve**).
- **Dedup**: exact event+rule key plus an hourly per-`pid`-per-`rule` window;
  seen map is bounded (5 000 entries, 24 h prune).
- **Correlation**: distinct rules firing for the same `pid` within 10 min
  escalate severity (+1 step ≥ 2 rules, +2 steps ≥ 3) and raise confidence
  (`+0.05` per extra rule). Always explainable via `correlated_rules`.
- **Confidence** = base + command-line (+0.03) + multi-evidence (+0.02) −
  snapshot penalty (−0.05), clamped to 0.10–0.95.
- **Ancestry**: parent-chain walk (max depth 8, cycle-broken) exposed per
  detection and via `GET /detections/:id`.
- **Snapshot vs spawn**: `origin: "snapshot"` events skip spawn-relationship
  rules (PROC-001/005) to avoid baseline false positives.

## API Endpoints (detection surface)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/detections/rules` | Active PROC rule catalog (`{ rules: [...] }`) |
| `GET` | `/api/detections` | Recent detections (limit/severity/status/rule_id filters; also returns `rules`) |
| `GET` | `/api/detections/stream` | SSE detection stream (emits `connected` + live detections) |
| `GET` | `/api/detections/:id` | Detail record + related + current process context + ancestry |
| `PATCH` | `/api/detections/:id` | Update lifecycle status (validated) |

Ingestion is unchanged from phase 1: `POST /api/events/process` and
`POST /api/processes` now feed the engine (via `routes/process.ts`) and push
produced detections into the event hub.

## Frontend

- `hooks/use-detections.ts` consumes the list + SSE stream + lifecycle updates;
  the rule catalog is available in hook state (fetched from `GET /detections`
  and used for filtering).
- **DetectionsPage** lists live, real detections with severity/confidence/
  process/status, filters by severity and rule, and opens a detail view with
  evidence, explanation, recommended action and ancestry.
- **RuleCatalogPage** (new) renders `rule_id`, `rule_name`, `description` for
  every active rule with a search box, and is wired to the previously broken
  `/detections/rules` link. An "ENGINE OFFLINE"-style banner shows when the
  catalog is empty.
- No demo data is used for detections: when the engine/API is down the page
  shows a `DETECTION ENGINE STANDBY` banner instead of fabricating incidents.

## What is REAL vs DEMO

REAL (when engine is running): process enumeration via psutil, process
create/terminate events, parent-child relationships, CPU/memory, executable
paths, username, **command-line capture**, detections produced from that
telemetry by the PROC rule set.

DEMO (always available, clearly labeled): the existing synthetic threat model
(synthetic threats, file/network scenarios, exposure/timeline/quarantine) on
other pages. The Detections page itself is never seeded.

## Verification

```bash
pnpm run typecheck                 # libs + api-server + argus + mockup-sandbox + scripts  ✔
pnpm --filter @workspace/api-server run test   # 56/56 pass, 20 suites                    ✔
pnpm run build                     # api-server + argus + mockup-sandbox build            ✔
```

## Limitations

1. **No auto-containment** — lifecycle transitions require an analyst PATCH.
2. **No database persistence** — detections live in the in-memory hub.
3. **No file/network-behaviour rules** — PROC set only; network topology is
   ingested but not yet correlated into detections.
4. **Polling-based telemetry** — 2 s poll; not ETW/WMI event-driven.
5. **Regenerated zod surface** — component schema consts are inlined; only the
   documented deprecated aliases were restored (dormant names only).
6. **Spec drift** — server mounts `GET /processes/icon` which is not yet
   documented in `lib/api-spec/openapi.yaml`.
7. **No auth on the API** — out of phase scope.

## Next Steps (Phase 3/4 candidates, not started)

- Correlate network connections/ports and file-scans into detections.
- Persist detections to `lib/db` (drizzle schema already staged for events).
- Analyst-driven auto-containment / quarantine integration into the lifecycle.
- Add `GET /processes/icon` (and other undocumented routes) to the OpenAPI spec
  and re-run codegen.