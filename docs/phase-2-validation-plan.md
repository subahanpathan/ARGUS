# ARGUS Phase 2 — Detection and Event-Correlation Validation Plan

**Problem Statement:** PS-24: Coordinated Cyberattack Path Predictor  
**Author role:** Cursor (Phase 2 audit / validation plan only)  
**Parallel owner:** Antigravity (Phase 1 simulation lifecycle — do not assume available)  
**Plan date:** 2026-10-10  
**Status:** AUDIT COMPLETE — no Phase 2 production implementation in this assignment  

---

## 1. Purpose and scope

This document records what detection and correlation already do in the repository, which contracts Phase 2 must validate, how to measure false positives/negatives with harmless synthetic events, and what Phase 1 must deliver before Phase 2 implementation starts.

**In scope for this assignment:** architecture audit, validation matrix, test inventory, dependency list, risks.  
**Out of scope:** implementing Phase 2 code, editing simulation routes/engine, changing shared OpenAPI contracts, frontend work.

**Working-copy caveat:** Uncommitted / untracked Phase 1 files may exist locally (`simulation-engine.ts`, `simulations.ts`, `simulation-lifecycle.test.ts`, normalize pass-through edits). This plan treats them as **unavailable** unless re-verified after Phase 1 lands. Anything not re-verified from stable sources is labeled **unknown**.

---

## 2. Existing detection and correlation architecture (verified)

### 2.1 High-level flow

```
Process / Network / File telemetry
        │
        ▼
  Normalize (domain-specific)
        │
        ▼
  DetectionEngine.ingest*
   ├─ evaluateRules (PROC)
   ├─ evaluateNetworkRules (NET)
   ├─ evaluateFileRules (FILE)
   ├─ dedup (exact + hourly unit window)
   └─ cross-domain correlate (same unit/pid, 10 min)
        │
        ▼
  EventHub.addDetection (+ optional SSE topic "detections")
        │
        ├─► AttackCorrelationEngine (PID incidents / timeline / graph / impact)
        ├─► ResponseOrchestrator (state machine / containment)
        └─► PredictionEngine (next-stage ranking, isPredicted=true)
```

### 2.2 Key modules (verified paths)

| Concern | Path |
|---|---|
| Detection engine | `artifacts/api-server/src/detection/engine.ts` |
| Rule catalogs | `artifacts/api-server/src/detection/catalog.ts`, `rules.ts`, `network/rules.ts`, `file/rules.ts` |
| Types | `artifacts/api-server/src/detection/types.ts` |
| Process normalize | `artifacts/api-server/src/detection/normalize.ts` |
| Network normalize | `artifacts/api-server/src/detection/network/normalize.ts` |
| File normalize | `artifacts/api-server/src/detection/file/normalize.ts` |
| Lab NET role helpers | `artifacts/api-server/src/detection/network/lists.ts` |
| EventHub | `artifacts/api-server/src/lib/event-hub.ts` |
| Attack correlation | `artifacts/api-server/src/lib/attack-correlation.ts` |
| Monitoring correlator | `artifacts/api-server/src/lib/correlation.ts` |
| Response / incidents | `artifacts/api-server/src/lib/response-orchestrator.ts`, `routes/incidents.ts` |
| Predictions | `artifacts/api-server/src/lib/prediction-engine.ts`, `routes/predictions.ts` |
| Backtrace enrichment | `artifacts/api-server/src/lib/backtrace-engine.ts` |
| Adaptive defense | `artifacts/api-server/src/lib/adaptive-defense.ts`, `routes/adaptive-defense.ts` |
| Detection HTTP/SSE | `artifacts/api-server/src/routes/detections.ts` |
| Ingest routes | `routes/process.ts`, `routes/network.ts`, `routes/file.ts` |

### 2.3 Rule catalog (23 rules, verified in `DetectionRuleId`)

| Domain | Rule IDs |
|---|---|
| PROC | `PROC-001-SUSPICIOUS-PARENT-CHILD` … `PROC-007-LOLBIN-EXECUTION` |
| NET | `NET-001-USER-WRITABLE-OUTBOUND` … `NET-009-DATA-EXFILTRATION` |
| FILE | `FILE-001-STARTUP-PERSISTENCE` … `FILE-007-RECON-SCRIPT` |

### 2.4 Detection result reporting (verified APIs)

| Method | Path | Notes |
|---|---|---|
| GET | `/api/detections/rules` | Full catalog |
| GET | `/api/detections` | Filters: `severity`, `status`, `rule_id` — **no** `is_simulation` filter verified |
| GET | `/api/detections/:id` | Detail + related + ancestry |
| PATCH | `/api/detections/:id` | Status lifecycle |
| POST | `/api/detections/probe` | Live probe (`source: "argus_live_probe"`) |
| GET | `/api/detections/stream` | SSE detections topic |
| GET | `/api/attack-traces*` | Correlated incidents / timeline / graph / impact / backtrace |
| GET | `/api/predictions` | Ranked next stages |
| GET/POST | `/api/incidents*` | Orchestrated response |
| GET/POST | `/api/adaptive-defense*` | Snapshot, rules, regression, incident-closure |

### 2.5 EventHub (verified)

- Process event buffer cap: 500  
- Detection buffer cap: 300  
- Topology/port history cap: 1000  
- File activity history: capped (~500)  
- `getEvents` / `getDetections` / SSE / `reset()` present  
- **No verified `is_simulation` filter** on hub getters or list APIs  
- `reset()` is in-process only — **no verified HTTP admin reset route**

### 2.6 Correlation behavior (verified)

- Engine-level: detections sharing the same unit (`pid > 0` or `metadata.stableKey`) within ~10 minutes escalate severity / confidence and set `correlated_rules`.
- Attack correlation: groups by **pid**; joins process ancestry/children, network sockets for related pids, file activity (pid / name / ±120s heuristics).
- Incident id pattern: `INC-2026-{pid}`.
- Evidence summary carries refs such as `detectionId`, `ruleId`, `connectionId`, `eventId`, with observation status OBSERVED / CORRELATED / INFERRED / UNKNOWN.
- Detections with `pid === 0` do **not** form PID incidents (verified by correlation design).

### 2.7 Attack-path prediction (verified subset)

`RULE_STAGE_MAP` currently maps only:

- `NET-008`, `NET-009`, `PROC-001`, `PROC-002`, `NET-001`, `FILE-001`, `NET-006`

Other catalog rules produce **no stage mapping** unless extended later. Predictions always set `isPredicted: true`. Confidence bands: 0.75 (≥2 matches), 0.55 (1), 0.4 (chain-adjacent), 0.25 otherwise.

### 2.8 Simulation-versus-live separation (current, without assuming Phase 1)

| Mechanism | Status |
|---|---|
| Live probe `source` / `observed` | Verified on probe path |
| `ARGUS_MODE=LAB` / `ALLOW_PRIVATE_RANGES_IN_DETECTION` | Verified — private LAN can count as remote for many NET rules |
| Loopback `127.0.0.1` treated as non-external | Verified — NET-008 / NET-009 **do not** treat loopback as C2 remote |
| Typed `is_simulation` on `Detection` / `SecurityEvent` | **Not verified** in committed types |
| API filters `?is_simulation=` / `simulation_id=` | **Not verified** |
| Phase 1 simulation lifecycle HTTP API | **Unknown / owned by Antigravity** — do not depend until coordinated |

---

## 3. Current event contracts and required fields

### 3.1 Process ingest / `SecurityEvent` (verified)

**API validation (process routes):** `pid` (number), `process_name` (string), `event_type` ∈ `PROCESS_STARTED` | `PROCESS_TERMINATED` | `SNAPSHOT`.

**Normalize:** `PROCESS_STARTED` / `PROCESS_TERMINATED` normalize to `SecurityEvent`; snapshot events follow snapshot path. Required normalized fields: `id`, `type`, `origin`, `timestamp`, `source`, `hostname`, `pid`, `process_name`. Optional: paths, command line, parent, username, `metadata`.

**Not on committed `SecurityEvent` type:** `is_simulation`, `simulation_id`, `scenario_id` (any working-tree pass-through is uncommitted and **unknown** for Phase 2 planning).

### 3.2 Network view (`NetworkViewEvent`)

Required: `id`, `type`, `origin`, `timestamp`, `source`, `hostname`, `pid`, `process_name`. Socket fields optional. `pid` may be `0` when owner unknown.

### 3.3 File view (`FileViewEvent`)

Required: `id`, `type`, `origin`, `timestamp`, `source`, `hostname`, `pid`, `process_name`, `file_path`, `file_name`. Optional: hash, size, category, finding reason, running flag.

**Important:** FILE rules evaluate **file scan findings**, not raw `FileActivityEvent` alone. Integrity-only file modifications without shaped findings may miss FILE-* rules.

### 3.4 Detection output (verified)

Required conceptual fields: `id`, `rule_id`, `rule_name`, `title`, `severity`, `confidence`, `status`, timestamps, `entity`, `pid`, `hostname`, `evidence[]` (`key`, `description`, `source`), `explanation`, `recommended_action`, `ancestry`, optional `correlated_rules`, `related_event_id`.

**Not on committed `Detection` type:** simulation tags.

---

## 4. Scenario → expected detection matrix (harmless synthetic)

Use **synthetic / loopback / private-lab** payloads only. No arbitrary shell execution against user data. Prefer private non-loopback destinations for NET-008/009 under `ARGUS_MODE=LAB`.

### 4.1 Verified from committed `lab-workflow.test.ts`

| Scenario (informal) | Synthetic fixture shape | Expected detections | Expected non-fires |
|---|---|---|---|
| Benign browser to private HTTPS | `chrome.exe` → `192.168.1.50:443`, `remote_role=PRIVATE`, LAB mode | none hostile | no `NET-008`, no `NET-002` |
| Reverse shell to private C2 | `powershell.exe` → `192.168.1.50:4444`, LAB mode | `NET-008-REVERSE-SHELL` (critical, confidence ≥ 0.9) | — |

### 4.2 Proposed Phase 2 matrix (synthetic; expected results to be confirmed in Phase 2 tests)

| ID | Scenario | Domain fixtures (harmless) | Expected primary rules | Expected correlation / evidence |
|---|---|---|---|---|
| P2-01 | Encoded PowerShell from Office parent | Process: `winword.exe` → `powershell.exe -nop -enc …` | `PROC-001` and/or `PROC-002` | `related_event_id` set; evidence keys from command_line / parent |
| P2-02 | LOLBin download-execute | Process: `certutil.exe -urlcache …` (probe-like) | `PROC-006` and/or `PROC-007` | Single pid unit; no user-file writes |
| P2-03 | Private reverse shell (LAB) | Network: interpreter → `192.168.1.50:4444` | `NET-008` | Evidence includes reverse socket tuple |
| P2-04 | Benign browser control | Network: chrome → private `:443` | **zero** hostile NET | FP control baseline |
| P2-05 | Cross-domain same pid | PROC encoded + NET-008 same pid within 10 min | both rules; `correlated_rules` non-empty | One attack-trace `INC-2026-{pid}` linking both |
| P2-06 | File startup persistence finding | File scan finding under Startup path with FILE category/reason | `FILE-001` | File path + hash in evidence |
| P2-07 | Credential artifact finding | Synthetic path resembling credential dump artifact | `FILE-003` | Path/hash evidence only; disposable path |
| P2-08 | Loopback control | Interpreter → `127.0.0.1:4444` | **expect no NET-008/009** under current lists | Documents loopback exclusion |
| P2-09 | Unknown socket owner | Network connection `pid=0` | may fire NET rules | **must not** invent PID incident |
| P2-10 | Dedup flood | Re-ingest identical process event | one detection per rule/unit/hour | Hub count stable |
| P2-11 | Prediction subset | Detections for mapped rules only | ranked stages, `isPredicted=true` | `evidenceRefs` include detection/rule ids |
| P2-12 | Unmapped rule only | e.g. FILE-007 alone | detection exists | prediction stages may be empty / low confidence — **document actual behavior** |

### 4.3 Draft Phase 1 scenario alignment risk (do not treat as committed)

Local draft allowlists (Antigravity-owned, **unknown until Phase 1 ships**) have proposed expectations such as:

| Draft scenario id | Draft expectedRules | Alignment risk vs verified engine |
|---|---|---|
| `reverse_shell_exfiltration` | NET-008, PROC-002, NET-009 | If fixtures use `127.0.0.1`, NET-008/009 likely **miss** |
| `suspicious_process_spawn` | PROC-001 | `ping` from `cmd` likely **does not** match PROC-001 parent/child lists |
| `simulated_network_transfer` | NET-009 | Network-only socket without transfer markers may **miss** NET-009 |
| `test_file_integrity` | FILE-001 | Raw file modify without scan finding shape may **miss** FILE-001 |
| `benign_browser_activity` | `[]` | Aligns with P2-04 if private `:443` used |

Phase 2 implementation must reconcile fixtures with rule predicates — not loosen safety to force green tests.

---

## 5. Expected correlation and evidence relationships

| Relationship | Expected behavior | Verification method |
|---|---|---|
| Detection → source event | `related_event_id` references ingested event id when available | Assert round-trip `GET /api/detections/:id` |
| Cross-domain same pid | `correlated_rules` lists peer rule ids; severity/confidence may escalate | Engine unit test + attack-trace detail |
| Incident grouping | `INC-2026-{pid}` aggregates detections for that pid | `GET /api/attack-traces/:id` |
| Timeline evidence | Entries carry `detectionId` / `ruleId` / optional `connectionId` / `eventId` | Timeline API assertions |
| Graph edges | Parent-child / process-network / process-file links marked OBSERVED or CORRELATED | Graph API; no INFERRED-only as sole proof for critical demo claims |
| Predictions | Always `isPredicted: true`; never presented as observed | Prediction API + UI contract later |
| Simulation isolation (post–Phase 1) | Sim-tagged detections excluded from default live lists **or** explicitly filterable | **Blocked** until Phase 1 tagging contract exists |

---

## 6. False-positive and false-negative validation methods

### 6.1 False positives (FP)

1. **Benign twin fixtures** for every hostile scenario (P2-04 style): same destination class, non-suspicious process.
2. **System-path controls:** `System32` listeners / normal Office without interpreter child → expect zero PROC hostile rules.
3. **Lab vs prod mode:** run P2-03 with and without `ARGUS_MODE=LAB`; document private-IP behavior difference.
4. **Adaptive defense:** use `POST /api/adaptive-defense/incident-closure` and `/regression` only after ≥5 labeled samples — current engine returns null FP rates until that threshold (**verified design**). Manual labeling required; automatic linkage from orchestrator closures is **unknown / incomplete**.

### 6.2 False negatives (FN)

1. **Ground-truth expectedRules** per scenario vs `firedRules`.
2. **Miss classification:** rule never evaluated vs predicate miss vs dedup suppression vs wrong normalize.
3. **Domain mismatch:** FILE rules need scan findings; NET-009 needs transfer markers; PROC-001 needs listed parent/child pairs.
4. **Loopback exclusion:** treat as intentional FN for 127.0.0.1 C2 unless product decision changes.

### 6.3 Metrics to record per scenario run

- `expectedRules`, `firedRules`, `matched`, `missed`, `extra`
- `detectionRate = matched / max(expected, 1)` (define benign `expected=[]` as pass iff `extra=[]`)
- Correlation: incident count for pid, evidence ref completeness
- Isolation (post–Phase 1): live-list contamination count

---

## 7. Tests required to verify detection and correlation

### 7.1 Existing independent tests (executed this assignment)

Command (explicit file list — **excludes** Antigravity `simulation-lifecycle.test.ts`):

```text
pnpm --filter @workspace/api-server exec tsx --test
  src/detection/__tests__/normalize.test.ts
  src/detection/__tests__/rules.test.ts
  src/detection/__tests__/engine.test.ts
  src/detection/__tests__/network.test.ts
  src/detection/__tests__/file.test.ts
  src/detection/__tests__/engine-domains.test.ts
  src/detection/__tests__/api.test.ts
  src/detection/__tests__/lab-workflow.test.ts
  src/detection/__tests__/attack-traces-impact.test.ts
  src/detection/__tests__/incidents-orchestrator.test.ts
  src/detection/__tests__/prediction-engine.test.ts
  src/detection/__tests__/adaptive-defense.test.ts
  src/detection/__tests__/monitoring-hub.test.ts
```

**Result (2026-10-10):** `# tests 157` / `# pass 144` / `# fail 13` / duration ~46.7s.

| Suite group | Result | Notes |
|---|---|---|
| Adaptive defense | PASS | |
| Detections HTTP/SSE (`api.test.ts`) | PASS | |
| Attack-traces impact | PASS | |
| Cross-domain engine | PASS | |
| Process engine / scoring / ancestry | PASS | |
| FILE catalog + rules | PASS | |
| Incidents orchestrator | PASS | |
| Lab workflow (NET-008 LAB + containment) | PASS | |
| NET catalog + rules | PASS | |
| Process normalize | PASS | |
| Prediction engine | PASS | |
| PROC catalog + rules | PASS | |
| `monitoring-hub.test.ts` | **FAIL (13)** | Missing EventHub APIs: `addMonitoringEvents`, `upsertScan`, `ingestFilesystemActivity`, `enqueueCommand`, `setAgentHeartbeat`, `getMonitoringSnapshot` (+ one security-provider assertion). **Not Phase 2 rule/correlation regressions**; monitoring hub surface drift. |

**Not executed (Antigravity-owned / untracked):** `simulation-lifecycle.test.ts`.  
**Not executed:** auth / desktop-download / recovery suites (out of Phase 2 validation focus).

### 7.2 Additional tests Phase 2 should add (after Phase 1 coordination — do not implement now)

| Test file (proposed) | Covers |
|---|---|
| `detection/__tests__/phase2-correlation-matrix.test.ts` | P2-01…P2-12 fixtures |
| `detection/__tests__/phase2-fp-fn-metrics.test.ts` | matched/missed/extra + benign controls |
| `detection/__tests__/phase2-isolation-filters.test.ts` | Requires Phase 1 tags + API filters |
| `detection/__tests__/phase2-evidence-roundtrip.test.ts` | `related_event_id` / timeline refs |
| Optional HTTP suite | detections/attack-traces filters under load |

---

## 8. Dependencies on Phase 1 simulation backend

Phase 2 validation of **isolation and scenario replay** requires Antigravity to deliver (coordinated contracts):

1. **Stable scenario allowlist** with `scenarioId`, description, safety note, `expectedRules`, phase list.  
2. **Consistent event tags:** at minimum `is_simulation`, `simulation_id`, `scenario_id`, and a distinguishable `source` (e.g. `"simulation"`).  
3. **Tag propagation onto detections** (or documented engine responsibility for Phase 2).  
4. **Fixtures that can actually fire rules** under verified predicates (private non-loopback for NET-008/009; correct parent/child for PROC-001; scan findings for FILE-*).  
5. **Lifecycle ops** usable by tests: start, status, events-by-simulation-id, cancel/cleanup, hub/engine reset between runs.  
6. **Workspace isolation** for disposable synthetic files only (e.g. `var/argus-lab-workspace`).  
7. **Documented HTTP paths** relative to `app.use("/api", …)` (avoid double `/api` prefix).  

Until those land, Phase 2 may still validate **rules + correlation on live-shaped synthetic payloads** (as existing unit tests already do) but **must not claim** end-to-end Simulation Lab isolation.

---

## 9. Files likely to require changes during Phase 2 implementation

*(Planning list only — not edited in this assignment.)*

- `artifacts/api-server/src/lib/event-hub.ts` — optional sim filters / dual views  
- `artifacts/api-server/src/detection/types.ts` — typed simulation / evidence fields if contracts agree  
- `artifacts/api-server/src/detection/engine.ts` — tag propagation, correlation metrics hooks  
- `artifacts/api-server/src/detection/normalize.ts`, `network/normalize.ts`, `file/normalize.ts`  
- `artifacts/api-server/src/routes/detections.ts`, `attack-traces.ts`, `predictions.ts`, `incidents.ts`  
- `artifacts/api-server/src/lib/attack-correlation.ts` — stronger evidence linkage / sim exclusion  
- `artifacts/api-server/src/lib/prediction-engine.ts` — expand `RULE_STAGE_MAP` if required  
- `artifacts/api-server/src/lib/adaptive-defense.ts` + tests — FP measurement harness wiring  
- `artifacts/api-server/src/detection/network/lists.ts` — only if product decides loopback lab policy  
- New Phase 2 test files under `detection/__tests__/`  
- `docs/implementation-roadmap.md` — Phase 2 status after implementation  
- Shared OpenAPI (`lib/api-spec`) — **only after explicit contract coordination**

**Do not touch for Phase 2 ownership conflict:** Antigravity simulation engine/routes/tests; frontend `artifacts/argus/**` until integration pass.

---

## 10. Unresolved questions and risks

1. **Loopback vs private C2:** Current NET helpers exclude `127.0.0.1`. Draft sims using loopback will FN on NET-008/009. Product decision required.  
2. **Phase 1 availability:** Untracked simulation files must not be assumed present on other machines or after clean checkout.  
3. **FILE rule input shape:** File-activity events alone are insufficient; scan findings required.  
4. **PROC-001 fixture honesty:** Spawning `ping` from `cmd` is a weak / likely-negative PROC-001 case.  
5. **NET-009 markers:** Exfiltration rule may need command-line / transfer markers beyond a bare socket.  
6. **Prediction coverage:** 16 of 23 rules lack stage mapping — demo narratives must not over-claim.  
7. **Backtrace fallback:** Missing incident IDs can yield synthetic demo data — tests must assert observed traces, not fallback.  
8. **Adaptive FP rates:** Remain null until enough labeled closures; orchestration auto-feed is unknown.  
9. **Monitoring hub drift:** `monitoring-hub.test.ts` fails against current EventHub API surface — separate from Phase 2 rules, but indicates hub feature churn risk.  
10. **Shared contract changes:** Any OpenAPI / Zod / React client updates need explicit coordination before editing.  
11. **In-memory hub:** No durable regression corpus without an external harness.  
12. **Authorization for sim start/stop:** Unknown until Phase 1 documents auth expectations; Phase 2 list filters must not leak sim noise into live SOC views.

---

## 11. Proposed next implementation steps (after Phase 1 is coordinated)

1. Freeze Phase 1 HTTP + event-tag contract in writing (paths, fields, status enum).  
2. Reconcile scenario fixtures with verified rule predicates (especially NET loopback and PROC-001).  
3. Implement API list filters / isolation for sim vs live (**Phase 2 code**).  
4. Add Phase 2 matrix tests (P2-01…P2-12) and FP/FN metric helpers.  
5. Wire adaptive-defense regression recording to scenario runs.  
6. Expand prediction map only where evidence-backed.  
7. Fix or quarantine monitoring-hub API drift independently.  
8. Integration test with frontend Simulation Lab **only after** both owners agree contracts are stable.  
9. Update `docs/implementation-roadmap.md` Phase 2 status with measured results.

**Stop condition for this assignment:** Audit + this plan only. Do **not** begin Phase 2 implementation until Phase 1 backend contracts and simulation lifecycle are available and coordinated.
