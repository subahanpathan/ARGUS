# ARGUS Security Intelligence — Implementation Roadmap

**Problem Statement:** PS-24: Coordinated Cyberattack Path Predictor  
**Baseline Date:** October 10, 2026  
**Status:** Phase 1 Complete — Ready for Phase 2  

---

## Phase Status Summary

| Phase | Title | Status | Verification / Artifacts |
|---|---|---|---|
| **Phase 0** | Repository Audit and Baseline | **COMPLETE** | `docs/current-architecture.md`, `docs/implementation-roadmap.md`, baseline audit report |
| **Phase 1** | Controlled Simulation Framework | **COMPLETE** | `POST /api/simulations`, `/api/simulations/:id`, `is_simulation` metadata, `artifacts/api-server/src/detection/__tests__/simulation-lifecycle.test.ts` (8/8 PASS) |
| **Phase 2** | Detection and Event Correlation | PENDING | Rule evaluation, incident grouping, false positive measurement |
| **Phase 3** | Attack-Path Reconstruction and Prediction | PENDING | Tree visualization, next-stage ranking, confidence scoring |
| **Phase 4** | Safe Automated Containment | PENDING | Policy enforcement, dry-run mode, process termination, audit log |
| **Phase 5** | Data Exposure and Damage Assessment | PENDING | File modification tracking, SHA-256 baseline comparison, transfer classification |
| **Phase 6** | Consent-Based Incident Reporting | PENDING | Incident summary, report preview, explicit consent check, submission handle |
| **Phase 7** | Investigation and Incident Timeline | PENDING | Forensic timeline workspace, analyst notes, evidence linkage |
| **Phase 8** | Recovery and Integrity Verification | PENDING | File restoration from staging, baseline hash verification |
| **Phase 9** | Adaptive Defense and Regression Testing | PENDING | Precision tracking, rule candidate generation, scenario replay comparison |
| **Phase 10** | End-to-End Judge Demonstration | PENDING | Repeatable end-to-end demo script, validation report |

---

## Phase 1 Implementation Summary

### 1. Verified Deliverables & Endpoints
- **Simulation Lifecycle Engine (`simulation-engine.ts`):** Orchestrates safe, repeatable attack scenarios (`reverse_shell_exfiltration`, `suspicious_process_spawn`, `simulated_network_transfer`, `test_file_integrity`, `benign_browser_activity`).
- **REST API Routes (`/api/simulations`):**
  - `POST /api/simulations` — Validate and start an allowlisted scenario. Rejects unknown scenarios and concurrent jobs.
  - `GET /api/simulations/scenarios` — Retrieve approved scenario allowlist.
  - `GET /api/simulations` — Retrieve all simulation run records.
  - `GET /api/simulations/:id` — Retrieve job status, progress, ground-truth logs, and detection rate.
  - `GET /api/simulations/:id/events` — Retrieve events generated for a simulation.
  - `POST /api/simulations/:id/stop` — Safely cancel active simulation and clean up workspace.
- **Event Isolation & Metadata Preservation:**
  - All generated events carry explicit metadata: `is_simulation: true`, `simulation_id`, `scenario_id`, `source: "simulation"`.
  - Ingested simulation events preserve metadata into resulting detections in `EventHub` and `DetectionEngine`.
  - Live host events maintain `source` (e.g. `windows_process_monitor`) and `is_simulation: false`.
- **File System & Process Safety:**
  - Synthetic test files are strictly confined to `var/argus-lab-workspace`.
  - Network connections use synthetic loopback or private lab IP endpoints (`10.0.2.15:4444`).
- **Frontend SPA Integration (`lab-page.tsx`):**
  - Updated `useLabSimulator` hook to consume real backend APIs (`/api/simulations`).
  - Displays target environment status indicator (`Authorized Local Test Workspace`), simulation ID badges, live event counts, and progress timeline.

### 2. Test Evidence
- **Simulation Lifecycle Unit Test Suite (`simulation-lifecycle.test.ts`):**
  - `8 passed` out of 8 tests (`node --import tsx --test src/detection/__tests__/simulation-lifecycle.test.ts`).
  - Verified scenario allowlist enforcement, unique simulation IDs, concurrent run rejection, event & detection metadata tagging, live event separation, safe cancellation, and file workspace isolation.

---

## Next Steps

Wait for explicit prompt `CONTINUE TO PHASE 2` before beginning implementation of **Phase 2: Detection and Event Correlation**.

