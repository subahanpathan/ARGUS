# ARGUS Security Intelligence — Judging Demonstration Runbook

**Problem Statement:** PS-24: Coordinated Cyberattack Path Predictor  
**Target Environment:** Local Windows / Dev Node Environment  
**Version:** 1.0 (Phase 1 & Phase 2 Verified Baseline)  

---

## 1. Executive Overview

This runbook provides a step-by-step, 5-minute judge demonstration of **ARGUS Security Intelligence**. It demonstrates an end-to-end, deterministic cyberattack simulation, real-time detection, attack trace correlation, forward-looking predictions with evidence references, and safe automated containment proposals.

---

## 2. Prerequisites & Requirements

- **Operating System:** Windows 10/11 or macOS/Linux.
- **Node.js:** Node 20.x or higher installed.
- **Package Manager:** `pnpm` (or `npm`).
- **Browser:** Any modern browser (Chrome, Edge, Firefox).

---

## 3. Quick-Start Verification (PowerShell)

To verify the test suite baseline before running the application:

```powershell
# Navigate to the repository root
cd d:\Mini

# Execute combined unit and end-to-end integration test suite
node --import tsx --test artifacts/api-server/src/detection/__tests__/simulation-lifecycle.test.ts artifacts/api-server/src/detection/__tests__/phase2-end-to-end.test.ts
```

**Expected Test Output:**
```text
TAP version 13
# Subtest: ARGUS Phase 2 — End-to-End Integration Verification (reverse_shell_exfiltration)
    ok 1 - Step 1 to 4: Simulation events -> Detections -> Correlated Incident -> Predictions with Evidence
ok 1 - ARGUS Phase 2 — End-to-End Integration Verification (reverse_shell_exfiltration)
# Subtest: ARGUS Phase 1 — Controlled Simulation Framework Lifecycle & Isolation
    ok 1 - Test 1: Scenario allowlist is defined and rejected for unknown scenarios
    ok 2 - Test 2: Starting an allowed scenario generates unique simulation_id and initial state
    ok 3 - Test 3: Duplicate concurrent starts are rejected
    ok 4 - Test 4: Simulation events carry explicit metadata (is_simulation, simulation_id, scenario_id)
    ok 5 - Test 5: Live events retain live telemetry source and non-simulated classification
    ok 6 - Test 6: Simulation event ingestion triggers detections tagged with simulation metadata
    ok 7 - Test 7: Stop simulation cancels active run and performs safe workspace cleanup
    ok 8 - Test 8: Test files are isolated within var/argus-lab-workspace/
ok 2 - ARGUS Phase 1 — Controlled Simulation Framework Lifecycle & Isolation
# tests 9
# pass 9
# fail 0
```

---

## 4. Application Startup Sequence

Launch the backend API server and frontend SPA in separate terminal windows:

### Terminal 1: Backend API Server
```powershell
cd d:\Mini
pnpm --filter @workspace/api-server run dev
```
*Backend listens at `http://localhost:3000` (or `http://localhost:5000`).*

### Terminal 2: Frontend SPA
```powershell
cd d:\Mini
pnpm --filter @workspace/argus run dev
```
*Frontend SPA serves at `http://localhost:5173/`.*

---

## 5. Judge Demonstration Steps (5-Minute Script)

### Step 1: Open Simulation Lab
1. Open browser to `http://localhost:5173/lab`.
2. Observe the top banner displaying:
   - **Target Environment:** `Authorized Local Test Workspace (var/argus-lab-workspace | Loopback 127.0.0.1)`
   - Safety indicator confirming all generated events carry `SIMULATION` metadata.

### Step 2: Select & Launch Scenario
1. Select **Reverse Shell + Exfiltration** from the scenario list.
2. Click **Run Scenario**.
3. Observe live lifecycle status change: `starting` → `running`.
4. A purple badge appears showing the unique run ID (e.g., `SIMULATION ID: sim-1728503920112-a892b`).

### Step 3: Observe Real-Time Phase Progression
Watch the phase progression panel as the simulation steps through harmless, deterministic phases:
- **PRE_ATTACK:** Deploys disposable synthetic test files (`lab_credentials.txt`, `lab_financial_data.xlsx`) in `var/argus-lab-workspace` and records baseline SHA-256 hashes.
- **INITIAL_ACCESS:** Emits synthetic outbound socket telemetry to lab IP `10.0.2.15:4444`.
- **EXECUTION:** Launches synthetic `powershell.exe -nop -w hidden -e JABj...` process under `winword.exe` (PID `9914`).
- **FILE_MODIFICATION:** Appends modification marker to disposable `lab_credentials.txt`.
- **POST_ATTACK:** Performs hash mismatch verification and completes evaluation.

### Step 4: Verify Ground Truth vs. Detection Comparison
Review the Ground Truth vs. Detections table:
- **Detection Rate:** `100%`
- **Matched Rules:**
  - `NET-008-REVERSE-SHELL` (Interactive shell socket)
  - `PROC-001-SUSPICIOUS-PARENT-CHILD` (`winword.exe` spawning `powershell.exe`)
  - `PROC-002-ENCODED-COMMAND-LINE` (Encoded command line flag)
- **Metadata Verification:** All detections carry `is_simulation: true` and the active `simulation_id`.

### Step 5: Verify Attack Trace & Predictions with Evidence
1. Navigate to **Incident Traces** (`/incidents` or `/attack-traces`).
2. Observe correlated incident **INC-2026-9914** for target PID 9914:
   - Multi-domain timeline linking network socket, process launch, and file modification.
3. Observe **Predictions Panel**:
   - Predicted Next Stages: `EXECUTION`, `PERSISTENCE`, `DEFENSE_EVASION`, `PRIVILEGE_ESCALATION`.
   - **Evidence References:** Linked directly to rule IDs (`NET-008`, `PROC-001`, `PROC-002`) and detection IDs.
   - **Uncertainty Quantification:** Labeled with `LOW` / `MEDIUM` / `HIGH` confidence levels.
   - **IsPredicted Flag:** Explicitly marked as `isPredicted: true` (never presented as confirmed fact).

### Step 6: Verify Safe Containment Action
1. Review the proposed containment plan for **INC-2026-9914**:
   - Proposed Action: Terminate process tree PID 9914 and block remote endpoint `10.0.2.15:4444`.
   - Explicit user consent required before execution.
   - Immutable audit trail record logged in system history.

---

---

## 6. Real-Time Windows Task Manager Comparison Procedure

During a live demonstration, open **Windows Task Manager** (`Ctrl + Shift + Esc`) side by side with the **ARGUS Live Monitoring Dashboard** (`http://localhost:5173/` or `/monitoring`).

### Direct Metric Comparison Matrix

| Metric | ARGUS Telemetry Source | Task Manager Source | Expected Alignment & Timing Differences |
|---|---|---|---|
| **CPU Utilization (%)** | `psutil.cpu_percent(interval=0)` sampled every 1.5s–2s | ETW / Performance Counters sampled every 1s–2s | **Close Trend Match:** Values track within ±2–5% of each other. Short spikes (<500ms) may align depending on exact sampling window. |
| **RAM Usage (%) & Bytes** | `psutil.virtual_memory()` (`used_bytes` / `total_bytes`) | Task Manager "Memory (In Use)" | **Exact Match (±0.5%):** Displays committed + active working set minus standby cache. |
| **Process Table (PID & Name)** | `psutil.pids()` / `Win32_Process` | Task Manager "Details" Tab | **100% Exact Match:** Process IDs, process names, and parent PIDs match identically across both tools. |
| **Network Throughput** | Bandwidth rate ($\Delta \text{bytes} / \Delta t$) from `psutil.net_io_counters()` | Task Manager "Performance -> Network" | **Velocity Trend Match:** Upload/download speed curves peak simultaneously during active file transfers or downloads. |

### Comparison Verification Steps
1. Open Windows Task Manager to the **Details** tab.
2. Open ARGUS to `http://localhost:5173/` (Dashboard) or `http://localhost:5173/monitoring` (Live Monitoring).
3. Verify that the **REAL WINDOWS TELEMETRY** badge is active.
4. Launch a process (e.g. `notepad.exe` or `calc.exe`) on your Windows PC.
5. Observe its PID appear in both Windows Task Manager and ARGUS process list simultaneously.
6. Verify that live host events carry the `LIVE` classification badge, while simulation lab events carry `SIMULATION` metadata.

---

## 7. Safe Reset & Cleanup

Click **Stop Simulation** or trigger a workspace reset. Verify that:
- Disposable files in `var/argus-lab-workspace` are safely removed.
- Spawned test processes (`ping.exe`) are terminated.
- Host system files and processes remain completely untouched.

---

## 8. Troubleshooting & FAQ

| Symptom | Cause | Resolution |
|---|---|---|
| `CONCURRENT_SIMULATION` error | A previous simulation run is still active. | Click **Stop Simulation** or wait 5 seconds for loop completion. |
| API server `500` connection error | Backend process not running. | Ensure `pnpm --filter @workspace/api-server run dev` is running in Terminal 1. |
| Detection rate displays `0%` | Remote IP classified as loopback `127.0.0.1`. | The engine uses synthetic lab IP `10.0.2.15` in `simulation-engine.ts` to trigger `NET-008` rules cleanly. |

---

## 9. Summary of Capabilities Demonstrated

- **PS-24 Coordinated Cyberattack Path Prediction**
- **Real-Time Windows Host Telemetry & Task Manager Alignment**
- **Deterministic Multi-Domain Correlation (Process, Network, File)**
- **Data Exposure & File Corruption Detection with Verified Backup Restoration**
- **Explainable Evidence-Backed Predictions (`isPredicted: true`)**
- **Safe Lab Simulation Isolation & Disposable File Containment**
- **Consent-Based Response & Immutable Audit Trail Logging**

