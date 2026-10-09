# ARGUS Security Intelligence — Current System Architecture

## Overview

**ARGUS Security Intelligence** is an endpoint security, digital forensics, and attack path prediction platform built for **Problem Statement PS-24: Coordinated Cyberattack Path Predictor**.

The application operates as a local-first, multi-tier hybrid system combining a Python native monitoring and simulation engine, a Node.js/Express API & event orchestrator, and a stateful React web application.

---

## High-Level System Architecture

```
+-----------------------------------------------------------------------------------+
|                                ARGUS Web Application                               |
|                     (React 19 + Vite + Wouter + Tailwind CSS)                     |
+---------------------------------------+-------------------------------------------+
                                        |
                             REST APIs / HTTP JSON
                                        |
+---------------------------------------v-------------------------------------------+
|                              Express 5 API Server                                 |
|                                (Node.js + TypeScript)                             |
|  +---------------------+  +----------------------+  +--------------------------+  |
|  | Event Hub & State   |  | Detection Engine     |  | Backtrace & Correlation  |  |
|  +---------------------+  +----------------------+  +--------------------------+  |
|  | Attack Path Predict |  | Response Orchestrator|  | Recovery & Verification  |  |
|  +---------------------+  +----------------------+  +--------------------------+  |
+---------------------------------------^-------------------------------------------+
                                        |
                             HTTP Telemetry & Commands
                                        |
+---------------------------------------+-------------------------------------------+
|                              Python Security Engine                               |
|                         (Python 3.14 + psutil + WMI)                              |
|  +---------------------+  +----------------------+  +--------------------------+  |
|  | Process Monitor     |  | Network Monitor      |  | File & System Watchers   |  |
|  +---------------------+  +----------------------+  +--------------------------+  |
|  | Defender & Security |  | Lab Attack Simulator |  | Synthetic File Generator |  |
|  +---------------------+  +----------------------+  +--------------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## System Components

### 1. Frontend Web Dashboard (`artifacts/argus`)
- **Tech Stack:** React 19, Vite 7.3, Wouter router, Tailwind CSS v4, Lucide React, Framer Motion, Recharts.
- **Port:** `5173` (development dev server) / static SPA bundle served by API server on port `5000`.
- **Key Modules:**
  - `dashboard-page.tsx`: SOC overview, threat severity gauges, live event feed, quick actions.
  - `threats-page.tsx`: Correlated incident inspection and severity breakdown.
  - `monitoring-page.tsx` & `processes-page.tsx`: Real-time system monitoring, process trees, resource utilization.
  - `lab-page.tsx`: Attack simulation lab control interface.
  - `exposure-page.tsx` & `exposure-window-page.tsx`: Forensic assessment of modified/exfiltrated synthetic files.
  - `timeline-page.tsx` & `backtrace-investigation-page.tsx`: Chronological forensic timeline and attack tree visualization.
  - `quarantine-page.tsx` & `auto-remediation-page.tsx`: Policy-driven containment and action logs.
  - `reports-page.tsx` & `cyber-cell-page.tsx`: Incident dossier generator and consent-gated reporting workflow.
  - `history-page.tsx`: Automated remediation ledger and historical audit logs.

### 2. Backend API Server (`artifacts/api-server`)
- **Tech Stack:** Express 5, Node.js 20+, TypeScript, Pino Logger, Zod schema validation.
- **Port:** `5000`.
- **Key Subsystems:**
  - **Event Hub (`src/lib/event-hub.ts`):** In-memory event bus that handles real-time process, network, and file telemetry, maintains active scans, agent heartbeats, and correlation states.
  - **Detection Engine (`src/detection/`):** Rule catalog (`catalog.ts`), normalization layer (`normalize.ts`), and explainable detection rules for LOLBin abuse, suspicious process spawns, network exfiltration, ransomware activity, and credential access.
  - **Backtrace & Correlation Engine (`src/lib/backtrace-engine.ts`, `attack-correlation.ts`):** Reconstructs process execution trees, parent-child lineages, and groups related domain events into unified incidents.
  - **PS-24 Attack Path Prediction Engine (`src/lib/prediction-engine.ts`):** Computes attack stages, calculates blast radius, evaluates confidence, and predicts likely next attack steps based on correlated evidence.
  - **Response Orchestrator (`src/lib/response-orchestrator.ts`):** Manages process termination, network isolation, quarantine staging, and rollback logging under configurable containment policies.
  - **Recovery Engine (`src/recovery/`):** Manages synthetic file backups, integrity hash verification (SHA-256), and automated restoration pipelines.
  - **Adaptive Defense Engine (`src/lib/adaptive-defense.ts`):** Tracks rule precision, false positive rates, candidate rule generation, and regression testing.

### 3. Python Security Engine (`artifacts/security-engine`)
- **Tech Stack:** Python 3.14, `psutil`, WMI, Win32 APIs, PyTest.
- **Key Modules:**
  - `process_monitor`: Live Windows process enumeration, parent PID tracking, command-line analysis.
  - `network_monitor`: Socket connection collector, port watcher, network topology map.
  - `file_monitor` / `filesystem_scan`: SHA-256 baseline hashing and modification tracking.
  - `security_providers`: Windows Defender and Security Center status collection.
  - `lab`:
    - `synthetic_files.py`: Generates classified test files (Public, Internal, Confidential, Sensitive).
    - `ground_truth.py`: Records ground-truth event logs for repeatable scenario evaluation.
    - `simulate_attack.py`: Harmless, controlled attack scenario simulator.

### 4. Shared Libraries & Schemas (`lib/`)
- `lib/api-spec`: OpenAPI 3.0 contract definition (`openapi.yaml`) and Orval configuration.
- `lib/api-zod`: Auto-generated Zod TypeScript schemas for API request/response validation.
- `lib/api-client-react`: React hooks for API interaction.
- `lib/db`: PostgreSQL + Drizzle ORM schema scaffold (optional fallback to local memory state).

---

## Inter-Process Communication (IPC) & Telemetry Flow

1. **Security Engine -> API Server:** Python engine collects system telemetry and posts JSON batches to `http://localhost:5000/api/telemetry/events`.
2. **API Server Processing:**
   - Ingests events into `EventHub`.
   - Runs `DetectionEngine` rules.
   - Correlates detections into incidents using `AttackCorrelation`.
   - Generates attack path predictions via `PredictionEngine`.
3. **API Server -> Frontend:** React dashboard consumes REST APIs (or polls monitoring streams) for live updates.
4. **User Action -> API Server -> Security Engine:** Actions taken in the UI (e.g. starting a lab scenario or containing a process) trigger API endpoints which dispatch commands to the Python engine or execute response policy orchestrators.
