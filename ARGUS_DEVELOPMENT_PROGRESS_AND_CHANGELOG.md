# ARGUS Security Intelligence — Development Progress & Changelog

This document tracks all development milestones, historical changes, active implementations, and feature completion rates for the ARGUS Security Intelligence Platform.

---

## 1. Feature Completion & Working Rate Matrix

| # | Feature / Subsystem | Baseline % | Current % | Operational Status | Verification Method |
|---|---|:---:|:---:|---|---|
| 1 | **Process Monitoring & Explorer** | 95% | **100%** | 🟢 Complete Upgrade | Dual Graph/Table view, real-time search, PID/path inspector, live Windows stream |
| 2 | **Network Connections & Sockets** | 95% | 95% | 🟢 Live Windows OS | Active TCP/UDP socket polling & IP classification |
| 3 | **Port Intelligence & Wildcard Audit** | 100% | 100% | 🟢 Live Windows OS | Listening port discovery & wildcard binding check |
| 4 | **Network Topology Mapping** | 90% | 90% | 🟢 Live Windows OS | Interface discovery, gateway & subnet graph |
| 5 | **3D Network Universe Visualizer** | 100% | 100% | 🟢 Complete WebGL | Three.js / React Three Fiber interactive scene |
| 6 | **Filesystem Threat Scanner** | 85% | 85% | 🟢 Live Windows OS | High-risk directory scanner (`AppData`, `Temp`, etc.) |
| 7 | **Deterministic Detection Engine** | 100% | 100% | 🟢 Complete Backend | 21 pure rules (PROC/NET/FILE) with 100% unit tests |
| 8 | **Threats Management Feed** | 85% | 85% | 🟡 Hybrid Live/Demo | Live correlation hook; status is React-state only |
| 9 | **Live Monitoring & System Vitals** | 75% | **100%** | 🟢 Complete Upgrade | Live host stream + demo fallback + top processes + bandwidth rate + resilient connection |
| 10 | **Active Endpoint Containment** | 15% | 15% | 🔴 Simulated UI | Confirmation dialogs; OS netsh/firewall pending |
| 11 | **Process Kill / Remediation** | 15% | **95%** | 🟢 Live Remediation | `POST /api/processes/:pid/terminate` with OS `taskkill /F /T`, PID 0/4 protection, critical process warning, SSE broadcast |
| 12 | **File Quarantine Action & Vault** | 15% | 15% | 🔴 Simulated UI | React inventory; physical `.quarantine` pending |
| 13 | **Exposure Analysis & Blast Radius** | 90% | 90% | 🟢 Complete | Risk scoring & compromised asset blast radius |
| 14 | **Exposure Window View** | 95% | 95% | 🟢 Complete | Timeline tracking first suspicious activity → containment |
| 15 | **Forensic Incident Timeline** | 90% | 90% | 🟢 Complete | Event reconstruction distinguishing observed vs potential |
| 16 | **Quarantine Inventory Management** | 70% | 70% | 🟡 In-Memory | Table with SHA-256 hashes, restore/delete actions |
| 17 | **Threat Intelligence & IOC Lookup** | 75% | 75% | 🟡 Simulated | Simulated IOC hash/IP query interface |
| 18 | **Incident Report Generation** | 85% | 85% | 🟡 UI-Only | Summary view detailing affected assets and timeline |
| 19 | **Cyber Cell / Law Enforcement Form**| 60% | 60% | 🟡 Simulated | 2-factor analyst consent export flow |
| 20 | **Autonomous Demo Simulation** | 100% | 100% | 🟢 Complete | 8-stage automated walkthrough mode |
| 21 | **Data Persistence & Database** | 15% | 15% | 🔴 Dormant | Schema in `lib/db`; API server runs in-memory |
| 22 | **Authentication & RBAC** | 15% | 15% | 🔴 Simulated | Client-side visual login; no backend JWT/session |
| 23 | **Frontend Code Architecture** | 40% | **55%** | 🟡 Modularizing | Extracted `monitoring-page.tsx` & `processes-page.tsx`; continuing per page |

---

## 2. Historical Milestone Summary (Prior Phases)

* **Phase 1 (Process Monitoring)**: Built Python `ProcessWatcher` (`psutil`) and Express route `/api/events/process` with SSE streaming.
* **Phase 2 (Process Detection)**: Implemented 7 deterministic process detection rules (`PROC-001` through `PROC-007`) with normalization and scoring engine.
* **Phase 3 (Network & Port Telemetry)**: Built socket connection watcher, port watcher, and network topology watcher in Python.
* **Phase 4 (Network & File Detection)**: Added 7 network rules (`NET-001` to `NET-007`) and 7 file rules (`FILE-001` to `FILE-007`), completing the 21-rule catalog.
* **Phase 5 (Filesystem Threat Scanner)**: Added periodic scanner in Python checking user-writable paths for script drops, masquerading binaries, and credential dumping artifacts.
* **Phase 6 & 7 (Network Universe 3D)**: Built the WebGL 3D topological visualizer using `@react-three/fiber` and Three.js with real-time SSE event animation.

---

## 3. Active Work & Detailed Changelog

### Session 1: Live Monitoring Modernization & Modularization (COMPLETED)

#### Problem Statement & Prior State
1. `MonitoringPage` was trapped directly inside the monolithic 1,169-line [`artifacts/argus/src/App.tsx`](file:///d:/PROJECT/ARGUS-main/artifacts/argus/src/App.tsx).
2. When the Python security engine was offline, the page displayed empty dashes (`—`), causing a broken offline demo experience.
3. Network throughput only displayed cumulative byte totals; it lacked real-time bandwidth velocity charts (KB/s or MB/s).
4. No visibility into which processes (Top CPU/Memory consumers) are driving host load.
5. No threshold or anomaly indicators for saturated system resources.

#### New Changes & Verification
* **Created Dedicated Page**: [`artifacts/argus/src/pages/monitoring-page.tsx`](file:///d:/PROJECT/ARGUS-main/artifacts/argus/src/pages/monitoring-page.tsx)
  * Clean, modular component receiving live `processMonitor` telemetry and `onNavigate` routing.
* **Dynamic Network Bandwidth Velocity**:
  * Calculates real-time delta between successive telemetry ticks to plot upload (KB/s) and download (KB/s / MB/s) velocity sparklines in `<LiveChart>`.
* **Top Resource-Consuming Processes Table**:
  * Dynamically computes top 5 processes by CPU and Memory usage from `processMonitor.snapshot` (or top simulated suspicious processes when offline).
  * Direct "Process Explorer" navigation link.
* **Offline Demo Fallback Stream**:
  * When the security engine is offline, generates smooth, realistic fluctuating telemetry with an informative guidance banner.
* **Resource Saturation & Anomaly Alerting**:
  * Real-time warning banner when CPU > 80%, RAM > 85%, or Disk > 90%.
* **App.tsx Refactoring**:
  * Removed 55 lines of inline code from `App.tsx` and wired the new modular component with navigation and process monitor bindings.
* **Vercel SPA Deployment Fix (`vercel.json`)**:
  * Fixed `buildCommand` to build both backend and frontend (`node ./artifacts/api-server/build.mjs && pnpm --filter @workspace/argus run build`).
  * Set `outputDirectory` to `artifacts/argus/dist/public`.
  * Added `filesystem` handling and SPA rewrite fallback (`/(.*)` -> `/index.html`) so direct navigation to `/monitoring`, `/dashboard`, etc. on Vercel serves the React app instead of 404 `Cannot GET /monitoring`.

### Session 2: Remote User Permission & 1-Click PC Sensor Connection (COMPLETED)

#### Problem Statement & Remote User Requirement
1. When friends or remote users open ARGUS on Vercel or in their browser, the web sandbox blocks browsers from accessing the user's host hardware, CPU, RAM, or processes directly without local agent permission.
2. Users needed an intuitive 1-click method to grant permission and connect their local PC telemetry to the dashboard.

#### New Changes & Verification
* **1-Click Windows Launcher Scripts**:
  * Added [`artifacts/argus/public/start-sensor.bat`](file:///d:/PROJECT/ARGUS-main/artifacts/argus/public/start-sensor.bat) and [`scripts/start-sensor.bat`](file:///d:/PROJECT/ARGUS-main/scripts/start-sensor.bat) to check for Python, install required dependencies (`psutil`, `requests`), and launch the security engine.
  * Added [`artifacts/argus/public/start-sensor.ps1`](file:///d:/PROJECT/ARGUS-main/artifacts/argus/public/start-sensor.ps1) with configurable `TARGET_URL` / `ApiUrl` for remote deployments.
* **Sensor Connection Modal & Top Action in Live Monitoring**:
  * Added **"Connect My PC Sensor"** button on the Live Monitoring page header and in the demo banner.
  * Interactive modal provides Option 1 (1-Click `.bat` download) and Option 2 (copyable terminal command `python artifacts/security-engine/main.py --api --snapshot`).
  * Real-time sensor indicator shows connection status dynamically (Waiting on port 5000 vs. Sensor streaming live).
* **Production Build Verified**:
  * Successfully built client bundle (`vite build`) and verified static asset serving.

### Session 3: Process Activity Modernization & Standalone Sensor Agent Fix (COMPLETED)

#### Problem Statement & Root Cause Analysis
1. **Sensor Connection Failure**:
   * Previously, `start-sensor.bat` ran `python artifacts/security-engine/main.py --api --snapshot`. When remote users or friends downloaded `start-sensor.bat` into their `Downloads` folder, the relative file path did not exist on their machine, causing Python to fail immediately (`No such file or directory`).
   * The status check in `MonitoringPage` relied strictly on `telemetry.connected` (the open SSE socket), causing the UI to flip to "ENGINE OFFLINE" whenever SSE reconnected or in proxy/serverless environments.
   * When live telemetry was active, the "Connect My PC Sensor" button was completely removed from the page, preventing users from opening setup instructions for secondary machines.
2. **Process Activity Limitations**:
   * `ProcessesPage` was hardcoded inside `App.tsx` (over 120 lines).
   * It lacked search, resource-level filtering, and an explorer table for navigating 300+ live Windows host processes.
   * Windows root process discovery in `ProcessGraph` failed because Windows processes report integer parent PIDs (`0`, `4`, etc.) rather than `null`.
   * Process termination was 100% simulated without a real backend execution endpoint.

#### New Changes & Verification
* **Standalone Sensor Agent (`argus_sensor.py`)**:
  * Created [`artifacts/argus/public/argus_sensor.py`](file:///d:/PROJECT/ARGUS-main/artifacts/argus/public/argus_sensor.py) as a completely self-contained Python sensor.
  * Auto-installs missing dependencies (`psutil`, `requests`) via `pip` on first run.
  * Streams real hardware vitals (CPU, RAM, Disks, Network interfaces) and full process snapshots to any ARGUS dashboard (local or remote/Vercel).
* **Self-Contained Launchers (`start-sensor.bat` & `start-sensor.ps1`)**:
  * Updated [`artifacts/argus/public/start-sensor.bat`](file:///d:/PROJECT/ARGUS-main/artifacts/argus/public/start-sensor.bat) to download `argus_sensor.py` dynamically if run outside the repository.
  * Added 1-line direct PowerShell execution support: `powershell -ExecutionPolicy Bypass -Command "irm '<target>/start-sensor.ps1' | iex"`.
* **Resilient Telemetry Connection**:
  * Updated [`artifacts/argus/src/hooks/use-telemetry-stream.ts`](file:///d:/PROJECT/ARGUS-main/artifacts/argus/src/hooks/use-telemetry-stream.ts) and [`artifacts/argus/src/pages/monitoring-page.tsx`](file:///d:/PROJECT/ARGUS-main/artifacts/argus/src/pages/monitoring-page.tsx) to treat recent polled data as an active live connection.
  * Added persistent "Sensor Agent Setup" button with an instant "Check Status" trigger.
* **Process Activity Subsystem Upgrade**:
  * Created dedicated [`artifacts/argus/src/pages/processes-page.tsx`](file:///d:/PROJECT/ARGUS-main/artifacts/argus/src/pages/processes-page.tsx).
  * Dual View Modes: **Interactive Process Graph** and **Sortable Process Explorer Table**.
  * Real-time search across Name, PID, User, and Path.
  * Filter by resource intensity (High CPU ≥ 2.0%, High RAM ≥ 150 MB).
  * Forensic Process Inspector with PID copy, executable path copy, and cross-subsystem links to Network and Files.
  * Real OS Process Termination endpoint: `POST /api/processes/:pid/terminate` with Windows `taskkill /F`, protected core PIDs (0/4), and SSE event broadcasting.
* **Verification**:
  * Tested live telemetry streaming in browser (`live_monitoring_page_1791103415182.png`): Confirmed `((o)) REAL WINDOWS TELEMETRY` active on 12 cores with 315 live processes.
  * Tested process explorer and search filter (`process_filtered_inspection_1791100880826.png`).

### Session 4: Process Activity Refinements, Threat Scoring & Forensic Exports (COMPLETED)

#### Problem Statement & Analyst Needs
1. Analysts needed heuristic risk classification for live host processes (distinguishing LOLBIN execution, masquerading binaries, and script interpreters from normal system services).
2. Lack of quick forensic export for incident response reporting.
3. Lack of safety guardrails when terminating processes (accidentally killing `explorer.exe`, `dwm.exe`, or `csrss.exe`), and inability to terminate entire process trees (`/T`).

#### New Changes & Verification
* **Heuristic Security Risk Scoring Engine (`computeProcessRisk`)**:
  * Implemented deterministic heuristic classifier evaluating executable name, execution path, and CPU utilization.
  * Detects script engines (`powershell`, `cmd`, `wscript`, `mshta`) executing from user-writable / staging directories (`AppData`, `Temp`, `Downloads`).
  * Identifies Living-off-the-Land binaries (LOLBINs: `rundll32`, `reg`, `vssadmin`, `certutil`, `whoami`).
  * Detects core binary masquerading (e.g. `svchost.exe` running outside `C:\Windows\System32`).
  * Flags high compute anomalies (CPU > 15%).
* **Risk Column & Badges in Explorer Table**:
  * Added visual `Risk` column with color-coded classification badges (`CRITICAL`, `SUSPICIOUS`, `ANOMALY`, `SYSTEM`, `NORMAL`).
* **Threats & Extended Filter Toolbar**:
  * Quick filter dropdown: `All Processes`, `Threats & Anomalies`, `High CPU (≥ 2.0%)`, `High RAM (≥ 150 MB)`, and `System Daemons`.
* **1-Click Forensic Snapshot Export**:
  * **Export to CSV**: Dumps PID, Name, PPID, CPU, Memory, Risk verdict, User, and full executable path.
  * **Export to JSON**: Structured array for SIEM/EDR log ingestion and forensic incident reports.
* **Process Detail Inspector Risk Card**:
  * Displays "Security Risk Assessment" block explaining the specific reason for the assigned verdict.
* **Remediation Guardrails & Child Process Tree Termination**:
  * Upgraded `POST /api/processes/:pid/terminate` to support `killTree: true` (`taskkill /F /T /PID <pid>`).
  * Added **System Critical Process Warning** in the termination confirmation modal if terminating core Windows subsystems (`explorer.exe`, `dwm.exe`, `csrss.exe`, `lsass.exe`, `services.exe`, `smss.exe`, `svchost.exe`).
  * Added checkbox toggle for `Terminate entire child process tree (/T)`.

### Session 5: File Activity & Filesystem Threat Surveillance (COMPLETED)

#### Problem Statement & Analyst Needs
1. `FilesPage` was a 10-line static dummy component inside `App.tsx` that ignored the real security engine's file scanner.
2. Lack of live host filesystem surveillance, cryptographic SHA-256 fingerprint verification, and directory categorization.
3. Lack of a dedicated forensic inspector for examining file security reasons, touching processes, and executing isolation/quarantine workflows.

#### New Changes & Verification
* **Dedicated Modular Files Subsystem (`artifacts/argus/src/pages/files-page.tsx`)**:
  * Extracted and replaced the inline dummy component with a comprehensive forensic investigation suite.
  * Connected live SSE / REST feed from `useFileScan` consuming `/api/files/scan` and `/api/files/scan/stream`.
  * Dual-mode telemetry badge: `((o)) REAL WINDOWS FILESYSTEM (X FINDINGS)` when connected, gracefully falling back to `DEMO INCIDENT FILE TELEMETRY` on cloud/Vercel.
* **4-Card KPI Analytics Strip**:
  * Real-time metrics for Monitored Target Files, Critical Threats, High Risk Inbound/Scripts, and Staging & Temp Artifacts.
* **Dual View Modes (Explorer Table & Directory Map)**:
  * **Explorer Table**: Interactive, sortable table displaying Time, Touching Process, File Name & Path, Operation, Classification, Severity Badge, SHA-256 Fingerprint (with 1-click copy), Size, and Remediation Actions.
  * **Directory Map**: Grouped forensic view across 4 surveillance vectors (Downloads & Inbound, Staging & Temp, Confidential & Sensitive DLP, Startup & Persistence).
* **Forensic Artifact Inspector Drawer/Modal**:
  * Complete target path with 1-click copy.
  * Cryptographic SHA-256 hash with copy and external VirusTotal threat intelligence lookup (`https://www.virustotal.com/gui/search/<hash>`).
  * Detailed Heuristic Analysis explaining the detection primitive.
  * Direct pivot link to `/processes` for the touching process.
  * Safe Quarantine/Isolation action adding artifacts directly into the ARGUS Quarantine Vault.
* **Search, Filters & 1-Click Forensic Exports**:
  * Real-time search across file path, process, classification, and SHA-256.
  * Category dropdown: `All File Events`, `Threats & Anomalies`, `Downloads & Inbound`, `Temp & Archive Staging`, `Startup & Persistence`, `Confidential / DLP`.
  * Dedicated DLP toggle button (`Filter Sensitive (DLP)`).
  * 1-Click **Export CSV** and **Export JSON** for incident reports and SIEM integration.
* **Verification**:
  * Tested live on Windows host via browser subagent: verified real telemetry connection with 2 live findings (`start-sensor.bat` scripts in Downloads), inspected modal with real SHA-256 hash, and captured screenshots (`files_forensic_inspector_local.png` and `files_directory_map_local.png`).

### Session 6: Exposure Assessment & Blast Radius Intelligence (COMPLETED)

#### Problem Statement & Analyst Needs
1. `ExposurePage` was an inline 15-line stub inside `App.tsx` with static scores and limited decision-support context.
2. Lack of a multi-tab investigation suite separating Kill-Chain progression, lateral asset blast radius, risk factor decomposition, and containment playbooks.
3. Lack of comprehensive export capabilities (CSV matrix, structured JSON incident dossier, and executive memo).

#### New Changes & Verification
* **Dedicated Modular Exposure Subsystem (`artifacts/argus/src/pages/exposure-page.tsx`)**:
  * Replaced inline stub with a decision-support and blast-radius analysis dashboard.
  * Connects to live threat analysis (`useThreatAnalysis`), process monitoring, and filesystem telemetry to calculate dynamic composite risk scores (`LIVE TELEMETRY EXPOSURE (RISK 96/100)`).
* **Hero Assessed Risk Score & Severity Dial**:
  * Multi-segment glowing risk meter with baseline scale: Baseline (0), Monitored (25), Elevated (50), High (75), Critical (100).
  * Direct host containment status indicator (`ENDPOINT ISOLATED` vs `EGRESS ACTIVE`).
* **4-Card KPI Analytics Strip**:
  * Primary Affected Host (`WS-0427`), Sensitive Documents Touched (`5 Files`), Staged / Inferred Flow (`18.4 KB`), and Confirmed Exfiltration (`None · Protected by DLP boundary`).
* **4 Subsystem Investigation Tabs**:
  * **Kill-Chain Evidence Chain**: 5-stage progression (Initial Vector, Collection, Staging, Potential Exfiltration, Confirmed Exfiltration) alongside the **ARGUS Defensible Evidence Model** card.
  * **Blast Radius & Asset Impact**: Asset cards covering Affected Host, User Identity (`CORP\mira.alvarez`), Data Repositories, and Adjacent VLAN Peers.
  * **Contributing Risk Factors**: Decomposes Data Sensitivity (84%), Process Novelty (78%), Destination Reputation (65%), Payload Visibility (32%), and Correlation Confidence (94%).
  * **Incident Response Playbook**: Immediate containment actions (Host Isolation toggle, Process Tree Termination pivot, Quarantine Vault pivot, Identity & Perimeter Safeguards).
* **1-Click Forensic Incident Exports**:
  * **Export CSV**: Complete tabular matrix of exposure stages, entities, status, and evidence models.
  * **Export JSON**: Structured incident response schema for SIEM/SOAR ingestion.
  * **Executive Memo**: Pre-formatted incident briefing memorandum.
* **Verification**:
  * Verified locally on dev server via browser subagent with live risk calculation (`96/100`), tab switching, and screenshot captures (`exposure_blast_radius_local_1791114536731.png` and `exposure_playbook_local_1791114576060.png`).





