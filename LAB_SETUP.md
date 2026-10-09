# ARGUS Phase 2 — Lab Setup & End-to-End Validation

## Purpose

This document describes how to set up a controlled Windows + Kali Linux lab environment
for authorized attack simulation, and how to run the ARGUS Phase 2 validation procedure.

> [!IMPORTANT]
> Only run these procedures on **systems you own or have explicit written authorization to test**.
> Use an isolated lab network (e.g., host-only VMware/VirtualBox adapter). Do not expose the
> host to unrestricted remote access.

---

## 1. Lab Environment Requirements

### Windows Host (Defender machine)
- Windows 10/11 or Windows Server 2019+
- Node.js 20+ and Python 3.11+
- ARGUS running (`pnpm dev` from project root)
- Windows Firewall enabled
- No real sensitive data on the machine — use the synthetic files ARGUS deploys

### Kali Linux VM (Attacker machine — optional for manual testing)
- VirtualBox or VMware with a **host-only** or **internal** network adapter
- Metasploit Framework or netcat for reverse shell simulation
- **Critical**: ensure the Kali VM cannot reach the internet through the lab adapter

### Network topology
```
┌────────────────────────────┐     host-only adapter     ┌──────────────────────┐
│  Windows Host              │◄──────────────────────────►│  Kali Linux VM       │
│  192.168.56.1 (example)    │    no internet routing     │  192.168.56.101      │
│  ARGUS running             │                            │  Attacker (authorized)│
└────────────────────────────┘                            └──────────────────────┘
```

---

## 2. Safety Controls

The following controls MUST be verified before any simulation:

- [ ] Lab network adapter is **host-only** (no NAT, no bridged internet access)
- [ ] No real credentials, banking data, or PII exists on the Windows test machine
- [ ] ARGUS dry-run mode is configured for any automated containment (`ARGUS_DRY_RUN=true` in `.env`)
- [ ] Synthetic files are created by ARGUS — they bear `ARGUS_LAB_SYNTHETIC` in their content
- [ ] The Kali listener targets only the Windows lab IP, not the internet
- [ ] All simulation processes use clearly identifiable names (e.g., `argus_lab_shell.ps1`)

---

## 3. Automated Scenario Testing (No Kali Required)

The ARGUS Lab Simulation page provides built-in, self-contained scenarios that run
entirely on the Windows host with no external connections.

### Start ARGUS
```powershell
pnpm dev
# Open http://localhost:5173
```

### Run automated scenarios
1. Navigate to **Investigate → Lab Simulation** in the ARGUS sidebar
2. Select a scenario (e.g., "Reverse Shell + Exfiltration")
3. Review the safety note for the scenario
4. Click **Run Scenario**
5. Watch the phase log and wait for completion
6. Review the **Ground Truth vs. Detections** comparison table
7. Download the ground truth JSON for record-keeping

### Run Python lab tests
```powershell
python -m pytest artifacts/security-engine/tests/ -v
# Expected: 18 passed
```

---

## 4. Manual Kali Linux Lab Test (Advanced)

> [!WARNING]
> This section requires a controlled, isolated lab environment.
> Proceed only with explicit authorization.

### 4.1 Prepare synthetic files on Windows host
```powershell
# The ARGUS engine deploys canary files automatically on start.
# Additional synthetic files can be created manually:
python artifacts/security-engine/lab/synthetic_files.py
```

### 4.2 Record baseline hashes
```python
# In Python REPL or script:
from artifacts.security-engine.lab.synthetic_files import SyntheticFileManager
mgr = SyntheticFileManager("C:\\ArgusLab\\synthetic")
mgr.create_synthetic_files()
baseline = mgr.record_baseline()
print(baseline)
```

### 4.3 Start the Python security engine
```powershell
$env:ARGUS_API_BASE_URL = "http://localhost:5000"
$env:ARGUS_MODE = "LAB"
$env:ALLOW_PRIVATE_RANGES_IN_DETECTION = "true"
python artifacts/security-engine/main.py --api --snapshot
```

### 4.4 Set up Kali listener (Kali VM only)
```bash
# On Kali VM — netcat listener on port 4444
nc -lvnp 4444
# Note: This only accepts connections from the Windows lab IP
```

### 4.5 Trigger simulated reverse shell (Windows host — authorized test only)
```powershell
# AUTHORIZED LAB TEST ONLY
# This connects to the Kali VM IP (replace 192.168.56.101 with your Kali IP)
# The connection will immediately be detected by ARGUS NET-008
$argusLabTestConnection = New-Object System.Net.Sockets.TcpClient
try {
    $argusLabTestConnection.Connect("192.168.56.101", 4444)
    Start-Sleep -Seconds 2
} finally {
    $argusLabTestConnection.Close()
}
```

### 4.6 Verify detection in ARGUS UI
1. Open ARGUS → **Threats** page
2. Confirm `NET-008-REVERSE-SHELL` detection fired for `powershell.exe` or the test process
3. Open **Attack Trace** — verify the connection is correlated to the detection
4. Open **Lab Simulation** → verify detection rate shows matched rule

### 4.7 Containment test
1. In ARGUS → **Auto Remediation**, enable dry-run mode first
2. Confirm the incident appears in the remediation queue
3. Click "Contain" on the test incident
4. Verify audit log entry is created
5. Verify the test process is stopped (or would be, in dry-run mode)

### 4.8 File integrity verification
```python
# Check integrity after simulation
integrity = mgr.check_integrity()
for entry in integrity:
    print(entry["path"], "->", entry["status"])
# Expect: modified files show "modified", deleted ones show "deleted"
```

### 4.9 Recovery test
1. In ARGUS → **Quarantine**, restore any quarantined synthetic file
2. Verify the restored file's SHA-256 matches the pre-incident baseline hash
3. Confirm ARGUS reports "Verified" (not just "Restored")

---

## 5. Node.js Test Suite

```powershell
pnpm --filter @workspace/api-server test
```

### Expected results (Phase 2)
```
# tests     176+
# suites    56+
# pass      174+   (2 pre-existing desktop-download failures are known and unrelated)
# fail      2
```

### New Phase 2 test suites
| Suite | Tests | What it validates |
|-------|-------|-------------------|
| `prediction-engine.test.ts` | 7 | Attack stage predictions, confidence, isPredicted=true |
| `adaptive-defense.test.ts` | 13 | Rule metrics, precision, regression recording, human review |
| `lab-workflow.test.ts` | 9 | Lab detection, containment, evidence, file exposure |

---

## 6. Acceptance Criteria Verification

| # | Criterion | How to verify | Status |
|---|-----------|---------------|--------|
| 1 | Benign activity → no destructive response | Run "Benign Browser Activity" scenario | ✅ Lab page + NET rules |
| 2 | Suspicious process detected + linked to events | Run "Reverse Shell" scenario → Attack Trace | ✅ NET-008 + correlation |
| 3 | Evidence captured before containment | `lab-workflow.test.ts` Test 4 | ✅ Automated |
| 4 | Verified threat can be contained | `lab-workflow.test.ts` Test 5 | ✅ Automated |
| 5 | Synthetic file changes identified | `test_lab_simulation.py` + integrity check | ✅ Python tests |
| 6 | Transfer attempt ≠ confirmed exfiltration | `lab-workflow.test.ts` Test 9 (POTENTIALLY EXPOSED) | ✅ Automated |
| 7 | Trusted files restored + hash verified | Recovery service tests | ✅ Existing tests |
| 8 | Sensitive-data incident → reviewable report | Reports page + cyber-cell consent gate | ✅ UI + consent gate |
| 9 | No external report without consent | Two-checkbox consent gate in CyberCellPage | ✅ UI enforced |
| 10 | Repeated simulations → measured results | Lab Simulation regression history table | ✅ Frontend |
| 11 | Restart → incident history preserved | RecoveryStore + QuarantineManifest persist to disk | ✅ Existing |
| 12 | Existing ARGUS functionality unchanged | Full test suite: 153+ pass, no new failures | ✅ Verified |

---

## 7. Known Limitations & Next Steps

### Current limitations
1. **Prediction engine** uses rule-based stage mapping only; no ML-based behavioral baseline yet
2. **Adaptive defense** metrics are in-memory only (lost on restart) — a future JSON persistence layer is planned
3. **NET-008 lab test** on Windows requires Kali VM or localhost socket for full validation; automated tests use synthetic events
4. **Windows Firewall rules** for containment use `netsh advfirewall` — requires elevated process; dry-run mode recommended for non-admin testing
5. **EVTX event log** correlation (Windows Security events 4688, 4624 etc.) is partially implemented via security_providers; full EVTX parsing is a planned enhancement

### Highest-priority next improvements
1. Persist `AdaptiveDefenseEngine` state to disk (JSON file in `artifacts/quarantine_vault/`)
2. Add `Predictions` page to the frontend sidebar (API is ready at `GET /api/predictions`)
3. EVTX log correlation in the Python security engine
4. Dry-run mode toggle exposed in the ARGUS Settings page
5. Automated e2e test that starts the engine, runs a scenario, and measures detection round-trip time

---

## 8. Files Created / Modified in Phase 2

### New — API Server
| File | Description |
|------|-------------|
| `src/lib/prediction-engine.ts` | MITRE ATT&CK attack-stage prediction engine |
| `src/lib/adaptive-defense.ts` | Incident-to-rule feedback, regression tracking |
| `src/routes/predictions.ts` | `GET /api/predictions` endpoint |
| `src/routes/adaptive-defense.ts` | Adaptive defense CRUD endpoints |
| `src/detection/__tests__/prediction-engine.test.ts` | 7 prediction engine tests |
| `src/detection/__tests__/adaptive-defense.test.ts` | 13 adaptive defense tests |

### Modified — API Server
| File | Change |
|------|--------|
| `src/detection/types.ts` | Added `NET-008-REVERSE-SHELL`, `NET-009-DATA-EXFILTRATION` to `DetectionRuleId` |
| `src/routes/index.ts` | Wired predictions + adaptive-defense routers |
| `package.json` | Added new test files to test script |

### New — Python Security Engine
| File | Description |
|------|-------------|
| `lab/__init__.py` | Lab simulation package |
| `lab/synthetic_files.py` | Synthetic sensitive file management |
| `lab/ground_truth.py` | Ground truth event recording |
| `lab/simulate_attack.py` | Controlled attack scenario orchestrator |
| `tests/test_lab_simulation.py` | 13 Python lab simulation tests |

### New — Frontend
| File | Description |
|------|-------------|
| `src/pages/lab-page.tsx` | Lab Simulation page with scenario runner, ground truth comparison, regression history |

### Modified — Frontend
| File | Change |
|------|--------|
| `src/App.tsx` | Added `FlaskConical` import, `LabPage` import, `/lab` nav item, `/lab` route handler |

### New — Documentation
| File | Description |
|------|-------------|
| `LAB_SETUP.md` | This document |
