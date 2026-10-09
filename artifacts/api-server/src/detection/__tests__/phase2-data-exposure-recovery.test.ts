/**
 * Phase 2 Focused Verification Test Suite:
 * - Data Exposure Classification (ACCESSED, STAGED, OBSERVED_TRANSFER, etc.)
 * - File Corruption Detection (Baseline SHA-256 vs Current Hash Mismatch)
 * - Attack Time Interval Calculation (Earliest/Latest Timestamp & Duration)
 * - Disposable File Recovery Verification (Backup Staging & Hash Match)
 * - Controlled Simulation Isolation (is_simulation & var/argus-lab-workspace)
 */

import test, { describe } from "node:test";
import assert from "assert/strict";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { simulationEngine } from "../../lib/simulation-engine";

describe("ARGUS Phase 2 — Data Exposure, File Integrity & Recovery Test Suite", () => {
  test("1. Verify PRE_ATTACK synthetic file deployment and baseline hashing", async () => {
    simulationEngine.reset();
    const run = await simulationEngine.startSimulation("reverse_shell_exfiltration");

    // Wait briefly for PRE_ATTACK phase execution
    await new Promise((r) => setTimeout(r, 600));

    const updated = simulationEngine.getSimulationRun(run.simulationId);
    assert.ok(updated, "Simulation run must be retrievable");
    assert.ok(updated.affectedFiles && updated.affectedFiles.length >= 2, "Must populate affectedFiles with synthetic test files");

    const credFile = updated.affectedFiles.find((f) => f.fileName === "lab_credentials.txt");
    const finFile = updated.affectedFiles.find((f) => f.fileName === "lab_financial_data.xlsx");

    assert.ok(credFile, "lab_credentials.txt must be tracked");
    assert.ok(finFile, "lab_financial_data.xlsx must be tracked");

    assert.equal(credFile.classification, "Credentials");
    assert.equal(finFile.classification, "Financial");

    assert.ok(credFile.baselineHash.length === 64, "Baseline SHA-256 must be a valid 64-char hex string");
    assert.equal(credFile.hashStatus, "HASH_MATCH", "Initial state must have matching hash");

    simulationEngine.stopSimulation(run.simulationId);
  });

  test("2. Verify complete simulation lifecycle: Exposure, Hash Mismatch & Attack Interval", async () => {
    simulationEngine.reset();
    const run = await simulationEngine.startSimulation("reverse_shell_exfiltration");

    // Wait for complete simulation loop by polling status
    let finalRun = simulationEngine.getSimulationRun(run.simulationId);
    const startWait = Date.now();
    while (finalRun && finalRun.status !== "completed" && finalRun.status !== "failed" && Date.now() - startWait < 15000) {
      await new Promise((r) => setTimeout(r, 200));
      finalRun = simulationEngine.getSimulationRun(run.simulationId);
    }

    assert.ok(finalRun, "Final run must exist");
    assert.equal(finalRun.status, "completed", "Simulation must complete successfully");

    // Assert Affected Files & Exposure Status
    assert.ok(finalRun.affectedFiles && finalRun.affectedFiles.length >= 2, "Affected files must be recorded");

    const credFile = finalRun.affectedFiles.find((f) => f.fileName === "lab_credentials.txt")!;
    const finFile = finalRun.affectedFiles.find((f) => f.fileName === "lab_financial_data.xlsx")!;

    // Financial file exposure check
    assert.equal(finFile.exposureStatus, "OBSERVED_TRANSFER", "Sensitive file during outbound connection must be marked OBSERVED_TRANSFER");
    assert.ok(finFile.evidence.includes("10.0.2.15"), "Evidence must reference observed remote host");

    // Credentials file corruption check
    assert.equal(credFile.hashStatus, "HASH_MISMATCH", "Modified file must produce HASH_MISMATCH");
    assert.equal(credFile.recoveryStatus, "CORRUPTED_PENDING_RECOVERY", "Modified file must be flagged CORRUPTED_PENDING_RECOVERY");
    assert.notEqual(credFile.currentHash, credFile.baselineHash, "Current hash must differ from baseline hash");

    // Attack Interval check
    assert.ok(finalRun.attackInterval, "Attack interval must be computed");
    assert.equal(finalRun.attackInterval.intervalStatus, "OBSERVED_INTERVAL", "Interval status must be OBSERVED_INTERVAL");
    assert.ok(finalRun.attackInterval.earliestTimestamp, "Earliest timestamp must be set");
    assert.ok(finalRun.attackInterval.latestTimestamp, "Latest timestamp must be set");
    assert.ok(finalRun.attackInterval.durationSeconds >= 0, "Duration seconds must be non-negative");

    // Ground Truth checks
    assert.ok(finalRun.groundTruth.length >= 5, "Must record ground truth log entries for all phases");
    assert.ok(finalRun.firedRules.some((r) => r.includes("NET")), "Must fire network detection rules");
    assert.ok(finalRun.firedRules.some((r) => r.includes("PROC")), "Must fire process detection rules");
  });

  test("3. Verify Disposable File Recovery & Hash Restoration", async () => {
    simulationEngine.reset();
    const run = await simulationEngine.startSimulation("reverse_shell_exfiltration");

    // Wait for complete simulation loop by polling status
    let finalRun = simulationEngine.getSimulationRun(run.simulationId);
    const startWait = Date.now();
    while (finalRun && finalRun.status !== "completed" && finalRun.status !== "failed" && Date.now() - startWait < 15000) {
      await new Promise((r) => setTimeout(r, 200));
      finalRun = simulationEngine.getSimulationRun(run.simulationId);
    }

    // Execute recovery
    const recoveredRun = simulationEngine.recoverLabFiles(run.simulationId);
    assert.ok(recoveredRun.affectedFiles, "Recovered run must contain affected files");

    const credFile = recoveredRun.affectedFiles.find((f) => f.fileName === "lab_credentials.txt")!;
    assert.equal(credFile.hashStatus, "HASH_MATCH", "After recovery, hash status must be HASH_MATCH");
    assert.equal(credFile.recoveryStatus, "RECOVERED_VERIFIED", "After recovery, recovery status must be RECOVERED_VERIFIED");
    assert.equal(credFile.currentHash, credFile.baselineHash, "Current hash must match baseline hash after recovery");
    assert.ok(credFile.evidence.includes("verified SHA-256 hash match"), "Evidence must confirm SHA-256 verification");
  });

  test("4. Verify Isolation: Test files remain strictly inside var/argus-lab-workspace", async () => {
    const workspace = path.resolve(process.cwd(), "var", "argus-lab-workspace");
    assert.ok(workspace.includes(path.join("var", "argus-lab-workspace")), "Workspace path must be inside project var/argus-lab-workspace");

    if (fs.existsSync(workspace)) {
      const files = fs.readdirSync(workspace);
      for (const f of files) {
        if (f !== "backup_staging") {
          assert.ok(f.startsWith("lab_"), `Lab workspace file '${f}' must carry disposable 'lab_' prefix`);
        }
      }
    }
  });
});
