import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { isRemoteRole, isExternalOrPrivateRole } from "../network/lists";
import { evaluateNetworkRules } from "../network/rules";
import { normalizeNetworkConnections } from "../network/normalize";
import { responseOrchestrator } from "../../lib/response-orchestrator";
import { eventHub } from "../../lib/event-hub";
import { performFileQuarantine } from "../../routes/quarantine";
import type { Detection } from "../types";

describe("ARGUS Controlled Lab Detection & Containment Workflow (Req 1-15)", () => {
  const originalArgusMode = process.env.ARGUS_MODE;
  const originalAllowPrivate = process.env.ALLOW_PRIVATE_RANGES_IN_DETECTION;

  before(() => {
    // Enable Lab Mode as specified in Requirements 1 & 14
    process.env.ARGUS_MODE = "LAB";
    process.env.ALLOW_PRIVATE_RANGES_IN_DETECTION = "true";
  });

  after(() => {
    process.env.ARGUS_MODE = originalArgusMode;
    process.env.ALLOW_PRIVATE_RANGES_IN_DETECTION = originalAllowPrivate;
  });

  test("Test 1: Private IP + normal application -> no alert", () => {
    // Chrome or Notepad talking to a private IP (e.g. 192.168.1.50) on HTTPS (port 443)
    const viewEvents = normalizeNetworkConnections({
      timestamp: new Date().toISOString(),
      connections: [
        {
          pid: 3100,
          process: "chrome.exe",
          executable_path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
          local_addr: "192.168.1.100",
          local_port: 52140,
          remote_addr: "192.168.1.50",
          remote_port: 443,
          protocol: "tcp",
          status: "ESTABLISHED",
          direction: "outbound",
          remote_role: "PRIVATE",
        },
      ],
    });

    assert.equal(viewEvents.length, 1);
    const matches = evaluateNetworkRules(viewEvents[0]);
    // Normal browser to internal server must not trigger reverse shell or C2 alerts
    const hostileAlerts = matches.filter(
      (m) => m.rule_id === "NET-008-REVERSE-SHELL" || m.rule_id === "NET-002-KNOWN-TOOL-PORT"
    );
    assert.equal(hostileAlerts.length, 0, "Normal app to private IP must NOT generate hostile alerts");
  });

  test("Test 2: Private IP + suspicious shell behavior -> detection (NET-008)", () => {
    // powershell.exe establishing socket to Kali private IP (e.g. 192.168.1.50:4444)
    const viewEvents = normalizeNetworkConnections({
      timestamp: new Date().toISOString(),
      connections: [
        {
          pid: 4820,
          process: "powershell.exe",
          executable_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          local_addr: "192.168.1.100",
          local_port: 49811,
          remote_addr: "192.168.1.50",
          remote_port: 4444,
          protocol: "tcp",
          status: "ESTABLISHED",
          direction: "outbound",
          remote_role: "PRIVATE",
        },
      ],
    });

    assert.equal(viewEvents.length, 1);
    const matches = evaluateNetworkRules(viewEvents[0]);
    const shellMatch = matches.find((m) => m.rule_id === "NET-008-REVERSE-SHELL");

    assert.ok(shellMatch, "Interactive reverse shell to private lab IP must be detected under ARGUS_MODE=LAB");
    assert.equal(shellMatch.baseSeverity, "critical");
    assert.ok(shellMatch.baseConfidence >= 0.9);
  });

  test("Test 3: Suspicious process + suspicious network connection -> CRITICAL correlation", () => {
    // Inject critical detection event into EventHub
    const detectionId = `det-lab-${Date.now()}`;
    const testPid = 7712;
    const mockDetection: Detection = {
      id: detectionId,
      rule_id: "NET-008-REVERSE-SHELL",
      rule_name: "Interactive shell or C2 reverse connection established",
      title: "powershell.exe connected to 192.168.1.50:4444",
      severity: "critical",
      confidence: 0.96,
      status: "detected",
      timestamp: new Date().toISOString(),
      event_timestamp: new Date().toISOString(),
      entity: "powershell.exe",
      pid: testPid,
      executable_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      commandLine: "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4AdAA...",
      evidence: [
        {
          key: "reverse_socket",
          description: "Established reverse socket: 192.168.1.100:49811 -> 192.168.1.50:4444",
          source: "network",
        },
      ],
      explanation: "Active reverse shell to attacker VM",
      recommended_action: "Execute automated host containment immediately",
      ancestry: [{ pid: 1000, process_name: "explorer.exe" }],
      hostname: "lab-workstation",
    };

    eventHub.addDetection(mockDetection);

    const incidents = responseOrchestrator.getOrchestratedIncidents();
    const incident = incidents.find((i) => i.correlatedTrace.primaryProcess.pid === testPid);

    assert.ok(incident, "Critical incident must be correlated for PID 7712");
    assert.equal(incident.severity, "critical");
    assert.equal(incident.responseLevel, "LEVEL_2_CONTAIN");
  });

  test("Test 4: Detection -> evidence captured before containment", () => {
    const testPid = 7713;
    const mockDetection: Detection = {
      id: `det-ev-test-${Date.now()}`,
      rule_id: "NET-008-REVERSE-SHELL",
      rule_name: "Interactive shell or C2 reverse connection established",
      title: "cmd.exe reverse connection",
      severity: "critical",
      confidence: 0.95,
      status: "detected",
      timestamp: new Date().toISOString(),
      event_timestamp: new Date().toISOString(),
      entity: "cmd.exe",
      pid: testPid,
      executable_path: "C:\\Windows\\System32\\cmd.exe",
      evidence: [],
      explanation: "Reverse shell detected",
      recommended_action: "Contain process",
      ancestry: [],
      hostname: "lab-pc",
    };

    eventHub.addDetection(mockDetection);

    const incidents = responseOrchestrator.getOrchestratedIncidents();
    const incident = incidents.find((i) => i.correlatedTrace.primaryProcess.pid === testPid);

    assert.ok(incident, "Incident must exist");
    assert.ok(incident.evidenceSnapshot, "Evidence snapshot MUST be captured");
    assert.equal(incident.primaryPid, testPid);
    assert.equal(incident.evidenceSnapshot.primaryProcess.pid, testPid);
    assert.ok(
      ["EVIDENCE_CAPTURED", "CONTAINMENT_STARTED", "CONTAINED"].includes(incident.state),
      `State should be EVIDENCE_CAPTURED or subsequent, got ${incident.state}`
    );
  });

  test("Test 5 & 6: Evidence captured -> containment -> successful process termination -> CONTAINED", async () => {
    const testPid = 7714;
    const mockDetection: Detection = {
      id: `det-contain-${Date.now()}`,
      rule_id: "NET-008-REVERSE-SHELL",
      rule_name: "Interactive reverse shell",
      title: "Interactive shell connected to 192.168.1.50",
      severity: "critical",
      confidence: 0.95,
      status: "detected",
      timestamp: new Date().toISOString(),
      event_timestamp: new Date().toISOString(),
      entity: "powershell.exe",
      pid: testPid,
      executable_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      evidence: [],
      explanation: "Interactive shell session",
      recommended_action: "Contain process",
      ancestry: [],
      hostname: "lab-pc",
    };

    eventHub.addDetection(mockDetection);
    const incident = responseOrchestrator.getOrchestratedIncidents().find((i) => i.correlatedTrace.primaryProcess.pid === testPid);
    assert.ok(incident);

    // Call orchestrateContainment
    const result = await responseOrchestrator.orchestrateContainment(incident.incidentId, {
      force: true,
      actor: "AUTOMATED_ORCHESTRATOR",
    });

    // Since PID 7714 does not exist on disk, terminateProcessTree safely verifies it is stopped, resulting in success
    assert.ok(result.success, "Containment execution should succeed");
    const updated = responseOrchestrator.getIncidentById(incident.incidentId);
    assert.ok(updated);
    assert.equal(updated.state, "CONTAINED", "Incident state must transition to CONTAINED");
    assert.equal(updated.containmentStatus, "CONTAINED");
    assert.ok(updated.t_contained, "Containment timestamp t_contained must be recorded");
  });

  test("Test 7: Failed termination -> record and audit failure state", async () => {
    const testPid = 1; // System idle / protected init
    const mockDetection: Detection = {
      id: `det-fail-${Date.now()}`,
      rule_id: "PROC-CRIT-FAIL",
      rule_name: "Critical System Mock",
      title: "Mock System Process",
      severity: "high",
      confidence: 0.9,
      status: "detected",
      timestamp: new Date().toISOString(),
      event_timestamp: new Date().toISOString(),
      entity: "system",
      pid: testPid,
      executable_path: "C:\\Windows\\System32\\ntoskrnl.exe",
      evidence: [],
      explanation: "Fail test",
      recommended_action: "Contain",
      ancestry: [],
      hostname: "lab-pc",
    };

    eventHub.addDetection(mockDetection);
    const incident = responseOrchestrator.getOrchestratedIncidents().find((i) => i.correlatedTrace.primaryProcess.pid === testPid);
    assert.ok(incident);

    // Record containment audit failure
    responseOrchestrator.recordAudit({
      incidentId: incident.incidentId,
      action: "TERMINATE_PROCESS",
      actor: "ARGUS_ORCHESTRATOR",
      target: `PID ${testPid}`,
      reason: "Access denied by OS",
      evidence: "EPERM",
      result: "FAILED",
      verification: "FAILED",
    });

    const updated = responseOrchestrator.getIncidentById(incident.incidentId);
    assert.ok(updated);
    assert.ok(updated.auditTrail.some((a) => a.result === "FAILED"), "Audit trail must preserve failure record");
  });

  test("Test 8: File changed during exposure -> MODIFIED DURING EXPOSURE", () => {
    const testPid = 8991;
    const mockDetection: Detection = {
      id: `det-file-mod-${Date.now()}`,
      rule_id: "NET-008-REVERSE-SHELL",
      rule_name: "Reverse shell",
      title: "Reverse shell with file touch",
      severity: "critical",
      confidence: 0.95,
      status: "detected",
      timestamp: new Date().toISOString(),
      event_timestamp: new Date().toISOString(),
      entity: "powershell.exe",
      pid: testPid,
      executable_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      evidence: [],
      explanation: "Reverse shell",
      recommended_action: "Contain",
      ancestry: [],
      hostname: "lab-pc",
    };

    eventHub.addDetection(mockDetection);
    const incident = responseOrchestrator.getOrchestratedIncidents().find((i) => i.correlatedTrace.primaryProcess.pid === testPid);
    assert.ok(incident);

    // Add a file event to trace
    incident.correlatedTrace.affectedFiles.push({
      filePath: "C:\\Users\\User\\Documents\\Financial_Q4.xlsx",
      operation: "MODIFY",
      timestamp: new Date().toISOString(),
      classification: "FINANCIAL",
      impactState: "MODIFIED",
      hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    });

    // Re-capture evidence
    responseOrchestrator.captureIncidentEvidence(incident.correlatedTrace);
    const updated = responseOrchestrator.getIncidentById(incident.incidentId);
    assert.ok(updated?.evidenceSnapshot);
    const file = updated.evidenceSnapshot.relevantFileEvents?.find((f: any) => f.filePath.includes("Financial_Q4.xlsx"));
    assert.ok(file, "File event should be in snapshot");
    assert.equal(file.exposureClassification, "MODIFIED DURING EXPOSURE");
  });

  test("Test 9: Changed file without transmission evidence -> POTENTIALLY EXPOSED", () => {
    const testPid = 8992;
    const mockDetection: Detection = {
      id: `det-file-pot-${Date.now()}`,
      rule_id: "NET-008-REVERSE-SHELL",
      rule_name: "Reverse shell",
      title: "Reverse shell with file access",
      severity: "critical",
      confidence: 0.95,
      status: "detected",
      timestamp: new Date().toISOString(),
      event_timestamp: new Date().toISOString(),
      entity: "powershell.exe",
      pid: testPid,
      executable_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      evidence: [],
      explanation: "Reverse shell",
      recommended_action: "Contain",
      ancestry: [],
      hostname: "lab-pc",
    };

    eventHub.addDetection(mockDetection);
    const incident = responseOrchestrator.getOrchestratedIncidents().find((i) => i.correlatedTrace.primaryProcess.pid === testPid);
    assert.ok(incident);

    incident.correlatedTrace.affectedFiles.push({
      filePath: "C:\\Users\\User\\Documents\\Strategy.docx",
      operation: "MODIFY",
      timestamp: new Date().toISOString(),
      classification: "DOCUMENT",
      impactState: "MODIFIED",
      hash: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    });

    responseOrchestrator.captureIncidentEvidence(incident.correlatedTrace);
    const updated = responseOrchestrator.getIncidentById(incident.incidentId);
    const file = updated?.evidenceSnapshot?.relevantFileEvents?.find((f: any) => f.filePath.includes("Strategy.docx"));
    assert.ok(file);
    // As per Requirement 13: Must NOT claim 'Confirmed Leaked' without packet payload proof
    assert.equal(file.leakStatus, "Potentially Exposed");
    assert.notEqual(file.leakStatus, "Confirmed Leaked");
  });

  test("Test 10: Quarantine -> vault copy verified -> original removed -> QUARANTINED", () => {
    // Create temporary file on disk to simulate malicious payload
    const tmpDir = os.tmpdir();
    const testFileName = `test_payload_${Date.now()}.ps1`;
    const testFilePath = path.join(tmpDir, testFileName);
    const fileContent = "Write-Host 'Controlled Lab Payload Simulation'";
    fs.writeFileSync(testFilePath, fileContent, "utf-8");

    assert.ok(fs.existsSync(testFilePath), "Test file must exist before quarantine");

    // Perform quarantine
    const res = performFileQuarantine({
      targetPath: testFilePath,
      name: testFileName,
      source: "controlled_lab_test",
      severity: "critical",
      reason: "Simulated malicious reverse shell script",
    });

    // 1. Vault copy verified
    assert.ok(res.success, "Quarantine must succeed");
    assert.equal(res.status, "Quarantined");
    assert.ok(res.item.isolatedFilePath, "Isolated vault path must be populated");
    assert.ok(fs.existsSync(res.item.isolatedFilePath!), "File must exist in quarantine vault");

    // 2. Original removed and verified
    assert.equal(fs.existsSync(testFilePath), false, "Original file must be removed from target path");

    // 3. Vault content matches original content
    const vaultContent = fs.readFileSync(res.item.isolatedFilePath!, "utf-8");
    assert.equal(vaultContent, fileContent, "Vault file content must match original");

    // Clean up vault file
    try {
      fs.unlinkSync(res.item.isolatedFilePath!);
    } catch {}
  });
});
