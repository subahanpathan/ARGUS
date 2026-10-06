import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { eventHub } from "../../lib/event-hub";
import { responseOrchestrator } from "../../lib/response-orchestrator";
import type { Detection } from "../types";

describe("Phase 5 & Phase 6: Automated Incident Response Orchestration & Verified Recovery", () => {
  test("Orchestrator generates response levels and explainable recommendations", () => {
    const mockDetection: Detection = {
      id: "det-orch-1",
      rule_id: "PROC-001-SUSPICIOUS-SPAWN",
      rule_name: "Suspicious Process Spawn",
      title: "Suspicious Cmd Execution",
      severity: "critical",
      confidence: 0.95,
      status: "detected",
      timestamp: new Date().toISOString(),
      event_timestamp: new Date().toISOString(),
      entity: "cmd.exe",
      pid: 8842,
      executable_path: "C:\\Windows\\System32\\cmd.exe",
      evidence: [],
      explanation: "Test critical detection",
      recommended_action: "Contain process",
      ancestry: [],
      hostname: "test-pc",
    };

    eventHub.addDetection(mockDetection);

    const incidents = responseOrchestrator.getOrchestratedIncidents();
    const incident = incidents.find((i) => i.correlatedTrace.primaryProcess.pid === 8842);

    assert.ok(incident, "Orchestrated incident should exist for PID 8842");
    assert.equal(incident.responseLevel, "LEVEL_2_CONTAIN");
    assert.equal(incident.recommendedAction, "CONTAIN_PROCESS");
    assert.ok(incident.recommendationReasons.length > 0);
    assert.ok(["DETECTED", "EVIDENCE_CAPTURED", "CONTAINMENT_STARTED", "TRACING", "INVESTIGATING", "CONTAINMENT_PENDING", "CONTAINED"].includes(incident.state));
  });

  test("Orchestrator records immutable audit log entries", () => {
    const audit = responseOrchestrator.recordAudit({
      incidentId: "INC-TEST-001",
      action: "TEST_CONTAINMENT",
      actor: "ARGUS_ORCHESTRATOR",
      target: "PID 1234",
      reason: "Unit test validation",
      evidence: "Test evidence",
      result: "SUCCESS",
      verification: "VERIFIED",
    });

    assert.ok(audit.auditId.startsWith("audit-"));
    assert.equal(audit.incidentId, "INC-TEST-001");
    assert.equal(audit.actor, "ARGUS_ORCHESTRATOR");
  });

  test("orchestrateClosure validates state machine before closing", () => {
    const mockDetection: Detection = {
      id: "det-orch-close-test",
      rule_id: "PROC-004-UNUSUAL-LOCATION",
      rule_name: "Unusual Location",
      title: "Unusual Binary Location",
      severity: "medium",
      confidence: 0.8,
      status: "detected",
      timestamp: new Date().toISOString(),
      event_timestamp: new Date().toISOString(),
      entity: "testapp.exe",
      pid: 7712,
      executable_path: "C:\\Downloads\\testapp.exe",
      evidence: [],
      explanation: "Test unusual location",
      recommended_action: "Inspect binary",
      ancestry: [],
      hostname: "test-pc",
    };

    eventHub.addDetection(mockDetection);
    const incidentId = "INC-2026-7712";

    // Attempting to close an uncontained incident should require user action
    const closureAttempt = responseOrchestrator.orchestrateClosure(incidentId);
    assert.equal(closureAttempt.success, false);
    assert.equal(closureAttempt.state, "REQUIRES_USER_ACTION");
  });
});
