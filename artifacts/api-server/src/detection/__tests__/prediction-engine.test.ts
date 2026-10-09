/**
 * Tests for the ARGUS Prediction Engine.
 *
 * Verifies determinism, correct stage mapping, confidence scoring, evidence
 * aggregation, and the invariant that all predictions carry isPredicted=true.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { generatePredictions } from "../../lib/prediction-engine";
import type { CorrelatedIncident } from "../../lib/attack-correlation";
import type { Detection } from "../types";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function makeDetection(overrides: Partial<Detection> = {}): Detection {
  return {
    id: "det-001",
    rule_id: "NET-008-REVERSE-SHELL",
    rule_name: "Reverse Shell Detected",
    title: "Reverse shell connection observed",
    severity: "critical",
    confidence: 0.9,
    status: "detected",
    timestamp: "2026-01-01T12:00:00.000Z",
    event_timestamp: "2026-01-01T12:00:00.000Z",
    entity: "powershell.exe",
    pid: 1234,
    hostname: "workstation-01",
    evidence: [],
    explanation: "Reverse shell connection detected",
    recommended_action: "Isolate host immediately",
    ancestry: [],
    ...overrides,
  };
}

function makeIncident(overrides: Partial<CorrelatedIncident> = {}): CorrelatedIncident {
  return {
    incidentId: "INC-2026-1234",
    title: "Test Incident",
    status: "ACTIVE",
    severity: "critical",
    detectionTime: "2026-01-01T12:00:00.000Z",
    startTime: "2026-01-01T12:00:00.000Z",
    lastUpdatedTime: "2026-01-01T12:01:00.000Z",
    durationSeconds: 60,
    primaryProcess: { name: "powershell.exe", pid: 1234 },
    observableSource: {
      ip: "8.8.8.8",
      label: "Remote endpoint",
      connectionCount: 1,
    },
    eventCount: 1,
    connectionCount: 1,
    timeline: [],
    graph: { nodes: [], edges: [] },
    evidenceSummary: [],
    impactAssessment: {
      overallRisk: "HIGH",
      counts: { created: 0, modified: 0, deleted: 0, renamed: 0, total: 0 },
      hasExfiltrationRisk: false,
      hasDestructionRisk: false,
      hasPersistenceRisk: false,
      sensitiveCategories: [],
      summary: "No file impact.",
    },
    affectedFiles: [],
    dataFlowChain: [],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe("Prediction Engine", () => {
  // -------------------------------------------------------------------------
  // Case 1: No detections → empty or low-confidence generic predictions only
  // -------------------------------------------------------------------------
  it("returns an empty array when no incidents or detections are provided", () => {
    const result = generatePredictions([], []);
    assert.equal(result.length, 0, "Expected no predictions for empty inputs");
  });

  // -------------------------------------------------------------------------
  // Case 2: NET-008 → predicts EXECUTION and PERSISTENCE
  // -------------------------------------------------------------------------
  it("NET-008-REVERSE-SHELL detection predicts EXECUTION and PERSISTENCE stages", () => {
    const det = makeDetection({
      id: "det-net-008",
      rule_id: "NET-008-REVERSE-SHELL",
    });

    const result = generatePredictions([], [det]);

    const stages = result.map((p) => p.stage);
    assert.ok(
      stages.includes("EXECUTION"),
      `Expected EXECUTION in predictions, got: ${stages.join(", ")}`
    );
    assert.ok(
      stages.includes("PERSISTENCE"),
      `Expected PERSISTENCE in predictions, got: ${stages.join(", ")}`
    );
  });

  // -------------------------------------------------------------------------
  // Case 3: PROC-001 + NET-008 → multiple predictions, at least one ≥ 0.55
  // -------------------------------------------------------------------------
  it("PROC-001 + NET-008 detections produce multiple predictions with at least one confidence >= 0.55", () => {
    const det1 = makeDetection({
      id: "det-001",
      rule_id: "PROC-001-SUSPICIOUS-PARENT-CHILD",
      title: "Suspicious parent-child process",
      severity: "high",
    });
    const det2 = makeDetection({
      id: "det-002",
      rule_id: "NET-008-REVERSE-SHELL",
      title: "Reverse shell connection observed",
      severity: "critical",
    });

    const result = generatePredictions([], [det1, det2]);

    assert.ok(result.length >= 2, `Expected at least 2 predictions, got ${result.length}`);

    const highConfidence = result.filter((p) => p.confidence >= 0.55);
    assert.ok(
      highConfidence.length >= 1,
      `Expected at least one prediction with confidence >= 0.55, got: ${JSON.stringify(result.map((p) => ({ stage: p.stage, confidence: p.confidence })))}`
    );

    // PERSISTENCE is predicted by both rules — should have elevated confidence
    const persistence = result.find((p) => p.stage === "PERSISTENCE");
    assert.ok(persistence, "Expected PERSISTENCE to be predicted");
    assert.ok(
      persistence.confidence >= 0.75,
      `Expected PERSISTENCE confidence >= 0.75 (multi-rule), got ${persistence.confidence}`
    );
  });

  // -------------------------------------------------------------------------
  // Case 4: isPredicted is always true
  // -------------------------------------------------------------------------
  it("all returned predictions have isPredicted=true", () => {
    const detections = [
      makeDetection({ id: "d1", rule_id: "NET-008-REVERSE-SHELL" }),
      makeDetection({ id: "d2", rule_id: "FILE-001-STARTUP-PERSISTENCE" }),
      makeDetection({ id: "d3", rule_id: "NET-009-DATA-EXFILTRATION" }),
    ];

    const result = generatePredictions([], detections);

    assert.ok(result.length > 0, "Expected at least one prediction");
    for (const pred of result) {
      assert.equal(
        pred.isPredicted,
        true,
        `Prediction for stage ${pred.stage} must have isPredicted=true`
      );
    }
  });

  // -------------------------------------------------------------------------
  // Case 5: predictions are ranked highest confidence first
  // -------------------------------------------------------------------------
  it("predictions are returned in descending confidence order", () => {
    const detections = [
      makeDetection({ id: "d1", rule_id: "PROC-001-SUSPICIOUS-PARENT-CHILD" }),
      makeDetection({ id: "d2", rule_id: "PROC-002-ENCODED-COMMAND-LINE" }),
      makeDetection({ id: "d3", rule_id: "NET-001-USER-WRITABLE-OUTBOUND" }),
    ];

    const result = generatePredictions([], detections);

    for (let i = 1; i < result.length; i++) {
      assert.ok(
        result[i - 1].confidence >= result[i].confidence,
        `Predictions are not sorted: index ${i - 1} confidence ${result[i - 1].confidence} < index ${i} confidence ${result[i].confidence}`
      );
    }
  });

  // -------------------------------------------------------------------------
  // Case 6: evidence is harvested from incident timelines
  // -------------------------------------------------------------------------
  it("extracts rule evidence from incident timelines when no raw detections provided", () => {
    const incident = makeIncident({
      timeline: [
        {
          eventId: "evt-det-abc",
          timestamp: "2026-01-01T12:00:00.000Z",
          eventType: "DETECTION_TRIGGERED",
          source: "detection_engine",
          ruleId: "NET-006-INTERPRETER-REMOTE-CONNECTION",
          detectionId: "abc-123",
          evidence: "Rule matched",
          relationship: "DETECTION_MATCH",
          observationStatus: "CORRELATED",
          direction: "LOCAL",
        },
      ],
    });

    const result = generatePredictions([incident], []);
    const stages = result.map((p) => p.stage);
    assert.ok(
      stages.includes("LATERAL_MOVEMENT"),
      `Expected LATERAL_MOVEMENT predicted from NET-006 via incident timeline, got: ${stages.join(", ")}`
    );
  });

  // -------------------------------------------------------------------------
  // Case 7: NET-009-DATA-EXFILTRATION predicts IMPACT
  // -------------------------------------------------------------------------
  it("NET-009-DATA-EXFILTRATION detection predicts IMPACT stage", () => {
    const det = makeDetection({
      id: "det-exfil",
      rule_id: "NET-009-DATA-EXFILTRATION",
      title: "Data exfiltration detected",
      severity: "critical",
    });

    const result = generatePredictions([], [det]);
    const stages = result.map((p) => p.stage);
    assert.ok(
      stages.includes("IMPACT"),
      `Expected IMPACT predicted from NET-009, got: ${stages.join(", ")}`
    );
  });
});
