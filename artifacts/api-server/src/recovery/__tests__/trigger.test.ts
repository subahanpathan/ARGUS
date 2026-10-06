/**
 * Automatic-recovery trigger policy.
 *
 * The gate exists to keep pure network telemetry from opening file-recovery
 * investigations. These tests pin the policy to the detection's own measured
 * fields, so the behaviour is auditable rather than emergent.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import type { Detection, DetectionSeverity } from "../../detection/types";
import { evaluateRecoveryTrigger, hasFileEvidence } from "../trigger";

function detection(overrides: Partial<Detection> = {}): Detection {
  const at = new Date().toISOString();
  return {
    id: "det-gate-1",
    rule_id: "PROC-002-ENCODED-COMMAND-LINE",
    rule_name: "Encoded PowerShell command line",
    title: "PowerShell executed with an encoded command",
    severity: "high",
    confidence: 0.82,
    status: "detected",
    timestamp: at,
    event_timestamp: at,
    entity: "powershell.exe",
    pid: 4242,
    executable_path: null,
    command_line: "powershell.exe -enc SQBFAFgA",
    parent_pid: 1200,
    parent_process_name: "explorer.exe",
    username: "CORP\\analyst",
    hostname: "WORKSTATION-01",
    evidence: [],
    explanation: "",
    recommended_action: "",
    correlated_rules: [],
    ancestry: [],
    related_event_id: null,
    ...overrides,
  };
}

const fileEvidence = { key: "path", description: "file", source: "file" as const, detail: "C:\\victim\\a.docx" };

describe("automatic recovery trigger gate", () => {
  it("triggers on critical severity without file evidence", () => {
    const decision = evaluateRecoveryTrigger(detection({ severity: "critical", confidence: 0.4 }));
    assert.equal(decision.trigger, true);
    assert.equal(decision.reason, "SEVERITY");
    assert.match(decision.detail, /critical/);
  });

  it("triggers on high severity without file evidence", () => {
    const decision = evaluateRecoveryTrigger(detection({ severity: "high", confidence: 0.3 }));
    assert.equal(decision.trigger, true);
    assert.equal(decision.reason, "SEVERITY");
  });

  it("triggers on confidence alone when severity is medium", () => {
    const decision = evaluateRecoveryTrigger(detection({ severity: "medium", confidence: 0.7 }));
    assert.equal(decision.trigger, true);
    assert.equal(decision.reason, "CONFIDENCE");
  });

  it("triggers on file evidence even when severity and confidence are both low", () => {
    const decision = evaluateRecoveryTrigger(
      detection({ severity: "low", confidence: 0.5, evidence: [fileEvidence] }),
    );
    assert.equal(decision.trigger, true);
    assert.equal(
      decision.reason,
      "FILE_EVIDENCE",
      "a low-severity on-disk artefact still names a concrete file to investigate",
    );
  });

  it("prefers file evidence over severity when both apply", () => {
    const decision = evaluateRecoveryTrigger(
      detection({ severity: "critical", confidence: 0.9, evidence: [fileEvidence] }),
    );
    assert.equal(decision.reason, "FILE_EVIDENCE");
  });

  it("skips a low-severity, low-confidence detection with no file evidence", () => {
    const decision = evaluateRecoveryTrigger(detection({ severity: "low", confidence: 0.5 }));
    assert.equal(decision.trigger, false);
    assert.equal(decision.reason, "BELOW_THRESHOLD");
  });

  it("reports the measured values in the skip reason so the decision is auditable", () => {
    const decision = evaluateRecoveryTrigger(detection({ severity: "medium", confidence: 0.65 }));
    assert.equal(decision.trigger, false);
    assert.match(decision.detail, /severity medium/);
    assert.match(decision.detail, /confidence 0\.65/);
    assert.match(decision.detail, /investigated on demand/, "a skip must say the detection is still recoverable by hand");
  });

  it("skips exactly the shape of a pure network observation", () => {
    // NET-007 remote fan-out: low severity, 0.5 confidence, no file evidence.
    // There is no file in it to reconstruct, so opening an incident would be noise.
    const decision = evaluateRecoveryTrigger(
      detection({ rule_id: "NET-007-REMOTE-FAN-OUT", severity: "low", confidence: 0.5, entity: "chrome.exe" }),
    );
    assert.equal(decision.trigger, false);
  });

  it("triggers exactly at the confidence boundary and not below it", () => {
    assert.equal(evaluateRecoveryTrigger(detection({ severity: "medium", confidence: 0.7 })).trigger, true);
    assert.equal(evaluateRecoveryTrigger(detection({ severity: "medium", confidence: 0.69 })).trigger, false);
  });

  it("recognises both file-bearing evidence sources and ignores the rest", () => {
    assert.equal(hasFileEvidence(detection({ evidence: [fileEvidence] })), true);
    assert.equal(
      hasFileEvidence(detection({ evidence: [{ key: "p", description: "d", source: "path", detail: "C:\\x" }] })),
      true,
    );
    assert.equal(
      hasFileEvidence(detection({ evidence: [{ key: "c", description: "d", source: "command_line" }] })),
      false,
    );
    assert.equal(hasFileEvidence(detection()), false);
  });

  it("gates on severity, not on a hardcoded rule list, so new rules inherit the policy", () => {
    const severities: Array<[DetectionSeverity, number, boolean]> = [
      ["critical", 0.1, true],
      ["high", 0.1, true],
      ["medium", 0.7, true],
      ["medium", 0.69, false],
      ["low", 0.95, true],
      ["low", 0.69, false],
    ];
    for (const [severity, confidence, expected] of severities) {
      const decision = evaluateRecoveryTrigger(detection({ severity, confidence }));
      assert.equal(decision.trigger, expected, `${severity}/${confidence} should be ${expected ? "triggered" : "skipped"}`);
    }
  });
});
