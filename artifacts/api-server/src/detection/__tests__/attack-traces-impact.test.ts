import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { eventHub } from "../../lib/event-hub";
import { attackCorrelationEngine } from "../../lib/attack-correlation";
import { classifySensitiveCategory, classifyImpactState, evaluateImpactAssessment } from "../../lib/file-impact";
import type { Detection } from "../types";

describe("Phase 3 & Phase 4: File Activity Correlation & Impact Analysis", () => {
  test("classifySensitiveCategory correctly categorizes files by extension and name pattern", () => {
    assert.equal(classifySensitiveCategory("C:\\Users\\test\\Documents\\document.docx"), "Documents");
    assert.equal(classifySensitiveCategory("C:\\Users\\test\\.env"), "Credentials");
    assert.equal(classifySensitiveCategory("C:\\Users\\test\\id_rsa.pem"), "Credentials");
    assert.equal(classifySensitiveCategory("C:\\Users\\test\\Finance\\invoice_2026.xlsx"), "Financial");
    assert.equal(classifySensitiveCategory("C:\\Users\\test\\resume.pdf"), "Personal");
    assert.equal(classifySensitiveCategory("D:\\Project\\app.ts"), "Source code");
    assert.equal(classifySensitiveCategory("C:\\Windows\\System32\\kernel32.dll"), "System files");
  });

  test("classifyImpactState identifies operations and encryption indicators", () => {
    const normalEvent = {
      eventId: "fe-1",
      timestamp: new Date().toISOString(),
      eventType: "FILE_MODIFIED" as const,
      filePath: "C:\\Users\\test\\doc.txt",
      operation: "MODIFY" as const,
      source: "test",
      observationStatus: "OBSERVED" as const,
    };
    assert.equal(classifyImpactState(normalEvent), "MODIFIED");

    const ransomEvent = {
      ...normalEvent,
      filePath: "C:\\Users\\test\\doc.txt.locked",
      oldFilePath: "C:\\Users\\test\\doc.txt",
      operation: "RENAME" as const,
      eventType: "FILE_RENAMED" as const,
    };
    assert.equal(classifyImpactState(ransomEvent), "ENCRYPTION_SUSPECTED");
  });

  test("evaluateImpactAssessment calculates deterministic damage score and exposure counts", () => {
    const fileEvents = [
      {
        eventId: "fe-1",
        timestamp: new Date().toISOString(),
        eventType: "FILE_MODIFIED" as const,
        filePath: "C:\\Users\\test\\Documents\\document.docx",
        operation: "MODIFY" as const,
        source: "test",
        observationStatus: "OBSERVED" as const,
      },
      {
        eventId: "fe-2",
        timestamp: new Date().toISOString(),
        eventType: "FILE_MODIFIED" as const,
        filePath: "C:\\Users\\test\\Finance\\invoice_2026.xlsx",
        operation: "MODIFY" as const,
        source: "test",
        observationStatus: "OBSERVED" as const,
      },
      {
        eventId: "fe-3",
        timestamp: new Date().toISOString(),
        eventType: "FILE_CREATED" as const,
        filePath: "C:\\Users\\test\\payload.tmp",
        operation: "CREATE" as const,
        source: "test",
        observationStatus: "OBSERVED" as const,
      },
    ];

    const assessment = evaluateImpactAssessment(fileEvents, true);

    assert.equal(assessment.affectedFilesCount, 3);
    assert.equal(assessment.counts.modified, 2);
    assert.equal(assessment.counts.created, 1);
    assert.equal(assessment.potentialSensitiveExposureCount, 2);
    assert.equal(typeof assessment.damageScore, "number");
    assert.ok(assessment.damageScore! > 0);
    assert.ok(assessment.damageScoreExplanation.length > 0);
  });

  test("AttackCorrelationEngine links file activity to correlated incident", () => {
    const mockDetection: Detection = {
      id: "det-file-test-1",
      rule_id: "PROC-001-SUSPICIOUS-PARENT-CHILD",
      rule_name: "Suspicious Process Spawn",
      title: "Suspicious PowerShell Execution",
      severity: "high",
      confidence: 0.9,
      status: "detected",
      timestamp: new Date().toISOString(),
      event_timestamp: new Date().toISOString(),
      entity: "powershell.exe",
      pid: 9912,
      executable_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      evidence: [],
      explanation: "Test detection explanation",
      recommended_action: "Inspect process",
      ancestry: [],
      hostname: "test-pc",
    };

    eventHub.addDetection(mockDetection);

    eventHub.addFileActivity({
      eventId: "fa-test-9912",
      timestamp: new Date().toISOString(),
      eventType: "FILE_MODIFIED",
      filePath: "C:\\Users\\test\\Documents\\important_data.docx",
      operation: "MODIFY",
      pid: 9912,
      processName: "powershell.exe",
      source: "readdirectorychangesw",
      observationStatus: "OBSERVED",
    });

    const incidents = attackCorrelationEngine.getCorrelatedIncidents();
    const targetIncident = incidents.find((i) => i.primaryProcess.pid === 9912);

    assert.ok(targetIncident, "Incident should be generated for target PID 9912");
    assert.ok(targetIncident.affectedFiles.length >= 1, "Affected files should include correlated file event");
    assert.equal(targetIncident.affectedFiles[0].filePath, "C:\\Users\\test\\Documents\\important_data.docx");
    assert.ok(targetIncident.impactAssessment.affectedFilesCount >= 1);
    assert.ok(targetIncident.dataFlowChain.length >= 4);

    const faNode = targetIncident.graph.nodes.find((n) => n.type === "FILE_ACTIVITY");
    assert.ok(faNode, "Attack graph should include FILE_ACTIVITY node");

    const affectedNode = targetIncident.graph.nodes.find((n) => n.type === "AFFECTED_FILES");
    assert.ok(affectedNode, "Attack graph should include AFFECTED_FILES node");
  });
});
