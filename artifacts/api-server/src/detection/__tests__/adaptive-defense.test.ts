/**
 * Tests for the ARGUS Adaptive Defense module.
 *
 * Verifies rule metrics tracking, regression test recording,
 * precision estimation, and human-review thresholds.
 */

import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { AdaptiveDefenseEngine } from "../../lib/adaptive-defense";

describe("AdaptiveDefenseEngine", () => {
  let engine: AdaptiveDefenseEngine;

  beforeEach(() => {
    engine = new AdaptiveDefenseEngine();
  });

  it("starts with empty metrics and no regression history", () => {
    const snap = engine.getSnapshot();
    assert.equal(snap.ruleMetrics.length, 0);
    assert.equal(snap.regressionHistory.length, 0);
    assert.equal(snap.totalIncidentsAnalyzed, 0);
  });

  it("recording a CONFIRMED_THREAT increments confirmedThreatCount", () => {
    engine.recordIncidentClosure("inc-001", ["NET-008-REVERSE-SHELL", "PROC-002-ENCODED-COMMAND-LINE"], "CONFIRMED_THREAT");
    const metrics = engine.getRuleMetrics("NET-008-REVERSE-SHELL");
    assert.ok(metrics, "Metrics must exist after closure");
    assert.equal(metrics.confirmedThreatCount, 1);
    assert.equal(metrics.falsePositiveCount, 0);
    assert.equal(metrics.totalFirings, 1);
  });

  it("recording a FALSE_POSITIVE increments falsePositiveCount", () => {
    engine.recordIncidentClosure("inc-002", ["NET-002-KNOWN-TOOL-PORT"], "FALSE_POSITIVE");
    const metrics = engine.getRuleMetrics("NET-002-KNOWN-TOOL-PORT");
    assert.ok(metrics);
    assert.equal(metrics.falsePositiveCount, 1);
    assert.equal(metrics.confirmedThreatCount, 0);
    assert.equal(metrics.totalFirings, 1);
  });

  it("records multiple closures and accumulates counts correctly", () => {
    engine.recordIncidentClosure("inc-a", ["NET-008-REVERSE-SHELL"], "CONFIRMED_THREAT");
    engine.recordIncidentClosure("inc-b", ["NET-008-REVERSE-SHELL"], "CONFIRMED_THREAT");
    engine.recordIncidentClosure("inc-c", ["NET-008-REVERSE-SHELL"], "FALSE_POSITIVE");
    const metrics = engine.getRuleMetrics("NET-008-REVERSE-SHELL");
    assert.ok(metrics);
    assert.equal(metrics.confirmedThreatCount, 2);
    assert.equal(metrics.falsePositiveCount, 1);
    assert.equal(metrics.totalFirings, 3);
  });

  it("precision estimate is null with fewer than 5 samples", () => {
    engine.recordIncidentClosure("inc-x", ["FILE-001-STARTUP-PERSISTENCE"], "CONFIRMED_THREAT");
    engine.recordIncidentClosure("inc-y", ["FILE-001-STARTUP-PERSISTENCE"], "CONFIRMED_THREAT");
    const metrics = engine.getRuleMetrics("FILE-001-STARTUP-PERSISTENCE");
    assert.ok(metrics);
    assert.equal(metrics.precisionEstimate, null, "Precision must be null with < 5 samples");
  });

  it("precision estimate is populated with 5+ samples", () => {
    for (let i = 0; i < 4; i++) {
      engine.recordIncidentClosure(`inc-p${i}`, ["PROC-001-SUSPICIOUS-PARENT-CHILD"], "CONFIRMED_THREAT");
    }
    engine.recordIncidentClosure("inc-p4", ["PROC-001-SUSPICIOUS-PARENT-CHILD"], "FALSE_POSITIVE");
    const metrics = engine.getRuleMetrics("PROC-001-SUSPICIOUS-PARENT-CHILD");
    assert.ok(metrics);
    assert.ok(metrics.precisionEstimate !== null, "Precision must be computed with 5 samples");
    // 4 confirmed / (4 confirmed + 1 fp) = 0.8
    assert.ok(
      Math.abs((metrics.precisionEstimate ?? 0) - 0.8) < 0.001,
      `Expected precision ~0.8, got ${metrics.precisionEstimate}`,
    );
  });

  it("regression run with perfect match returns passed=true and detectionRate=1.0", () => {
    const result = engine.recordRegressionRun(
      "reverse_shell_exfiltration",
      ["NET-008-REVERSE-SHELL", "PROC-002-ENCODED-COMMAND-LINE"],
      ["NET-008-REVERSE-SHELL", "PROC-002-ENCODED-COMMAND-LINE"],
    );
    assert.equal(result.passed, true);
    assert.equal(result.detectionRate, 1.0);
    assert.equal(result.matched.length, 2);
    assert.equal(result.missed.length, 0);
    assert.equal(result.extra.length, 0);
    assert.equal(result.falsePositiveCount, 0);
  });

  it("regression run with missed rules returns passed=false", () => {
    const result = engine.recordRegressionRun(
      "persistence_test",
      ["FILE-001-STARTUP-PERSISTENCE", "PROC-001-SUSPICIOUS-PARENT-CHILD"],
      ["FILE-001-STARTUP-PERSISTENCE"],  // PROC-001 missed
    );
    assert.equal(result.passed, false);
    assert.ok(result.detectionRate < 1.0);
    assert.equal(result.missed.length, 1);
    assert.equal(result.missed[0], "PROC-001-SUSPICIOUS-PARENT-CHILD");
  });

  it("regression run with extra (false positive) rules returns passed=false", () => {
    const result = engine.recordRegressionRun(
      "benign_test",
      [],  // expected: no hostile rules
      ["NET-002-KNOWN-TOOL-PORT"],  // incorrectly fired
    );
    assert.equal(result.passed, false);
    assert.equal(result.falsePositiveCount, 1);
    assert.equal(result.extra.length, 1);
  });

  it("getRegressionHistory returns most recent first", () => {
    engine.recordRegressionRun("scenario-a", ["NET-008-REVERSE-SHELL"], ["NET-008-REVERSE-SHELL"]);
    engine.recordRegressionRun("scenario-b", ["FILE-001-STARTUP-PERSISTENCE"], ["FILE-001-STARTUP-PERSISTENCE"]);
    const history = engine.getRegressionHistory();
    assert.ok(history.length >= 2);
    // Most recent (scenario-b) should appear first
    assert.equal(history[0].scenarioName, "scenario-b");
    assert.equal(history[1].scenarioName, "scenario-a");
  });

  it("requiresHumanReview returns true when precision drops below threshold", () => {
    // Record 3 false positives + 2 confirmed (precision = 0.4, below 0.6 threshold)
    for (let i = 0; i < 2; i++) {
      engine.recordIncidentClosure(`inc-low-tp${i}`, ["NET-002-KNOWN-TOOL-PORT"], "CONFIRMED_THREAT");
    }
    for (let i = 0; i < 3; i++) {
      engine.recordIncidentClosure(`inc-low-fp${i}`, ["NET-002-KNOWN-TOOL-PORT"], "FALSE_POSITIVE");
    }
    // Need 5 samples for precision estimate — we have 5 now
    assert.equal(
      engine.requiresHumanReview("NET-002-KNOWN-TOOL-PORT"),
      true,
      "Low-precision rule must require human review",
    );
  });

  it("requiresHumanReview returns false for a high-precision rule", () => {
    // 5 confirmed, 0 false positives → precision = 1.0
    for (let i = 0; i < 5; i++) {
      engine.recordIncidentClosure(`inc-hi${i}`, ["NET-008-REVERSE-SHELL"], "CONFIRMED_THREAT");
    }
    assert.equal(
      engine.requiresHumanReview("NET-008-REVERSE-SHELL"),
      false,
      "High-precision rule must not require human review",
    );
  });

  it("requiresHumanReview returns false for unknown rule (insufficient data)", () => {
    // Rule never seen → no samples → precision null → no review triggered
    assert.equal(engine.requiresHumanReview("PROC-007-LOLBIN-EXECUTION"), false);
  });

  it("getSnapshot totalIncidentsAnalyzed counts unique incident IDs", () => {
    engine.recordIncidentClosure("inc-unique-1", ["NET-008-REVERSE-SHELL"], "CONFIRMED_THREAT");
    engine.recordIncidentClosure("inc-unique-2", ["NET-009-DATA-EXFILTRATION"], "FALSE_POSITIVE");
    const snap = engine.getSnapshot();
    assert.equal(snap.totalIncidentsAnalyzed, 2);
  });

  it("getRegressionHistory respects limit parameter", () => {
    for (let i = 0; i < 5; i++) {
      engine.recordRegressionRun(`scenario-${i}`, [], []);
    }
    const limited = engine.getRegressionHistory(3);
    assert.equal(limited.length, 3);
  });
});
