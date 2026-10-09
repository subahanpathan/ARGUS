import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { benchmarkEvaluationEngine, BENCHMARK_SCENARIOS } from "../benchmark";

describe("ARGUS Detection Benchmark & Evaluation Engine", () => {
  it("evaluates deterministic benchmark dataset and calculates quantitative metrics", () => {
    const results = benchmarkEvaluationEngine.evaluateBenchmark();

    assert.ok(results, "Benchmark results should be returned");
    assert.equal(results.datasetLabel, "SYNTHETIC_LAB_BENCHMARK_V1");
    assert.equal(results.isSyntheticDataset, true);
    assert.equal(results.totalScenarios, BENCHMARK_SCENARIOS.length);

    // Verify aggregate quantitative metrics
    const agg = results.aggregateMetrics;
    assert.ok(typeof agg.precision === "number" && agg.precision >= 0 && agg.precision <= 1.0, "Precision in [0, 1]");
    assert.ok(typeof agg.recall === "number" && agg.recall >= 0 && agg.recall <= 1.0, "Recall in [0, 1]");
    assert.ok(typeof agg.f1Score === "number" && agg.f1Score >= 0 && agg.f1Score <= 1.0, "F1 Score in [0, 1]");
    assert.ok(typeof agg.falsePositivesPerHour === "number" && agg.falsePositivesPerHour >= 0, "FP/hr >= 0");
    assert.ok(typeof agg.predictionTop1Accuracy === "number" && agg.predictionTop1Accuracy >= 0 && agg.predictionTop1Accuracy <= 1.0, "Top1 accuracy in [0, 1]");
    assert.ok(typeof agg.predictionTop3Accuracy === "number" && agg.predictionTop3Accuracy >= 0 && agg.predictionTop3Accuracy <= 1.0, "Top3 accuracy in [0, 1]");
    assert.ok(typeof agg.evidenceCoverage === "number" && agg.evidenceCoverage >= 0 && agg.evidenceCoverage <= 1.0, "Evidence coverage in [0, 1]");

    // Verify per-scenario results breakdown
    assert.equal(results.scenarioResults.length, BENCHMARK_SCENARIOS.length);
    for (const scResult of results.scenarioResults) {
      assert.ok(scResult.scenarioId, "Scenario ID present");
      assert.ok(scResult.category, "Category present");
      assert.ok(typeof scResult.precision === "number", "Precision is numeric");
      assert.ok(typeof scResult.recall === "number", "Recall is numeric");
      assert.ok(Array.isArray(scResult.expectedRules), "Expected rules array");
      assert.ok(Array.isArray(scResult.firedRules), "Fired rules array");
    }

    // Verify per-rule results breakdown
    assert.ok(Array.isArray(results.ruleResults) && results.ruleResults.length > 0, "Rule results present");
    for (const rResult of results.ruleResults) {
      assert.ok(rResult.ruleId, "Rule ID present");
      assert.ok(typeof rResult.truePositives === "number", "TP is numeric");
      assert.ok(typeof rResult.falsePositives === "number", "FP is numeric");
    }
  });

  it("handles benign scenarios with 0 false positives", () => {
    const results = benchmarkEvaluationEngine.evaluateBenchmark();
    const benignScenarios = results.scenarioResults.filter((s) => s.category === "BENIGN_ACTIVITY");

    assert.ok(benignScenarios.length > 0, "Should contain benign test scenarios");
    for (const sc of benignScenarios) {
      assert.equal(sc.falsePositives, 0, `Benign scenario ${sc.scenarioId} should produce 0 false positives`);
      assert.equal(sc.precision, 1.0, `Precision for benign scenario ${sc.scenarioId} should be 1.0`);
    }
  });
});
