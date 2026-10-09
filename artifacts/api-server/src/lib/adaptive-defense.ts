/**
 * ARGUS Adaptive Defense — incident-to-rule feedback loop.
 *
 * Tracks which detection rules fired for each closed incident,
 * measures false positive rate, missed detection rate, and
 * regression test outcomes over time.
 *
 * Design rules:
 * - Never auto-changes production rules without human review
 * - Only stores data from closed, verified incidents
 * - Honest about uncertainty: report unknown rates as unknown
 */

import { randomUUID } from "node:crypto";

// ---------------------------------------------------------------------------
// Exported types
// ---------------------------------------------------------------------------

export type RuleMetrics = {
  ruleId: string;
  ruleName: string;
  totalFirings: number;
  confirmedThreatCount: number; // incident closed as RESOLVED/CONTAINED
  falsePositiveCount: number; // incident closed as NOT_THREAT (human review)
  pendingReviewCount: number; // incident still open
  lastFiredAt: string | null;
  precisionEstimate: number | null; // confirmedThreat / (confirmed + fp), null if < 5 samples
};

export type RegressionTestResult = {
  testId: string;
  scenarioName: string;
  runAt: string;
  expectedRules: string[]; // ground truth expected detections
  firedRules: string[]; // rules that actually fired
  matched: string[]; // intersection
  missed: string[]; // expected but not fired
  extra: string[]; // fired but not expected
  detectionRate: number; // matched.length / expectedRules.length
  falsePositiveCount: number; // extra.length
  passed: boolean; // detectionRate >= 1.0 && falsePositiveCount === 0
};

export type AdaptiveDefenseSnapshot = {
  ruleMetrics: RuleMetrics[];
  regressionHistory: RegressionTestResult[];
  totalIncidentsAnalyzed: number;
  lastUpdatedAt: string;
};

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

/** Minimum number of closed-incident samples before we report a precision estimate. */
const MIN_SAMPLES_FOR_PRECISION = 5;

/**
 * Precision below this threshold triggers a requiresHumanReview = true result.
 * A precision of 0.80 means 20 % of firings were false positives.
 */
const HUMAN_REVIEW_PRECISION_THRESHOLD = 0.8;

// ---------------------------------------------------------------------------
// AdaptiveDefenseEngine
// ---------------------------------------------------------------------------

export class AdaptiveDefenseEngine {
  private readonly _ruleMetrics = new Map<string, RuleMetrics>();
  private readonly _regressionHistory: RegressionTestResult[] = [];
  private _totalIncidentsAnalyzed = 0;
  private _lastUpdatedAt: string = new Date().toISOString();

  // ------------------------------------------------------------------
  // Rule metrics
  // ------------------------------------------------------------------

  /**
   * Update rule metrics after a human operator closes an incident.
   *
   * @param incidentId  ID of the closed incident (informational — used for
   *                    de-duplication in future extensions).
   * @param firedRules  Rule IDs that fired during the incident.
   * @param outcome     How the incident was classified.
   */
  recordIncidentClosure(
    incidentId: string,
    firedRules: string[],
    outcome: "CONFIRMED_THREAT" | "FALSE_POSITIVE" | "INCONCLUSIVE",
  ): void {
    const now = new Date().toISOString();

    for (const ruleId of firedRules) {
      const existing = this._ruleMetrics.get(ruleId) ?? this._emptyMetrics(ruleId);

      const updated: RuleMetrics = {
        ...existing,
        totalFirings: existing.totalFirings + 1,
        lastFiredAt: now,
        confirmedThreatCount:
          outcome === "CONFIRMED_THREAT"
            ? existing.confirmedThreatCount + 1
            : existing.confirmedThreatCount,
        falsePositiveCount:
          outcome === "FALSE_POSITIVE"
            ? existing.falsePositiveCount + 1
            : existing.falsePositiveCount,
        // INCONCLUSIVE does not change confirmed/fp counts but does count as a firing.
      };

      updated.precisionEstimate = this._calcPrecision(updated);
      this._ruleMetrics.set(ruleId, updated);
    }

    this._totalIncidentsAnalyzed += 1;
    this._lastUpdatedAt = now;
  }

  // ------------------------------------------------------------------
  // Regression testing
  // ------------------------------------------------------------------

  /**
   * Record a regression test run and return its result.
   *
   * @param scenarioName   Name of the lab scenario that was executed.
   * @param expectedRules  Rule IDs the scenario was designed to trigger.
   * @param firedRules     Rule IDs that actually fired during the run.
   */
  recordRegressionRun(
    scenarioName: string,
    expectedRules: string[],
    firedRules: string[],
  ): RegressionTestResult {
    const expectedSet = new Set(expectedRules);
    const firedSet = new Set(firedRules);

    const matched = expectedRules.filter((r) => firedSet.has(r));
    const missed = expectedRules.filter((r) => !firedSet.has(r));
    const extra = firedRules.filter((r) => !expectedSet.has(r));

    const detectionRate = expectedRules.length === 0 ? 1.0 : matched.length / expectedRules.length;

    const result: RegressionTestResult = {
      testId: randomUUID(),
      scenarioName,
      runAt: new Date().toISOString(),
      expectedRules,
      firedRules,
      matched,
      missed,
      extra,
      detectionRate,
      falsePositiveCount: extra.length,
      passed: detectionRate >= 1.0 && extra.length === 0,
    };

    // Prepend so most-recent-first ordering is maintained.
    this._regressionHistory.unshift(result);
    this._lastUpdatedAt = result.runAt;
    return result;
  }

  // ------------------------------------------------------------------
  // Queries
  // ------------------------------------------------------------------

  /** Returns a full snapshot of all metrics and regression history. */
  getSnapshot(): AdaptiveDefenseSnapshot {
    return {
      ruleMetrics: Array.from(this._ruleMetrics.values()),
      regressionHistory: [...this._regressionHistory],
      totalIncidentsAnalyzed: this._totalIncidentsAnalyzed,
      lastUpdatedAt: this._lastUpdatedAt,
    };
  }

  /** Returns metrics for a single rule, or null if the rule has never fired. */
  getRuleMetrics(ruleId: string): RuleMetrics | null {
    return this._ruleMetrics.get(ruleId) ?? null;
  }

  /**
   * Returns regression test history, most recent first.
   *
   * @param limit  Optional cap on the number of results returned.
   */
  getRegressionHistory(limit?: number): RegressionTestResult[] {
    const history = [...this._regressionHistory];
    return limit !== undefined ? history.slice(0, limit) : history;
  }

  /**
   * Whether a rule's precision has dropped below the threshold and a human
   * should review its configuration.
   *
   * Returns false if there are not yet enough samples to make a judgement.
   */
  requiresHumanReview(ruleId: string): boolean {
    const metrics = this._ruleMetrics.get(ruleId);
    if (!metrics || metrics.precisionEstimate === null) {
      // Not enough data — do not raise a false alarm.
      return false;
    }
    return metrics.precisionEstimate < HUMAN_REVIEW_PRECISION_THRESHOLD;
  }

  // ------------------------------------------------------------------
  // Private helpers
  // ------------------------------------------------------------------

  private _emptyMetrics(ruleId: string): RuleMetrics {
    return {
      ruleId,
      // Rule names are resolved externally; store the ID as a placeholder.
      ruleName: ruleId,
      totalFirings: 0,
      confirmedThreatCount: 0,
      falsePositiveCount: 0,
      pendingReviewCount: 0,
      lastFiredAt: null,
      precisionEstimate: null,
    };
  }

  private _calcPrecision(metrics: RuleMetrics): number | null {
    const denominator = metrics.confirmedThreatCount + metrics.falsePositiveCount;
    if (denominator < MIN_SAMPLES_FOR_PRECISION) {
      return null;
    }
    return metrics.confirmedThreatCount / denominator;
  }
}

// ---------------------------------------------------------------------------
// Module-level singleton
// ---------------------------------------------------------------------------

/** Shared singleton for use by the API layer and other server-side consumers. */
export const adaptiveDefenseEngine = new AdaptiveDefenseEngine();
