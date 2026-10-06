/**
 * Automatic-recovery trigger policy.
 *
 * Recovery is expensive: every investigation reads live telemetry, hashes files
 * and probes the host for shadow copies. Running that for every rule the engine
 * can emit would mean investigating pure network telemetry (a connection fan-out
 * counter has no file to reconstruct) and drowning real incidents in noise.
 *
 * So the automatic path is gated on the detection having reached a threat state
 * that could plausibly have damaged data. This is a *gate on automation only*.
 * `RecoveryService.investigate()` stays ungated, so an operator or a test can
 * always force an investigation of any detection, including one that scores
 * below the automatic threshold.
 *
 * The policy is deliberately expressed over the detection's own measured fields
 * (severity, confidence, evidence sources) rather than over a hardcoded rule-id
 * list, so a new detection rule inherits sensible behaviour instead of silently
 * opting itself in or out of recovery.
 */

import type { Detection, DetectionSeverity } from "../detection/types";

/** Severities that represent a confirmed enough threat to investigate on their own. */
const AUTO_TRIGGER_SEVERITIES: ReadonlySet<DetectionSeverity> = new Set<DetectionSeverity>(["critical", "high"]);

/**
 * Confidence at or above which a detection is treated as high-confidence even
 * when its severity is only medium. Matches the floor used by the engine's own
 * high-severity rules, so the gate does not reject a signal the engine
 * considers strong.
 */
const AUTO_TRIGGER_CONFIDENCE = 0.7;

/** Evidence sources that mean the detection named a concrete file on disk. */
const FILE_EVIDENCE_SOURCES: ReadonlySet<string> = new Set(["file", "path"]);

/** Machine-readable outcome, so the decision is auditable without parsing prose. */
export type RecoveryTriggerReason =
  | "FILE_EVIDENCE"
  | "SEVERITY"
  | "CONFIDENCE"
  | "BELOW_THRESHOLD"
  | "RECOVERY_DISABLED";

export type RecoveryTriggerDecision = {
  /** Whether the automatic path should start an investigation. */
  trigger: boolean;
  reason: RecoveryTriggerReason;
  /** Human-readable explanation including the measured values behind it. */
  detail: string;
};

/** True when the detection's own evidence names at least one concrete file path. */
export function hasFileEvidence(detection: Detection): boolean {
  return detection.evidence.some((item) => FILE_EVIDENCE_SOURCES.has(item.source));
}

/**
 * Decide whether a detection should start a recovery investigation automatically.
 *
 * Precedence, strongest evidence first:
 *
 *  1. `FILE_EVIDENCE` — the engine produced a file/path finding for this
 *     detection. Impact discovery has a real starting point regardless of how
 *     the rule chose to score itself, so this triggers even for a low-severity
 *     on-disk artefact such as a reconnaissance script.
 *  2. `SEVERITY` — critical or high. A confirmed, high-confidence threat.
 *  3. `CONFIDENCE` — medium severity but confidence at or above the threshold.
 *  4. `BELOW_THRESHOLD` — neither. Recorded and skipped, never silently dropped.
 */
export function evaluateRecoveryTrigger(detection: Detection): RecoveryTriggerDecision {
  if (hasFileEvidence(detection)) {
    return {
      trigger: true,
      reason: "FILE_EVIDENCE",
      detail: "the detection carries file evidence, so impact discovery has a concrete path to start from",
    };
  }

  if (AUTO_TRIGGER_SEVERITIES.has(detection.severity)) {
    return {
      trigger: true,
      reason: "SEVERITY",
      detail: `severity ${detection.severity} is at or above the automatic recovery threshold`,
    };
  }

  if (detection.confidence >= AUTO_TRIGGER_CONFIDENCE) {
    return {
      trigger: true,
      reason: "CONFIDENCE",
      detail: `confidence ${detection.confidence} is at or above the ${AUTO_TRIGGER_CONFIDENCE} automatic threshold`,
    };
  }

  return {
    trigger: false,
    reason: "BELOW_THRESHOLD",
    detail:
      `severity ${detection.severity} with confidence ${detection.confidence} and no file evidence ` +
      `is below the automatic recovery threshold (severity high/critical, confidence >= ${AUTO_TRIGGER_CONFIDENCE}, or file evidence); ` +
      "the detection is still recorded and can be investigated on demand",
  };
}
