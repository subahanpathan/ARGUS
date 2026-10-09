/**
 * ARGUS Prediction Engine.
 *
 * Consumes correlated incidents and raw detections produced by the detection
 * engine and generates forward-looking, uncertainty-quantified predictions
 * about likely next attack stages.
 *
 * Design principles:
 * - Fully deterministic: identical inputs always produce identical outputs.
 * - Explainable: every prediction carries evidence references and a human-readable
 *   explanation so operators can trace why a stage was predicted.
 * - Conservative: predictions are clearly flagged as predicted (isPredicted=true)
 *   and never presented as confirmed observations.
 * - MITRE ATT&CK-anchored: stage identifiers and technique IDs map onto the
 *   ATT&CK Enterprise matrix.
 */

import type { CorrelatedIncident } from "./attack-correlation";
import type { Detection, DetectionRuleId } from "../detection/types";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** A named stage in the deterministic MITRE ATT&CK-inspired attack progression. */
export type AttackStage =
  | "INITIAL_ACCESS"
  | "EXECUTION"
  | "PERSISTENCE"
  | "PRIVILEGE_ESCALATION"
  | "DEFENSE_EVASION"
  | "LATERAL_MOVEMENT"
  | "COLLECTION"
  | "EXFILTRATION"
  | "IMPACT";

/** The information basis used to derive a particular prediction. */
export type PredictionBasis =
  | "RULE_CORRELATION"
  | "TEMPORAL_PATTERN"
  | "BEHAVIORAL_PATTERN";

/** Uncertainty level reflecting the degree of evidential support for a prediction. */
export type PredictionUncertainty = "LOW" | "MEDIUM" | "HIGH";

/**
 * A single forward-looking stage prediction produced by the engine.
 *
 * `isPredicted` is ALWAYS true — these are never claimed to be confirmed events.
 */
export type StagePrediction = {
  /** Named attack stage being predicted. */
  stage: AttackStage;
  /** Optional MITRE ATT&CK technique ID for the predicted stage. */
  mitreId?: string;
  /** Probability-like confidence score in [0, 1]. */
  confidence: number;
  /** Qualitative uncertainty label derived from the confidence score. */
  uncertainty: PredictionUncertainty;
  /** Detection IDs and rule IDs that provide evidential support for this prediction. */
  evidenceRefs: string[];
  /** Human-readable explanation of why this stage is predicted next. */
  explanation: string;
  /** Always true — predictions are never claimed as confirmed observations. */
  isPredicted: true;
  /** The reasoning basis used to derive this prediction. */
  basis: PredictionBasis;
};

// ---------------------------------------------------------------------------
// Internal model definitions
// ---------------------------------------------------------------------------

/**
 * The canonical linear attack progression modelled by the engine.
 * Stages are listed in ascending order of advancement along the kill chain.
 */
const ATTACK_CHAIN: AttackStage[] = [
  "INITIAL_ACCESS",
  "EXECUTION",
  "PERSISTENCE",
  "PRIVILEGE_ESCALATION",
  "DEFENSE_EVASION",
  "LATERAL_MOVEMENT",
  "COLLECTION",
  "EXFILTRATION",
];

/** Optional MITRE technique IDs for each named stage. */
const STAGE_MITRE_IDS: Partial<Record<AttackStage, string>> = {
  INITIAL_ACCESS: "TA0001",
  EXECUTION: "TA0002",
  PERSISTENCE: "TA0003",
  PRIVILEGE_ESCALATION: "TA0004",
  DEFENSE_EVASION: "TA0005",
  LATERAL_MOVEMENT: "TA0008",
  COLLECTION: "TA0009",
  EXFILTRATION: "TA0010",
  IMPACT: "TA0040",
};

/**
 * Per-rule mapping: which stage the rule indicates is currently underway, and
 * which subsequent stages it predicts.
 */
type RuleMapping = {
  /** Stage the rule evidences as currently observed. */
  currentStage: AttackStage;
  /** Stages that are likely to follow given this rule firing. */
  predictedStages: AttackStage[];
};

const RULE_STAGE_MAP: Partial<Record<DetectionRuleId, RuleMapping>> = {
  "NET-008-REVERSE-SHELL": {
    currentStage: "INITIAL_ACCESS",
    predictedStages: ["EXECUTION", "PERSISTENCE"],
  },
  "NET-009-DATA-EXFILTRATION": {
    currentStage: "EXFILTRATION",
    predictedStages: ["IMPACT"],
  },
  "PROC-001-SUSPICIOUS-PARENT-CHILD": {
    currentStage: "EXECUTION",
    predictedStages: ["PERSISTENCE", "PRIVILEGE_ESCALATION"],
  },
  "PROC-002-ENCODED-COMMAND-LINE": {
    currentStage: "EXECUTION",
    predictedStages: ["DEFENSE_EVASION", "PERSISTENCE"],
  },
  "NET-001-USER-WRITABLE-OUTBOUND": {
    currentStage: "EXECUTION",
    predictedStages: ["PERSISTENCE", "EXFILTRATION"],
  },
  "FILE-001-STARTUP-PERSISTENCE": {
    currentStage: "PERSISTENCE",
    predictedStages: ["PRIVILEGE_ESCALATION"],
  },
  "NET-006-INTERPRETER-REMOTE-CONNECTION": {
    currentStage: "EXECUTION",
    predictedStages: ["LATERAL_MOVEMENT"],
  },
};

// ---------------------------------------------------------------------------
// Confidence / uncertainty helpers
// ---------------------------------------------------------------------------

/**
 * Derive a confidence score based on how many independent rule matches support
 * the predicted stage.
 */
function scoreConfidence(matchCount: number, chainAdjacent: boolean): number {
  if (matchCount >= 2) return 0.75;
  if (matchCount === 1) return 0.55;
  if (chainAdjacent) return 0.4;
  return 0.25;
}

/**
 * Map a numeric confidence score to a qualitative uncertainty label.
 * LOW  = well-evidenced, HIGH = speculative.
 */
function deriveUncertainty(confidence: number): PredictionUncertainty {
  if (confidence > 0.7) return "LOW";
  if (confidence >= 0.4) return "MEDIUM";
  return "HIGH";
}

// ---------------------------------------------------------------------------
// Core prediction logic
// ---------------------------------------------------------------------------

/**
 * Collect all unique rule IDs observed across incidents and standalone
 * detections, together with the detection IDs that evidence them.
 */
function collectObservedRules(
  incidents: CorrelatedIncident[],
  detections: Detection[]
): Map<DetectionRuleId, string[]> {
  const observed = new Map<DetectionRuleId, string[]>();

  // Harvest from incident timelines
  for (const inc of incidents) {
    for (const event of inc.timeline) {
      if (event.ruleId) {
        const ruleId = event.ruleId as DetectionRuleId;
        const refs = observed.get(ruleId) ?? [];
        if (event.detectionId && !refs.includes(event.detectionId)) {
          refs.push(event.detectionId);
        }
        observed.set(ruleId, refs);
      }
    }
  }

  // Harvest from raw detections
  for (const det of detections) {
    const refs = observed.get(det.rule_id) ?? [];
    if (!refs.includes(det.id)) refs.push(det.id);
    observed.set(det.rule_id, refs);
  }

  return observed;
}

/**
 * Determine the highest observed stage index in the attack chain so we can
 * identify chain-adjacent stages for fallback confidence.
 */
function highestObservedChainIndex(observedRules: Map<DetectionRuleId, string[]>): number {
  let maxIdx = -1;
  for (const ruleId of observedRules.keys()) {
    const mapping = RULE_STAGE_MAP[ruleId];
    if (!mapping) continue;
    const idx = ATTACK_CHAIN.indexOf(mapping.currentStage);
    if (idx > maxIdx) maxIdx = idx;
  }
  return maxIdx;
}

/**
 * Build a human-readable explanation for a predicted stage.
 */
function buildExplanation(
  stage: AttackStage,
  evidenceRefs: string[],
  supportingRules: DetectionRuleId[],
  matchCount: number
): string {
  const mitre = STAGE_MITRE_IDS[stage];
  const mitreNote = mitre ? ` (MITRE ${mitre})` : "";
  const ruleList = supportingRules.length > 0 ? ` — supported by rule(s): ${supportingRules.join(", ")}` : "";
  if (matchCount >= 2) {
    return (
      `Stage ${stage}${mitreNote} is predicted with elevated confidence: ` +
      `${matchCount} independent rule matches provide corroborating evidence${ruleList}.`
    );
  }
  if (matchCount === 1) {
    return (
      `Stage ${stage}${mitreNote} is predicted based on a single rule match${ruleList}. ` +
      `Adversarial progression from the observed stage makes this a plausible next step.`
    );
  }
  return (
    `Stage ${stage}${mitreNote} is predicted by chain adjacency — ` +
    `it follows naturally from the highest currently observed stage in the kill chain.`
  );
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generate ranked, uncertainty-quantified predictions about likely next
 * attack stages given the current set of correlated incidents and detections.
 *
 * The function is pure and deterministic: the same inputs always produce the
 * same ordered output.
 *
 * @param incidents - Correlated incidents from the AttackCorrelationEngine.
 * @param detections - Raw detections from the DetectionEngine / EventHub.
 * @returns Predictions sorted by descending confidence (highest confidence first).
 */
export function generatePredictions(
  incidents: CorrelatedIncident[],
  detections: Detection[]
): StagePrediction[] {
  // No telemetry — no meaningful predictions
  if (incidents.length === 0 && detections.length === 0) {
    return [];
  }

  const observedRules = collectObservedRules(incidents, detections);

  // If we have detections but none mapped to known rules, nothing to predict
  if (observedRules.size === 0) {
    return [];
  }

  // Accumulate evidential support per predicted stage
  const stageEvidence = new Map<
    AttackStage,
    { refs: string[]; supportingRules: DetectionRuleId[]; matchCount: number }
  >();

  for (const [ruleId, refs] of observedRules.entries()) {
    const mapping = RULE_STAGE_MAP[ruleId];
    if (!mapping) continue;

    for (const predictedStage of mapping.predictedStages) {
      const existing = stageEvidence.get(predictedStage) ?? {
        refs: [],
        supportingRules: [],
        matchCount: 0,
      };

      // Merge evidence refs, avoiding duplicates
      for (const ref of refs) {
        if (!existing.refs.includes(ref)) existing.refs.push(ref);
      }
      if (!existing.supportingRules.includes(ruleId)) {
        existing.supportingRules.push(ruleId);
      }
      existing.matchCount += 1;

      stageEvidence.set(predictedStage, existing);
    }
  }

  // Chain-adjacency fallback: predict the stage immediately following the
  // highest observed stage, if it has not already been covered by rule matches.
  const highestIdx = highestObservedChainIndex(observedRules);
  const nextChainStage: AttackStage | undefined =
    highestIdx >= 0 && highestIdx + 1 < ATTACK_CHAIN.length
      ? ATTACK_CHAIN[highestIdx + 1]
      : undefined;

  if (nextChainStage && !stageEvidence.has(nextChainStage)) {
    stageEvidence.set(nextChainStage, {
      refs: [],
      supportingRules: [],
      matchCount: 0,
    });
  }

  // Assemble final StagePrediction objects
  const predictions: StagePrediction[] = [];

  for (const [stage, evidence] of stageEvidence.entries()) {
    const isChainAdjacent = stage === nextChainStage;
    const confidence = scoreConfidence(evidence.matchCount, isChainAdjacent);
    const uncertainty = deriveUncertainty(confidence);
    const explanation = buildExplanation(
      stage,
      evidence.refs,
      evidence.supportingRules,
      evidence.matchCount
    );

    predictions.push({
      stage,
      mitreId: STAGE_MITRE_IDS[stage],
      confidence,
      uncertainty,
      evidenceRefs: [...evidence.refs, ...evidence.supportingRules],
      explanation,
      isPredicted: true,
      basis: evidence.matchCount > 0 ? "RULE_CORRELATION" : "BEHAVIORAL_PATTERN",
    });
  }

  // Sort by descending confidence, then alphabetically by stage for stability
  predictions.sort((a, b) => {
    const diff = b.confidence - a.confidence;
    if (diff !== 0) return diff;
    return a.stage.localeCompare(b.stage);
  });

  return predictions;
}
