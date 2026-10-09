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
  | "CREDENTIAL_ACCESS"
  | "LATERAL_MOVEMENT"
  | "COLLECTION"
  | "EXFILTRATION"
  | "IMPACT"
  | "INSUFFICIENT_EVIDENCE";

/** The information basis used to derive a particular prediction. */
export type PredictionBasis =
  | "RULE_CORRELATION"
  | "TEMPORAL_PATTERN"
  | "BEHAVIORAL_PATTERN"
  | "EVIDENCE_TRANSITION";

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
  /** Rationale for the transition based on observed evidence. */
  rationale: string;
  /** Always true — predictions are never claimed as confirmed observations. */
  isPredicted: true;
  /** Visual stage status label to keep observed, inferred, and predicted distinct. */
  stageClassification: "PREDICTED";
  /** The reasoning basis used to derive this prediction. */
  basis: PredictionBasis;
};

// ---------------------------------------------------------------------------
// Internal model definitions
// ---------------------------------------------------------------------------

/** Optional MITRE technique IDs for each named stage. */
const STAGE_MITRE_IDS: Partial<Record<AttackStage, string>> = {
  INITIAL_ACCESS: "TA0001",
  EXECUTION: "TA0002",
  PERSISTENCE: "TA0003",
  PRIVILEGE_ESCALATION: "TA0004",
  DEFENSE_EVASION: "TA0005",
  CREDENTIAL_ACCESS: "TA0006",
  LATERAL_MOVEMENT: "TA0008",
  COLLECTION: "TA0009",
  EXFILTRATION: "TA0010",
  IMPACT: "TA0040",
};

/**
 * Per-rule mapping: which stage the rule indicates is currently underway, and
 * which subsequent stages it predicts based on documented transition logic.
 */
type RuleMapping = {
  currentStage: AttackStage;
  predictedStages: AttackStage[];
  rationale: string;
};

const RULE_STAGE_MAP: Partial<Record<DetectionRuleId, RuleMapping>> = {
  "NET-008-REVERSE-SHELL": {
    currentStage: "INITIAL_ACCESS",
    predictedStages: ["EXECUTION", "PERSISTENCE"],
    rationale: "Established reverse shell socket provides direct interactive execution host access.",
  },
  "NET-009-DATA-EXFILTRATION": {
    currentStage: "EXFILTRATION",
    predictedStages: ["IMPACT"],
    rationale: "Active data transfer socket indicates potential data loss or operational impact.",
  },
  "PROC-001-SUSPICIOUS-PARENT-CHILD": {
    currentStage: "EXECUTION",
    predictedStages: ["PERSISTENCE", "PRIVILEGE_ESCALATION"],
    rationale: "Macro/browser process spawn of script interpreter precedes persistence or privilege escalation attempts.",
  },
  "PROC-002-ENCODED-COMMAND-LINE": {
    currentStage: "EXECUTION",
    predictedStages: ["DEFENSE_EVASION", "PERSISTENCE"],
    rationale: "Obfuscated command line indicates active defense evasion while staging secondary payload.",
  },
  "PROC-003-INTERPRETER-UNUSUAL-SCRIPT": {
    currentStage: "EXECUTION",
    predictedStages: ["PERSISTENCE", "COLLECTION"],
    rationale: "Script execution from user-writable directory stages payload or system collection commands.",
  },
  "PROC-004-UNUSUAL-LOCATION": {
    currentStage: "EXECUTION",
    predictedStages: ["DEFENSE_EVASION", "PERSISTENCE"],
    rationale: "Execution from dropped path obscures legitimate binary location and attempts persistence.",
  },
  "PROC-005-INTERPRETER-CHAIN": {
    currentStage: "EXECUTION",
    predictedStages: ["PRIVILEGE_ESCALATION", "LATERAL_MOVEMENT"],
    rationale: "Multi-hop interpreter chain indicates multi-stage execution leading to privilege escalation or lateral movement.",
  },
  "PROC-006-DOWNLOAD-EXECUTE": {
    currentStage: "EXECUTION",
    predictedStages: ["PERSISTENCE", "EXFILTRATION"],
    rationale: "Download cradle staging fetches secondary payload or C2 agent.",
  },
  "PROC-007-LOLBIN-EXECUTION": {
    currentStage: "DEFENSE_EVASION",
    predictedStages: ["PERSISTENCE", "PRIVILEGE_ESCALATION"],
    rationale: "LOLBin execution bypasses application controls to register persistence or escalate privileges.",
  },
  "NET-001-USER-WRITABLE-OUTBOUND": {
    currentStage: "EXECUTION",
    predictedStages: ["PERSISTENCE", "EXFILTRATION"],
    rationale: "Dropped binary connecting to external IP indicates C2 beacon or data exfiltration staging.",
  },
  "FILE-001-STARTUP-PERSISTENCE": {
    currentStage: "PERSISTENCE",
    predictedStages: ["PRIVILEGE_ESCALATION", "EXECUTION"],
    rationale: "Startup folder registry entry establishes auto-run persistence across reboots.",
  },
  "FILE-003-CREDENTIAL-ACCESS-ARTIFACT": {
    currentStage: "CREDENTIAL_ACCESS",
    predictedStages: ["PRIVILEGE_ESCALATION", "LATERAL_MOVEMENT"],
    rationale: "Credential dumping artifact provides user/hash credentials for privilege escalation or lateral movement.",
  },
  "NET-006-INTERPRETER-REMOTE-CONNECTION": {
    currentStage: "EXECUTION",
    predictedStages: ["LATERAL_MOVEMENT", "EXFILTRATION"],
    rationale: "Script interpreter maintaining active socket connection enables remote lateral movement or exfiltration.",
  },
};

// ---------------------------------------------------------------------------
// Confidence / uncertainty helpers
// ---------------------------------------------------------------------------

function scoreConfidence(matchCount: number, distinctRulesCount: number): number {
  if (matchCount >= 3 || distinctRulesCount >= 2) return 0.85;
  if (matchCount === 2) return 0.70;
  if (matchCount === 1) return 0.55;
  return 0.30;
}

function deriveUncertainty(confidence: number): PredictionUncertainty {
  if (confidence >= 0.75) return "LOW";
  if (confidence >= 0.50) return "MEDIUM";
  return "HIGH";
}

// ---------------------------------------------------------------------------
// Core prediction logic
// ---------------------------------------------------------------------------

function collectObservedRules(
  incidents: CorrelatedIncident[],
  detections: Detection[]
): Map<DetectionRuleId, string[]> {
  const observed = new Map<DetectionRuleId, string[]>();

  for (const inc of incidents as any[]) {
    const timeline = Array.isArray(inc.timeline)
      ? inc.timeline
      : Array.isArray(inc.correlatedTrace?.timeline)
      ? inc.correlatedTrace.timeline
      : [];
    for (const event of timeline) {
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

  for (const det of detections) {
    const refs = observed.get(det.rule_id) ?? [];
    if (!refs.includes(det.id)) refs.push(det.id);
    observed.set(det.rule_id, refs);
  }

  return observed;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generate ranked, uncertainty-quantified predictions about likely next
 * attack stages given the current set of correlated incidents and detections.
 *
 * Requires explicit evidence support: predictions are only produced for stages
 * supported by observed evidence and documented transition logic.
 */
export function generatePredictions(
  incidents: CorrelatedIncident[],
  detections: Detection[]
): StagePrediction[] {
  // No telemetry or detections — return INSUFFICIENT_EVIDENCE
  if (incidents.length === 0 && detections.length === 0) {
    return [
      {
        stage: "INSUFFICIENT_EVIDENCE",
        confidence: 0,
        uncertainty: "HIGH",
        evidenceRefs: [],
        explanation: "Insufficient telemetry evidence to formulate forward attack-stage predictions.",
        rationale: "No active threat detections or incident timelines observed.",
        isPredicted: true,
        stageClassification: "PREDICTED",
        basis: "EVIDENCE_TRANSITION",
      },
    ];
  }

  const observedRules = collectObservedRules(incidents, detections);

  if (observedRules.size === 0) {
    return [
      {
        stage: "INSUFFICIENT_EVIDENCE",
        confidence: 0,
        uncertainty: "HIGH",
        evidenceRefs: [],
        explanation: "Observed detections do not map to documented attack transition rules.",
        rationale: "Telemetry present but no rule matches support forward stage transition.",
        isPredicted: true,
        stageClassification: "PREDICTED",
        basis: "EVIDENCE_TRANSITION",
      },
    ];
  }

  const stageEvidence = new Map<
    AttackStage,
    { refs: string[]; supportingRules: DetectionRuleId[]; matchCount: number; rationales: string[] }
  >();

  for (const [ruleId, refs] of observedRules.entries()) {
    const mapping = RULE_STAGE_MAP[ruleId];
    if (!mapping) continue;

    for (const predictedStage of mapping.predictedStages) {
      const existing = stageEvidence.get(predictedStage) ?? {
        refs: [],
        supportingRules: [],
        matchCount: 0,
        rationales: [],
      };

      for (const ref of refs) {
        if (!existing.refs.includes(ref)) existing.refs.push(ref);
      }
      if (!existing.supportingRules.includes(ruleId)) {
        existing.supportingRules.push(ruleId);
      }
      if (!existing.rationales.includes(mapping.rationale)) {
        existing.rationales.push(mapping.rationale);
      }
      existing.matchCount += 1;

      stageEvidence.set(predictedStage, existing);
    }
  }

  const predictions: StagePrediction[] = [];

  for (const [stage, evidence] of stageEvidence.entries()) {
    const confidence = scoreConfidence(evidence.matchCount, evidence.supportingRules.length);
    const uncertainty = deriveUncertainty(confidence);
    const mitreNote = STAGE_MITRE_IDS[stage] ? ` (MITRE ${STAGE_MITRE_IDS[stage]})` : "";

    const explanation =
      `Predicted attack stage ${stage}${mitreNote} supported by ${evidence.supportingRules.length} ` +
      `observed detection rule(s): ${evidence.supportingRules.join(", ")}.`;

    const rationale = evidence.rationales.join("; ");

    predictions.push({
      stage,
      mitreId: STAGE_MITRE_IDS[stage],
      confidence,
      uncertainty,
      evidenceRefs: [...evidence.refs, ...evidence.supportingRules],
      explanation,
      rationale,
      isPredicted: true,
      stageClassification: "PREDICTED",
      basis: evidence.supportingRules.length >= 2 ? "RULE_CORRELATION" : "EVIDENCE_TRANSITION",
    });
  }

  // Sort by descending confidence, then by stage name for determinism
  predictions.sort((a, b) => {
    const diff = b.confidence - a.confidence;
    if (diff !== 0) return diff;
    return a.stage.localeCompare(b.stage);
  });

  return predictions;
}
