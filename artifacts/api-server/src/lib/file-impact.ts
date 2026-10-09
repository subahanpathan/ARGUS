/**
 * ARGUS File Impact & Exposure Analysis Library.
 *
 * Provides normalized sensitive data classification, impact classification,
 * behavioral encryption detection, and explainable damage score calculation.
 */

import type { FileActivityEvent } from "./event-hub";

export type SensitiveCategory =
  | "Documents"
  | "Credentials"
  | "Financial"
  | "Personal"
  | "Source code"
  | "Configuration"
  | "System files"
  | "Other";

export type FileImpactState =
  | "ACCESSED"
  | "CREATED"
  | "MODIFIED"
  | "RENAMED"
  | "DELETED"
  | "TRANSFORMED"
  | "ENCRYPTION_SUSPECTED"
  | "CORRUPTION_SUSPECTED"
  | "UNKNOWN";

export type ImpactCounts = {
  created: number;
  modified: number;
  renamed: number;
  deleted: number;
  accessed: number;
  suspiciouslyTransformed: number;
  total?: number;
};

export type AffectedFileRecord = {
  eventId: string;
  timestamp: string;
  operation: string;
  filePath: string;
  oldFilePath?: string | null;
  classification: SensitiveCategory;
  impactState: FileImpactState;
  processName: string;
  pid?: number | null;
  observationStatus: "OBSERVED" | "CORRELATED" | "INFERRED" | "UNKNOWN";
  evidence: string;
  hashStatus: "HASH_OBSERVED" | "HASH_NOT_AVAILABLE";
  hash?: string | null;
};

export type ImpactAssessment = {
  affectedFilesCount: number;
  counts: ImpactCounts;
  potentialSensitiveExposureCount: number;
  suspiciousTransformationDetected: boolean;
  encryptionSuspected: boolean;
  evidenceConfidence: "HIGH" | "MEDIUM" | "LOW" | "INCOMPLETE";
  damageScore: number | null;
  damageScoreExplanation: string;
  overallRisk?: string;
  hasExfiltrationRisk?: boolean;
  hasDestructionRisk?: boolean;
  hasPersistenceRisk?: boolean;
  sensitiveCategories?: string[];
  summary?: string;
};

const RANSOM_EXTENSIONS = new Set([
  ".locked", ".crypto", ".enc", ".crypted", ".ransom", ".vault",
  ".zero", ".lock", ".wnry", ".ryuk", ".locky", ".mamba"
]);

/**
 * Classifies a file into a sensitive data category using filename/extension metadata only.
 */
export function classifySensitiveCategory(filePath: string): SensitiveCategory {
  const norm = filePath.toLowerCase();
  const base = norm.split(/[/\\]/).pop() || "";
  const ext = base.includes(".") ? "." + base.split(".").pop() : "";

  if (
    base.includes("id_rsa") || base.includes("credentials") || base.includes("shadow") ||
    base.includes("sam") || base.includes("passwd") || ext === ".kdbx" || ext === ".pem" ||
    ext === ".key" || base === ".env" || base.includes("secret")
  ) {
    return "Credentials";
  }

  if (
    base.includes("tax") || base.includes("invoice") || base.includes("bank") ||
    base.includes("payroll") || base.includes("financial") || base.includes("ledger") ||
    base.includes("budget") || base.includes("strategy") || base.includes("forecast")
  ) {
    return "Financial";
  }

  if (
    base.includes("passport") || base.includes("ssn") || base.includes("resume") ||
    base.includes("medical") || base.includes("photo")
  ) {
    return "Personal";
  }

  if (
    [".docx", ".doc", ".pdf", ".xlsx", ".xls", ".pptx", ".txt", ".rtf", ".odt", ".csv"].includes(ext)
  ) {
    return "Documents";
  }

  if (
    [".ts", ".js", ".py", ".c", ".cpp", ".rs", ".go", ".java", ".cs", ".html", ".css", ".json"].includes(ext)
  ) {
    return "Source code";
  }

  if ([".conf", ".yaml", ".yml", ".xml", ".ini", ".config", ".toml"].includes(ext)) {
    return "Configuration";
  }

  if ([".dll", ".exe", ".sys", ".drv", ".ocx"].includes(ext)) {
    return "System files";
  }

  return "Other";
}

/**
 * Classifies the impact state of a single file event.
 */
export function classifyImpactState(
  event: FileActivityEvent,
  processContext?: { suspicious?: boolean; rapidChanges?: boolean }
): FileImpactState {
  const normPath = event.filePath.toLowerCase();
  const ext = event.extension
    ? event.extension.toLowerCase()
    : normPath.includes(".")
    ? "." + normPath.split(".").pop()
    : "";

  const oldPath = (event.oldFilePath || "").toLowerCase();
  const oldExt = oldPath.includes(".") ? "." + oldPath.split(".").pop() : "";

  // Check for behavioral ransomware extension change
  if (RANSOM_EXTENSIONS.has(ext) || RANSOM_EXTENSIONS.has(oldExt)) {
    return "ENCRYPTION_SUSPECTED";
  }

  if (processContext?.rapidChanges && processContext?.suspicious && event.operation === "MODIFY") {
    return "ENCRYPTION_SUSPECTED";
  }

  switch (event.operation) {
    case "CREATE":
      return "CREATED";
    case "MODIFY":
      return "MODIFIED";
    case "DELETE":
      return "DELETED";
    case "RENAME":
      return "RENAMED";
    case "ACCESS":
      return "ACCESSED";
    default:
      return "UNKNOWN";
  }
}

/**
 * Computes an explainable impact assessment from a list of correlated file events
 * and network context.
 */
export function evaluateImpactAssessment(
  events: FileActivityEvent[],
  hasOutboundSockets: boolean
): ImpactAssessment {
  if (!events || events.length === 0) {
    return {
      affectedFilesCount: 0,
      counts: { created: 0, modified: 0, renamed: 0, deleted: 0, accessed: 0, suspiciouslyTransformed: 0 },
      potentialSensitiveExposureCount: 0,
      suspiciousTransformationDetected: false,
      encryptionSuspected: false,
      evidenceConfidence: "INCOMPLETE",
      damageScore: null,
      damageScoreExplanation: "No file activity observed for this incident.",
    };
  }

  const counts: ImpactCounts = {
    created: 0,
    modified: 0,
    renamed: 0,
    deleted: 0,
    accessed: 0,
    suspiciouslyTransformed: 0,
  };

  let sensitiveExposureCount = 0;
  let encryptionSuspected = false;

  // Track modification velocity per process
  const modifyTimes: number[] = [];

  for (const e of events) {
    const impact = classifyImpactState(e);
    const cat = classifySensitiveCategory(e.filePath);

    if (impact === "ENCRYPTION_SUSPECTED") {
      encryptionSuspected = true;
      counts.suspiciouslyTransformed++;
    }

    switch (e.operation) {
      case "CREATE":
        counts.created++;
        break;
      case "MODIFY":
        counts.modified++;
        modifyTimes.push(new Date(e.timestamp).getTime());
        break;
      case "RENAME":
        counts.renamed++;
        break;
      case "DELETE":
        counts.deleted++;
        break;
      case "ACCESS":
        counts.accessed++;
        break;
    }

    // Identify potential sensitive file exposure if sensitive and accessed/modified
    if (["Credentials", "Financial", "Personal", "Documents"].includes(cat)) {
      if (e.operation === "ACCESS" || e.operation === "MODIFY" || e.operation === "RENAME") {
        sensitiveExposureCount++;
      }
    }
  }

  // Check rapid modification burst (e.g. >5 files modified within 10s)
  if (modifyTimes.length >= 6) {
    modifyTimes.sort((a, b) => a - b);
    const span = (modifyTimes[modifyTimes.length - 1] - modifyTimes[0]) / 1000;
    if (span < 15) {
      encryptionSuspected = true;
      counts.suspiciouslyTransformed += Math.floor(modifyTimes.length / 2);
    }
  }

  const totalAffected = events.length;

  // Deterministic, explainable damage score (0 - 100)
  let baseScore = 0;
  const reasons: string[] = [];

  if (totalAffected > 0) {
    baseScore += Math.min(30, totalAffected * 3);
    reasons.push(`${totalAffected} file(s) affected (+${Math.min(30, totalAffected * 3)})`);
  }

  if (counts.deleted > 0) {
    baseScore += Math.min(25, counts.deleted * 8);
    reasons.push(`${counts.deleted} file deletion(s) observed (+${Math.min(25, counts.deleted * 8)})`);
  }

  if (sensitiveExposureCount > 0) {
    baseScore += Math.min(25, sensitiveExposureCount * 7);
    reasons.push(`${sensitiveExposureCount} sensitive file(s) involved (+${Math.min(25, sensitiveExposureCount * 7)})`);
  }

  if (encryptionSuspected) {
    baseScore += 20;
    reasons.push("Suspicious file transformation / rapid modification detected (+20)");
  }

  if (sensitiveExposureCount > 0 && hasOutboundSockets) {
    baseScore += 15;
    reasons.push("Potential exfiltration path: sensitive file access linked to outbound socket (+15)");
  }

  const finalScore = Math.min(100, baseScore);
  const confidence = totalAffected >= 3 ? "HIGH" : totalAffected > 0 ? "MEDIUM" : "INCOMPLETE";

  return {
    affectedFilesCount: totalAffected,
    counts,
    potentialSensitiveExposureCount: sensitiveExposureCount,
    suspiciousTransformationDetected: counts.suspiciouslyTransformed > 0,
    encryptionSuspected,
    evidenceConfidence: confidence,
    damageScore: finalScore,
    damageScoreExplanation: reasons.length > 0 ? reasons.join(" · ") : "Low impact file baseline.",
  };
}
