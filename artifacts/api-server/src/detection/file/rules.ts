/**
 * Deterministic, explainable detection rules for file & persistence telemetry.
 *
 * Every rule is a pure function `(event) => RuleMatch | null` over a
 * FileViewEvent — a real artifact found by the engine's read-only scanner
 * (path, real SHA-256 hash, size, mtime, scanner category, running flag).
 * Rules map the deterministic scanner categories to engine detections so that
 * file findings gain the same dedup / correlation / lifecycle as process
 * detections, and so a payload that is *executing* links back to its process.
 */

import { categoryTokens, hasCategoryToken, PAYLOAD_ESCALATION_TOKENS } from "./lists";
import type {
  DetectionEvidence,
  DetectionEvidenceSource,
  DetectionSeverity,
  FileViewEvent,
  RuleMatch,
} from "../types";

const ev = (
  key: string,
  description: string,
  source: DetectionEvidenceSource,
  detail?: string,
): DetectionEvidence => ({ key, description, source, ...(detail ? { detail } : {}) });

const SEVERITY_ORDER: DetectionSeverity[] = ["low", "medium", "high", "critical"];

function escalate(severity: DetectionSeverity, steps: number): DetectionSeverity {
  const idx = SEVERITY_ORDER.indexOf(severity);
  const next = Math.min(Math.max(idx + steps, 0), SEVERITY_ORDER.length - 1);
  return SEVERITY_ORDER[next];
}

function fileEvidence(event: FileViewEvent): DetectionEvidence[] {
  const out: DetectionEvidence[] = [
    ev("file_path", `Suspicious artifact on disk`, "file", event.file_path),
  ];
  if (event.file_hash && event.file_hash.length > 0) {
    out.push(ev("file_hash", `SHA-256 of the artifact`, "file", event.file_hash));
  }
  if (event.file_size !== undefined && event.file_size !== null) {
    out.push(ev("file_size", `Artifact size ${event.file_size} bytes`, "file"));
  }
  return out;
}

/**
 * FILE-001: An executable/script sits in a Windows Startup folder — a classic
 * persistence mechanism. If it is also software that can dump credentials or
 * run encoded/obfuscated content, it is elevated to critical.
 */
const startupPersistence: (event: FileViewEvent) => RuleMatch | null = (event) => {
  if (!hasCategoryToken(event.category, "startup-file")) return null;

  const tokens = categoryTokens(event.category);
  const escalation = tokens.some((t) => PAYLOAD_ESCALATION_TOKENS.has(t));
  const severity: DetectionSeverity = escalation ? "critical" : "high";

  return {
    rule_id: "FILE-001-STARTUP-PERSISTENCE",
    rule_name: "Persistent payload in a Windows Startup folder",
    title: `Persistent payload registered in a Startup folder: ${event.file_name}`,
    explanation: `${event.file_path} is an executable/script placed in a Windows Startup folder (${event.className || "persistence"}), which runs automatically at every login.${escalation ? " It also carries credential/obfuscation payload indicators, making it a strong persistence-and-execution beacon." : ""}`,
    recommended_action:
      "Remove the Startup entry, quarantine the artifact (SHA-256 recorded) and check the machine for sibling persistence (scheduled tasks, Run keys, services).",
    evidence: [
      ...fileEvidence(event),
      ev("startup_folder", `Artifact is resident in a Startup folder`, "path", event.file_path),
      ...(escalation
        ? [ev("payload_token", `Artifact category includes payload markers: ${tokens.join(", ")}`, "file")]
        : []),
    ],
    baseSeverity: severity,
    baseConfidence: escalation ? 0.8 : 0.7,
  };
};

/**
 * FILE-002: Encoding/obfuscation or download primitives inside a script on
 * disk. Download cradles and encoded PowerShell are how staged payloads land
 * and execute.
 */
const encodedDownloader: (event: FileViewEvent) => RuleMatch | null = (event) => {
  const hasEncoded = hasCategoryToken(event.category, "encoded-powershell");
  const hasCradle = hasCategoryToken(event.category, "download-cradle");
  const hasObfuscated = hasCategoryToken(event.category, "obfuscated-string");
  if (!hasEncoded && !hasCradle && !hasObfuscated) return null;

  const severity: DetectionSeverity = hasEncoded || hasCradle ? "high" : "medium";
  const strength = (hasEncoded ? 1 : 0) + (hasCradle ? 1 : 0) + (hasObfuscated ? 1 : 0);

  return {
    rule_id: "FILE-002-ENCODED-DOWNLOADER",
    rule_name: "Encoded or downloader script on disk",
    title: `Download/obfuscation script found on disk: ${event.file_name}`,
    explanation: `${event.file_path} contains ${hasEncoded ? "encoded PowerShell" : ""}${hasCradle ? (hasEncoded ? " and " : "") + "download-cradle primitives" : ""}${hasObfuscated ? (hasEncoded || hasCradle ? " and " : "") + "obfuscated content" : ""}. Scripts that fetch and decode remote payloads are how droppers stage the next stage.`,
    recommended_action:
      "Open the script (never execute it), extract the download target and block it. Preserve the SHA-256 and review recent executions of this path.",
    evidence: [
      ...fileEvidence(event),
      ev("script_indicators", `Artifact category: ${event.category || "unknown"}`, "file"),
    ],
    baseSeverity: severity,
    baseConfidence: Math.min(0.8, 0.6 + (strength - 1) * 0.05),
  };
};

/**
 * FILE-003: A script/artifact references credential-access primitives (LSASS,
 * mimikatz, procdump ...). Credential dumping artifacts are uniformly critical.
 */
const credentialAccessArtifact: (event: FileViewEvent) => RuleMatch | null = (event) => {
  if (!hasCategoryToken(event.category, "lsass-access")) return null;

  return {
    rule_id: "FILE-003-CREDENTIAL-ACCESS-ARTIFACT",
    rule_name: "Credential-access artifact on disk",
    title: `Credential-access script on disk: ${event.file_name}`,
    explanation: `${event.file_path} references credential-dumping primitives (lsass, mimikatz, procdump/comsvcs ...). Credential-access tooling on disk is a high-priority containment trigger regardless of whether it is currently running.`,
    recommended_action:
      "Quarantine the artifact immediately, reset affected account credentials, and assume LSASS may have been touched — hunt for live credential-access processes (Rule PROC / FILE-006).",
    evidence: [
      ...fileEvidence(event),
      ev("credential_token", `Artifact category: ${event.category || "unknown"}`, "file"),
    ],
    baseSeverity: "critical",
    baseConfidence: 0.8,
  };
};

/**
 * FILE-004: A script schedules tasks — a persistence mechanism independent of
 * the Startup folder (schtasks / Register-ScheduledTask).
 */
const scheduledTaskPersistence: (event: FileViewEvent) => RuleMatch | null = (event) => {
  if (!hasCategoryToken(event.category, "scheduled-task")) return null;

  return {
    rule_id: "FILE-004-SCHEDULED-TASK-PERSISTENCE",
    rule_name: "Scheduled-task persistence script",
    title: `Scheduled-task persistence script on disk: ${event.file_name}`,
    explanation: `${event.file_path} uses scheduled-task primitives (schtasks / Register-ScheduledTask). Scheduled tasks are a common way malware survives reboots and re-launches payloads at defined times.`,
    recommended_action:
      "List scheduled tasks (`schtasks /query`) for entries created in the same window and remove the script + associated task. Preserve the SHA-256 for correlation.",
    evidence: [
      ...fileEvidence(event),
      ev("scheduled_task", `Artifact category: ${event.category || "unknown"}`, "file"),
    ],
    baseSeverity: "medium",
    baseConfidence: 0.6,
  };
};

/**
 * FILE-005: The filename is designed to look like a benign document or known
 * file while actually being an executable/script (double extension, invoice
 * patterns ...) — the classic disguised-payload social-engineering trick.
 */
const disguisedExecutable: (event: FileViewEvent) => RuleMatch | null = (event) => {
  if (!hasCategoryToken(event.category, "misleading-name")) return null;

  return {
    rule_id: "FILE-005-DISGUISED-EXECUTABLE",
    rule_name: "Disguised executable file",
    title: `Disguised executable found on disk: ${event.file_name}`,
    explanation: `${event.file_name} is named to appear as a document or well-known file while actually being an executable/script. Disguised filenames are a hallmark of emailed/attachment-borne attacks.`,
    recommended_action:
      "Never open the file. Quarantine it and check for sibling files with matching naming patterns; correlate with recent process starts (Rule PROC-001/004).",
    evidence: [
      ...fileEvidence(event),
      ev("misleading_name", `Filename masquerades as a benign document`, "file", event.file_name),
    ],
    baseSeverity: "medium",
    baseConfidence: 0.6,
  };
};

/**
 * FILE-006: A file that tripped a heuristic is currently executing (it maps to
 * a running process). Being active elevates the artifact one severity step —
 * this is the direct file→process correlation the Phase-4 surface is built on.
 */
const runningSuspect: (event: FileViewEvent) => RuleMatch | null = (event) => {
  if (event.is_running !== true) return null;

  const baseSeverity: DetectionSeverity =
    event.finding_severity && SEVERITY_ORDER.includes(event.finding_severity as DetectionSeverity)
      ? (event.finding_severity as DetectionSeverity)
      : "medium";
  const severity = escalate(baseSeverity, 1);
  const pid = typeof event.pid === "number" && event.pid > 0 ? event.pid : null;

  return {
    rule_id: "FILE-006-RUNNING-SUSPECT",
    rule_name: "Suspicious file currently executing",
    title: `Suspicious artifact is running: ${event.file_name}`,
    explanation: `${event.file_path} is flagged by the file scanner (${event.category || "suspicious"}) and is currently executing${pid ? ` as pid ${pid}` : ""}. A heuristic-flagged artifact that has already started means the threat window is open — execution elevates the risk one level.`,
    recommended_action:
      "Confirm which process owns the artifact (see pid evidence), inspect its command line, network connections (Rule NET-*) and, if justified, terminate and isolate.",
    evidence: [
      ...fileEvidence(event),
      ev("running", `Artifact is mapped to a running process${pid ? ` (pid ${pid})` : ""}`, "file"),
    ],
    baseSeverity: severity,
    baseConfidence: 0.65,
  };
};

/**
 * FILE-007: A script performs system discovery/reconnaissance (whoami, net
 * user, systeminfo, ipconfig /all ...). Individually low-signal, but a strong
 * context signal when it correlates with other rules for the same host.
 */
const reconScript: (event: FileViewEvent) => RuleMatch | null = (event) => {
  if (!hasCategoryToken(event.category, "recon-commands")) return null;

  return {
    rule_id: "FILE-007-RECON-SCRIPT",
    rule_name: "Reconnaissance script on disk",
    title: `Reconnaissance script found on disk: ${event.file_name}`,
    explanation: `${event.file_path} executes system-discovery commands (whoami, net user, systeminfo, ipconfig /all ...). Recon scripts are the first stage of lateral movement / privilege escalation and are rarely used by legitimate scheduled jobs.`,
    recommended_action:
      "Review what the script collects and where it sends the output. Correlate with network exfil patterns (Rule NET-001/007) before deciding containment.",
    evidence: [
      ...fileEvidence(event),
      ev("recon", `Artifact category: ${event.category || "unknown"}`, "file"),
    ],
    baseSeverity: "low",
    baseConfidence: 0.5,
  };
};

/** The ordered, stable set of FILE rules evaluated for every file finding. */
export const FILE_RULES: Array<(event: FileViewEvent) => RuleMatch | null> = [
  startupPersistence,
  encodedDownloader,
  credentialAccessArtifact,
  scheduledTaskPersistence,
  disguisedExecutable,
  runningSuspect,
  reconScript,
];

export function evaluateFileRules(event: FileViewEvent): RuleMatch[] {
  const matches: RuleMatch[] = [];
  for (const rule of FILE_RULES) {
    try {
      const match = rule(event);
      if (match) matches.push(match);
    } catch (error) {
      // A rule must never take down the ingestion pipeline.
      void error;
    }
  }
  return matches;
}

export type RuleCatalogEntry = {
  rule_id: string;
  rule_name: string;
  description: string;
};

/** Stable catalog of the active FILE rules, exposed via the API. */
export const FILE_RULE_CATALOG: RuleCatalogEntry[] = [
  {
    rule_id: "FILE-001-STARTUP-PERSISTENCE",
    rule_name: "Persistent payload in a Windows Startup folder",
    description:
      "An executable/script sits in a Startup folder (auto-run at logon); elevated to critical when it also carries credential/obfuscation payload markers.",
  },
  {
    rule_id: "FILE-002-ENCODED-DOWNLOADER",
    rule_name: "Encoded or downloader script on disk",
    description:
      "A script on disk contains encoded PowerShell, download-cradle or obfuscated-content primitives.",
  },
  {
    rule_id: "FILE-003-CREDENTIAL-ACCESS-ARTIFACT",
    rule_name: "Credential-access artifact on disk",
    description:
      "A script/artifact on disk references credential-dumping primitives (lsass, mimikatz, procdump/comsvcs).",
  },
  {
    rule_id: "FILE-004-SCHEDULED-TASK-PERSISTENCE",
    rule_name: "Scheduled-task persistence script",
    description:
      "A script on disk schedules tasks (schtasks / Register-ScheduledTask) — a persistence mechanism outside the Startup folder.",
  },
  {
    rule_id: "FILE-005-DISGUISED-EXECUTABLE",
    rule_name: "Disguised executable file",
    description:
      "A file's name is designed to appear as a document or known file while actually being an executable/script.",
  },
  {
    rule_id: "FILE-006-RUNNING-SUSPECT",
    rule_name: "Suspicious file currently executing",
    description:
      "A file that tripped a scanner heuristic is mapped to a currently running process — execution elevates the artifact one severity step.",
  },
  {
    rule_id: "FILE-007-RECON-SCRIPT",
    rule_name: "Reconnaissance script on disk",
    description:
      "A script on disk performs system-discovery/reconnaissance commands (whoami, net user, systeminfo, ipconfig /all).",
  },
];