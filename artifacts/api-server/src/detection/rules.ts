/**
 * Deterministic, explainable detection rules for Windows process telemetry.
 *
 * Every rule is a pure function `(event) => RuleMatch | null`. Rules never
 * fabricate data: they only reason over the fields present on the normalized
 * SecurityEvent (process name, executable path, command line, parent info).
 * Each rule returns explicit evidence and a human explanation so any detection
 * can be audited end-to-end.
 */

import {
  containsUserWritableDir,
  isLolBin,
  isProductivityApp,
  isScriptInterpreter,
  isUserWritableExecutionPath,
  snippet,
  SCRIPT_EXTENSION_RE,
} from "./lists";
import type { DetectionEvidenceSource, RuleMatch, SecurityEvent } from "./types";

type RuleFunction = (event: SecurityEvent) => RuleMatch | null;

const cmd = (event: SecurityEvent): string =>
  (event.command_line || "").trim().toLowerCase();

const hasCommandLine = (event: SecurityEvent): boolean =>
  Boolean(event.command_line && event.command_line.trim().length > 0);

const evidence = (
  key: string,
  description: string,
  source: DetectionEvidenceSource = "process",
  detail?: string,
) => ({ key, description, source, ...(detail ? { detail } : {}) });

/**
 * PROC-001: A productivity or user-facing application (browser, Office, mail)
 * directly spawned a script interpreter or a living-off-the-land binary. This
 * parent/child pairing is a hall-mark of macro/document-based attacks.
 */
const suspiciousParentChild: RuleFunction = (event) => {
  // Spawn-relationship rules only apply to fresh spawns; snapshot telemetry
  // cannot tell whether the parent relationship is the original spawn.
  if (event.origin === "snapshot") return null;

  const child = event.process_name;
  const parent = event.parent_process_name;

  if (!parent || !child) return null;

  const interpreterChild = isScriptInterpreter(child);
  const lolbinChild = isLolBin(child);

  const productivityParent = isProductivityApp(parent);
  const interpreterParent = isScriptInterpreter(parent);

  if (!(productivityParent || interpreterParent)) return null;
  if (!(interpreterChild || lolbinChild)) return null;

  const isPowershellChild = /^powershell(_ise)?\.exe$|^pwsh\.exe$/i.test(child);
  const parentSpawnedInterpreter = productivityParent && interpreterChild;
  const interpreterSpawnedLolbin = interpreterParent && lolbinChild;
  const productivitySpawnedLolbin = productivityParent && lolbinChild;

  const high = parentSpawnedInterpreter && isPowershellChild;
  const medium = parentSpawnedInterpreter || interpreterSpawnedLolbin || productivitySpawnedLolbin;

  const ev: RuleMatch["evidence"] = [
    evidence(
      "child_process",
      `${child} (pid ${event.pid}) was started by ${parent} (ppid ${event.parent_pid ?? "unknown"})`,
      "parent",
    ),
  ];

  if (productivityParent) {
    ev.push(
      evidence(
        "parent_category",
        `${parent} is a productivity/browser/mail application`,
        "parent",
      ),
    );
  }
  if (interpreterParent) {
    ev.push(
      evidence(
        "parent_category",
        `${parent} is a script interpreter`,
        "parent",
      ),
    );
  }

  if (high) {
    return {
      rule_id: "PROC-001-SUSPICIOUS-PARENT-CHILD",
      rule_name: "Suspicious parent-child relationship",
      title: `${parent} spawned PowerShell ${child}`,
      explanation: `${parent} (pid ${event.parent_pid ?? "unknown"}) started ${child} (pid ${event.pid}). Productivity, browser and mail applications do not normally launch script interpreters; this pairing is commonly used by macro/document-based malware to run embedded commands.`,
      recommended_action:
        "Verify whether this process was started by a user action in the parent application. If not expected, investigate the parent process memory and the media (document/email) that triggered it.",
      evidence: ev,
      baseSeverity: "high",
      baseConfidence: 0.7,
    };
  }

  if (medium) {
    return {
      rule_id: "PROC-001-SUSPICIOUS-PARENT-CHILD",
      rule_name: "Suspicious parent-child relationship",
      title: `${parent} spawned suspicious child ${child}`,
      explanation: `${parent} (pid ${event.parent_pid ?? "unknown"}) started ${child} (pid ${event.pid}) on an unexpected execution path. Quietly spawning a script interpreter or system utility from a user application is a known precursor to command-and-control and payload deployment.`,
      recommended_action:
        "Correlate with other signals for this process (command line, network connections) before deciding. If unexplained, treat the parent-child relationship as a containment candidate.",
      evidence: ev,
      baseSeverity: "medium",
      baseConfidence: 0.65,
    };
  }

  return null;
};

const ENCODED_PATTERN_RE =
  /-e(nc|n|)?(?:dcommand)?\s+[a-z0-9+/=]{20,}/i;
const FROM_BASE64_RE = /frombase64string\s*\(/i;
const HEX_ESCAPE_RE = /\\x[0-9a-f]{2}/i;
const HIDDEN_PS_RE = /-windowstyle\s+hidden/i;
const BYPASS_PS_RE = /-executionpolicy\s+bypass/i;

/**
 * PROC-002: The command line contains encoded or obfuscated script content.
 * Encoded PowerShell, embedded Base64 and hex-escaped characters obscure what
 * the process is actually executing.
 */
const encodedCommandLine: RuleFunction = (event) => {
  if (!hasCommandLine(event)) return null;
  const line = cmd(event);

  const indicators: Array<{ key: string; description: string }> = [];
  if (ENCODED_PATTERN_RE.test(line)) indicators.push({ key: "encoded_command", description: "Command line contains an encoded command flag (-EncodedCommand / -e) with a long Base64 payload" });
  if (FROM_BASE64_RE.test(line)) indicators.push({ key: "base64_decode", description: "Command line invokes FromBase64String / base64 decoding" });
  if (HEX_ESCAPE_RE.test(line)) indicators.push({ key: "hex_escapes", description: "Command line contains hexadecimal escape sequences (\\xNN) used to hide characters" });
  if (HIDDEN_PS_RE.test(line)) indicators.push({ key: "hidden_window", description: "PowerShell runs with a hidden window style" });
  if (BYPASS_PS_RE.test(line)) indicators.push({ key: "execution_bypass", description: "PowerShell execution policy is set to Bypass" });

  if (indicators.length === 0) return null;

  const serious = indicators.filter((i) =>
    ["encoded_command", "base64_decode", "hex_escapes"].includes(i.key),
  ).length;
  const flags = indicators.filter((i) =>
    ["hidden_window", "execution_bypass"].includes(i.key),
  ).length;

  const baseConfidence = Math.min(0.8, 0.7 + (serious - 1) * 0.05 + flags * 0.02);
  const severity = serious >= 2 ? "high" : serious === 1 ? "high" : "medium";

  return {
    rule_id: "PROC-002-ENCODED-COMMAND-LINE",
    rule_name: "Encoded or obfuscated command line",
    title: `${event.process_name} ran an encoded or obfuscated command line`,
    explanation: `${event.process_name} (pid ${event.pid}) invoked a command line that ${indicators
      .map((i) => i.description)
      .join("; additionally, it ")}. Encoded/obfuscated script content is heavily used by malware to evade detection and to hide the true payload from tools and users.`,
    recommended_action:
      "Decode the embedded payload from the captured command line and review it before deciding. If the encoding cannot be attributed to a routine admin task, treat this process as a priority candidate for isolation.",
    evidence: [
      evidence(
        indicators[0].key,
        indicators[0].description,
        "command_line",
        snippet(event.command_line),
      ),
      ...indicators.slice(1).map((i) => evidence(i.key, i.description, "command_line", snippet(event.command_line))),
    ],
    baseSeverity: severity as RuleMatch["baseSeverity"],
    baseConfidence,
  };
};

const SCRIPT_ARG_RE =
  /(?:"|'|\/)((?:[a-z]:)?[^"']*?(?:\\temp\\|\\downloads?\\|\\appdata\\|\\desktop\\|\\documents\\|\\onedrive\\|\/tmp\/|\/home\/)[^"']*?\.(?:ps1|psm1|vbs|vbe|js|jse|hta|bat|cmd|scr|jar|lnk))/i;

/**
 * PROC-003: A script interpreter was pointed at a script file that lives in a
 * user-writable directory (Temp, Downloads, AppData, Desktop, ...). Dropped
 * payload scripts nearly always land in user-writable locations.
 */
const interpreterUnusualScript: RuleFunction = (event) => {
  if (!isScriptInterpreter(event.process_name)) return null;
  if (!hasCommandLine(event)) return null;

  const line = event.command_line || "";
  const m = line.match(SCRIPT_ARG_RE);
  const scriptPath = m ? m[1] : null;

  if (!scriptPath || !containsUserWritableDir(scriptPath)) return null;

  return {
    rule_id: "PROC-003-INTERPRETER-UNUSUAL-SCRIPT",
    rule_name: "Interpreter executing a script from a user-writable directory",
    title: `${event.process_name} executed a script from a user-writable directory`,
    explanation: `${event.process_name} (pid ${event.pid}) was launched with a script argument located in a user-writable directory (${scriptPath}). Legitimate scripts rarely run from Temp/Downloads/AppData; payloads dropped by malware are overwhelmingly located there.`,
    recommended_action:
      "Review the script file and how it got there. Hash and inspect it before execution continues; if the file is not a known tool, isolate the host and preserve the artifact.",
    evidence: [
      evidence(
        "script_path",
        `Script argument points into a user-writable directory: ${scriptPath}`,
        "command_line",
        snippet(event.command_line),
      ),
      evidence("child_process", `${event.process_name} is a script interpreter`, "process"),
    ],
    baseSeverity: "high",
    baseConfidence: 0.75,
  };
};

/**
 * PROC-004: A script interpreter or LOLBin binary itself resides in a
 * user-writable location (instead of its normal Windows directory).
 */
const unusualLocation: RuleFunction = (event) => {
  const path = event.executable_path;
  if (!path) return null;

  const suspicious = isScriptInterpreter(event.process_name) || isLolBin(event.process_name);
  if (!suspicious) return null;

  if (!isUserWritableExecutionPath(path)) return null;

  const severity =
    isScriptInterpreter(event.process_name) && /powershell|pwsh|cmd\.exe/i.test(event.process_name)
      ? "high"
      : "medium";

  return {
    rule_id: "PROC-004-UNUSUAL-LOCATION",
    rule_name: "Execution from a user-writable location",
    title: `${event.process_name} is running from a user-writable directory`,
    explanation: `${event.process_name} (pid ${event.pid}) is executing from '${path}', a user-writable directory. ${event.process_name} normally lives under Windows or Program Files; copies in Temp/Downloads/AppData are a strong indication of a dropped or self-copied binary.`,
    recommended_action:
      "Confirm the file's provenance and signature. Compare its hash against the original Windows binary if the name matches a system tool, and remove/quarantine the copy if it differs.",
    evidence: [
      evidence(
        "executable_path",
        `Binary path points into a user-writable directory`,
        "executable_path",
        path,
      ),
    ],
    baseSeverity: severity,
    baseConfidence: 0.7,
  };
};

/**
 * PROC-005: A script interpreter spawned another script interpreter. Chains of
 * interpreters are used to stage multi-stage attacks (HTML/JS drop → PowerShell
 * → CMD → payload). Detected only for fresh spawns.
 */
const interpreterChain: RuleFunction = (event) => {
  if (event.origin === "snapshot") return null;
  if (!isScriptInterpreter(event.process_name)) return null;
  const parent = event.parent_process_name;
  if (!parent) return null;
  if (!isScriptInterpreter(parent)) return null;

  return {
    rule_id: "PROC-005-INTERPRETER-CHAIN",
    rule_name: "Interpreter spawning another interpreter",
    title: `${parent} chained into ${event.process_name}`,
    explanation: `${parent} (ppid ${event.parent_pid ?? "unknown"}) spawned ${event.process_name} (pid ${event.pid}) — an interpreter running an interpreter. Interpreter-to-interpreter chains are a hallmark of staged attacks that hop from one script host to the next.`,
    recommended_action:
      "Walk the full parent chain shown in the ancestry and inspect every command line in the chain. A multi-interpreter chain with encoded content at any hop warrants isolation.",
    evidence: [
      evidence(
        "parent_category",
        `Parent '${parent}' is a script interpreter`,
        "parent",
      ),
      evidence("child_process", `${event.process_name} is a script interpreter`, "process"),
    ],
    baseSeverity: "medium",
    baseConfidence: 0.65,
  };
};

const DOWNLOAD_MARKERS = [
  "net.webclient",
  "downloadstring",
  "downloadfile",
  "start-bits",
  "bitsadmin",
  "/transfer",
  "urlcache",
  "invoke-webrequest",
  "-outfile",
  "-o http",
  "cerutil",
  "certutil -urlcache",
  "certutil -f",
  "certutil -split",
  "-decode",
  "wget",
  "curl",
  "invoke-request",
];

/**
 * PROC-006: The command line shows a download-and-execute behavior: a tool is
 * fetching a payload from the network into the process/NTFS stream or executing
 * it immediately.
 */
const downloadExecute: RuleFunction = (event) => {
  if (!hasCommandLine(event)) return null;
  if (!isLolBin(event.process_name) && !isScriptInterpreter(event.process_name)) return null;

  const line = cmd(event);
  const hits = DOWNLOAD_MARKERS.filter((m) => line.includes(m.toLowerCase()));
  if (hits.length === 0) return null;

  const confidence = Math.min(0.85, 0.75 + (hits.length - 1) * 0.05);

  return {
    rule_id: "PROC-006-DOWNLOAD-EXECUTE",
    rule_name: "Download-and-execute behaviour",
    title: `${event.process_name} shows download-and-execute behaviour`,
    explanation: `${event.process_name} (pid ${event.pid}) invoked a command line that can fetch remote content and/or execute it in place (matched markers: ${hits.join(", ")}). Staging malware routinely downloads a secondary payload right before execution.`,
    recommended_action:
      "Identify the download URL/source from the command line and check it against blocklists. If the destination is not an approved repository/CDN, block the source and inspect for a dropped payload.",
    evidence: [
      evidence(
        "download_marker",
        `Command line contains download/execution markers: ${hits.join(", ")}`,
        "command_line",
        snippet(event.command_line),
      ),
    ],
    baseSeverity: "high",
    baseConfidence: confidence,
  };
};

const LOLBIN_USE_MARKERS = [
  /scrobj\.dll/i,
  /regsvr32.*\/(i|s)/i,
  /rundll32.*(javascript:|vbscript:|\.dll,|http)/i,
  /mshta.*(https?:|vbscript:|javascript:|about:)/i,
  /certutil.*(-urlcache|-split|-f|-decode)/i,
  /bitsadmin.*(\/transfer|\/create)/i,
  /wmic.*process.*call.*create/i,
  /schtasks\s+\/create/i,
  /forfiles.*\/p.*\/c/i,
];

/**
 * PROC-007: A living-off-the-land binary is being used for its abuse patterns —
 * script-host registration, remote script execution, download/decode of content,
 * or remote command scheduling — rather than its legitimate maintenance role.
 */
const lolbinExecution: RuleFunction = (event) => {
  if (!isLolBin(event.process_name)) return null;

  const evidenceList: RuleMatch["evidence"] = [];
  let suspicious = false;
  let severity: RuleMatch["baseSeverity"] = "medium";

  if (hasCommandLine(event)) {
    const line = (event.command_line || "").toLowerCase();
    for (const re of LOLBIN_USE_MARKERS) {
      if (re.test(line)) {
        suspicious = true;
        severity = "high";
        evidenceList.push(
          evidence(
            "lolbin_use",
            `${event.process_name} used with an abuse pattern (${re.source})`,
            "command_line",
            snippet(event.command_line),
          ),
        );
        break;
      }
    }
  }

  if (!suspicious) {
    return null;
  }

  return {
    rule_id: "PROC-007-LOLBIN-EXECUTION",
    rule_name: "Living-off-the-land binary use",
    title: `${event.process_name} used with an abuse pattern`,
    explanation: `${event.process_name} (pid ${event.pid}) was invoked in a way that is a recognised living-off-the-land technique (script registration, remote script execution, download/decode or remote scheduling). These binaries ship with Windows, so attackers reuse them to stay under the radar.`,
    recommended_action:
      "Check the exact arguments against the org's known usage of this tool. Unless it maps to an approved automation task, treat the invocation as malicious and trace what it would have registered/executed.",
    evidence: evidenceList.length > 0 ? evidenceList : [
      evidence("child_process", `${event.process_name} is a living-off-the-land binary`, "process"),
    ],
    baseSeverity: severity,
    baseConfidence: 0.7,
  };
};

/**
 * The ordered, stable set of rules evaluated for every security event.
 * Rules that reason about spawn relationships are skipped for snapshot-origin
 * events to avoid false positives from long-running baseline processes.
 */
export const RULES: RuleFunction[] = [
  suspiciousParentChild,
  encodedCommandLine,
  interpreterUnusualScript,
  unusualLocation,
  interpreterChain,
  downloadExecute,
  lolbinExecution,
];

export function evaluateRules(event: SecurityEvent): RuleMatch[] {
  const matches: RuleMatch[] = [];
  for (const rule of RULES) {
    try {
      const match = rule(event);
      if (match) matches.push(match);
    } catch {
      // A rule must never take down the ingestion pipeline.
    }
  }
  return matches;
}

export type RuleCatalogEntry = {
  rule_id: string;
  rule_name: string;
  description: string;
};

/** Stable catalog of active rules, exposed via the API for explainability. */
export const RULE_CATALOG: RuleCatalogEntry[] = [
  {
    rule_id: "PROC-001-SUSPICIOUS-PARENT-CHILD",
    rule_name: "Suspicious parent-child relationship",
    description:
      "A productivity, browser or mail process spawned a script interpreter or living-off-the-land binary; or an interpreter spawned a LOLBin.",
  },
  {
    rule_id: "PROC-002-ENCODED-COMMAND-LINE",
    rule_name: "Encoded or obfuscated command line",
    description:
      "Command line contains encoded or obfuscated script content (EncodedCommand, embedded Base64, hex escapes, hidden window, execution-policy bypass).",
  },
  {
    rule_id: "PROC-003-INTERPRETER-UNUSUAL-SCRIPT",
    rule_name: "Interpreter executing a script from a user-writable directory",
    description:
      "A script interpreter was pointed at a script file inside a user-writable directory (Temp, Downloads, AppData, Desktop, Documents).",
  },
  {
    rule_id: "PROC-004-UNUSUAL-LOCATION",
    rule_name: "Execution from a user-writable location",
    description:
      "A script interpreter or LOLBin binary itself resides in a user-writable directory instead of its normal Windows location.",
  },
  {
    rule_id: "PROC-005-INTERPRETER-CHAIN",
    rule_name: "Interpreter spawning another interpreter",
    description:
      "A script interpreter spawned another script interpreter — a hallmark of staged, multi-hop attacks.",
  },
  {
    rule_id: "PROC-006-DOWNLOAD-EXECUTE",
    rule_name: "Download-and-execute behaviour",
    description:
      "Command line matches download-and-execute markers (bitsadmin transfer, certutil urlcache, Invoke-WebRequest -OutFile, curl/wget download, ...).",
  },
  {
    rule_id: "PROC-007-LOLBIN-EXECUTION",
    rule_name: "Living-off-the-land binary use",
    description:
      "A living-off-the-land binary is used with an abuse pattern (script registration, remote script execution, download/decode, remote scheduling).",
  },
];

export { SCRIPT_EXTENSION_RE };