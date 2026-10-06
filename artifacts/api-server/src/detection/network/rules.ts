/**
 * Deterministic, explainable detection rules for network & port telemetry.
 *
 * Every rule is a pure function `(event) => RuleMatch | null` that reasons
 * only over fields the security engine really reports: connection roles
 * (from `classify_address`), TCP/port states, binding scope, process name,
 * executable path and ports. Rules never label an address "malicious" by
 * itself — a remote endpoint is only ever evidence inside a context (a
 * process in a user-writable location, a wildcard listener, a known tooling
 * port, an interpreter holding a live connection).
 */

import {
  isExternalOrPrivateRole,
  isKnownToolPort,
  isRemoteRole,
  isWildcardBinding,
  KNOWN_TOOL_PORT_LIST,
} from "./lists";
import {
  isLolBin,
  isScriptInterpreter,
  isUserWritableExecutionPath,
} from "../lists";
import type {
  DetectionEvidence,
  DetectionEvidenceSource,
  DetectionSeverity,
  NetworkViewEvent,
  RuleMatch,
} from "../types";

const ev = (
  key: string,
  description: string,
  source: DetectionEvidenceSource,
  detail?: string,
): DetectionEvidence => ({ key, description, source, ...(detail ? { detail } : {}) });

const LISTENING_STATES = new Set(["LISTEN", "LISTENING"]);

const isListening = (event: NetworkViewEvent): boolean =>
  Boolean(event.state && LISTENING_STATES.has(event.state));

const isEstablished = (event: NetworkViewEvent): boolean => event.state === "ESTABLISHED";

/** String to display for a socket endpoint in evidence/descriptions. */
const endpoint = (addr: string | undefined, port: number | undefined): string =>
  addr ? `${addr}:${port ?? ""}` : "unknown";

/**
 * NET-001: A binary that lives in a user-writable directory (Temp, Downloads,
 * AppData, ...) is talking to the public internet. Dropped payloads commonly
 * beacon out before or during execution.
 */
const userWritableOutbound: (event: NetworkViewEvent) => RuleMatch | null = (event) => {
  if (!isEstablished(event)) return null;
  if (!isRemoteRole(event.remote_role)) return null;
  const path = event.executable_path;
  if (!path || !isUserWritableExecutionPath(path)) return null;

  return {
    rule_id: "NET-001-USER-WRITABLE-OUTBOUND",
    rule_name: "Outbound network I/O from a user-writable binary",
    title: `${event.process_name} reaching the internet from a user-writable directory`,
    explanation: `${event.process_name} (pid ${event.pid}) opened an established connection to '${endpoint(event.remote_addr, event.remote_port)}' while its binary runs from '${path}', a user-writable directory. Executables living in Temp/Downloads/AppData are a strong indicator of a dropped or self-copied payload that should not be talking to the internet.`,
    recommended_action:
      "Correlate this connection with the process's origin and any file-scan finding for the same path. If the binary is not an approved tool, block the destination and isolate the host.",
    evidence: [
      ev("executable_path", `Binary runs from a user-writable directory`, "path", path),
      ev("remote_endpoint", `Established connection to ${endpoint(event.remote_addr, event.remote_port)}`, "network", `${endpoint(event.local_addr, event.local_port)} -> ${endpoint(event.remote_addr, event.remote_port)}`),
    ],
    baseSeverity: "high",
    baseConfidence: 0.7,
  };
};

/**
 * NET-002: A remote connection to a port commonly associated with offensive
 * tooling / implant C2 channels. A *pattern*, not attribution: the port alone
 * is not proof, so the severity stays medium and the recommended action asks
 * for local corroboration.
 */
const knownToolPort: (event: NetworkViewEvent) => RuleMatch | null = (event) => {
  if (!isEstablished(event)) return null;
  if (!isRemoteRole(event.remote_role)) return null;
  if (!isKnownToolPort(event.remote_port)) return null;

  return {
    rule_id: "NET-002-KNOWN-TOOL-PORT",
    rule_name: "Connection on a port associated with offensive tooling",
    title: `${event.process_name} connected to ${event.remote_addr}:${event.remote_port}`,
    explanation: `${event.process_name} (pid ${event.pid}) established a connection to ${endpoint(event.remote_addr, event.remote_port)}. Port ${event.remote_port} is on the list of ports commonly used by offensive tooling and C2 implants (${KNOWN_TOOL_PORT_LIST.join(", ")}). This is a pattern match — correlate with local context before acting.`,
    recommended_action:
      "Confirm whether the destination is expected in this environment and check the process for additional indicators (command line, file-scan, other connections). Block only if the destination cannot be attributed to legitimate tooling.",
    evidence: [
      ev("remote_endpoint", `Established connection to ${endpoint(event.remote_addr, event.remote_port)}`, "network", `${endpoint(event.local_addr, event.local_port)} -> ${endpoint(event.remote_addr, event.remote_port)}`),
      ev("known_tool_port", `Port ${event.remote_port} is on the offensive-tooling port list`, "network"),
    ],
    baseSeverity: "medium",
    baseConfidence: 0.6,
  };
};

/**
 * NET-003: A script interpreter (PowerShell, cscript, mshta, ...) exposes a
 * network listener bound to all interfaces. Interpreters are not service hosts;
 * a wildcard listener under one is a remote-shell/backdoor technique.
 */
const scriptInterpreterListener: (event: NetworkViewEvent) => RuleMatch | null = (event) => {
  if (!isListening(event)) return null;
  if (!isWildcardBinding(event.local_addr, event.binding_type)) return null;
  if (!isScriptInterpreter(event.process_name)) return null;

  return {
    rule_id: "NET-003-SCRIPT-INTERPRETER-LISTENER",
    rule_name: "Script interpreter exposing a network listener",
    title: `${event.process_name} is listening on all interfaces`,
    explanation: `${event.process_name} (pid ${event.pid}) is listening on ${endpoint(event.local_addr, event.local_port)} (all interfaces). Script interpreters are not normally service hosts; a wildcard listener under one is a common way for an implant to expose a shell or accept follow-up commands.`,
    recommended_action:
      "Identify what created this listener (check the process command line) and whether any configured service legitimately uses it. If not, treat it as a suspected remote-access listener and isolate the process.",
    evidence: [
      ev("listener", `${event.process_name} listening on ${endpoint(event.local_addr, event.local_port)} (wildcard)`, "network"),
      ev("interpreter", `${event.process_name} is a script interpreter`, "process"),
    ],
    baseSeverity: "medium",
    baseConfidence: 0.65,
  };
};

/**
 * NET-004: A brand-new port was opened by a process whose binary lives in a
 * user-writable directory. Port-open events are rare, so this is a strong,
 * low-noise signal for an implant registering a backdoor service.
 */
const newListenerUserWritable: (event: NetworkViewEvent) => RuleMatch | null = (event) => {
  if (event.type !== "NETWORK_PORT") return null;
  if (event.event_type !== "PORT_OPENED") return null;
  const path = event.executable_path;
  if (!path || !isUserWritableExecutionPath(path)) return null;

  const scope = isWildcardBinding(event.local_addr, event.binding_type)
    ? `all interfaces (${event.local_addr || "wildcard"})`
    : `address ${event.local_addr || "unknown"}`;

  return {
    rule_id: "NET-004-NEW-LISTENER-USER-WRITABLE",
    rule_name: "New listener opened by a user-writable binary",
    title: `${event.process_name} opened a new listener on port ${event.local_port ?? "?"}`,
    explanation: `${event.process_name} (pid ${event.pid}) just opened port ${event.local_port ?? "unknown"} bound to ${scope}. The binary runs from '${path}', a user-writable directory. A freshly opened listener from a dropped binary is a classic backdoor registration step.`,
    recommended_action:
      "Check what immediately preceded the new listener (process events, file-scan findings for the same path) and test the service. Suspicious = preserve the binary hash and isolate the host.",
    evidence: [
      ev("new_listener", `${event.process_name} opened port ${event.local_port ?? "unknown"} on ${scope}`, "port", `port_id ${event.port_id ?? event.local_port ?? ""}`),
      ev("executable_path", `Binary runs from a user-writable directory`, "path", path),
    ],
    baseSeverity: "high",
    baseConfidence: 0.75,
  };
};

/**
 * NET-005: A wildcard listener owned by a user-writable binary that is already
 * listening (baseline state, caught by snapshot scans rather than the open event).
 */
const wildcardListenerUserWritable: (event: NetworkViewEvent) => RuleMatch | null = (event) => {
  if (!isListening(event)) return null;
  if (!isWildcardBinding(event.local_addr, event.binding_type)) return null;
  const path = event.executable_path;
  if (!path || !isUserWritableExecutionPath(path)) return null;

  return {
    rule_id: "NET-005-WILDCARD-LISTENER-USER-WRITABLE",
    rule_name: "Wildcard listener from a user-writable binary",
    title: `${event.process_name} exposes ${endpoint(event.local_addr, event.local_port)} from a user-writable directory`,
    explanation: `${event.process_name} (pid ${event.pid}) is listening on ${endpoint(event.local_addr, event.local_port)} bound to all interfaces while its binary lives in '${path}'. A service accepting connections from anywhere, running from a dropped location, is a backdoor/remote-access indicator.`,
    recommended_action:
      "Verify the listener's purpose and the binary's provenance. If the path is not an approved install location, treat this as a suspected backdoor listener and isolate the host.",
    evidence: [
      ev("listener", `${event.process_name} listening on ${endpoint(event.local_addr, event.local_port)} (wildcard)`, "network"),
      ev("executable_path", `Binary runs from a user-writable directory`, "path", path),
    ],
    baseSeverity: "high",
    baseConfidence: 0.75,
  };
};

/**
 * NET-006: A script interpreter or LOLBin holds a live established connection
 * into the internet. Interpreters maintaining active network connections is a
 * C2/beaconing pattern (e.g. PowerShell WebClient keep-alives).
 */
const interpreterRemoteConnection: (event: NetworkViewEvent) => RuleMatch | null = (event) => {
  if (!isEstablished(event)) return null;
  if (!isRemoteRole(event.remote_role)) return null;
  const interpreter = isScriptInterpreter(event.process_name);
  const lolbin = isLolBin(event.process_name);
  if (!interpreter && !lolbin) return null;

  return {
    rule_id: "NET-006-INTERPRETER-REMOTE-CONNECTION",
    rule_name: "Script interpreter with an active remote connection",
    title: `${event.process_name} maintains an active connection to ${event.remote_addr}`,
    explanation: `${event.process_name} (pid ${event.pid}) holds an established connection to ${endpoint(event.remote_addr, event.remote_port)}. ${interpreter ? "Script interpreters" : "Living-off-the-land binaries"} maintaining live internet connections is a recognised beaconing/C2 pattern; combined with a suspicious command line it warrants immediate review.`,
    recommended_action:
      "Inspect the interpreter's command line and recent parent activity. If the connection persists across multiple polls and the source is not an approved admin channel, block the destination and terminate the chain.",
    evidence: [
      ev("remote_endpoint", `Established connection to ${endpoint(event.remote_addr, event.remote_port)}`, "network", `${endpoint(event.local_addr, event.local_port)} -> ${endpoint(event.remote_addr, event.remote_port)}`),
      ev(
        "interpreter",
        `${event.process_name} is ${interpreter ? "a script interpreter" : "a living-off-the-land binary"}`,
        "process",
      ),
    ],
    baseSeverity: "medium",
    baseConfidence: 0.6,
  };
};

/**
 * NET-007: One process talking to many distinct public destinations within a
 * single snapshot — a fan-out / scanning shape. Volume-based, low confidence,
 * but useful when it correlates with other per-process rules.
 */
const remoteFanOut = (event: NetworkViewEvent): RuleMatch | null => {
  const fanOut = Number(event.metadata?.fanOut ?? 0);
  const MIN_FAN_OUT = 10;
  if (!Number.isFinite(fanOut) || fanOut < MIN_FAN_OUT) return null;

  return {
    rule_id: "NET-007-REMOTE-FAN-OUT",
    rule_name: "Unusual remote fan-out by a single process",
    title: `${event.process_name} contacted ${fanOut} remote destinations`,
    explanation: `${event.process_name} (pid ${event.pid}) established connections to ${fanOut} distinct public destinations in one sampling window. Reaching that many independent remotes is a volume-based anomaly consistent with scanning, resolver abuse or a heavily distributing implant.`,
    recommended_action:
      "Review the destination set for a pattern (same host ranges = scanning, many CDNs = possible data staging). Correlate with the process command line and file-scan findings before acting.",
    evidence: [
      ev("fan_out", `${event.process_name} contacted ${fanOut} distinct remote addresses`, "network", (event.metadata?.remoteIps as string[] | undefined)?.join(", ")),
    ],
    baseSeverity: "low",
    baseConfidence: 0.5,
  };
};

/**
 * Shell binaries that should never maintain established interactive network sockets.
 */
const INTERACTIVE_SHELLS = new Set([
  "cmd.exe",
  "powershell.exe",
  "pwsh.exe",
  "nc.exe",
  "ncat.exe",
  "netcat.exe",
  "socat.exe",
  "bash.exe",
  "sh.exe",
]);

/**
 * NET-008: Active reverse shell or C2 connection established to an external
 * or private endpoint (e.g. Kali VM). High-fidelity critical signal.
 */
const interactiveReverseShell: (event: NetworkViewEvent) => RuleMatch | null = (event) => {
  if (!isEstablished(event)) return null;
  if (!isExternalOrPrivateRole(event.remote_role, event.remote_addr)) return null;

  const procLower = (event.process_name || "").toLowerCase();
  const isShell = INTERACTIVE_SHELLS.has(procLower);
  const isToolPort = isKnownToolPort(event.remote_port);
  const isInterpreter = isScriptInterpreter(event.process_name) || isLolBin(event.process_name);

  if (isShell || (isInterpreter && isToolPort)) {
    return {
      rule_id: "NET-008-REVERSE-SHELL",
      rule_name: "Interactive shell or C2 reverse connection established",
      title: `Critical reverse shell: ${event.process_name} connected to ${endpoint(event.remote_addr, event.remote_port)}`,
      explanation: `${event.process_name} (pid ${event.pid}) established an active network socket to '${endpoint(event.remote_addr, event.remote_port)}'. Command shells and script interpreters maintaining direct sockets to remote or private virtual hosts (such as an attacker VM) indicate an active interactive reverse shell or C2 payload session.`,
      recommended_action:
        "Execute automated host containment immediately: terminate process tree, block remote endpoint in Windows Firewall, and quarantine the payload.",
      evidence: [
        ev("reverse_socket", `Established reverse socket: ${endpoint(event.local_addr, event.local_port)} -> ${endpoint(event.remote_addr, event.remote_port)}`, "network"),
        ev("shell_process", `Process ${event.process_name} (PID ${event.pid}) running shell/interpreter`, "process", event.executable_path),
        ...(event.remote_port ? [ev("remote_port", `Target port ${event.remote_port}`, "network")] : []),
      ],
      baseSeverity: "critical",
      baseConfidence: 0.95,
    };
  }

  return null;
};

/**
 * NET-009: Data exfiltration attempt over network socket.
 */
const dataExfiltration: (event: NetworkViewEvent) => RuleMatch | null = (event) => {
  if (!isEstablished(event)) return null;
  if (!isExternalOrPrivateRole(event.remote_role, event.remote_addr)) return null;

  const cmdLower = (event.command_line || "").toLowerCase();
  const isTransferCmd =
    cmdLower.includes("upload") ||
    cmdLower.includes("transfer") ||
    cmdLower.includes("scp") ||
    cmdLower.includes("curl -f") ||
    cmdLower.includes("bitsadmin /transfer");

  if (isTransferCmd) {
    return {
      rule_id: "NET-009-DATA-EXFILTRATION",
      rule_name: "Active data exfiltration transfer detected",
      title: `${event.process_name} exfiltrating data to ${event.remote_addr}`,
      explanation: `${event.process_name} (pid ${event.pid}) is executing a transfer command while holding an established connection to '${endpoint(event.remote_addr, event.remote_port)}'. Potential data theft in progress.`,
      recommended_action:
        "Sever network connection, kill process tree, and verify affected files.",
      evidence: [
        ev("exfil_socket", `Exfiltration endpoint: ${endpoint(event.remote_addr, event.remote_port)}`, "network"),
        ev("command_line", `Transfer command: ${event.command_line}`, "process"),
      ],
      baseSeverity: "high",
      baseConfidence: 0.85,
    };
  }

  return null;
};

/**
 * The ordered, stable set of NET rules evaluated for every normalized network/
 * port event.
 */
export const NET_RULES: Array<(event: NetworkViewEvent) => RuleMatch | null> = [
  interactiveReverseShell,
  dataExfiltration,
  userWritableOutbound,
  knownToolPort,
  scriptInterpreterListener,
  newListenerUserWritable,
  wildcardListenerUserWritable,
  interpreterRemoteConnection,
  remoteFanOut,
];

/**
 * The fan-out rule operates on a synthetic per-process aggregation event built
 * by the engine (metadata.fanOut / metadata.remoteIps); it is evaluated once per
 * snapshot per process.
 */
export { remoteFanOut };

export function evaluateNetworkRules(event: NetworkViewEvent): RuleMatch[] {
  const matches: RuleMatch[] = [];
  for (const rule of NET_RULES) {
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

/** Stable catalog of the active NET rules, exposed via the API. */
export const NET_RULE_CATALOG: RuleCatalogEntry[] = [
  {
    rule_id: "NET-008-REVERSE-SHELL",
    rule_name: "Interactive shell or C2 reverse connection established",
    description:
      "An interactive shell (cmd, powershell, netcat) or interpreter holds an established connection to an external or private endpoint (e.g. Kali VM).",
  },
  {
    rule_id: "NET-009-DATA-EXFILTRATION",
    rule_name: "Active data exfiltration transfer detected",
    description:
      "A process holds an established connection while executing file transfer or upload commands.",
  },
  {
    rule_id: "NET-001-USER-WRITABLE-OUTBOUND",
    rule_name: "Outbound network I/O from a user-writable binary",
    description:
      "A process whose executable lives in a user-writable directory (Temp, Downloads, AppData) holds an established connection to a public address.",
  },
  {
    rule_id: "NET-002-KNOWN-TOOL-PORT",
    rule_name: "Connection on a port associated with offensive tooling",
    description:
      "An established connection to a remote endpoint on a port commonly used by offensive tooling / C2 implants (pattern match, not attribution).",
  },
  {
    rule_id: "NET-003-SCRIPT-INTERPRETER-LISTENER",
    rule_name: "Script interpreter exposing a network listener",
    description:
      "A script interpreter (PowerShell, cscript, mshta, ...) is listening on all interfaces — a remote-shell/backdoor technique.",
  },
  {
    rule_id: "NET-004-NEW-LISTENER-USER-WRITABLE",
    rule_name: "New listener opened by a user-writable binary",
    description:
      "A PORT_OPENED lifecycle event shows a brand-new listener being opened by a process whose binary lives in a user-writable directory.",
  },
  {
    rule_id: "NET-005-WILDCARD-LISTENER-USER-WRITABLE",
    rule_name: "Wildcard listener from a user-writable binary",
    description:
      "An existing listener bound to all interfaces is owned by a process running from a user-writable directory.",
  },
  {
    rule_id: "NET-006-INTERPRETER-REMOTE-CONNECTION",
    rule_name: "Script interpreter with an active remote connection",
    description:
      "A script interpreter or living-off-the-land binary maintains a live established connection to a public address.",
  },
  {
    rule_id: "NET-007-REMOTE-FAN-OUT",
    rule_name: "Unusual remote fan-out by a single process",
    description:
      "A single process talks to 10 or more distinct public destinations within one snapshot (volume-based anomaly).",
  },
];