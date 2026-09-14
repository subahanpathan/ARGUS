/**
 * Core types for the deterministic, explainable process detection engine.
 *
 * The engine consumes normalized SecurityEvents (derived from real telemetry
 * emitted by the security engine) and produces Detections that carry explicit
 * evidence, an explanation, recommended actions and ancestry so every result
 * can be traced back to the telemetry that produced it.
 */

export type DetectionSeverity = "critical" | "high" | "medium" | "low";

export type DetectionStatus =
  | "observed"
  | "detected"
  | "investigated"
  | "contained"
  | "resolved";

/**
 * A stable identifier for a single detection rule.
 * Domains: PROC-* (process & behavioural), NET-* (network & port), FILE-* (file & persistence).
 */
export type DetectionRuleId =
  | "PROC-001-SUSPICIOUS-PARENT-CHILD"
  | "PROC-002-ENCODED-COMMAND-LINE"
  | "PROC-003-INTERPRETER-UNUSUAL-SCRIPT"
  | "PROC-004-UNUSUAL-LOCATION"
  | "PROC-005-INTERPRETER-CHAIN"
  | "PROC-006-DOWNLOAD-EXECUTE"
  | "PROC-007-LOLBIN-EXECUTION"
  | "NET-001-USER-WRITABLE-OUTBOUND"
  | "NET-002-KNOWN-TOOL-PORT"
  | "NET-003-SCRIPT-INTERPRETER-LISTENER"
  | "NET-004-NEW-LISTENER-USER-WRITABLE"
  | "NET-005-WILDCARD-LISTENER-USER-WRITABLE"
  | "NET-006-INTERPRETER-REMOTE-CONNECTION"
  | "NET-007-REMOTE-FAN-OUT"
  | "FILE-001-STARTUP-PERSISTENCE"
  | "FILE-002-ENCODED-DOWNLOADER"
  | "FILE-003-CREDENTIAL-ACCESS-ARTIFACT"
  | "FILE-004-SCHEDULED-TASK-PERSISTENCE"
  | "FILE-005-DISGUISED-EXECUTABLE"
  | "FILE-006-RUNNING-SUSPECT"
  | "FILE-007-RECON-SCRIPT";

export type DetectionEvidenceSource =
  | "process"
  | "command_line"
  | "executable_path"
  | "parent"
  | "ancestry"
  | "network"
  | "connection"
  | "port"
  | "file"
  | "path";

/** A single, explainable piece of evidence captured by a rule. */
export type DetectionEvidence = {
  key: string;
  description: string;
  source: DetectionEvidenceSource;
  /** Optional bounded observable value (e.g. a truncated command line). */
  detail?: string;
};

/** One hop of the parent chain leading to the detected process. */
export type DetectionAncestryNode = {
  pid: number;
  process_name: string;
  executable_path?: string | null;
  command_line?: string | null;
  username?: string | null;
};

/** A full detection produced by the engine. */
export type Detection = {
  id: string;
  rule_id: DetectionRuleId;
  rule_name: string;
  title: string;
  severity: DetectionSeverity;
  confidence: number;
  status: DetectionStatus;
  timestamp: string;
  event_timestamp: string;
  /** Display name of the affected process. */
  entity: string;
  pid: number;
  executable_path?: string | null;
  command_line?: string | null;
  parent_pid?: number | null;
  parent_process_name?: string | null;
  username?: string | null;
  hostname: string | null;
  evidence: DetectionEvidence[];
  explanation: string;
  recommended_action: string;
  /** Other rules that also fired for the same process (correlation). */
  correlated_rules?: string[];
  ancestry: DetectionAncestryNode[];
  related_event_id?: string | null;
};

/**
 * A normalized security event derived from raw telemetry. This is the single
 * input shape consumed by the rule engine.
 */
export type SecurityEventType = "PROCESS_CREATED" | "PROCESS_TERMINATED" | "PROCESS_SNAPSHOT";

/** Whether the event reflects a fresh spawn ("created") or a later snapshot (origin snapshot). */
export type SecurityEventOrigin = "created" | "snapshot";

export type SecurityEvent = {
  id: string;
  type: SecurityEventType;
  origin: SecurityEventOrigin;
  timestamp: string;
  source: string;
  hostname: string | null;
  pid: number;
  process_name: string;
  executable_path?: string | null;
  command_line?: string | null;
  parent_pid?: number | null;
  parent_process_name?: string | null;
  username?: string | null;
  metadata?: Record<string, unknown>;
};

/** The output of a single rule evaluation (before scoring/correlation). */
export type RuleMatch = {
  rule_id: DetectionRuleId;
  rule_name: string;
  title: string;
  explanation: string;
  recommended_action: string;
  evidence: DetectionEvidence[];
  baseSeverity: DetectionSeverity;
  baseConfidence: number;
};

/**
 * A normalized network/port telemetry event consumed by the NET rules.
 * Derived from real connection and port-intelligence snapshots pushed by the
 * security engine; roles come straight from `classify_address` (LOCAL/LOOPBACK/
 * PRIVATE/LINK_LOCAL/REMOTE/UNKNOWN). `pid` is 0 when the socket owner was not
 * resolvable (kernel/system connections).
 */
export type NetworkViewEvent = {
  id: string;
  type: "NETWORK_CONNECTION" | "NETWORK_PORT";
  origin: "created" | "snapshot";
  timestamp: string;
  source: string;
  hostname: string | null;
  pid: number;
  process_name: string;
  executable_path?: string | null;
  protocol?: string;
  address_family?: string;
  local_addr?: string;
  local_port?: number;
  remote_addr?: string;
  remote_port?: number;
  local_role?: string;
  remote_role?: string;
  /** Connection state (ESTABLISHED/LISTEN/...) or port state (LISTENING/NONE). */
  state?: string;
  /** Port binding scope: LOOPBACK / WILDCARD / INTERFACE. */
  binding_type?: string;
  connection_id?: string;
  port_id?: string;
  /** Port lifecycle event type (PORT_OPENED / PORT_CLOSED / PORT_CHANGED). */
  event_type?: string;
  metadata?: Record<string, unknown>;
};

/**
 * A normalized file finding consumed by the FILE rules. Every detection
 * references the real on-disk artifact (path, real SHA-256 hash, size, mtime)
 * and, when the artifact is currently executing, the owning `pid`.
 */
export type FileViewEvent = {
  id: string;
  type: "FILE_FINDING";
  origin: "snapshot";
  timestamp: string;
  source: string;
  hostname: string | null;
  pid: number;
  process_name: string;
  file_path: string;
  file_name: string;
  file_extension?: string;
  file_hash?: string;
  file_size?: number;
  file_modified?: string;
  category?: string;
  className?: string;
  is_running?: boolean;
  finding_severity?: string;
  finding_reason?: string;
  executable_path?: string | null;
  metadata?: Record<string, unknown>;
};