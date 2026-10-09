/**
 * Runtime correlation across the monitoring domains.
 *
 * Correlations are *derived* from observations the agent has already made — the
 * engine never invents a link. Every correlation records the evidence that
 * produced it and the reason the match was made, so the UI can show why two
 * unrelated-looking events were grouped.
 *
 * Matching is deliberately conservative:
 *
 * * a file event links to a process only when the path is that process's
 *   observed executable path
 * * a port/connection links to a process only through its observed owning pid
 * * a security-provider detection links to a file event only when the provider
 *   reported that exact resource path
 *
 * When nothing real matches, no correlation is produced. Absence of correlation
 * is information; inventing one is not.
 */

import type { Detection } from "../detection/types";
import type { MonitoringEvent, NetworkConnection, PortInfo } from "./event-hub";

export type CorrelationEvidenceKind =
  | "process"
  | "file"
  | "port"
  | "connection"
  | "detection"
  | "security_provider";

export type CorrelationEvidence = {
  kind: CorrelationEvidenceKind;
  id: string;
  at: string;
  summary: string;
  /** 0..1 strength of the match. 1.0 means an exact identifier match. */
  score: number;
};

export type CorrelationRecord = {
  correlationId: string;
  createdAt: string;
  subject: {
    kind: string;
    id: string;
    name: string;
    source: string;
  };
  severity: string | null;
  evidence: CorrelationEvidence[];
  matchReasons: string[];
};

export type CorrelationProcess = {
  pid: number;
  name: string;
  executable_path?: string;
  command_line?: string;
};

export type CorrelationContext = {
  processes: CorrelationProcess[];
  connections: NetworkConnection[];
  ports: PortInfo[];
  detections: Array<Pick<Detection, "id" | "rule_id" | "title" | "timestamp" | "severity"> & { pid?: number | null; entity?: string | null }>;
  /** Recent filesystem change events, newest last, already bounded. */
  fileEvents: MonitoringEvent[];
  now: string;
};

/** Files that must never be treated as a match on name alone. */
const MIN_NAME_MATCH_LENGTH = 4;

function normPath(value: string | undefined | null): string {
  if (!value) return "";
  return value.trim().replace(/\//g, "\\").replace(/\\+$/, "").toLowerCase();
}

function correlationId(subject: string, anchor: string): string {
  let hash = 0x811c9dc5;
  const material = `${subject}|${anchor}`;
  for (let i = 0; i < material.length; i += 1) {
    hash ^= material.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `corr-${hash.toString(16).padStart(8, "0")}`;
}

function fileEventPath(event: MonitoringEvent): string {
  const raw = event.evidence?.path;
  return typeof raw === "string" ? raw : "";
}

function resourcePaths(evidence: Record<string, unknown> | undefined): string[] {
  const raw = evidence?.resources;
  if (!Array.isArray(raw)) return [];
  return raw.filter((item): item is string => typeof item === "string");
}

/**
 * Correlate one normalized event against everything the API currently knows.
 * Returns `null` when no real evidence exists.
 */
export function correlate(
  event: MonitoringEvent,
  context: CorrelationContext,
): CorrelationRecord | null {
  const evidence: CorrelationEvidence[] = [];
  const reasons: string[] = [];
  const kind = event.eventType;

  const addProcess = (process: CorrelationProcess, reason: string, score: number) => {
    evidence.push({
      kind: "process",
      id: `pid-${process.pid}`,
      at: event.timestamp,
      summary: `${process.name} (PID ${process.pid})`,
      score,
    });
    reasons.push(reason);
  };

  // -- filesystem change -> the process that owns that exact binary ----------
  if (kind.startsWith("FILE_")) {
    const path = normPath(fileEventPath(event));
    if (path) {
      for (const process of context.processes) {
        if (normPath(process.executable_path) === path) {
          addProcess(process, `process executable path matches the changed file (${process.executable_path})`, 1);
        }
      }
      for (const connection of context.connections) {
        if (normPath(connection.executable_path) === path) {
          evidence.push({
            kind: "connection",
            id: connection.connection_id || `${connection.process}:${connection.local_port ?? ""}`,
            at: connection.timestamp || context.now,
            summary: `${connection.local_addr ?? "?"}:${connection.local_port ?? "?"} → ${connection.remote_addr ?? "?"}:${connection.remote_port ?? "?"}`,
            score: 0.9,
          });
          reasons.push(`network connection owned by the process at ${connection.executable_path}`);
        }
      }
    }
  }

  // -- port / connection -> the observed owning process ---------------------
  if (kind === "PORT_OPENED" || kind === "PORT_CHANGED") {
    const pid = typeof event.evidence?.pid === "number" ? event.evidence.pid : null;
    if (pid != null) {
      for (const process of context.processes) {
        if (process.pid === pid) {
          addProcess(process, `port event carries the owning pid ${pid}`, 1);
        }
      }
    }
  }

  // -- security provider detection -> file / process / engine detection ------
  if (event.source === "security_provider" && event.evidence?.kind === "DETECTION") {
    const paths = resourcePaths(event.evidence).map(normPath).filter(Boolean);
    const providerProcess = typeof event.evidence?.process_name === "string" ? event.evidence.process_name : "";

    for (const recent of context.fileEvents) {
      if (recent.eventId === event.eventId) continue;
      const recentPath = normPath(fileEventPath(recent));
      if (!recentPath || !paths.includes(recentPath)) continue;
      evidence.push({
        kind: "file",
        id: recent.eventId,
        at: recent.timestamp,
        summary: recentPath,
        score: 1,
      });
      reasons.push(`provider reported this exact path and it changed at ${recent.timestamp}`);
    }

    for (const process of context.processes) {
      const processPath = normPath(process.executable_path);
      if (processPath && paths.includes(processPath)) {
        addProcess(process, `provider reported the running process path ${process.executable_path}`, 1);
        continue;
      }
      if (
        providerProcess &&
        process.name.toLowerCase() === providerProcess.toLowerCase() &&
        providerProcess.length >= MIN_NAME_MATCH_LENGTH
      ) {
        addProcess(process, `provider named this running process (${providerProcess})`, 0.7);
      }
    }

    for (const detection of context.detections) {
      const samePid =
        detection.pid != null && context.processes.some((p) => p.pid === detection.pid);
      const entity = normPath(detection.entity ?? undefined);
      if ((entity && paths.includes(entity)) || (samePid && providerProcess)) {
        evidence.push({
          kind: "detection",
          id: detection.id,
          at: detection.timestamp,
          summary: `${detection.rule_id} · ${detection.title}`,
          score: entity ? 0.95 : 0.6,
        });
        reasons.push(`engine detection ${detection.rule_id} refers to the same entity`);
      }
    }
  }

  if (evidence.length === 0) return null;

  const subjectId = event.entity?.id || event.eventId;
  return {
    correlationId: correlationId(`${event.source}:${event.entity?.kind ?? "entity"}:${subjectId}`, event.eventId),
    createdAt: context.now,
    subject: {
      kind: event.entity?.kind ?? "entity",
      id: subjectId,
      name: event.entity?.name ?? "",
      source: event.source ?? "unknown",
    },
    severity: event.severity ?? null,
    evidence: evidence.sort((a, b) => b.score - a.score).slice(0, 12),
    matchReasons: [...new Set(reasons)],
  };
}

/** Merge evidence for an existing correlation instead of duplicating it. */
export function mergeCorrelation(
  existing: CorrelationRecord,
  incoming: CorrelationRecord,
): CorrelationRecord {
  const byKey = new Map<string, CorrelationEvidence>();
  for (const item of [...existing.evidence, ...incoming.evidence]) {
    byKey.set(`${item.kind}:${item.id}`, item);
  }
  return {
    ...incoming,
    evidence: [...byKey.values()].sort((a, b) => b.score - a.score).slice(0, 12),
    matchReasons: [...new Set([...existing.matchReasons, ...incoming.matchReasons])],
  };
}
