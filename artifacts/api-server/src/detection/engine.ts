/**
 * DetectionEngine — deterministic process, network and file detection.
 *
 * Responsibilities:
 *  - normalize raw telemetry (process events/snapshots, network/port snapshots,
 *    file scans) into normalized view events
 *  - evaluate every rule against each event (PROC / NET / FILE rule sets)
 *  - apply explainable confidence/severity scoring (base + evidence + correlation)
 *  - de-duplicate repeated or re-ingested events and snapshots (bounded memory)
 *  - correlate *across domains* — distinct rules firing for the same process
 *    (pid) within a window escalate urgency
 *  - build parent-chain ancestry and remember process context for investigation
 */

import type {
  FileScanSnapshot,
  NetworkSnapshot,
  PortIntelligenceSnapshot,
  ProcessEvent,
  ProcessSnapshot,
} from "../lib/event-hub";
import { normalizeProcessEvent, normalizeSnapshotProcesses, HOSTNAME } from "./normalize";
import { evaluateRules } from "./rules";
import { evaluateNetworkRules } from "./network/rules";
import { evaluateFileRules } from "./file/rules";
import {
  aggregateRemoteFanOut,
  normalizeNetworkConnections,
  normalizePortSnapshot,
} from "./network/normalize";
import { normalizeFileFindings } from "./file/normalize";
import type {
  Detection,
  DetectionAncestryNode,
  DetectionRuleId,
  DetectionSeverity,
  FileViewEvent,
  NetworkViewEvent,
  RuleMatch,
  SecurityEvent,
} from "./types";

const MAX_ANCESTRY_DEPTH = 8;
/** Hourly window used to avoid creating duplicate detections for the same unit+rule. */
const DEDUP_WINDOW_MS = 60 * 60 * 1000;
const MAX_SEEN_ENTRIES = 5000;
const SEEN_PRUNE_AGE_MS = 24 * 60 * 60 * 1000;
/** Detections for the same pid matching different rules within this window are correlated. */
const CORRELATION_WINDOW_MS = 10 * 60 * 1000;

const SEVERITY_ORDER: DetectionSeverity[] = ["low", "medium", "high", "critical"];

/**
 * The common, normalized shape the engine evaluates rules against. Process,
 * network and file normalization all produce objects assignable to this view.
 */
type ViewEvent = {
  id: string;
  type: string;
  origin: "created" | "snapshot";
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

export type ProcessContext = {
  pid: number;
  process_name: string;
  executable_path?: string | null;
  command_line?: string | null;
  parent_pid?: number | null;
  parent_process_name?: string | null;
  username?: string | null;
  timestamp?: string | null;
};

type CorrelationState = {
  ruleIds: Set<DetectionRuleId>;
  firstAt: number;
};

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function round2(value: number): number {
  return Math.round(value * 100) / 100;
}

function escalate(severity: DetectionSeverity, steps: number): DetectionSeverity {
  const idx = SEVERITY_ORDER.indexOf(severity);
  const next = clamp(idx + steps, 0, SEVERITY_ORDER.length - 1);
  return SEVERITY_ORDER[next];
}

export class DetectionEngine {
  private seq = 0;
  private readonly seen = new Map<string, number>();
  private readonly correlations = new Map<string, CorrelationState>();
  private readonly processes = new Map<number, ProcessContext>();
  private lastSnapshotTimestamp: string | null = null;

  /** Reset all in-memory state (used by tests and admin reset). */
  reset(): void {
    this.seq = 0;
    this.seen.clear();
    this.correlations.clear();
    this.processes.clear();
    this.lastSnapshotTimestamp = null;
  }

  /** Process a raw process event (start/terminate). Returns new detections. */
  ingestEvent(event: ProcessEvent): Detection[] {
    const sec = normalizeProcessEvent(event);
    if (!sec) return [];

    this.remember(sec);
    if (sec.type === "PROCESS_TERMINATED") return [];
    return this.evaluate(sec);
  }

  /** Process a full snapshot. Returns new detections (deduped across snapshots). */
  ingestSnapshot(snapshot: ProcessSnapshot): Detection[] {
    if (!snapshot || !Array.isArray(snapshot.processes)) return [];
    const ts = snapshot.timestamp || new Date().toISOString();
    if (this.lastSnapshotTimestamp === ts) return [];
    this.lastSnapshotTimestamp = ts;

    for (const p of snapshot.processes) {
      this.processes.set(p.pid, {
        pid: p.pid,
        process_name: p.name || String(p.pid),
        executable_path: p.executable_path ?? null,
        command_line: p.command_line ?? null,
        parent_pid: p.parent_pid ?? null,
        parent_process_name: p.parent_name ?? null,
        username: p.username ?? null,
        timestamp: ts,
      });
    }

    const out: Detection[] = [];
    for (const sec of normalizeSnapshotProcesses(snapshot)) {
      for (const det of this.evaluate(sec)) out.push(det);
    }
    return out;
  }

  /**
   * Process a network connection snapshot. Every connection is evaluated
   * against the NET rules; the per-process remote fan-out aggregation (NET-007)
   * is evaluated once per snapshot per pid.
   */
  ingestNetworkSnapshot(snapshot: NetworkSnapshot): Detection[] {
    if (!snapshot || !Array.isArray(snapshot.connections)) return [];

    const out: Detection[] = [];
    const timestamp = snapshot.timestamp || new Date().toISOString();

    for (const evt of normalizeNetworkConnections(snapshot)) {
      for (const det of this.evaluateMatches(evt, evaluateNetworkRules(evt))) out.push(det);
    }

    for (const rec of aggregateRemoteFanOut(snapshot)) {
      const fanEvt: NetworkViewEvent = {
        id: `net:fan:${rec.pid}:${timestamp}`,
        type: "NETWORK_CONNECTION",
        origin: "snapshot",
        timestamp,
        source: "windows_network_monitor",
        hostname: HOSTNAME,
        pid: rec.pid,
        process_name: rec.process_name,
        metadata: { stableKey: `fan:${rec.pid}`, fanOut: rec.count, remoteIps: rec.remote_ips },
      };
      for (const det of this.evaluateMatches(fanEvt, evaluateNetworkRules(fanEvt))) out.push(det);
    }

    return out;
  }

  /** Process a port-intelligence snapshot (listeners, endpoints, open events). */
  ingestPortSnapshot(snapshot: PortIntelligenceSnapshot): Detection[] {
    if (!snapshot) return [];

    const out: Detection[] = [];
    for (const evt of normalizePortSnapshot(snapshot)) {
      for (const det of this.evaluateMatches(evt, evaluateNetworkRules(evt))) out.push(det);
    }
    return out;
  }

  /**
   * Process a file scan snapshot. Findings whose artifact is currently running
   * are linked to the owning pid (resolved from the remembered process context)
   * so file detections correlate with process/network detections.
   */
  ingestFileScan(snapshot: FileScanSnapshot): Detection[] {
    if (!snapshot || !Array.isArray(snapshot.findings)) return [];

    const out: Detection[] = [];
    for (const evt of normalizeFileFindings(snapshot, (path) => this.resolvePidForPath(path))) {
      for (const det of this.evaluateMatches(evt, evaluateFileRules(evt))) out.push(det);
    }
    return out;
  }

  /** Look up the remembered process context for a pid (snapshot or event). */
  getProcessContext(pid: number): ProcessContext | null {
    return this.processes.get(pid) ?? null;
  }

  /** Build the parent chain (root ancestor → pid) from remembered context. */
  getAncestry(pid: number): DetectionAncestryNode[] {
    const collected: ProcessContext[] = [];
    const visited = new Set<number>();
    let current: ProcessContext | null | undefined = this.processes.get(pid);

    while (current && collected.length < MAX_ANCESTRY_DEPTH) {
      if (visited.has(current.pid)) break;
      visited.add(current.pid);
      collected.unshift(current);
      if (current.parent_pid == null) break;
      current = this.processes.get(current.parent_pid);
    }

    return collected.map((c) => ({
      pid: c.pid,
      process_name: c.process_name,
      executable_path: c.executable_path ?? null,
      command_line: c.command_line ?? null,
      username: c.username ?? null,
    }));
  }

  /**
   * Resolve the pid of any remembered process whose executable path matches a
   * file (case-insensitive). Used to link a *running* flagged artifact back to
   * its owning process so cross-domain correlation works.
   */
  resolvePidForPath(path: string): number | null {
    if (!path) return null;
    const target = path.toLowerCase();
    for (const [pid, ctx] of this.processes) {
      if (ctx.executable_path && ctx.executable_path.toLowerCase() === target) return pid;
    }
    return null;
  }

  private remember(sec: SecurityEvent): void {
    this.processes.set(sec.pid, {
      pid: sec.pid,
      process_name: sec.process_name,
      executable_path: sec.executable_path ?? null,
      command_line: sec.command_line ?? null,
      parent_pid: sec.parent_pid ?? null,
      parent_process_name: sec.parent_process_name ?? null,
      username: sec.username ?? null,
      timestamp: sec.timestamp,
    });
  }

  private evaluate(sec: SecurityEvent): Detection[] {
    return this.evaluateMatches(sec, evaluateRules(sec));
  }

  /**
   * The stable dedup/correlation unit for an event: the process pid when the
   * owner is known (so PROC/NET/FILE rules correlate across domains), else a
   * domain-scoped stable key (connection/serving port/path).
   */
  private unitOf(sec: ViewEvent): string {
    if (typeof sec.pid === "number" && sec.pid > 0) return String(sec.pid);
    const stableKey = sec.metadata?.stableKey;
    return typeof stableKey === "string" && stableKey.length > 0
      ? stableKey
      : `evt:${sec.id}`;
  }

  private evaluateMatches(sec: ViewEvent, matches: RuleMatch[]): Detection[] {
    const out: Detection[] = [];
    const now = Date.now();
    const unit = this.unitOf(sec);

    for (const match of matches) {
      // Never re-evaluate the exact same event+rule (engine retries / duplicates).
      const exactKey = `${match.rule_id}|${sec.id}`;
      if (this.seen.has(exactKey)) continue;

      // Avoid flooding: at most one detection per unit+rule per hourly window.
      const windowKey = `${match.rule_id}|${unit}|${Math.floor(now / DEDUP_WINDOW_MS)}`;
      if (this.seen.has(windowKey)) {
        this.seen.set(exactKey, now);
        continue;
      }

      this.seen.set(exactKey, now);
      this.seen.set(windowKey, now);
      this.pruneSeen();

      out.push(this.buildDetection(sec, match));
    }

    return out;
  }

  private buildDetection(sec: ViewEvent, match: RuleMatch): Detection {
    const now = Date.now();
    const unit = this.unitOf(sec);
    const correlation = this.correlations.get(unit);

    const correlatedRules: DetectionRuleId[] = [];
    let severity = match.baseSeverity;
    let confidence = match.baseConfidence;

    if (correlation && now - correlation.firstAt <= CORRELATION_WINDOW_MS) {
      correlation.ruleIds.add(match.rule_id);
      const distinct = correlation.ruleIds.size;
      if (distinct >= 2) {
        // More independent rules firing for the same unit = stronger signal.
        severity = escalate(severity, distinct >= 3 ? 2 : 1);
        confidence += (distinct - 1) * 0.05;
        correlatedRules.push(...Array.from(correlation.ruleIds));
      }
    } else {
      this.correlations.set(unit, {
        ruleIds: new Set([match.rule_id]),
        firstAt: now,
      });
    }

    // Explainable confidence modifiers from the available evidence.
    if (sec.command_line && sec.command_line.trim().length > 0) confidence += 0.03;
    if (match.evidence.length >= 2) confidence += 0.02;
    if (sec.type === "PROCESS_SNAPSHOT" && match.baseConfidence > 0) confidence -= 0.05;

    confidence = round2(clamp(confidence, 0.1, 0.95));

    return {
      id: `det-${++this.seq}`,
      rule_id: match.rule_id,
      rule_name: match.rule_name,
      title: match.title,
      severity,
      confidence,
      status: "detected",
      timestamp: new Date(now).toISOString(),
      event_timestamp: sec.timestamp || new Date(now).toISOString(),
      entity: sec.process_name,
      pid: sec.pid,
      executable_path: sec.executable_path ?? null,
      command_line: sec.command_line ?? null,
      parent_pid: sec.parent_pid ?? null,
      parent_process_name: sec.parent_process_name ?? null,
      username: sec.username ?? null,
      hostname: sec.hostname,
      evidence: match.evidence,
      explanation: match.explanation,
      recommended_action: match.recommended_action,
      correlated_rules: correlatedRules.length > 0 ? correlatedRules : undefined,
      ancestry: this.getAncestry(sec.pid),
      related_event_id: sec.id,
    };
  }

  private pruneSeen(): void {
    if (this.seen.size <= MAX_SEEN_ENTRIES) return;
    const cutoff = Date.now() - SEEN_PRUNE_AGE_MS;
    for (const [key, ts] of this.seen) {
      if (ts < cutoff) this.seen.delete(key);
    }
  }
}

/** Detection singleton used by the API server. */
export const detectionEngine = new DetectionEngine();