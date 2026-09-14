/**
 * Normalization layer: converts raw process telemetry into SecurityEvents.
 * Every event is stamped with the real hostname and marked as real
 * ("observed") telemetry so downstream consumers never confuse detections
 * with demo/fabricated data.
 */

import os from "node:os";
import type { ProcessEvent, ProcessSnapshot } from "../lib/event-hub";
import type {
  SecurityEvent,
  SecurityEventOrigin,
  SecurityEventType,
} from "./types";

export const HOSTNAME: string | null = os.hostname();

function eventType(type: string): SecurityEventType {
  if (type === "PROCESS_TERMINATED") return "PROCESS_TERMINATED";
  return "PROCESS_CREATED";
}

/**
 * Normalize a single raw process event (start/terminate) into a SecurityEvent.
 * Returns null for events that cannot be normalized (e.g. non-process SNAPSHOT
 * events, which are handled via the snapshot endpoint instead).
 */
export function normalizeProcessEvent(event: ProcessEvent): SecurityEvent | null {
  if (!event) return null;
  if (typeof event.pid !== "number" || typeof event.process_name !== "string") {
    return null;
  }
  if (event.event_type !== "PROCESS_STARTED" && event.event_type !== "PROCESS_TERMINATED") {
    return null;
  }

  const metadata = event.metadata ?? {};
  const username = typeof metadata.username === "string" ? metadata.username : null;

  return {
    id: event.id,
    type: eventType(event.event_type),
    origin: "created" as SecurityEventOrigin,
    timestamp: event.timestamp || new Date().toISOString(),
    source: event.source || "unknown",
    hostname: HOSTNAME,
    pid: event.pid,
    process_name: event.process_name,
    executable_path: event.executable_path ?? null,
    command_line: event.command_line ?? null,
    parent_pid: event.parent_pid ?? null,
    parent_process_name: event.parent_process_name ?? null,
    username,
    metadata,
  };
}

/** Normalize every process in a snapshot into a SecurityEvent (origin "snapshot"). */
export function normalizeSnapshotProcesses(snapshot: ProcessSnapshot): SecurityEvent[] {
  if (!snapshot || !Array.isArray(snapshot.processes)) return [];

  const timestamp = snapshot.timestamp || new Date().toISOString();

  return snapshot.processes.map((p) => ({
    id: `snap:${p.pid}:${timestamp}`,
    type: "PROCESS_SNAPSHOT" as SecurityEventType,
    origin: "snapshot" as SecurityEventOrigin,
    timestamp,
    source: "windows_process_monitor",
    hostname: HOSTNAME,
    pid: p.pid,
    process_name: p.name || String(p.pid),
    executable_path: p.executable_path ?? null,
    command_line: p.command_line ?? null,
    parent_pid: p.parent_pid ?? null,
    parent_process_name: p.parent_name ?? null,
    username: p.username ?? null,
  }));
}