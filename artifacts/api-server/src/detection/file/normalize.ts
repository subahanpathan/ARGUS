/**
 * Normalization layer for the FILE/PERSISTENCE detection domain: converts a
 * real filesystem threat scan (the FileFinding list produced by the engine's
 * read-only scanner) into FileViewEvents for the FILE rules. When a finding is
 * currently executing, the owning pid is resolved from the process context so
 * file detections can correlate with process and network detections.
 */

import { HOSTNAME } from "../normalize";
import type { FileScanSnapshot } from "../../lib/event-hub";
import type { FileViewEvent } from "../types";

export type PidResolver = (path: string) => number | null;

/**
 * Normalize every finding in a file scan snapshot into a FileViewEvent.
 * `pid` is 0 when the artifact is not running or its owner could not be
 * resolved from the remembered process context.
 */
export function normalizeFileFindings(
  snapshot: FileScanSnapshot,
  resolvePid: PidResolver,
): FileViewEvent[] {
  if (!snapshot || !Array.isArray(snapshot.findings)) return [];
  const timestamp = snapshot.timestamp || new Date().toISOString();

  return snapshot.findings.map((f) => {
    const isRunning = f.is_running === true;
    const pid = isRunning ? resolvePid(f.path) ?? 0 : 0;
    const pathLower = f.path.toLowerCase();
    return {
      id: `file:${f.id}`,
      type: "FILE_FINDING",
      origin: "snapshot",
      timestamp,
      source: f.source || "file_scanner",
      hostname: HOSTNAME,
      pid,
      process_name: f.name || f.path.split(/[\\/]/).pop() || "unknown",
      file_path: f.path,
      file_name: f.name,
      file_extension: f.extension,
      file_hash: f.hash,
      file_size: f.size_bytes,
      file_modified: f.modified,
      category: f.category,
      className: f.className,
      is_running: isRunning,
      finding_severity: f.severity,
      finding_reason: f.reason,
      executable_path: f.path,
      metadata: { stableKey: `file:${pathLower}` },
    };
  });
}