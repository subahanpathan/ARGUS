/**
 * Bounded in-memory store for impact incidents and their recovery state.
 *
 * Deliberately in-memory, like `EventHub`: recovery state is derived from live
 * telemetry, and the durable shape lives in the Drizzle schema. The store is
 * bounded on three axes so a burst of file events cannot exhaust memory —
 * incidents, affected files per incident, and evidence entries per file.
 *
 * Deduplication is keyed on detection id, and within a detection on the
 * canonical path, so the same file reported by several telemetry sources
 * collapses into one record that keeps every evidence reference.
 */

import { eventHub } from "../lib/event-hub";
import type {
  AffectedFile,
  ImpactIncident,
  RecoveryLimits,
  RecoveryPhase,
  RecoveryPipelineStage,
  RecoveryProgress,
  RecoverySnapshot,
  RecoverySourceSupport,
  RecoveryState,
  RecoverySummary,
} from "./types";
import { RECOVERY_PIPELINE_STAGES } from "./types";

/** Hard caps. Overridable downward by the service, never upward. */
export const DEFAULT_LIMITS: RecoveryLimits = {
  maxAffectedFilesPerIncident: 500,
  maxSourcesPerFile: 4,
  maxAttemptsPerFile: 2,
  maxHashBytes: 256 * 1024 * 1024,
  maxEvidenceRefsPerFile: 24,
  sourceSearchTimeoutMs: 15_000,
  maxIncidentHistory: 25,
};

/** Where the pipeline is, given which stages a phase implies. */
const PHASE_STAGES: Record<RecoveryPhase, RecoveryPipelineStage[]> = {
  QUEUED: ["THREAT_DETECTED"],
  DISCOVERING: ["THREAT_DETECTED", "IMPACT_DISCOVERY"],
  SOURCE_SEARCH: ["THREAT_DETECTED", "IMPACT_DISCOVERY", "RECOVERY_SOURCE_SEARCH"],
  RECOVERING: ["THREAT_DETECTED", "IMPACT_DISCOVERY", "RECOVERY_SOURCE_SEARCH", "SAFE_RECOVERY"],
  VERIFYING: ["THREAT_DETECTED", "IMPACT_DISCOVERY", "RECOVERY_SOURCE_SEARCH", "SAFE_RECOVERY", "VERIFICATION"],
  COMPLETE: [...RECOVERY_PIPELINE_STAGES],
  FAILED: ["THREAT_DETECTED"],
};

/** Count records in one recovery state. */
function countInState(files: readonly AffectedFile[], state: RecoveryState): number {
  return files.reduce((total, file) => (file.recovery_state === state ? total + 1 : total), 0);
}

function countDamage(files: readonly AffectedFile[], classification: AffectedFile["damage"]): number {
  return files.reduce((total, file) => (file.damage === classification ? total + 1 : total), 0);
}

export class RecoveryStore {
  private readonly incidents = new Map<string, ImpactIncident>();
  /** detection_id -> incident_id, so re-investigating a detection is a no-op. */
  private readonly incidentByDetection = new Map<string, string>();
  private limits: RecoveryLimits = { ...DEFAULT_LIMITS };
  private lastError: string | null = null;
  /** Incremented on every mutation, so the UI can cheaply detect staleness. */
  private revision = 0;

  configure(limits: Partial<RecoveryLimits>): RecoveryLimits {
    this.limits = { ...this.limits, ...limits };
    return this.limits;
  }

  getLimits(): RecoveryLimits {
    return this.limits;
  }

  getRevision(): number {
    return this.revision;
  }

  getLastError(): string | null {
    return this.lastError;
  }

  setLastError(message: string | null): void {
    this.lastError = message;
  }

  /** True once at least one incident exists. Drives "no data" vs "no findings". */
  hasObservedAnything(): boolean {
    return this.incidents.size > 0;
  }

  getIncident(incidentId: string): ImpactIncident | null {
    const incident = this.incidents.get(incidentId);
    return incident ? structuredClone(incident) : null;
  }

  /** The incident already created for a detection, if any. */
  getIncidentByDetection(detectionId: string): ImpactIncident | null {
    const incidentId = this.incidentByDetection.get(detectionId);
    return incidentId ? this.getIncident(incidentId) : null;
  }

  listIncidents(limit = this.limits.maxIncidentHistory): ImpactIncident[] {
    const all = [...this.incidents.values()].sort((a, b) => b.created_at.localeCompare(a.created_at));
    return all.slice(0, Math.max(1, limit)).map((incident) => structuredClone(incident));
  }

  /**
   * Insert an incident, evicting the oldest beyond the history cap.
   *
   * Returns the stored incident, or the pre-existing one when this detection was
   * already investigated — which is what makes triggering idempotent.
   */
  upsertIncident(incident: ImpactIncident): { incident: ImpactIncident; created: boolean } {
    const existingId = this.incidentByDetection.get(incident.detection_id);
    if (existingId) {
      const existing = this.incidents.get(existingId);
      if (existing) {
        existing.updated_at = incident.updated_at;
        return { incident: structuredClone(existing), created: false };
      }
    }

    this.incidents.set(incident.incident_id, incident);
    this.incidentByDetection.set(incident.detection_id, incident.incident_id);

    while (this.incidents.size > this.limits.maxIncidentHistory) {
      const oldest = [...this.incidents.values()].sort((a, b) => a.created_at.localeCompare(b.created_at))[0];
      if (!oldest) break;
      this.incidents.delete(oldest.incident_id);
      this.incidentByDetection.delete(oldest.detection_id);
    }

    this.revision += 1;
    return { incident: structuredClone(incident), created: true };
  }

  /** Locate the affected-file record for a path within an incident. */
  findRecord(incidentId: string, recordId: string): AffectedFile | null {
    const incident = this.incidents.get(incidentId);
    if (!incident) return null;
    const found = incident.affected_files.find((file) => file.record_id === recordId);
    return found ? structuredClone(found) : null;
  }

  /**
   * Add or merge an affected-file record.
   *
   * Merging keeps the first-seen time, widens the observation window, unions the
   * evidence list and picks the strongest attribution basis seen so far.
   */
  mergeRecord(incidentId: string, record: AffectedFile): { record: AffectedFile | null; created: boolean } {
    const incident = this.incidents.get(incidentId);
    if (!incident) throw new Error(`unknown incident ${incidentId}`);

    const index = incident.affected_files.findIndex((file) => file.record_id === record.record_id);
    if (index === -1) {
      if (incident.affected_files.length < this.limits.maxAffectedFilesPerIncident) {
        incident.affected_files.push(record);
        this.recompute(incident);
        this.revision += 1;
        return { record: structuredClone(record), created: true };
      }
      // At the per-incident cap: report honestly rather than silently dropping.
      incident.affected_files_truncated = true;
      this.recompute(incident);
      return { record: null, created: false };
    }

    const existing = incident.affected_files[index];
    const merged: AffectedFile = {
      ...existing,
      // Latest observation wins for "current" facts.
      operation: rankOperation(record.operation) > rankOperation(existing.operation) ? record.operation : existing.operation,
      previous_path: existing.previous_path ?? record.previous_path,
      last_seen_at: record.last_seen_at > existing.last_seen_at ? record.last_seen_at : existing.last_seen_at,
      observation_count: existing.observation_count + 1,
      pid: existing.pid ?? record.pid,
      process_name: existing.process_name ?? record.process_name,
      process_ancestry: existing.process_ancestry.length > 0 ? existing.process_ancestry : record.process_ancestry,
      attribution: rankAttribution(record.attribution) > rankAttribution(existing.attribution) ? record.attribution : existing.attribution,
      attribution_strength:
        rankAttribution(record.attribution) > rankAttribution(existing.attribution) ? record.attribution_strength : existing.attribution_strength,
      previous_metadata: existing.previous_metadata ?? record.previous_metadata,
      current_metadata: record.current_metadata,
      damage: rankDamage(record.damage) > rankDamage(existing.damage) ? record.damage : existing.damage,
      damage_signals: dedupeBy([...existing.damage_signals, ...record.damage_signals], (signal) => signal.kind),
      evidence: dedupeBy([...existing.evidence, ...record.evidence], (item) => `${item.source}:${item.ref}`).slice(
        0,
        this.limits.maxEvidenceRefsPerFile,
      ),
      notes: [...new Set([...existing.notes, ...record.notes])],
    };

    incident.affected_files[index] = merged;
    this.recompute(incident);
    this.revision += 1;
    return { record: structuredClone(merged), created: false };
  }

  /** Replace one affected-file record wholesale (used by the recovery engine). */
  updateRecord(incidentId: string, record: AffectedFile): AffectedFile | null {
    const incident = this.incidents.get(incidentId);
    if (!incident) return null;
    const index = incident.affected_files.findIndex((file) => file.record_id === record.record_id);
    if (index === -1) return null;
    incident.affected_files[index] = record;
    this.recompute(incident);
    this.revision += 1;
    return structuredClone(record);
  }

  /** Move an incident to a new phase and broadcast the change. */
  setPhase(incidentId: string, phase: RecoveryPhase, error?: { stage: string; message: string }): ImpactIncident | null {
    const incident = this.incidents.get(incidentId);
    if (!incident) return null;
    incident.phase = phase;
    incident.stages_reached = [...PHASE_STAGES[phase]];
    incident.updated_at = new Date().toISOString();
    if (error) {
      incident.errors.push({ at: incident.updated_at, stage: error.stage, message: error.message });
    }
    this.recompute(incident);
    this.revision += 1;
    const snapshot = structuredClone(incident);
    eventHub.publish("recovery.incident", { incident: snapshot, revision: this.revision });
    return snapshot;
  }

  /** Broadcast a record-level change (recovery found, verified, failed, ...). */
  publishRecord(record: AffectedFile, revision = this.revision): void {
    eventHub.publish("recovery.record", { record, revision });
  }

  /** Recompute derived progress for an incident from its records. */
  private recompute(incident: ImpactIncident): void {
    const files = incident.affected_files;
    const progress: RecoveryProgress = {
      total: files.length,
      discovered: files.filter((file) => file.recovery_state !== "DISCOVERED").length,
      sources_found: countInState(files, "RECOVERY_SOURCE_FOUND"),
      attempted: countInState(files, "RECOVERY_ATTEMPTED") + countInState(files, "RECOVERED") + countInState(files, "VERIFIED"),
      recovered: countInState(files, "RECOVERED"),
      verified: countInState(files, "VERIFIED"),
      unrecoverable: countInState(files, "UNRECOVERABLE"),
      stage_percent: stagePercent(incident.phase),
    };
    incident.progress = progress;
    incident.updated_at = new Date().toISOString();

    // An investigation is finished once every record reached a terminal state.
    const terminal = countInState(files, "VERIFIED") + countInState(files, "UNRECOVERABLE") + countInState(files, "NO_RECOVERY_SOURCE");
    if (files.length > 0 && terminal === files.length) {
      incident.phase = "COMPLETE";
      incident.stages_reached = [...RECOVERY_PIPELINE_STAGES];
      incident.progress.stage_percent = 100;
    }
  }

  /**
   * Counts for the API and UI.
   *
   * Every field is a tally over retained records. `encryptedSuspectedFiles` is a
   * subset of the operation counters, which the payload states explicitly so the
   * UI does not add it to `modifiedFiles`.
   */
  buildSummary(): RecoverySummary {
    const incidents = [...this.incidents.values()];
    const files = incidents.flatMap((incident) => incident.affected_files);
    const activeCount = (state: RecoveryState): number => countInState(files, state);
    const availableSources = files.reduce(
      (total, file) => total + file.recovery_sources.filter((source) => source.available).length,
      0,
    );

    return {
      generatedAt: new Date().toISOString(),
      affectedFiles: files.length,
      modifiedFiles: countDamage(files, "MODIFIED"),
      deletedFiles: countDamage(files, "DELETED"),
      renamedFiles: countDamage(files, "RENAMED"),
      createdFiles: countDamage(files, "CREATED"),
      encryptedSuspectedFiles: countDamage(files, "ENCRYPTED_OR_CORRUPTED_SUSPECTED"),
      unknownDamageFiles: countDamage(files, "UNKNOWN"),
      recoveryCandidates: activeCount("RECOVERY_CANDIDATE"),
      recoverySourceFound: activeCount("RECOVERY_SOURCE_FOUND"),
      recoveryAttempted: activeCount("RECOVERY_ATTEMPTED"),
      recovered: activeCount("RECOVERED"),
      verified: activeCount("VERIFIED"),
      unrecoverable: activeCount("UNRECOVERABLE"),
      noRecoverySource: activeCount("NO_RECOVERY_SOURCE"),
      recoverySourcesFound: availableSources,
      incidents: incidents.length,
      incidentsInvestigating: incidents.filter((incident) => incident.phase !== "COMPLETE" && incident.phase !== "FAILED").length,
      inferredAttribution: files.filter((file) => file.attribution_strength === "INFERRED").length,
      uncertainAttribution: files.filter((file) => file.attribution_strength === "ATTRIBUTION_UNCERTAIN").length,
      damageClassificationTotals:
        "the six damage counters are mutually exclusive and sum to affectedFiles: a file classified as suspected encryption is counted in encryptedSuspectedFiles and not also in modifiedFiles",
      evidenceCompleteness: {
        hashed: files.filter((file) => file.current_metadata.sha256 !== null).length,
        hashSkipped: files.filter((file) => file.current_metadata.sha256 === null && file.current_metadata.exists !== false).length,
        missingOnDisk: files.filter((file) => file.current_metadata.exists === false).length,
        unreadable: files.filter((file) => file.notes.some((note) => note.includes("could not be read"))).length,
      },
    };
  }

  /** Full snapshot for `GET /api/recovery`. */
  buildSnapshot(sources: RecoverySourceSupport, recoveryRoot: string | null, enabled: boolean): RecoverySnapshot {
    const incidents = this.listIncidents();
    const stages = RECOVERY_PIPELINE_STAGES.map((stage) => ({
      stage,
      reached: incidents.some((incident) => incident.stages_reached.includes(stage)),
    }));
    return {
      generatedAt: new Date().toISOString(),
      observed: this.hasObservedAnything(),
      enabled,
      stages,
      summary: this.buildSummary(),
      incidents,
      sources,
      recoveryRoot,
      limits: this.limits,
      lastError: this.lastError,
    };
  }

  /** Clear everything (tests, admin reset, eventHub.reset()). */
  reset(): void {
    this.incidents.clear();
    this.incidentByDetection.clear();
    this.limits = { ...DEFAULT_LIMITS };
    this.lastError = null;
    this.revision = 0;
  }
}

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

/** Progress percentage over pipeline stages. */
function stagePercent(phase: RecoveryPhase): number {
  const reached = PHASE_STAGES[phase].length;
  return Math.round((reached / RECOVERY_PIPELINE_STAGES.length) * 100);
}

/** Later operations win when two sources disagree about the same path. */
function rankOperation(operation: AffectedFile["operation"]): number {
  return ["UNKNOWN", "DIRECTORY_CHANGED", "CREATED", "MODIFIED", "RENAMED", "DELETED"].indexOf(operation);
}

/** Strongest damage class wins, so an escalation is never lost on merge. */
function rankDamage(damage: AffectedFile["damage"]): number {
  return [
    "UNKNOWN",
    "CREATED",
    "MODIFIED",
    "RENAMED",
    "DELETED",
    "ENCRYPTED_OR_CORRUPTED_SUSPECTED",
  ].indexOf(damage);
}

/**
 * Exact identifiers outrank directory co-location, which outranks the bare time
 * window. The order is weakest-first so a plain `indexOf` comparison ranks
 * strength correctly.
 */
function rankAttribution(basis: AffectedFile["attribution"]): number {
  return [
    "INCIDENT_TIME_WINDOW",
    "PROCESS_LINEAGE_DIRECTORY",
    "PROCESS_ANCESTRY_PATH",
    "ENGINE_FILE_DETECTION",
    "PROCESS_EXECUTABLE_PATH",
    "SECURITY_PROVIDER_RESOURCE",
  ].indexOf(basis);
}

function dedupeBy<T>(items: readonly T[], key: (item: T) => string): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const item of items) {
    const id = key(item);
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(item);
  }
  return out;
}

export const recoveryStore = new RecoveryStore();
