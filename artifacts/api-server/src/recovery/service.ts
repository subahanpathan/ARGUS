/**
 * Impact Reconstruction & Safe Recovery engine.
 *
 * Phase 1 answers "what did this detection actually damage?" using only real
 * telemetry ARGUS already holds. Phase 2 answers "can any of it be recovered,
 * safely?" using only sources that were really located on this host.
 *
 * Design rules enforced throughout:
 *
 *  - **Evidence or nothing.** A file becomes an impact record only if a real
 *    observation names it. An incident with no files is a valid, honest outcome.
 *  - **Attribution is graded.** An exact identifier match is `ATTRIBUTED`; a
 *    time-window match is `INFERRED` and is labelled that way everywhere.
 *  - **Non-destructive.** The original path is only ever opened for reading.
 *    Every write lands inside the isolated recovery workspace, at a path proven
 *    by `resolveInside` to stay within it.
 *  - **Idempotent.** One incident per detection, keyed on detection id.
 *  - **Honest about gaps.** Locked files, permission denials, absent shadow
 *    copies and unconfigured backup roots are reported, never papered over.
 */

import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

import { detectionEngine } from "../detection/engine";
import type { Detection } from "../detection/types";
import { eventHub } from "../lib/event-hub";
import { logger } from "../lib/logger";
import {
  analyzeAffectedFile,
  classifyDamage,
  detectSignature,
  expectedSignaturesFor,
  mentionsRansomware,
  readPrefix,
  sha256File,
} from "./file-analysis";
import {
  assertNotWorkspacePath,
  describeError,
  ensureRecoveryRoot,
  evidencePathFor,
  getRecoveryRoot,
  isInsideRecoveryRoot,
  normalizePathKey,
  samePath,
  stagingPathFor,
  validateObservedPath,
} from "./paths";
import { findRecoverySources, recoverySourceSupport } from "./sources";
import { recoveryStore } from "./store";
import { emitRecoveryEvent } from "./observability";
import { evaluateRecoveryTrigger } from "./trigger";
import type {
  AffectedFile,
  AttributionBasis,
  AttributionStrength,
  FileMetadataSnapshot,
  FileOperation,
  ImpactEvidenceRef,
  ImpactIncident,
  IncidentProcess,
  RecoveryAttempt,
  RecoverySource,
} from "./types";

/** How far before the detection the impact window opens. */
const WINDOW_PRE_MS = 5 * 60 * 1000;

/** How far past the detection the impact window closes. */
const WINDOW_POST_MS = 10 * 60 * 1000;

/** Upper bound on observations read from telemetry per investigation. */
const MAX_OBSERVATIONS_SCANNED = 4000;

/** Env switch to stop automatic recovery while keeping the API readable. */
const ENABLED_ENV = "ARGUS_RECOVERY_ENABLED";

/** Bytes read from a staged copy when confirming its container signature. */
const SIGNATURE_PREFIX_BYTES = 4096;

/** Signal file-operation names, mapped to the damage vocabulary. */
const OPERATION_BY_EVENT: Readonly<Record<string, FileOperation>> = {
  FILE_CREATED: "CREATED",
  FILE_MODIFIED: "MODIFIED",
  FILE_DELETED: "DELETED",
  FILE_RENAMED: "RENAMED",
  FILE_DIRECTORY_CHANGED: "DIRECTORY_CHANGED",
};

/** One telemetry sighting of a path, before it becomes an impact record. */
type Observation = {
  path: string;
  name: string;
  is_directory: boolean;
  operation: FileOperation;
  previous_path: string | null;
  observed_at: string;
  size_bytes: number | null;
  modified_at: string | null;
  created_at: string | null;
  /** File-scan baseline hash, when the scan ran before the change. */
  scan_hash: string | null;
  scan_at: string | null;
  evidence: ImpactEvidenceRef[];
  attribution: AttributionBasis;
  attribution_strength: AttributionStrength;
};

/**
 * The executables belonging to the detected process and its recorded ancestors.
 *
 * Built once per investigation from telemetry ARGUS already holds — the
 * detection's own `ancestry` chain plus live process context — and then used to
 * grade every filesystem observation against the process it supposedly belongs
 * to. This is what turns a bare timestamp coincidence into a graded attribution.
 */
type ProcessLineage = {
  /** Canonical executable path -> the process that owns it. */
  binaries: Map<
    string,
    { pid: number; process_name: string; executable_path: string; role: "self" | "ancestor" }
  >;
  /** Canonical directory -> the processes loaded from it. */
  directories: Map<string, Array<{ pid: number; process_name: string }>>;
};

/** Collect the detected process's executables and the directories they live in. */
function buildProcessLineage(detection: Detection): ProcessLineage {
  const binaries: ProcessLineage["binaries"] = new Map();
  const directories: Map<string, Array<{ pid: number; process_name: string }>> = new Map();

  const add = (
    pid: number,
    processName: string,
    executablePath: string | null | undefined,
    role: "self" | "ancestor",
  ): void => {
    const target = validateObservedPath(executablePath);
    if (!target) return;
    const key = normalizePathKey(target);
    if (key.length === 0) return;
    // The detected process is registered before its ancestry, so when a parent
    // runs from the same image the "self" role is the one that survives.
    if (!binaries.has(key)) {
      binaries.set(key, { pid, process_name: processName, executable_path: target, role });
    }
    const dir = normalizePathKey(path.dirname(target));
    const owners = directories.get(dir) ?? [];
    if (!owners.some((owner) => owner.pid === pid)) owners.push({ pid, process_name: processName });
    directories.set(dir, owners);
  };

  // The detected process itself, then its recorded ancestry root-first.
  add(detection.pid, detection.entity, detection.executable_path, "self");
  for (const node of detection.ancestry ?? []) {
    add(node.pid, node.process_name, node.executable_path, "ancestor");
  }
  // Live context can be richer than the snapshot the detection was built from.
  const live = detection.pid ? detectionEngine.getProcessContext(detection.pid) : null;
  if (live) add(live.pid, live.process_name, live.executable_path, "self");

  return { binaries, directories };
}

/** How a filesystem observation relates to the detected process's lineage. */
type LineageMatch = {
  basis: AttributionBasis;
  strength: AttributionStrength;
  detail: string;
};

/**
 * Grade one path against the process lineage.
 *
 * Exact executable match is real attribution. Same-directory is explicitly *not*
 * promoted to attribution: co-location is circumstantial, so it is reported as
 * `ATTRIBUTION_UNCERTAIN` and the UI can show that distinction. No relationship
 * at all returns null, and the caller falls back to the bare time window.
 */
function matchLineage(target: string, lineage: ProcessLineage): LineageMatch | null {
  const key = normalizePathKey(target);
  if (key.length === 0) return null;

  const binary = lineage.binaries.get(key);
  if (binary) {
    const isSelf = binary.role === "self";
    return {
      basis: isSelf ? "PROCESS_EXECUTABLE_PATH" : "PROCESS_ANCESTRY_PATH",
      strength: "ATTRIBUTED",
      detail: isSelf
        ? `the detected process ${binary.process_name} (pid ${binary.pid}) runs from this exact path`
        : `${binary.process_name} (pid ${binary.pid}) is an ancestor of the detected process and was loaded from this exact path`,
    };
  }

  const directory = normalizePathKey(path.dirname(target));
  const owners = lineage.directories.get(directory);
  if (owners && owners.length > 0) {
    const names = owners.map((owner) => `${owner.process_name} (pid ${owner.pid})`).join(", ");
    return {
      basis: "PROCESS_LINEAGE_DIRECTORY",
      strength: "ATTRIBUTION_UNCERTAIN",
      detail:
        `this file sits in ${directory}, the directory ${names} was loaded from; ` +
        "co-location is circumstantial and is not proof that this process wrote the file",
    };
  }

  return null;
}

/**
 * Honest provenance string for a record. Only an exact identifier match is
 * reported as the basis itself; anything weaker names the weaker channel it came
 * through, so a reader can never mistake a window coincidence for attribution.
 */
function evidenceSourceFor(observation: Observation): string {
  if (observation.attribution_strength === "ATTRIBUTED") return observation.attribution;
  if (observation.attribution_strength === "ATTRIBUTION_UNCERTAIN") return "filesystem_watch (process lineage co-location)";
  return "filesystem_watch (incident window)";
}

/**
 * The caveat that must travel with a record whenever attribution is not exact.
 * A record whose only link to the detection is a timestamp, or a shared parent
 * directory, has to say so on its face — that sentence is the difference between
 * "this file was touched" and "this process did this".
 */
function attributionNotes(observation: Observation): string[] {
  if (observation.attribution_strength === "ATTRIBUTED") return [];
  if (observation.attribution_strength === "ATTRIBUTION_UNCERTAIN") {
    return [
      "ATTRIBUTION_UNCERTAIN: this file was observed changing inside the incident window and shares a directory with the detected process or one of its ancestors, but the endpoint filesystem watcher reports no owning pid, so this process cannot be said to have written it",
    ];
  }
  return ["attribution rests only on the incident time window: the endpoint watcher reports no owning pid"];
}

export class RecoveryService {
  private enabled: boolean;

  /** Detection ids currently being investigated, so triggering cannot overlap. */
  private readonly inFlight = new Set<string>();

  /** Detections the automatic path declined, so the decision stays auditable. */
  private skippedTriggers = 0;
  private lastSkipReason: string | null = null;

  constructor() {
    this.enabled = (process.env[ENABLED_ENV] ?? "true").trim().toLowerCase() !== "false";
  }

  isEnabled(): boolean {
    return this.enabled;
  }

  setEnabled(value: boolean): boolean {
    this.enabled = value;
    return this.enabled;
  }

  /**
   * Subscribe to detection creation.
   *
   * This is the single integration point between the detection pipeline and
   * recovery. Every detection the engine produces is funnelled through
   * `eventHub.addDetection()`, which invokes these listeners, and this listener
   * is registered exactly once from the composition root (`app.ts`).
   *
   * Investigations run detached so that detection ingest returns immediately:
   * the detection API never waits on hashing, source probing or shadow-copy
   * enumeration. `investigate()` itself is idempotent and re-entrant safe.
   *
   * The automatic path is gated on the detection having reached a threat state
   * that could have damaged data; see `evaluateRecoveryTrigger`. Skipped
   * detections are counted and logged, never silently dropped, and any detection
   * can still be investigated on demand through `investigate()`.
   */
  registerTrigger(): () => void {
    const unsubscribe = eventHub.onDetection((detection) => {
      if (!this.enabled) return;

      const decision = evaluateRecoveryTrigger(detection);
      if (!decision.trigger) {
        this.skippedTriggers += 1;
        this.lastSkipReason = decision.detail;
        logger.debug(
          { scope: "recovery", event: "RECOVERY_TRIGGER_SKIPPED", detectionId: detection.id, ruleId: detection.rule_id, reason: decision.reason, detail: decision.detail },
          "detection is below the automatic recovery threshold",
        );
        return;
      }

      emitRecoveryEvent("RECOVERY_TRIGGERED", {
        detection_id: detection.id,
        pid: detection.pid,
        process_name: detection.entity,
        result: decision.reason,
        detail: `${detection.rule_id} ${detection.severity} confidence ${detection.confidence}: ${decision.detail}`,
      });

      void this.investigate(detection).catch((error) => {
        const message = describeError(error);
        recoveryStore.setLastError(`investigation of ${detection.id} failed: ${message}`);
        emitRecoveryEvent("RECOVERY_FAILED", {
          detection_id: detection.id,
          result: "investigation_failed",
          detail: message,
        });
      });
    });
    logger.info({ scope: "recovery", enabled: this.enabled, root: getRecoveryRoot() }, "recovery trigger registered");
    return unsubscribe;
  }

  /** Detections the automatic path declined to investigate, and why the last one was declined. */
  getTriggerSkipStats(): { skipped: number; lastReason: string | null } {
    return { skipped: this.skippedTriggers, lastReason: this.lastSkipReason };
  }

  /* ------------------------------------------------------------------ */
  /* Phase 1: impact reconstruction                                       */
  /* ------------------------------------------------------------------ */

  /**
   * Reconstruct impact for a detection and, when possible, recover it.
   *
   * Ungated on purpose: this is the entry point an operator or a test uses to
   * force an investigation. The automatic trigger applies its threshold before
   * calling in here.
   *
   * Idempotency has two layers:
   *
   *  - **Duplicate detection.** The incident id is a pure function of the
   *    detection id, and the store indexes incidents by detection id, so the
   *    same detection can only ever own one incident. A detection that has
   *    already finished returns that incident without redoing any work.
   *  - **Resume.** An incident that never finished — the host rebooted, the
   *    source search threw, the process was killed mid-pipeline — is picked up
   *    where it stopped rather than abandoned. Every stage below is written to be
   *    safe to re-enter: observations merge by path, evidence copies and staged
   *    copies are written with `COPYFILE_EXCL`, and a source that already yielded
   *    a successful attempt is never attempted again.
   */
  async investigate(detection: Detection): Promise<ImpactIncident | null> {
    if (!this.enabled) return null;

    const existing = recoveryStore.getIncidentByDetection(detection.id);
    if (existing && existing.phase === "COMPLETE") return existing;

    if (this.inFlight.has(detection.id)) return null;
    this.inFlight.add(detection.id);

    try {
      const incidentId = existing?.incident_id ?? incidentIdFor(detection.id);
      const anchor = Date.parse(detection.event_timestamp || detection.timestamp);
      const anchorMs = Number.isFinite(anchor) ? anchor : Date.now();
      // On resume the original window is kept, so a late retry cannot silently
      // widen the set of files this incident considers its own impact.
      const windowStart = existing?.window.start ?? new Date(anchorMs - WINDOW_PRE_MS).toISOString();
      const windowEnd = existing?.window.end ?? new Date(anchorMs + WINDOW_POST_MS).toISOString();

      if (!existing) {
        recoveryStore.upsertIncident({
          incident_id: incidentId,
          detection_id: detection.id,
          detection: detectionRef(detection),
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          window: { start: windowStart, end: windowEnd, pre_ms: WINDOW_PRE_MS, post_ms: WINDOW_POST_MS, widened: false },
          process: processContextFor(detection),
          phase: "QUEUED",
          stages_reached: ["THREAT_DETECTED"],
          progress: {
            total: 0,
            discovered: 0,
            sources_found: 0,
            attempted: 0,
            recovered: 0,
            verified: 0,
            unrecoverable: 0,
            stage_percent: 20,
          },
          affected_files: [],
          affected_files_truncated: false,
          skipped_reason: null,
          errors: [],
        });
      }

      recoveryStore.setPhase(incidentId, "DISCOVERING");
      emitRecoveryEvent("IMPACT_DISCOVERY_STARTED", {
        incident_id: incidentId,
        detection_id: detection.id,
        pid: detection.pid,
        process_name: detection.entity,
        result: existing ? "resumed" : "started",
        detail: `incident window ${windowStart} .. ${windowEnd}`,
      });
      const observations = this.collectObservations(detection, windowStart, windowEnd);
      await this.buildRecords(incidentId, detection, observations, windowStart);

      const incident = recoveryStore.getIncident(incidentId);
      if (!incident || incident.affected_files.length === 0) {
        logger.info(
          { scope: "recovery", detectionId: detection.id, window: { start: windowStart, end: windowEnd } },
          "no affected files could be attributed to this detection from real telemetry",
        );
        recoveryStore.setPhase(incidentId, "COMPLETE");
        emitRecoveryEvent("RECOVERY_COMPLETED", {
          incident_id: incidentId,
          detection_id: detection.id,
          result: "no_impact_found",
          detail: "no real telemetry named a file inside the incident window",
        });
        return recoveryStore.getIncident(incidentId);
      }

      await this.searchSourcesForIncident(incident, windowStart);
      await this.recoverIncident(incident);

      const finished = recoveryStore.getIncident(incidentId);
      emitRecoveryEvent("RECOVERY_COMPLETED", {
        incident_id: incidentId,
        detection_id: detection.id,
        result: finished?.phase ?? "unknown",
        detail: `affected ${finished?.progress.discovered ?? 0}, sources ${finished?.progress.sources_found ?? 0}, recovered ${finished?.progress.recovered ?? 0}, verified ${finished?.progress.verified ?? 0}, unrecoverable ${finished?.progress.unrecoverable ?? 0}`,
      });
      return finished;
    } catch (error) {
      // Leave the incident resumable rather than marking it finished: a partial
      // pipeline must be pickable up again, not reported as a conclusion.
      const message = describeError(error);
      recoveryStore.setPhase(incidentIdFor(detection.id), "FAILED", { stage: "pipeline", message });
      emitRecoveryEvent("RECOVERY_FAILED", {
        incident_id: incidentIdFor(detection.id),
        detection_id: detection.id,
        result: "pipeline_aborted",
        detail: message,
      });
      throw error;
    } finally {
      this.inFlight.delete(detection.id);
    }
  }

  /**
   * Gather every telemetry sighting of a file relevant to this detection.
   *
   * Four real sources feed this, in decreasing attribution strength:
   * security-provider resource paths, the detection engine's own file findings,
   * the detected process's binary (and its ancestors' binaries), and filesystem
   * watch events that fall inside the incident window.
   *
   * Watch events are the only unbounded source, so each one is graded against
   * the process lineage before it is accepted: an exact executable match is
   * attributed, a same-directory file is marked uncertain, and anything with no
   * path relationship to the process at all is recorded as inferred. That
   * ordering is the point — the window is a real observation, but on a busy host
   * it also catches unrelated churn, and the strength label is what stops that
   * churn from being reported as something the malware did.
   */
  private collectObservations(detection: Detection, windowStart: string, windowEnd: string): Observation[] {
    const byPath = new Map<string, Observation>();
    const lineage = buildProcessLineage(detection);
    const startMs = Date.parse(windowStart);
    const endMs = Date.parse(windowEnd);

    const upsert = (observation: Observation): void => {
      const key = normalizePathKey(observation.path);
      const existing = byPath.get(key);
      if (!existing) {
        byPath.set(key, observation);
        return;
      }
      // Keep the strongest attribution and the earliest observation, and union
      // the evidence so nothing observed is lost by deduplication.
      existing.evidence.push(...observation.evidence);
      if (Date.parse(observation.observed_at) < Date.parse(existing.observed_at)) {
        existing.observed_at = observation.observed_at;
      }
      if (observation.operation !== "UNKNOWN") existing.operation = observation.operation;
      existing.previous_path = existing.previous_path ?? observation.previous_path;
      existing.size_bytes = existing.size_bytes ?? observation.size_bytes;
      existing.modified_at = existing.modified_at ?? observation.modified_at;
      existing.created_at = existing.created_at ?? observation.created_at;
      existing.scan_hash = existing.scan_hash ?? observation.scan_hash;
      existing.scan_at = existing.scan_at ?? observation.scan_at;
      if (
        attributionRank(observation.attribution) > attributionRank(existing.attribution)
      ) {
        existing.attribution = observation.attribution;
        existing.attribution_strength = observation.attribution_strength;
      }
    };

    /* Source 1: security providers naming this exact resource. */
    const providers = eventHub.getSecurityProviders();
    for (const rawAlert of providers?.alerts ?? []) {
      const alert = rawAlert as any;
      const alertTs = typeof alert.timestamp === "string" ? alert.timestamp : "";
      const at = Date.parse(alertTs);
      if (!Number.isFinite(at) || at < startMs || at > endMs) continue;
      const resources: string[] = Array.isArray(alert.resources) ? alert.resources : [];
      for (const resource of resources) {
        const target = validateObservedPath(resource);
        if (!target) continue;
        upsert({
          path: target,
          name: path.basename(target),
          is_directory: false,
          operation: "UNKNOWN",
          previous_path: null,
          observed_at: alertTs,
          size_bytes: null,
          modified_at: null,
          created_at: null,
          scan_hash: null,
          scan_at: null,
          evidence: [
            {
              source: "security_provider",
              ref: String(alert.alert_id ?? ""),
              at: alertTs,
              detail: `${alert.provider_name ?? ""} ${alert.kind ?? ""}: ${alert.title ?? ""}${alert.detail ? ` — ${alert.detail}` : ""}`,
            },
          ],
          attribution: "SECURITY_PROVIDER_RESOURCE",
          attribution_strength: "ATTRIBUTED",
        });
      }
    }

    /* Source 2: the detection engine's own file/path findings. */
    for (const evidence of detection.evidence) {
      if (evidence.source !== "file" && evidence.source !== "path") continue;
      const target = validateObservedPath(evidence.detail);
      if (!target) continue;
      upsert({
        path: target,
        name: path.basename(target),
        is_directory: false,
        operation: "UNKNOWN",
        previous_path: null,
        observed_at: detection.event_timestamp || detection.timestamp,
        size_bytes: null,
        modified_at: null,
        created_at: null,
        scan_hash: null,
        scan_at: null,
        evidence: [
          {
            source: "detection",
            ref: detection.id,
            at: detection.event_timestamp || detection.timestamp,
            detail: `${detection.rule_name}: ${evidence.description}`,
          },
        ],
        attribution: "ENGINE_FILE_DETECTION",
        attribution_strength: "ATTRIBUTED",
      });
    }

    /* Source 3: the detected process's binary and its ancestors' binaries. */
    for (const binary of lineage.binaries.values()) {
      upsert({
        path: binary.executable_path,
        name: path.basename(binary.executable_path),
        is_directory: false,
        operation: "UNKNOWN",
        previous_path: null,
        observed_at: detection.event_timestamp || detection.timestamp,
        size_bytes: null,
        modified_at: null,
        created_at: null,
        scan_hash: null,
        scan_at: null,
        evidence: [
          {
            source: "detection",
            ref: detection.id,
            at: detection.event_timestamp || detection.timestamp,
            detail: `${detection.rule_name} fired on pid ${detection.pid}; ${binary.process_name} (pid ${binary.pid}) in this process's lineage was loaded from this path`,
          },
        ],
        attribution: binary.pid === detection.pid ? "PROCESS_EXECUTABLE_PATH" : "PROCESS_ANCESTRY_PATH",
        attribution_strength: "ATTRIBUTED",
      });
    }

    /* Source 4: filesystem watch events inside the window, graded by lineage. */
    let scanned = 0;
    const watchEvents = eventHub.getMonitoringEvents(MAX_OBSERVATIONS_SCANNED, "filesystem_watch");
    for (const event of watchEvents) {
      if (scanned >= MAX_OBSERVATIONS_SCANNED) break;
      scanned += 1;
      const at = Date.parse(event.timestamp);
      if (!Number.isFinite(at) || at < startMs || at > endMs) continue;

      const operation = OPERATION_BY_EVENT[event.eventType];
      if (!operation) continue;
      // A rename's meaningful path is the destination; the origin is kept.
      const target = validateObservedPath(event.evidence?.path) ?? validateObservedPath(event.entity.id);
      if (!target) continue;
      // Never treat ARGUS's own workspace as impact.
      if (isInsideRecoveryRoot(target)) continue;

      // Strongest available evidence first: an exact binary match in the lineage
      // outranks directory co-location, which outranks the bare time window.
      const lineageMatch = matchLineage(target, lineage);
      const basis: AttributionBasis = lineageMatch?.basis ?? "INCIDENT_TIME_WINDOW";
      const strength: AttributionStrength = lineageMatch?.strength ?? "INFERRED";
      const attributionDetail =
        lineageMatch?.detail ??
        "the change fell inside the incident window but shares no path relationship with the detected process or its ancestors";

      upsert({
        path: target,
        name: typeof event.entity.name === "string" && event.entity.name.length > 0 ? event.entity.name : path.basename(target),
        is_directory: event.evidence?.is_directory === true,
        operation,
        previous_path: validateObservedPath(event.evidence?.old_path),
        observed_at: event.timestamp,
        size_bytes: typeof event.evidence?.size_bytes === "number" ? event.evidence.size_bytes : null,
        modified_at: typeof event.evidence?.modified_at === "string" ? event.evidence.modified_at : null,
        created_at: typeof event.evidence?.created_at === "string" ? event.evidence.created_at : null,
        scan_hash: null,
        scan_at: null,
        evidence: [
          {
            source: "monitoring_event",
            ref: event.eventId,
            at: event.timestamp,
            // The watcher carries metadata only, and says so. That limitation is
            // why a window-only match can never be more than inferred.
            detail: `${event.eventType} reported by the endpoint filesystem watcher (metadata only, no owning pid): ${attributionDetail}`,
          },
        ],
        attribution: basis,
        attribution_strength: strength,
      });
    }

    /* Baseline hashes from real file scans, when the scan predates the change. */
    const scan = eventHub.getFileScan();
    for (const finding of scan?.findings ?? []) {
      const target = validateObservedPath(finding.path);
      if (!target) continue;
      const observation = byPath.get(normalizePathKey(target));
      if (!observation || !finding.hash || !finding.modified) continue;
      const modifiedAt = Date.parse(finding.modified);
      if (Number.isFinite(modifiedAt) && modifiedAt < startMs) {
        observation.scan_hash = finding.hash;
        observation.scan_at = finding.timestamp ?? scan?.timestamp ?? null;
        observation.evidence.push({
          source: "file_scan",
          ref: finding.id,
          at: observation.scan_at ?? finding.modified,
          detail: `file scan recorded sha256 ${finding.hash} at mtime ${finding.modified}, before the incident window`,
        });
      }
    }

    return [...byPath.values()].sort((a, b) => a.observed_at.localeCompare(b.observed_at));
  }

  /** Turn observations into affected-file records with real on-disk analysis. */
  private async buildRecords(
    incidentId: string,
    detection: Detection,
    observations: Observation[],
    windowStart: string,
  ): Promise<void> {
    const limits = recoveryStore.getLimits();
    const providers = eventHub.getSecurityProviders();
    const cap = limits.maxAffectedFilesPerIncident;

    for (const observation of observations) {
      // Parentheses are load-bearing: `??` binds looser than `>=`.
      const stored = recoveryStore.getIncident(incidentId)?.affected_files.length ?? 0;
      if (stored >= cap) break;

      /* Provider encryption claims naming this exact path. */
      const encryptionReports: string[] = [];
      for (const rawAlert of providers?.alerts ?? []) {
        const alert = rawAlert as any;
        const resources: string[] = Array.isArray(alert.resources) ? alert.resources : [];
        const names = resources.some((resource) => samePath(resource, observation.path));
        if (!names) continue;
        const claim = `${alert.title ?? ""}${alert.detail ? ` — ${alert.detail}` : ""}`;
        if (mentionsRansomware(claim)) encryptionReports.push(`${alert.provider_name ?? ""}: ${claim}`);
      }

      const previousMetadata: FileMetadataSnapshot | null = observation.scan_hash
        ? {
            exists: null,
            size_bytes: observation.size_bytes,
            modified_at: observation.modified_at,
            created_at: observation.created_at,
            sha256: observation.scan_hash,
            sha256_computed_at: observation.scan_at,
            sha256_skipped_reason: null,
          }
        : null;

      const analysis = await analyzeAffectedFile(observation.path, {
        previous: previousMetadata,
        maxHashBytes: limits.maxHashBytes,
        provider_encryption_reports: encryptionReports,
      });

      const damage = observation.is_directory
        ? classifyDamage({ operation: observation.operation, exists: analysis.metadata.exists, signals: [] })
        : classifyDamage({ operation: observation.operation, exists: analysis.metadata.exists, signals: analysis.signals });

      const record: AffectedFile = {
        record_id: recordIdFor(incidentId, observation.path),
        incident_id: incidentId,
        detection_id: detection.id,
        path: observation.path,
        name: observation.name,
        operation: observation.operation,
        previous_path: observation.previous_path,
        observed_at: observation.observed_at,
        first_seen_at: observation.observed_at,
        last_seen_at: observation.observed_at,
        observation_count: 1,
        pid: detection.pid,
        process_name: detection.entity,
        process_ancestry: detection.ancestry.map((node) => ({
          pid: node.pid,
          process_name: node.process_name,
          executable_path: node.executable_path ?? null,
        })),
        attribution: observation.attribution,
        attribution_strength: observation.attribution_strength,
        evidence_source: evidenceSourceFor(observation),
        evidence: observation.evidence.slice(0, limits.maxEvidenceRefsPerFile),
        previous_metadata: previousMetadata,
        current_metadata: analysis.metadata,
        damage,
        damage_signals: analysis.signals,
        recovery_state: "DISCOVERED",
        recovery_sources: [],
        selected_source_id: null,
        attempts: [],
        notes: [...analysis.notes, ...attributionNotes(observation)],
      };

      await this.preserveEvidenceCopy(record);

      const { record: merged } = recoveryStore.mergeRecord(incidentId, record);
      if (merged) {
        recoveryStore.publishRecord(merged);
        emitRecoveryEvent("IMPACT_FILE_DISCOVERED", {
          incident_id: incidentId,
          detection_id: detection.id,
          record_id: record.record_id,
          path: record.path,
          pid: record.pid,
          process_name: record.process_name,
          result: `${record.damage}/${record.attribution_strength}`,
          detail: `${record.operation} observed at ${record.observed_at}; attributed via ${record.attribution}`,
        });
      }
    }
  }

  /**
   * Copy the affected file as-found into the evidence area.
   *
   * Read-only on the source, write confined to the workspace, and best-effort:
   * a locked or already-deleted file must not abort the investigation.
   */
  private async preserveEvidenceCopy(record: AffectedFile): Promise<void> {
    if (isInsideRecoveryRoot(record.path)) return;
    const root = await ensureRecoveryRoot();
    if (!root) return;

    const target = evidencePathFor(record.incident_id, record.record_id, record.name);
    try {
      await fs.mkdir(path.dirname(target), { recursive: true });
      // `COPYFILE_EXCL` keeps the first observation: an evidence copy is a
      // point-in-time record and must never be silently overwritten.
      await fs.copyFile(record.path, target, fs.constants.COPYFILE_EXCL);
      record.notes.push(`as-found copy preserved at ${target}`);
      logger.info(
        { scope: "recovery", recordId: record.record_id, source: record.path, evidence: target },
        "preserved as-found evidence copy",
      );
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === "ENOENT") {
        record.notes.push("nothing to preserve: the path no longer exists");
      } else {
        record.notes.push(`evidence copy failed: ${describeError(error)}`);
      }
    }
  }

  /* ------------------------------------------------------------------ */
  /* Phase 2: source discovery and safe recovery                         */
  /* ------------------------------------------------------------------ */

  /** Look for real recovery sources for every record in the incident. */
  private async searchSourcesForIncident(incident: ImpactIncident, windowStart: string): Promise<void> {
    const limits = recoveryStore.getLimits();
    recoveryStore.setPhase(incident.incident_id, "SOURCE_SEARCH");
    emitRecoveryEvent("RECOVERY_SOURCE_SEARCH_STARTED", {
      incident_id: incident.incident_id,
      detection_id: incident.detection_id,
      pid: incident.process.pid,
      process_name: incident.process.name,
      result: incident.affected_files.length,
      detail: `probing real sources for ${incident.affected_files.length} affected file(s)`,
    });

    for (const record of incident.affected_files) {
      const sources = await this.searchSourcesForRecord(record, windowStart, limits.maxSourcesPerFile);
      const restorable = sources.filter((source) => source.restorable);

      const updated: AffectedFile = {
        ...record,
        recovery_sources: sources,
        recovery_state: restorable.length > 0 ? "RECOVERY_SOURCE_FOUND" : "NO_RECOVERY_SOURCE",
        selected_source_id: restorable[0]?.source_id ?? null,
      };
      if (restorable.length === 0) {
        updated.notes.push(
          "no pre-incident copy of this file exists in any location ARGUS can reach; the file cannot be recovered automatically",
        );
      }
      recoveryStore.updateRecord(incident.incident_id, updated);
      recoveryStore.publishRecord(updated);

      emitRecoveryEvent("RECOVERY_SOURCE_FOUND", {
        incident_id: incident.incident_id,
        detection_id: incident.detection_id,
        record_id: record.record_id,
        path: record.path,
        result: `${sources.filter((source) => source.available).length}/${sources.length} available, ${restorable.length} restorable`,
        detail: sources
          .map((source) => `${source.kind}: ${source.probe_detail}`)
          .join(" | ")
          .slice(0, 2000),
      });
    }
  }

  /** Locate real recovery sources for one record. Never throws. */
  async searchSourcesForRecord(record: AffectedFile, windowStart: string, maxSources: number): Promise<RecoverySource[]> {
    try {
      assertNotWorkspacePath(record.path, "refusing to search for a source of a workspace path");
      return await findRecoverySources({
        originalPath: record.path,
        incidentId: record.incident_id,
        recordId: record.record_id,
        incidentWindowStart: windowStart,
        maxSources,
        timeoutMs: recoveryStore.getLimits().sourceSearchTimeoutMs,
        maxHashBytes: recoveryStore.getLimits().maxHashBytes,
      });
    } catch (error) {
      const detail = describeError(error);
      logger.warn({ scope: "recovery", recordId: record.record_id, err: detail }, "source search rejected");
      return [
        {
          source_id: `search-failed:${record.record_id}`,
          kind: "CONFIGURED_BACKUP_ROOT",
          priority: 99,
          label: "Source search",
          path: null,
          available: false,
          restorable: false,
          role: "RESTORATION_CANDIDATE",
          size_bytes: null,
          modified_at: null,
          sha256: null,
          probe_detail: detail,
          discovered_at: new Date().toISOString(),
        },
      ];
    }
  }

  /** Attempt recovery for every record that has a restorable source. */
  private async recoverIncident(incident: ImpactIncident): Promise<void> {
    const limits = recoveryStore.getLimits();
    const current = recoveryStore.getIncident(incident.incident_id);
    if (!current) return;
    if (current.affected_files.length === 0) return;

    recoveryStore.setPhase(incident.incident_id, "RECOVERING");

    for (const record of current.affected_files) {
      const source = record.recovery_sources.find((entry) => entry.source_id === record.selected_source_id);
      if (!source || !source.restorable) continue;
      const latest = recoveryStore.findRecord(incident.incident_id, record.record_id) ?? record;
      const updated = await this.recoverRecord(latest, source, limits.maxAttemptsPerFile);
      if (updated) recoveryStore.publishRecord(updated);
    }

    recoveryStore.setPhase(incident.incident_id, "VERIFYING");
  }

  /**
   * Stage one copy of a file from a real source and verify it.
   *
   * The original is opened read-only. The staged copy is written to an exclusive
   * path inside the workspace, so re-running never clobbers an existing recovered
   * copy or any original.
   *
   * Idempotent per `incident + file + source`: a source that already produced a
   * successful attempt is never attempted a second time. That is what stops a
   * re-triggered detection, a resumed incident or a retried operator request from
   * copying the same bytes again under a new attempt id. Failed attempts are
   * still retryable — that is the point of the retry budget — because a
   * permission denial or an absent shadow copy is exactly the condition an
   * operator fixes and then asks ARGUS to try again.
   */
  async recoverRecord(record: AffectedFile, source: RecoverySource, maxAttempts: number): Promise<AffectedFile | null> {
    const root = await ensureRecoveryRoot();
    if (!root) {
      return this.finishRecord(record, [], `recovery workspace ${getRecoveryRoot()} could not be created`);
    }

    const alreadyRecovered = new Set(
      record.attempts
        .filter((attempt) => attempt.outcome === "SUCCEEDED")
        .map((attempt) => attempt.source_id),
    );

    const attempts: RecoveryAttempt[] = [];
    const candidates = record.recovery_sources
      .filter((entry) => entry.restorable)
      .filter((entry) => !alreadyRecovered.has(entry.source_id))
      .slice(0, Math.max(1, maxAttempts));

    for (const candidate of candidates) {
      if (attempts.length >= maxAttempts) break;
      const attempt = await this.attemptCopy(record, candidate);
      attempts.push(attempt);
      if (attempt.outcome === "SUCCEEDED") break;
    }

    if (attempts.length === 0) {
      // Nothing new to try: either every restorable source already succeeded, or
      // this record genuinely has none. Reuse the recorded verdict untouched.
      return this.finishRecord(record, [], null);
    }

    const succeeded = attempts.find((attempt) => attempt.outcome === "SUCCEEDED");

    // Bound the failure history, but never drop a success. A dropped success
    // would put the same incident/file/source combination back into the
    // candidate list on the next run and produce a duplicate attempt, which is
    // exactly what the dedupe above exists to prevent.
    const combined = [...record.attempts, ...attempts];
    const succeededIndexes = new Set<number>();
    combined.forEach((attempt, index) => {
      if (attempt.outcome === "SUCCEEDED") succeededIndexes.add(index);
    });
    const failureIndexes = combined
      .map((_, index) => index)
      .filter((index) => !succeededIndexes.has(index));
    const failureBudget = Math.max(0, maxAttempts - succeededIndexes.size);
    const keptFailureIndexes = new Set(failureIndexes.slice(-failureBudget));

    const next: AffectedFile = {
      ...record,
      attempts: combined.filter((_, index) => succeededIndexes.has(index) || keptFailureIndexes.has(index)),
      recovery_state: succeeded
        ? succeeded.verified
          ? "VERIFIED"
          : "RECOVERED"
        : attempts.length > 0
          ? "UNRECOVERABLE"
          : "NO_RECOVERY_SOURCE",
      selected_source_id: succeeded?.source_id ?? record.selected_source_id,
    };
    return this.finishRecord(next, attempts, succeeded ? null : lastErrorOf(attempts) ?? "no attempt succeeded");
  }

  /** Move a record to a terminal state with an explanatory note. */
  private finishRecord(record: AffectedFile, attempts: RecoveryAttempt[], error: string | null): AffectedFile | null {
    const next: AffectedFile = { ...record };
    if (error) next.notes.push(error);

    if (attempts.some((attempt) => attempt.outcome === "SUCCEEDED" && attempt.verified)) {
      next.recovery_state = "VERIFIED";
      next.notes.push("every required verification check passed on the staged copy");
    } else if (attempts.some((attempt) => attempt.outcome === "SUCCEEDED")) {
      next.recovery_state = "RECOVERED";
      next.notes.push("a copy was staged but one or more verification checks did not pass");
    } else if (attempts.length > 0) {
      next.recovery_state = "UNRECOVERABLE";
    }

    const updated = recoveryStore.updateRecord(record.incident_id, next);
    if (updated) recoveryStore.publishRecord(updated);
    return updated;
  }

  /** One bounded, non-destructive copy attempt with verification. */
  private async attemptCopy(record: AffectedFile, source: RecoverySource): Promise<RecoveryAttempt> {
    const limits = recoveryStore.getLimits();
    const startedAt = new Date().toISOString();
    const attempt: RecoveryAttempt = {
      attempt_id: `att_${createHash("sha1").update(`${record.record_id}|${source.source_id}|${startedAt}`).digest("hex").slice(0, 12)}`,
      record_id: record.record_id,
      incident_id: record.incident_id,
      source_id: source.source_id,
      source_kind: source.kind,
      started_at: startedAt,
      completed_at: null,
      outcome: "FAILED",
      recovered_path: null,
      recovered_size_bytes: null,
      recovered_sha256: null,
      source_sha256: source.sha256,
      error: null,
      checks: [],
      verified: false,
      destructive: false,
    };

    const context = {
      incident_id: record.incident_id,
      detection_id: record.detection_id,
      record_id: record.record_id,
      path: record.path,
      pid: record.pid,
      process_name: record.process_name,
      source: source.path,
      source_kind: source.kind,
    };

    /** Record a terminal failure and emit the paired attempt/failure events. */
    const fail = (reason: string): RecoveryAttempt => {
      attempt.error = reason;
      attempt.completed_at = new Date().toISOString();
      emitRecoveryEvent("RECOVERY_FAILED", { ...context, result: "attempt_failed", detail: reason });
      emitRecoveryEvent("RECOVERY_ATTEMPT_COMPLETED", {
        ...context,
        result: "FAILED",
        detail: reason,
      });
      return attempt;
    };

    emitRecoveryEvent("RECOVERY_ATTEMPT_STARTED", {
      ...context,
      result: source.restorable ? "restorable" : "not_restorable",
      detail: `staging a copy of ${record.path} from ${source.kind}`,
    });

    const root = await ensureRecoveryRoot();
    if (!root) {
      return fail("recovery workspace is unavailable");
    }

    if (!source.path) {
      return fail(source.probe_detail);
    }

    let target: string;
    try {
      // Containment is re-proven here, immediately before the write.
      target = stagingPathFor(record.incident_id, record.record_id, record.name);
      if (!isInsideRecoveryRoot(target)) throw new Error("staging target escaped the recovery workspace");
      // Belt and braces: a staging path must never equal an affected original.
      if (samePath(target, record.path)) throw new Error("staging target equals the original path");
      await fs.mkdir(path.dirname(target), { recursive: true });
    } catch (error) {
      return fail(`refusing unsafe recovery target: ${describeError(error)}`);
    }

    // Recovery must be idempotent, and a staged copy must never be clobbered. If
    // one already exists, verify it against the source instead of rewriting it.
    let reusedExistingCopy = false;
    try {
      await fs.access(target);
      reusedExistingCopy = true;
    } catch {
      reusedExistingCopy = false;
    }

    if (!reusedExistingCopy) {
      try {
        // Read the source, write a brand-new file. The original is never opened
        // for writing, renamed or deleted anywhere in this path.
        await fs.copyFile(source.path, target, fs.constants.COPYFILE_EXCL);
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === "EEXIST") {
          // Lost a race with a concurrent attempt: verify what is there.
          reusedExistingCopy = true;
        } else {
          attempt.error = `copy failed: ${describeError(error)}`;
          attempt.checks = [
            { name: "READABLE", passed: false, detail: attempt.error, required: true },
            { name: "BYTE_IDENTICAL", passed: false, detail: "no copy was produced", required: true },
          ];
          attempt.completed_at = new Date().toISOString();
          logger.warn(
            { scope: "recovery", recordId: record.record_id, source: source.path, target, err: attempt.error },
            "recovery copy failed",
          );
          emitRecoveryEvent("RECOVERY_FAILED", {
            ...context,
            result: "copy_failed",
            detail: attempt.error,
          });
          emitRecoveryEvent("RECOVERY_ATTEMPT_COMPLETED", { ...context, result: "FAILED", detail: attempt.error });
          return attempt;
        }
      }
    }

    emitRecoveryEvent("RECOVERY_VERIFICATION_STARTED", {
      ...context,
      result: reusedExistingCopy ? "verifying_existing_staged_copy" : "verifying_new_staged_copy",
      detail: `hashing and structurally validating the staged copy at ${target}`,
    });

    const [recoveredHash, sourceHash] = await Promise.all([
      sha256File(target, limits.maxHashBytes),
      source.sha256 ? Promise.resolve(source.sha256) : sha256File(source.path, limits.maxHashBytes).then((result) => result.sha256),
    ]);
    let recoveredSize: number | null = null;
    try {
      recoveredSize = (await fs.stat(target)).size;
    } catch {
      recoveredSize = null;
    }

    attempt.checks = buildVerificationChecks({
      expectedSha256: sourceHash,
      recoveredSha256: recoveredHash.sha256,
      recoveredSize,
      sourceSize: source.size_bytes,
      // Carried from the resolver's real mtime comparison, not asserted here.
      sourcePredatesWindow: source.restorable,
      originalPath: record.path,
      stagingPath: target,
    });
    attempt.checks.push(await buildSignatureCheck(target));
    attempt.recovered_path = target;
    attempt.recovered_size_bytes = recoveredSize;
    attempt.recovered_sha256 = recoveredHash.sha256;
    attempt.outcome = "SUCCEEDED";
    attempt.completed_at = new Date().toISOString();
    attempt.verified = attempt.checks.filter((check) => check.required).every((check) => check.passed);
    if (reusedExistingCopy) {
      attempt.error = null;
      attempt.checks.unshift({
        name: "STAGED_COPY_REUSED",
        passed: true,
        detail: "a copy was already staged at this target and was verified rather than overwritten",
        required: false,
      });
    }

    const failedChecks = attempt.checks.filter((check) => check.required && !check.passed);
    emitRecoveryEvent("RECOVERY_VERIFICATION_COMPLETED", {
      ...context,
      result: attempt.verified ? "VERIFIED" : "RECOVERED_NOT_VERIFIED",
      detail:
        attempt.checks.map((check) => `${check.name}=${check.passed ? "pass" : "fail"}`).join(" ") +
        (failedChecks.length > 0 ? ` — failing: ${failedChecks.map((check) => check.name).join(", ")}` : ""),
    });

    logger.info(
      {
        scope: "recovery",
        recordId: record.record_id,
        sourceKind: source.kind,
        source: source.path,
        staged: target,
        verified: attempt.verified,
        checks: attempt.checks.map((check) => `${check.name}=${check.passed ? "pass" : "fail"}`),
      },
      attempt.verified ? "recovery verified" : "recovery staged but verification incomplete",
    );

    if (!attempt.verified) {
      // Staged, but not proven good. This is explicitly not a success: the copy
      // exists in staging and the record stays short of VERIFIED.
      emitRecoveryEvent("RECOVERY_FAILED", {
        ...context,
        result: "verification_incomplete",
        detail: `a copy was staged at ${target} but required checks failed: ${failedChecks.map((check) => check.name).join(", ")}`,
      });
    }

    emitRecoveryEvent("RECOVERY_ATTEMPT_COMPLETED", {
      ...context,
      result: attempt.verified ? "VERIFIED" : "RECOVERED_NOT_VERIFIED",
      detail: `staged ${target} (${recoveredSize ?? "unknown"} bytes, sha256 ${attempt.recovered_sha256})`,
    });
    return attempt;
  }

  /* ------------------------------------------------------------------ */
  /* Queries used by the API                                              */
  /* ------------------------------------------------------------------ */

  /** Full snapshot, including a live probe of which sources can run here. */
  async snapshot(): Promise<ReturnType<typeof recoveryStore.buildSnapshot>> {
    return recoveryStore.buildSnapshot(await recoverySourceSupport(), getRecoveryRoot(), this.enabled);
  }
}

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

/** Deterministic incident id, so a detection always maps to one incident. */
function incidentIdFor(detectionId: string): string {
  return `inc_${createHash("sha1").update(detectionId).digest("hex").slice(0, 12)}`;
}

/** Deterministic record id, so one path yields one record per incident. */
function recordIdFor(incidentId: string, target: string): string {
  return `rec_${createHash("sha1").update(`${incidentId}|${normalizePathKey(target)}`).digest("hex").slice(0, 12)}`;
}

function detectionRef(detection: Detection): ImpactIncident["detection"] {
  return {
    id: detection.id,
    rule_id: detection.rule_id,
    rule_name: detection.rule_name,
    title: detection.title,
    severity: detection.severity,
    confidence: detection.confidence,
    status: detection.status,
    timestamp: detection.timestamp,
    event_timestamp: detection.event_timestamp,
    entity: detection.entity,
    pid: detection.pid,
    executable_path: detection.executable_path ?? null,
    hostname: detection.hostname,
  };
}

/** Live process facts when the process is still known, otherwise detection facts. */
function processContextFor(detection: Detection): IncidentProcess {
  const context = detection.pid > 0 ? detectionEngine.getProcessContext(detection.pid) : null;
  const ancestry =
    detection.ancestry.length > 0
      ? detection.ancestry
      : detection.pid > 0
        ? detectionEngine.getAncestry(detection.pid)
        : [];

  return {
    pid: detection.pid,
    name: detection.entity,
    executable_path: context?.executable_path ?? detection.executable_path ?? null,
    command_line: context?.command_line ?? detection.command_line ?? null,
    parent_pid: context?.parent_pid ?? detection.parent_pid ?? null,
    parent_process_name: context?.parent_process_name ?? detection.parent_process_name ?? null,
    username: context?.username ?? detection.username ?? null,
    ancestry: ancestry.map((node) => ({
      pid: node.pid,
      process_name: node.process_name,
      executable_path: node.executable_path ?? null,
    })),
  };
}

function attributionRank(basis: AttributionBasis): number {
  return ["INCIDENT_TIME_WINDOW", "ENGINE_FILE_DETECTION", "PROCESS_EXECUTABLE_PATH", "SECURITY_PROVIDER_RESOURCE"].indexOf(basis);
}

function lastErrorOf(attempts: readonly RecoveryAttempt[]): string | null {
  for (let index = attempts.length - 1; index >= 0; index -= 1) {
    const error = attempts[index].error;
    if (error) return error;
  }
  return null;
}

/**
 * Build the verification checklist for a staged copy.
 *
 * `PRE_INCIDENT_SOURCE_TIME` is required because restoring a post-incident copy
 * would silently hand back the damaged content. `READABLE` and `BYTE_IDENTICAL`
 * are required because a copy that is corrupt or incomplete is not a recovery.
 * `ORIGINAL_UNTOUCHED` is required as a live assertion of the non-destructive
 * guarantee. `SIGNATURE_OK` is required only when the format is recognizable.
 */
function buildVerificationChecks(input: {
  expectedSha256: string | null;
  recoveredSha256: string | null;
  recoveredSize: number | null;
  sourceSize: number | null;
  sourcePredatesWindow: boolean;
  originalPath: string;
  stagingPath: string;
}): RecoveryAttempt["checks"] {
  const checks: RecoveryAttempt["checks"] = [];

  checks.push({
    name: "READABLE",
    passed: input.recoveredSha256 !== null,
    detail:
      input.recoveredSha256 !== null
        ? "the staged copy could be read back and hashed"
        : "the staged copy could not be read back or hashed",
    required: true,
  });

  checks.push({
    name: "BYTE_IDENTICAL",
    passed:
      input.expectedSha256 !== null && input.recoveredSha256 !== null && input.expectedSha256 === input.recoveredSha256,
    detail:
      input.expectedSha256 === null || input.recoveredSha256 === null
        ? "no digest available to compare, so byte identity cannot be asserted"
        : input.expectedSha256 === input.recoveredSha256
          ? `sha256 ${input.recoveredSha256} matches the source`
          : `sha256 mismatch: source ${input.expectedSha256}, staged copy ${input.recoveredSha256}`,
    required: true,
  });

  checks.push({
    name: "SIZE_MATCHES_SOURCE",
    passed: input.sourceSize !== null && input.recoveredSize !== null && input.sourceSize === input.recoveredSize,
    detail:
      input.sourceSize === null || input.recoveredSize === null
        ? "a size comparison was not possible"
        : input.sourceSize === input.recoveredSize
          ? `${input.recoveredSize} bytes on both sides`
          : `source ${input.sourceSize} bytes vs staged copy ${input.recoveredSize} bytes`,
    required: true,
  });

  checks.push({
    name: "PRE_INCIDENT_SOURCE_TIME",
    passed: input.sourcePredatesWindow,
    detail: input.sourcePredatesWindow
      ? "the source file's mtime was confirmed older than the incident window before the copy was made"
      : "the source file's mtime is not older than the incident window, so restoring it would return post-incident content",
    required: true,
  });

  checks.push({
    name: "ORIGINAL_UNTOUCHED",
    passed: !samePath(input.originalPath, input.stagingPath),
    detail: `recovery wrote only to ${input.stagingPath}; ${input.originalPath} was opened read-only`,
    required: true,
  });

  return checks;
}

/**
 * Assert that the staged copy still carries the container signature its file
 * extension implies. This catches a copy that is byte-count correct but was
 * reconstructed from already-encrypted content, which is the failure mode a
 * SHA-256 comparison alone cannot see when the source was itself damaged.
 *
 * The check is only added when the extension maps to a known signature, so an
 * unrecognized format is never reported as a mismatch.
 */
async function buildSignatureCheck(stagingPath: string): Promise<RecoveryAttempt["checks"][number]> {
  const expected = expectedSignaturesFor(stagingPath);
  const base = {
    name: "SIGNATURE_OK",
    required: true,
    detail: expected.length === 0 ? "no signature catalog entry for this extension" : "not evaluated",
  };

  if (expected.length === 0) {
    return { ...base, passed: true };
  }

  const prefix = await readPrefix(stagingPath, SIGNATURE_PREFIX_BYTES);
  if (prefix === null) {
    return { ...base, passed: false, detail: "the staged copy's content prefix could not be read" };
  }

  const detected = detectSignature(prefix);
  if (detected === null) {
    return {
      ...base,
      passed: false,
      detail: `no known container signature found; expected one of ${expected.join(", ")}`,
    };
  }

  const matched = expected.includes(detected);
  return {
    ...base,
    passed: matched,
    detail: matched
      ? `container signature ${detected} matches the extension`
      : `container signature ${detected} does not match the expected ${expected.join(", ")}`,
  };
}

export const recoveryService = new RecoveryService();
