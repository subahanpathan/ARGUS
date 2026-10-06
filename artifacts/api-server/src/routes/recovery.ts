import { Router, type IRouter, type Request, type Response } from "express";

import { eventHub } from "../lib/event-hub";
import { logger } from "../lib/logger";
import { getRecoveryRoot } from "../recovery/paths";
import { configuredBackupRoots, recoverySourceSupport } from "../recovery/sources";
import { recoveryService } from "../recovery/service";
import { recoveryStore } from "../recovery/store";
import { DAMAGE_CATALOG, ATTRIBUTION_CATALOG, RECOVERY_PIPELINE_STAGES, RECOVERY_STATE_CATALOG } from "../recovery/types";

const router: IRouter = Router();

/** Cap on files returned by the list endpoint so a large incident cannot stall a client. */
const MAX_FILES_PER_RESPONSE = 500;

function clampLimit(value: unknown, fallback: number, max: number): number {
  const parsed = parseInt(String(value ?? ""), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.min(parsed, max);
}

/**
 * GET /api/recovery
 * Full impact + recovery snapshot: summary, incidents, affected files,
 * per-record sources and attempts, plus a live probe of which recovery sources
 * can actually run on this host.
 */
router.get("/recovery", async (_req: Request, res: Response) => {
  try {
    res.json(await recoveryService.snapshot());
  } catch (error) {
    logger.error({ scope: "recovery", err: error }, "failed to build recovery snapshot");
    res.status(500).json({ error: "Recovery snapshot unavailable" });
  }
});

/**
 * GET /api/recovery/summary
 * Aggregate counts only. Every field is a tally over real records; when nothing
 * has been observed the counts are all zero and `observed` is false.
 */
router.get("/recovery/summary", (_req: Request, res: Response) => {
  const snapshot = recoveryStore.buildSnapshot([], getRecoveryRoot(), recoveryService.isEnabled());
  res.json({
    observed: snapshot.observed,
    enabled: snapshot.enabled,
    stages: snapshot.stages,
    summary: snapshot.summary,
    lastError: snapshot.lastError,
  });
});

/**
 * GET /api/recovery/catalog
 * The vocabularies the API and UI share, so both agree on what each
 * classification and recovery state means.
 */
router.get("/recovery/catalog", (_req: Request, res: Response) => {
  res.json({
    stages: RECOVERY_PIPELINE_STAGES,
    damage: DAMAGE_CATALOG,
    recoveryStates: RECOVERY_STATE_CATALOG,
    attribution: ATTRIBUTION_CATALOG,
  });
});

/**
 * GET /api/recovery/config
 * Runtime configuration and effective limits. Reports what is actually in
 * effect, including which backup roots were parsed from the environment.
 */
router.get("/recovery/config", (_req: Request, res: Response) => {
  const snapshot = recoveryStore.buildSnapshot([], getRecoveryRoot(), recoveryService.isEnabled());
  res.json({
    enabled: snapshot.enabled,
    recoveryRoot: snapshot.recoveryRoot,
    limits: snapshot.limits,
    configuredBackupRoots: configuredBackupRoots(),
    // Why the automatic path did or did not pick up recent detections. Without
    // this, a detection that was skipped is indistinguishable from one that
    // never happened.
    automaticTrigger: {
      skippedDetections: recoveryService.getTriggerSkipStats().skipped,
      lastSkipReason: recoveryService.getTriggerSkipStats().lastReason,
    },
    environment: {
      root: "ARGUS_RECOVERY_ROOT",
      enabled: "ARGUS_RECOVERY_ENABLED",
      backupRoots: "ARGUS_RECOVERY_BACKUP_ROOTS",
    },
  });
});

/**
 * GET /api/recovery/sources
 * Which recovery source kinds are supported here, and why. Each row is backed by
 * a real platform check or configuration read — never an assumption.
 */
router.get("/recovery/sources", async (_req: Request, res: Response) => {
  try {
    res.json({ sources: await recoverySourceSupport(), configuredBackupRoots: configuredBackupRoots() });
  } catch (error) {
    logger.error({ scope: "recovery", err: error }, "failed to probe recovery sources");
    res.status(500).json({ error: "Recovery source probe failed" });
  }
});

/**
 * GET /api/recovery/incidents
 * Reconstructed incidents, newest first.
 */
router.get("/recovery/incidents", (req: Request, res: Response) => {
  const limit = clampLimit(req.query.limit, 25, recoveryStore.getLimits().maxIncidentHistory);
  const incidents = recoveryStore.listIncidents(limit);

  if (req.query.include_files === "false") {
    res.json({
      count: incidents.length,
      incidents: incidents.map(({ affected_files: _files, ...rest }) => rest),
    });
    return;
  }
  res.json({ count: incidents.length, incidents });
});

/**
 * GET /api/recovery/incidents/:incidentId
 * One incident with its affected files, evidence and recovery state.
 */
router.get("/recovery/incidents/:incidentId", (req: Request, res: Response) => {
  const incident = recoveryStore.getIncident(String(req.params.incidentId));
  if (!incident) {
    res.status(404).json({ error: "Incident not found" });
    return;
  }
  res.json({ incident });
});

/**
 * GET /api/recovery/incidents/:incidentId/files
 * Affected files for an incident, with optional filtering.
 */
router.get("/recovery/incidents/:incidentId/files", (req: Request, res: Response) => {
  const incident = recoveryStore.getIncident(String(req.params.incidentId));
  if (!incident) {
    res.status(404).json({ error: "Incident not found" });
    return;
  }

  const limit = clampLimit(req.query.limit, MAX_FILES_PER_RESPONSE, MAX_FILES_PER_RESPONSE);
  let files = incident.affected_files;
  if (typeof req.query.damage === "string") files = files.filter((file) => file.damage === req.query.damage);
  if (typeof req.query.recovery_state === "string") {
    files = files.filter((file) => file.recovery_state === req.query.recovery_state);
  }
  if (req.query.attribution_strength === "ATTRIBUTED" || req.query.attribution_strength === "ATTRIBUTION_UNCERTAIN" || req.query.attribution_strength === "INFERRED") {
    files = files.filter((file) => file.attribution_strength === req.query.attribution_strength);
  }
  if (typeof req.query.search === "string" && req.query.search.trim().length > 0) {
    const needle = req.query.search.trim().toLowerCase();
    files = files.filter(
      (file) =>
        file.path.toLowerCase().includes(needle) ||
        file.name.toLowerCase().includes(needle) ||
        (file.process_name ?? "").toLowerCase().includes(needle),
    );
  }

  res.json({
    incident_id: incident.incident_id,
    count: files.length,
    total: incident.affected_files.length,
    truncated: incident.affected_files_truncated,
    files: files.slice(0, limit),
  });
});

/**
 * GET /api/recovery/incidents/:incidentId/files/:recordId
 * One affected file with its full evidence chain, probed recovery sources and
 * every recovery attempt with its verification checks.
 */
router.get("/recovery/incidents/:incidentId/files/:recordId", (req: Request, res: Response) => {
  const incidentId = String(req.params.incidentId);
  const record = recoveryStore.findRecord(incidentId, String(req.params.recordId));
  if (!record) {
    res.status(404).json({ error: "Affected file not found" });
    return;
  }
  res.json({ record });
});

/**
 * POST /api/recovery/incidents/:incidentId/files/:recordId/recover
 * Retry recovery for one file using the sources already located.
 *
 * Still non-destructive: it stages a copy inside the recovery workspace and
 * never touches the original. Re-running is safe — an existing staged copy is
 * never overwritten.
 */
router.post("/recovery/incidents/:incidentId/files/:recordId/recover", async (req: Request, res: Response) => {
  const incidentId = String(req.params.incidentId);
  const record = recoveryStore.findRecord(incidentId, String(req.params.recordId));
  if (!record) {
    res.status(404).json({ error: "Affected file not found" });
    return;
  }
  if (!recoveryService.isEnabled()) {
    res.status(409).json({ error: "Recovery is disabled (ARGUS_RECOVERY_ENABLED=false)" });
    return;
  }

  const sourceId = typeof req.body?.source_id === "string" ? req.body.source_id : null;
  const source = sourceId
    ? record.recovery_sources.find((entry) => entry.source_id === sourceId)
    : record.recovery_sources.find((entry) => entry.restorable);

  if (!source) {
    res.status(409).json({
      error: "No restorable recovery source is known for this file",
      sources: record.recovery_sources.map((entry) => ({
        kind: entry.kind,
        label: entry.label,
        path: entry.path,
        available: entry.available,
        restorable: entry.restorable,
        probe_detail: entry.probe_detail,
      })),
    });
    return;
  }

  try {
    const updated = await recoveryService.recoverRecord(record, source, recoveryStore.getLimits().maxAttemptsPerFile);
    res.json({ record: updated, destructive: false });
  } catch (error) {
    logger.error(
      { scope: "recovery", recordId: record.record_id, err: error },
      "manual recovery attempt failed",
    );
    res.status(500).json({ error: "Recovery attempt failed" });
  }
});

/**
 * POST /api/recovery/incidents/:incidentId/rescan-sources
 * Re-run source discovery for every file in an incident, e.g. after a backup
 * root or shadow copy has become available.
 */
router.post("/recovery/incidents/:incidentId/rescan-sources", async (req: Request, res: Response) => {
  const incident = recoveryStore.getIncident(String(req.params.incidentId));
  if (!incident) {
    res.status(404).json({ error: "Incident not found" });
    return;
  }

  const limits = recoveryStore.getLimits();
  const rescanned: Array<{ record_id: string; path: string; sources_found: number; restorable: number }> = [];

  recoveryStore.setPhase(incident.incident_id, "SOURCE_SEARCH");
  for (const record of incident.affected_files) {
    const sources = await recoveryService.searchSourcesForRecord(record, incident.window.start, limits.maxSourcesPerFile);
    const restorable = sources.filter((source) => source.restorable);
    const updated = {
      ...record,
      recovery_sources: sources,
      recovery_state: restorable.length > 0 ? ("RECOVERY_SOURCE_FOUND" as const) : ("NO_RECOVERY_SOURCE" as const),
      selected_source_id: restorable[0]?.source_id ?? null,
    };
    recoveryStore.updateRecord(incident.incident_id, updated);
    recoveryStore.publishRecord(updated);
    rescanned.push({
      record_id: record.record_id,
      path: record.path,
      sources_found: sources.filter((source) => source.available).length,
      restorable: restorable.length,
    });
  }

  res.json({
    incident_id: incident.incident_id,
    files_rescanned: rescanned.length,
    sources: await recoverySourceSupport(),
    results: rescanned,
  });
});

/**
 * GET /api/recovery/stream
 * SSE endpoint for live incident and affected-file updates.
 */
router.get("/recovery/stream", (req: Request, res: Response) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  const incidents = recoveryStore.listIncidents(10);
  res.write(
    `data: ${JSON.stringify({
      type: "connected",
      timestamp: new Date().toISOString(),
      observed: recoveryStore.hasObservedAnything(),
      enabled: recoveryService.isEnabled(),
      incidents,
    })}\n\n`,
  );

  const clientId = eventHub.addSSEClient((data: string) => {
    try {
      res.write(data);
    } catch {
      eventHub.removeSSEClient(clientId);
    }
  }, ["recovery"]);

  const heartbeat = setInterval(() => {
    try {
      res.write(": heartbeat\n\n");
    } catch {
      clearInterval(heartbeat);
      eventHub.removeSSEClient(clientId);
    }
  }, 15000);

  req.on("close", () => {
    clearInterval(heartbeat);
    eventHub.removeSSEClient(clientId);
  });
});

export default router;
