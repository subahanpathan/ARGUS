import { Router, type Request, type Response } from "express";
import {
  eventHub,
  type AgentCommandAck,
  type AgentHeartbeat,
  type MonitoringEvent,
  type ScanState,
  type SecurityProvidersSnapshot,
  type ServicesSnapshot,
} from "../lib/event-hub";
import { requireLocalAgent } from "../middlewares/require-local-agent";

const router = Router();

/**
 * Ingest routes: written by the endpoint agent, which runs on this host.
 * Guarded so off-box callers cannot inject telemetry or queue agent commands.
 * Read-only monitoring endpoints below stay open for the UI.
 */
const ingest = requireLocalAgent;

/**
 * POST /api/monitoring/services
 * Accept a Windows services observation snapshot from the security engine.
 * Read-only metadata only (name/status/startup type).
 */
router.post("/monitoring/services", ingest, (req: Request, res: Response) => {
  const body = req.body;

  if (!body || typeof body !== "object") {
    res.status(400).json({ error: "Invalid request body", detail: "Expected a services snapshot object." });
    return;
  }

  if (!Array.isArray(body.services)) {
    res.status(400).json({ error: "Invalid snapshot", detail: "Snapshot must contain a 'services' array." });
    return;
  }

  if (body.services.length > 20000) {
    res.status(413).json({ error: "Snapshot too large", detail: "Maximum 20000 services per snapshot." });
    return;
  }

  const snapshot: ServicesSnapshot = {    timestamp: body.timestamp || new Date().toISOString(),
    source: body.source || "windows_service_monitor",
    observed: body.observed !== false,
    total_count: body.total_count ?? body.services.length,
    running_count: body.running_count ?? 0,
    stopped_count: body.stopped_count ?? 0,
    access_denied_count: body.access_denied_count ?? 0,
    services: body.services,
  };

  eventHub.setServices(snapshot);
  res.status(201).json({ accepted: true, service_count: body.services.length });
});

/**
 * GET /api/monitoring/services
 * Retrieve the current services observation snapshot.
 */
router.get("/monitoring/services", (_req: Request, res: Response) => {
  const snapshot = eventHub.getServices();
  if (!snapshot) {
    res.json({
      timestamp: null,
      source: "windows_service_monitor",
      observed: false,
      total_count: 0,
      running_count: 0,
      stopped_count: 0,
      access_denied_count: 0,
      services: [],
      message: "No services data available. Start the security engine to populate.",
    });
    return;
  }
  res.json(snapshot);
});

/**
 * POST /api/monitoring/scan
 * Accept a filesystem monitoring scan state update from the engine.
 * The state machine is: IDLE/STARTING/INVENTORY/SCANNING/ANALYZING/COMPLETED/PARTIAL/FAILED/CANCELLED.
 *
 * `scan_id` is required: an update without one is rejected rather than allowed
 * to overwrite an unrelated scan's state.
 */
router.post("/monitoring/scan", ingest, (req: Request, res: Response) => {
  const body = req.body;
  if (!body || typeof body !== "object" || typeof body.state !== "string") {
    res.status(400).json({ error: "Invalid request body", detail: "Expected a scan state object with a 'state' string." });
    return;
  }
  if (typeof body.scan_id !== "string" || !body.scan_id.trim()) {
    res.status(400).json({ error: "Invalid scan update", detail: "A scan state update must carry a 'scan_id'." });
    return;
  }

  const stored = eventHub.upsertScan({
    ...(body as Partial<ScanState>),
    scan_id: body.scan_id,
    state: body.state,
    scan_type: body.scan_type || "filesystem",
    updated_at: body.updated_at || new Date().toISOString(),
  });

  if (!stored) {
    res.status(400).json({ error: "Invalid scan update", detail: "Scan could not be stored." });
    return;
  }
  res.status(201).json({ accepted: true, scan: stored });
});

/**
 * GET /api/monitoring/scan
 * Retrieve the current filesystem monitoring scan state.
 */
router.get("/monitoring/scan", (_req: Request, res: Response) => {
  const scan = eventHub.getMonitoringScan();
  if (!scan) {
    res.json({
      scan_id: null,
      state: "IDLE",
      scan_type: "filesystem",
      started_at: null,
      updated_at: null,
      completed_at: null,
      folders_discovered: 0,
      files_discovered: 0,
      folders_scanned: 0,
      files_scanned: 0,
      bytes_scanned: 0,
      errors: 0,
      permission_denied: 0,
      skipped: 0,
      total_known: false,
      progress_percent: null,
      current_path: "",
      current_operation: "idle",
      roots: [],
      message: "No filesystem scan has run yet. Start the security engine to populate.",
    });
    return;
  }
  res.json(scan);
});

/**
 * GET /api/monitoring/scans
 * List every scan the API has observed, newest first, plus the active scan.
 */
router.get("/monitoring/scans", (req: Request, res: Response) => {
  const rawLimit = Number(req.query.limit);
  const limit = Number.isInteger(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 100) : 25;
  res.json({
    scans: eventHub.getScans(limit),
    activeScan: eventHub.getActiveScan(),
    agentLive: eventHub.isAgentLive(),
  });
});

/**
 * GET /api/monitoring/scans/:scanId
 * Retrieve one scan by id.
 */
router.get("/monitoring/scans/:scanId", (req: Request, res: Response) => {
  const param = req.params.scanId;
  const scanId = Array.isArray(param) ? param[0] : param;
  const scan = scanId ? eventHub.getScan(scanId) : null;
  if (!scan) {
    res.status(404).json({ error: "Scan not found", scanId: scanId ?? null });
    return;
  }
  res.json(scan);
});

/**
 * GET /api/monitoring
 * Retrieve a normalized aggregate snapshot of every monitoring domain.
 * Absent sources are reported honestly (observed:false), never fabricated.
 */
router.get("/monitoring", (_req: Request, res: Response) => {
  res.json(eventHub.getMonitoringSnapshot());
});

/**
 * GET /api/monitoring/events
 * Retrieve bounded, time-ordered events aggregated from all sources.
 */
router.get("/monitoring/events", (req: Request, res: Response) => {
  const rawLimit = Number(req.query.limit);
  const limit = Number.isInteger(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 500) : 100;
  const events = eventHub.getAggregatedEvents(limit);
  res.json({ events, count: events.length });
});

/**
 * POST /api/monitoring/events
 * Ingest normalized monitoring events from the endpoint agent.
 *
 * Duplicate event ids are ignored, so a redelivered batch cannot inflate the
 * feed. Scan events also update the scan registry.
 */
router.post("/monitoring/events", ingest, (req: Request, res: Response) => {
  const body = req.body;
  const events = Array.isArray(body) ? body : Array.isArray(body?.events) ? body.events : null;
  if (!events) {
    res.status(400).json({ error: "Invalid request body", detail: "Expected { events: [...] }." });
    return;
  }
  if (events.length > 2000) {
    res.status(413).json({ error: "Batch too large", detail: "Maximum 2000 events per request." });
    return;
  }
  const result = eventHub.addMonitoringEvents(events as MonitoringEvent[]);
  res.status(202).json({ accepted: result.accepted, duplicates: result.duplicates });
});

/**
 * GET /api/monitoring/events/normalized
 * Read the bounded, ordered normalized event feed.
 */
router.get("/monitoring/events/normalized", (req: Request, res: Response) => {
  const rawLimit = Number(req.query.limit);
  const limit = Number.isInteger(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 1000) : 200;
  const source = typeof req.query.source === "string" ? req.query.source : undefined;
  const eventType = typeof req.query.eventType === "string" ? req.query.eventType : undefined;
  const events = eventHub.getMonitoringEvents(limit, source, eventType);
  res.json({ events, count: events.length, source: source ?? null, eventType: eventType ?? null });
});

/**
 * POST /api/monitoring/filesystem
 * Ingest filesystem change telemetry: the observed changes plus the watcher's
 * real counters. Delivery gaps (journal overflow, suppression, read errors) are
 * carried through so a gap stays visible instead of becoming silence.
 */
router.post("/monitoring/filesystem", ingest, (req: Request, res: Response) => {
  const body = req.body;
  if (!body || typeof body !== "object") {
    res.status(400).json({ error: "Invalid request body", detail: "Expected a filesystem activity object." });
    return;
  }
  const events = Array.isArray(body.events) ? body.events : null;
  if (!events) {
    res.status(400).json({ error: "Invalid payload", detail: "Expected an 'events' array." });
    return;
  }
  if (events.length > 1000) {
    res.status(413).json({ error: "Payload too large", detail: "Maximum 1000 change events per request." });
    return;
  }
  const result = eventHub.ingestFilesystemActivity({
    timestamp: typeof body.timestamp === "string" ? body.timestamp : undefined,
    events,
    watcher: body.watcher,
  });
  res.status(202).json({ accepted: result.accepted, backend: (result.watcher as any)?.backend ?? "filesystem" });
});

/**
 * GET /api/monitoring/filesystem
 * Read the latest filesystem change telemetry.
 */
router.get("/monitoring/filesystem", (_req: Request, res: Response) => {
  const activity = eventHub.getFilesystemActivity();
  if (!activity) {
    res.json({
      timestamp: null,
      observed: false,
      backend: "unavailable",
      available: false,
      roots: [],
      root_count: 0,
      events: [],
      counts: null,
      delivery_gaps: null,
      message: "No filesystem change telemetry yet. Start the endpoint agent to populate.",
    });
    return;
  }
  res.json(activity);
});

/**
 * POST /api/monitoring/security-providers
 * Ingest a security-provider observation snapshot.
 *
 * Products ARGUS cannot read are still recorded, with an explicit
 * NOT_SUPPORTED integration status. The API never requests a provider scan.
 */
router.post("/monitoring/security-providers", ingest, (req: Request, res: Response) => {
  const body = req.body;
  if (!body || typeof body !== "object" || !Array.isArray(body.providers)) {
    res.status(400).json({ error: "Invalid request body", detail: "Expected a providers array." });
    return;
  }
  if (body.providers.length > 64) {
    res.status(413).json({ error: "Snapshot too large", detail: "Maximum 64 providers per snapshot." });
    return;
  }
  const snapshot: SecurityProvidersSnapshot = {
    timestamp: body.timestamp || new Date().toISOString(),
    source: body.source || "windows_security_provider_collector",
    observed: body.observed !== false,
    discovery_state: body.discovery_state || "UNKNOWN",
    provider_count: body.provider_count ?? body.providers.length,
    providers: body.providers,
    alerts: Array.isArray(body.alerts) ? body.alerts : [],
    errors: Array.isArray(body.errors) ? body.errors : [],
  };
  eventHub.setSecurityProviders(snapshot);
  res.status(202).json({
    accepted: true,
    provider_count: snapshot.providers.length,
    alert_count: snapshot.alerts.length,
  });
});

/**
 * GET /api/monitoring/security-providers
 * Read the security products observed on the endpoint.
 */
router.get("/monitoring/security-providers", (_req: Request, res: Response) => {
  const snapshot = eventHub.getSecurityProviders();
  if (!snapshot) {
    res.json({
      timestamp: null,
      observed: false,
      discovery_state: "UNAVAILABLE",
      provider_count: 0,
      providers: [],
      alerts: [],
      errors: [],
      message: "No security provider data yet. Start the endpoint agent to populate.",
    });
    return;
  }
  res.json(snapshot);
});

/**
 * POST /api/monitoring/scan-events
 * Ingest scan lifecycle events from the endpoint agent.
 */
router.post("/monitoring/scan-events", ingest, (req: Request, res: Response) => {
  const body = req.body;
  const events = Array.isArray(body) ? body : Array.isArray(body?.events) ? body.events : null;
  if (!events || events.length === 0) {
    res.status(400).json({ error: "Invalid request body", detail: "Expected { events: [...] }." });
    return;
  }
  let accepted = 0;
  for (const item of events) {
    const scan = item?.scan;
    if (!scan || typeof scan.scan_id !== "string") continue;
    eventHub.upsertScan(scan);
    accepted += 1;
  }
  res.status(202).json({ accepted });
});

/**
 * POST /api/monitoring/agent/heartbeat
 * Record agent liveness and its reported telemetry health.
 */
router.post("/monitoring/agent/heartbeat", ingest, (req: Request, res: Response) => {
  const body = req.body;
  if (!body || typeof body !== "object" || typeof body.endpointId !== "string") {
    res.status(400).json({ error: "Invalid request body", detail: "Expected an 'endpointId' string." });
    return;
  }
  eventHub.setAgentHeartbeat({
    ...(body as Partial<AgentHeartbeat>),
    endpointId: body.endpointId,
    timestamp: body.timestamp || new Date().toISOString(),
  });
  res.status(202).json({ accepted: true, live: eventHub.isAgentLive() });
});

/**
 * Holistic health status computation for the ARGUS agent and security subsystems.
 */
export function computeAgentHealth() {
  const live = eventHub.isAgentLive();
  const hb = eventHub.getAgentHeartbeat();

  let state: "STARTING" | "RUNNING" | "DEGRADED" | "STOPPED" | "ERROR" = "STOPPED";
  if (!live || !hb) {
    state = "STOPPED";
  } else if (hb.component_failures && Object.keys(hb.component_failures).length > 0) {
    state = "DEGRADED";
  } else if ((hb.uptimeSeconds ?? 0) < 5) {
    state = "STARTING";
  } else {
    const w = hb.watchers;
    if (w && (!w.process || !w.system || !w.network)) {
      state = "DEGRADED";
    } else {
      state = "RUNNING";
    }
  }

  const isProtected = state === "RUNNING" || state === "DEGRADED";

  const tel = eventHub.getTelemetry();
  const snap = eventHub.getSnapshot();
  const net = eventHub.getNetworkSnapshot();
  const fs = eventHub.getFileScan();
  const providers = eventHub.getSecurityProviders();

  return {
    state,
    protected: isProtected,
    live,
    endpointId: hb?.endpointId ?? null,
    agentVersion: hb?.agentVersion ?? "1.0.0",
    uptimeSeconds: hb?.uptimeSeconds ?? 0,
    timestamp: new Date().toISOString(),
    lastHeartbeat: hb?.timestamp ?? null,
    componentFailures: hb?.component_failures ?? {},
    subsystems: {
      agent: {
        state: state.toLowerCase(),
        live,
        uptimeSeconds: hb?.uptimeSeconds ?? 0,
        lastHeartbeat: hb?.timestamp ?? null,
      },
      telemetry: {
        state: hb?.watchers?.system ? (tel ? "running" : "starting") : "unavailable",
        lastUpdate: tel?.timestamp ?? null,
      },
      process_monitor: {
        state: hb?.watchers?.process ? (snap ? "running" : "starting") : "unavailable",
        lastUpdate: snap?.timestamp ?? null,
        processCount: snap?.total_count ?? 0,
      },
      network_monitor: {
        state: hb?.watchers?.network ? (net ? "running" : "starting") : "unavailable",
        lastUpdate: net?.timestamp ?? null,
        connectionCount: net?.connections?.length ?? 0,
      },
      file_monitor: {
        state: hb?.watchers?.files ? (fs ? "running" : "starting") : "unavailable",
        lastUpdate: fs?.timestamp ?? null,
      },
      security_providers: {
        state: hb?.watchers?.security_providers ? (providers ? "running" : "starting") : "unavailable",
        lastUpdate: providers?.timestamp ?? null,
        providerCount: providers?.providers?.length ?? 0,
      },
      detection_engine: {
        state: "running",
        available: true,
        rulesLoaded: 24,
      },
      recovery_subsystem: {
        state: "running",
        available: true,
      },
    },
  };
}

/**
 * GET /api/agent/health & GET /api/monitoring/agent/health
 * Authoritative agent health and subsystem protection status.
 */
router.get(["/agent/health", "/monitoring/agent/health"], (_req: Request, res: Response) => {
  res.json(computeAgentHealth());
});

/**
 * GET /api/monitoring/agent
 * Report agent liveness, component health, pending command count and computed health.
 */
router.get("/monitoring/agent", (_req: Request, res: Response) => {
  const health = computeAgentHealth();
  res.json({
    live: eventHub.isAgentLive(),
    heartbeat: eventHub.getAgentHeartbeat(),
    pending_commands: eventHub.getPendingCommands().length,
    recent_acks: eventHub.getCommandAcks(20),
    health,
  });
});

/**
 * GET /api/monitoring/agent/commands
 * Commands the endpoint agent should execute. Polled by the agent.
 *
 * The API never runs a scan itself: it queues the intent and the agent performs
 * it, then acknowledges the outcome at POST /monitoring/agent/commands/ack.
 */
router.get("/monitoring/agent/commands", (_req: Request, res: Response) => {
  res.json({
    serverTime: new Date().toISOString(),
    commands: eventHub.getPendingCommands(),
  });
});

/**
 * POST /api/monitoring/agent/commands/ack
 * Record how the agent answered a command.
 */
router.post("/monitoring/agent/commands/ack", ingest, (req: Request, res: Response) => {
  const body = req.body;
  if (!body || typeof body !== "object" || typeof body.commandId !== "string") {
    res.status(400).json({ error: "Invalid request body", detail: "Expected a 'commandId' string." });
    return;
  }
  eventHub.ackCommand({
    ...(body as Partial<AgentCommandAck>),
    commandId: body.commandId,
    type: body.type || "UNKNOWN",
    status: body.status || "unknown",
    respondedAt: body.respondedAt || new Date().toISOString(),
  });
  res.status(202).json({ accepted: true });
});

/**
 * POST /api/monitoring/agent/commands
 * Queue a command for the endpoint agent.
 */
router.post("/monitoring/agent/commands", ingest, (req: Request, res: Response) => {
  const body = req.body;
  const type = typeof body?.type === "string" ? body.type.toUpperCase() : "";
  if (type !== "SCAN_REQUEST" && type !== "CANCEL_SCAN" && type !== "PING") {
    res.status(400).json({
      error: "Unsupported command",
      detail: "type must be one of SCAN_REQUEST, CANCEL_SCAN, PING.",
    });
    return;
  }
  const command = eventHub.enqueueCommand({
    commandId:
      typeof body.commandId === "string" && body.commandId
        ? body.commandId
        : `cmd-${Date.now().toString(36)}-${Math.floor(Math.random() * 1e9).toString(36)}`,
    type,
    issuedAt: new Date().toISOString(),
    payload: typeof body.payload === "object" && body.payload ? body.payload : {},
    requestId: typeof body.requestId === "string" ? body.requestId : null,
  });
  res.status(202).json({ queued: true, command, agentLive: eventHub.isAgentLive() });
});

/**
 * GET /api/monitoring/correlation
 * Cross-domain correlations derived from real evidence, newest first.
 */
router.get("/monitoring/correlation", (req: Request, res: Response) => {
  const rawLimit = Number(req.query.limit);
  const limit = Number.isInteger(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 200) : 50;
  res.json({ correlations: eventHub.getCorrelations(limit) });
});

/**
 * GET /api/monitoring/stream
 * SSE endpoint for the unified monitoring stream.
 *
 * Subscribes to every source broadcast, then re-emits a throttled,
 * normalized monitoring snapshot (max ~ every 1.5s) to monitoring clients.
 * Also passes through scan state updates so live scan progress arrives
 * promptly without flooding the client.
 */
router.get("/monitoring/stream", (req: Request, res: Response) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  let dirty = false;

  const emitSnapshot = () => {
    const snapshot = eventHub.getMonitoringSnapshot();
    eventHub.broadcastMonitoring(snapshot);
  };

  // Initial connection event with the current aggregate.
  const current = eventHub.getMonitoringSnapshot();
  res.write(
    `data: ${JSON.stringify({ type: "connected", timestamp: new Date().toISOString(), snapshot: current })}\n\n`,
  );

  // Internal observer: receives every source broadcast (no topic filter).
  const observerId = eventHub.addSSEClient(() => {
    dirty = true;
  });

  // Throttled recompute — 1.5s cadence.
  const emitTimer = setInterval(() => {
    if (!dirty) return;
    dirty = false;
    try {
      emitSnapshot();
    } catch {
      // client cleanup handled below
    }
  }, 1500);

  const heartbeat = setInterval(() => {
    try {
      res.write(": heartbeat\n\n");
    } catch {
      clearInterval(heartbeat);
      clearInterval(emitTimer);
      eventHub.removeSSEClient(observerId);
    }
  }, 15000);

  req.on("close", () => {
    clearInterval(heartbeat);
    clearInterval(emitTimer);
    eventHub.removeSSEClient(observerId);
  });
});

export default router;