import { Router, type IRouter, type Request, type Response } from "express";
import { eventHub, type FileScanSnapshot, type FileActivityEvent, type FileActivityOperation } from "../lib/event-hub";
import { detectionEngine } from "../detection/engine";

const router: IRouter = Router();

/** Validate the shape of a single file finding. */
function validateFinding(f: unknown): { valid: true } | { valid: false; error: string } {
  if (!f || typeof f !== "object") {
    return { valid: false, error: "Finding must be an object" };
  }
  const finding = f as Record<string, unknown>;
  if (typeof finding.path !== "string" || finding.path.length === 0) {
    return { valid: false, error: "finding.path must be a non-empty string" };
  }
  if (typeof finding.name !== "string" || finding.name.length === 0) {
    return { valid: false, error: "finding.name must be a non-empty string" };
  }
  if (typeof finding.severity !== "string") {
    return { valid: false, error: "finding.severity must be a string" };
  }
  return { valid: true };
}

/**
 * POST /api/files/scan
 * Accept a filesystem threat scan snapshot from the security engine.
 * Stores the latest snapshot and broadcasts it to SSE clients.
 */
router.post("/files/scan", (req: Request, res: Response) => {
  const body = req.body;

  if (!body || typeof body !== "object") {
    res.status(400).json({
      error: "Invalid request body",
      detail: "Expected a file scan snapshot object.",
    });
    return;
  }

  if (!Array.isArray(body.findings)) {
    res.status(400).json({
      error: "Invalid snapshot",
      detail: "Snapshot must contain a 'findings' array.",
    });
    return;
  }

  if (body.findings.length > 1000) {
    res.status(413).json({
      error: "Snapshot too large",
      detail: "Maximum 1000 findings per snapshot.",
    });
    return;
  }

  const findings: unknown[] = body.findings;
  const validated: unknown[] = [];
  const errors: Array<{ index: number; error: string }> = [];

  for (let i = 0; i < findings.length; i++) {
    const validation = validateFinding(findings[i]);
    if (validation.valid) {
      validated.push(findings[i]);
    } else {
      errors.push({ index: i, error: validation.error });
    }
  }

  const snapshot: FileScanSnapshot = {
    timestamp: body.timestamp || new Date().toISOString(),
    directories_scanned: body.directories_scanned || 0,
    files_candidates: body.files_candidates || 0,
    files_hashed: body.files_hashed || 0,
    files_read: body.files_read || 0,
    total_count: validated.length,
    findings: validated as FileScanSnapshot["findings"],
  };

  eventHub.setFileScan(snapshot);

  const detections = detectionEngine.ingestFileScan(snapshot);
  for (const detection of detections) {
    eventHub.addDetection(detection);
  }

  res.status(201).json({
    accepted: validated.length,
    rejected: errors.length,
    ...(errors.length > 0 ? { errors } : {}),
  });
});

/**
 * GET /api/files/scan
 * Retrieve the current file scan snapshot.
 */
router.get("/files/scan", (_req: Request, res: Response) => {
  const scan = eventHub.getFileScan();
  if (!scan) {
    res.json({
      timestamp: null,
      directories_scanned: 0,
      files_candidates: 0,
      files_hashed: 0,
      files_read: 0,
      total_count: 0,
      findings: [],
      message: "No file scan available. Start the security engine to populate.",
    });
    return;
  }
  res.json(scan);
});

/**
 * POST /api/files/events
 * Accept real-time file activity events from the endpoint security engine or watcher.
 */
router.post("/files/events", (req: Request, res: Response) => {
  const body = req.body;
  if (!body) {
    res.status(400).json({ error: "Missing body" });
    return;
  }

  const rawEvents = Array.isArray(body) ? body : Array.isArray(body.events) ? body.events : [body];
  const accepted: FileActivityEvent[] = [];

  for (const raw of rawEvents) {
    if (!raw || typeof raw !== "object" || !raw.filePath) continue;

    let op: FileActivityOperation = "MODIFY";
    const rawKind = (raw.operation || raw.eventType || raw.kind || "MODIFY").toUpperCase();

    if (rawKind.includes("CREATE") || rawKind === "ADDED") op = "CREATE";
    else if (rawKind.includes("DELETE") || rawKind === "REMOVED") op = "DELETE";
    else if (rawKind.includes("RENAME")) op = "RENAME";
    else if (rawKind.includes("ACCESS")) op = "ACCESS";

    let evtType: FileActivityEvent["eventType"] = "FILE_MODIFIED";
    if (op === "CREATE") evtType = "FILE_CREATED";
    else if (op === "DELETE") evtType = "FILE_DELETED";
    else if (op === "RENAME") evtType = "FILE_RENAMED";
    else if (op === "ACCESS") evtType = "FILE_ACCESSED";

    const baseName = (raw.filePath as string).split(/[/\\]/).pop() || "";
    const ext = baseName.includes(".") ? "." + baseName.split(".").pop()?.toLowerCase() : null;

    const evt: FileActivityEvent = {
      eventId: raw.eventId || `fa-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      timestamp: raw.timestamp || new Date().toISOString(),
      eventType: evtType,
      filePath: raw.filePath,
      oldFilePath: raw.oldFilePath || raw.old_path || null,
      newFilePath: raw.newFilePath || null,
      operation: op,
      pid: raw.pid || null,
      processName: raw.processName || raw.process_name || null,
      executablePath: raw.executablePath || raw.executable_path || null,
      parentPid: raw.parentPid || raw.parent_pid || null,
      parentProcessName: raw.parentProcessName || raw.parent_process_name || null,
      fileSize: typeof raw.fileSize === "number" ? raw.fileSize : typeof raw.size_bytes === "number" ? raw.size_bytes : null,
      extension: ext,
      hash: raw.hash || null,
      source: raw.source || "readdirectorychangesw",
      observationStatus: raw.observationStatus || (raw.pid ? "OBSERVED" : "CORRELATED"),
      hashStatus: raw.hash ? "HASH_OBSERVED" : "HASH_NOT_AVAILABLE",
      metadata: raw.metadata || {},
    };

    eventHub.addFileActivity(evt);
    accepted.push(evt);
  }

  res.status(201).json({
    status: "ok",
    acceptedCount: accepted.length,
    events: accepted,
  });
});

/**
 * GET /api/files/events
 * Retrieve recent real-time file activity events.
 */
router.get("/files/events", (req: Request, res: Response) => {
  const limit = parseInt((req.query.limit as string) || "100", 10);
  const events = eventHub.getFileActivity(limit);
  res.json({
    timestamp: new Date().toISOString(),
    count: events.length,
    events,
  });
});

/**
 * GET /api/files/scan/stream
 * SSE endpoint for real-time file scan result streaming.
 */
router.get("/files/scan/stream", (req: Request, res: Response) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  const current = eventHub.getFileScan();
  res.write(
    `data: ${JSON.stringify({ type: "connected", timestamp: new Date().toISOString(), ...(current ? { scan: current } : {}) })}\n\n`,
  );

  const clientId = eventHub.addSSEClient((data: string) => {
    try {
      res.write(data);
    } catch {
      eventHub.removeSSEClient(clientId);
    }
  }, ["files.scan"]);

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