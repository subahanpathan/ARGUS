import { Router, type IRouter, type Request, type Response } from "express";
import { eventHub, type FileScanSnapshot } from "../lib/event-hub";
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

  // Enforce payload size limit: max 1000 findings per snapshot
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

  // Evaluate the scan findings against the FILE rule set (startup
  // persistence, loot, downloader strings, …) and broadcast new detections.
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
 * GET /api/files/scan/stream
 * SSE endpoint for real-time file scan result streaming.
 */
router.get("/files/scan/stream", (req: Request, res: Response) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  // Send initial connection event with the current scan if available
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