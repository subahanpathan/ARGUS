import { Router, type IRouter, type Request, type Response } from "express";
import { eventHub, type ProcessEvent, type ProcessSnapshot } from "../lib/event-hub";
import { detectionEngine } from "../detection/engine";

const router: IRouter = Router();

/**
 * POST /api/events/process
 * Accept one or more process events from the security engine.
 */
router.post("/events/process", (req: Request, res: Response) => {
  const body = req.body;

  if (!body || (typeof body !== "object" && !Array.isArray(body))) {
    res.status(400).json({
      error: "Invalid request body",
      detail: "Expected a process event object or array of events.",
    });
    return;
  }

  const events: ProcessEvent[] = Array.isArray(body) ? body : [body];
  const validated: ProcessEvent[] = [];
  const errors: Array<{ index: number; error: string }> = [];

  for (let i = 0; i < events.length; i++) {
    const event = events[i];
    const validation = validateProcessEvent(event);
    if (validation.valid) {
      validated.push(event);
    } else {
      errors.push({ index: i, error: validation.error });
    }
  }

  // Enforce payload size limit: max 100 events per batch
  if (validated.length > 100) {
    res.status(413).json({
      error: "Payload too large",
      detail: "Maximum 100 events per batch.",
    });
    return;
  }

  for (const event of validated) {
    eventHub.addEvent(event);
    // Run deterministic detection over real telemetry and surface any findings.
    const detections = detectionEngine.ingestEvent(event);
    for (const detection of detections) {
      eventHub.addDetection(detection);
    }
  }

  if (errors.length > 0 && validated.length === 0) {
    res.status(422).json({
      error: "Validation failed",
      details: errors,
    });
    return;
  }

  res.status(201).json({
    accepted: validated.length,
    rejected: errors.length,
    ...(errors.length > 0 ? { errors } : {}),
  });
});

/**
 * GET /api/events/process
 * Retrieve recent process events.
 */
router.get("/events/process", (req: Request, res: Response) => {
  const eventType =
    typeof req.query.event_type === "string" ? req.query.event_type : undefined;
  const limit = Math.min(
    parseInt(String(req.query.limit ?? "100"), 10) || 100,
    500,
  );

  const events = eventHub.getEvents(eventType, limit);
  res.json({ events, count: events.length });
});

/**
 * GET /api/events/process/stream
 * SSE endpoint for real-time process event streaming.
 */
router.get("/events/process/stream", (req: Request, res: Response) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  // Send initial connection event
  res.write(
    `data: ${JSON.stringify({ type: "connected", timestamp: new Date().toISOString() })}\n\n`,
  );

  const clientId = eventHub.addSSEClient((data: string) => {
    try {
      res.write(data);
    } catch {
      eventHub.removeSSEClient(clientId);
    }
  }, ["process"]);

  // Heartbeat to keep connection alive
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

/**
 * POST /api/processes
 * Accept a full process snapshot from the security engine.
 */
router.post("/processes", (req: Request, res: Response) => {
  const body = req.body;

  if (!body || typeof body !== "object") {
    res.status(400).json({
      error: "Invalid request body",
      detail: "Expected a process snapshot object.",
    });
    return;
  }

  if (!Array.isArray(body.processes)) {
    res.status(400).json({
      error: "Invalid snapshot",
      detail: "Snapshot must contain a 'processes' array.",
    });
    return;
  }

  // Enforce size limit: max 10000 processes
  if (body.processes.length > 10000) {
    res.status(413).json({
      error: "Snapshot too large",
      detail: "Maximum 10000 processes per snapshot.",
    });
    return;
  }

  const snapshot: ProcessSnapshot = {
    timestamp: body.timestamp || new Date().toISOString(),
    total_count: body.total_count || body.processes.length,
    access_denied_count: body.access_denied_count || 0,
    processes: body.processes,
  };

  eventHub.setSnapshot(snapshot);

  // Accept the snapshot into the detection engine once (gate on timestamp).
  const detections = detectionEngine.ingestSnapshot(snapshot);
  for (const detection of detections) {
    eventHub.addDetection(detection);
  }

  res.status(201).json({
    accepted: true,
    process_count: body.processes.length,
  });
});

/**
 * GET /api/processes
 * Retrieve the current process snapshot.
 */
router.get("/processes", (_req: Request, res: Response) => {
  const snapshot = eventHub.getSnapshot();
  if (!snapshot) {
    res.json({
      timestamp: null,
      total_count: 0,
      access_denied_count: 0,
      processes: [],
      message: "No snapshot available. Start the security engine to populate.",
    });
    return;
  }
  res.json(snapshot);
});

/** Validate required fields of a process event. */
function validateProcessEvent(event: unknown): { valid: true } | { valid: false; error: string } {
  if (!event || typeof event !== "object") {
    return { valid: false, error: "Event must be an object" };
  }
  const e = event as Record<string, unknown>;

  if (typeof e.pid !== "number") {
    return { valid: false, error: "pid must be a number" };
  }
  if (typeof e.process_name !== "string") {
    return { valid: false, error: "process_name must be a string" };
  }
  if (typeof e.event_type !== "string") {
    return { valid: false, error: "event_type must be a string" };
  }
  if (
    e.event_type !== "PROCESS_STARTED" &&
    e.event_type !== "PROCESS_TERMINATED" &&
    e.event_type !== "SNAPSHOT"
  ) {
    return {
      valid: false,
      error: `event_type must be PROCESS_STARTED, PROCESS_TERMINATED, or SNAPSHOT`,
    };
  }
  return { valid: true };
}

export default router;
