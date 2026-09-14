import { Router, type IRouter, type Request, type Response } from "express";
import { eventHub } from "../lib/event-hub";

const router: IRouter = Router();

/**
 * POST /api/system/telemetry
 * Accept a system telemetry snapshot from the security engine.
 * Stores the latest snapshot and broadcasts it to SSE clients.
 */
router.post("/system/telemetry", (req: Request, res: Response) => {
  const body = req.body;

  if (!body || typeof body !== "object") {
    res.status(400).json({
      error: "Invalid request body",
      detail: "Expected a system telemetry object.",
    });
    return;
  }

  if (body.source && body.source !== "windows_system_monitor") {
    res.status(422).json({
      error: "Invalid source",
      detail: "source must be 'windows_system_monitor'.",
    });
    return;
  }

  eventHub.setTelemetry(body);
  res.status(201).json({ accepted: true });
});

/**
 * GET /api/system/telemetry
 * Retrieve the current system telemetry snapshot.
 */
router.get("/system/telemetry", (_req: Request, res: Response) => {
  const telemetry = eventHub.getTelemetry();
  if (!telemetry) {
    res.status(503).json({
      error: "Telemetry unavailable",
      detail: "No telemetry snapshot available. Start the security engine to populate.",
      telemetry: null,
    });
    return;
  }
  res.json(telemetry);
});

/**
 * GET /api/system/telemetry/stream
 * SSE endpoint for real-time system telemetry streaming.
 */
router.get("/system/telemetry/stream", (req: Request, res: Response) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  // Send initial connection event with current telemetry if available
  const current = eventHub.getTelemetry();
  res.write(
    `data: ${JSON.stringify({ type: "connected", timestamp: new Date().toISOString(), ...(current ? { telemetry: current } : {}) })}\n\n`,
  );

  const clientId = eventHub.addSSEClient((data: string) => {
    try {
      res.write(data);
    } catch {
      eventHub.removeSSEClient(clientId);
    }
  }, ["telemetry"]);

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
