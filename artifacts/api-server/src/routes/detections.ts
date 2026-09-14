import { Router, type IRouter, type Request, type Response } from "express";
import { eventHub } from "../lib/event-hub";
import { detectionEngine } from "../detection/engine";
import { ALL_RULE_CATALOG } from "../detection/catalog";
import type { Detection, DetectionSeverity, DetectionStatus } from "../detection/types";

const VALID_STATUSES: DetectionStatus[] = [
  "observed",
  "detected",
  "investigated",
  "contained",
  "resolved",
];

const VALID_SEVERITIES: DetectionSeverity[] = ["critical", "high", "medium", "low"];

const router: IRouter = Router();

/**
 * GET /api/detections/rules
 * Returns the catalog of active detection rules (for explainability).
 */
router.get("/detections/rules", (_req: Request, res: Response) => {
  res.json({ rules: ALL_RULE_CATALOG });
});

/**
 * GET /api/detections
 * Retrieve recent detections, optionally filtered.
 */
router.get("/detections", (req: Request, res: Response) => {
  const limit = Math.min(
    parseInt(String(req.query.limit ?? "100"), 10) || 100,
    300,
  );
  const severity =
    typeof req.query.severity === "string" ? req.query.severity : undefined;
  const status =
    typeof req.query.status === "string" ? req.query.status : undefined;
  const ruleId =
    typeof req.query.rule_id === "string" ? req.query.rule_id : undefined;

  let detections = eventHub.getDetections(limit * 2);

  if (severity) detections = detections.filter((d) => d.severity === severity);
  if (status) detections = detections.filter((d) => d.status === status);
  if (ruleId) detections = detections.filter((d) => d.rule_id === ruleId);

  detections = detections.slice(0, limit);

  res.json({ detections, count: detections.length, rules: ALL_RULE_CATALOG });
});

/**
 * GET /api/detections/stream
 * SSE endpoint for real-time detection streaming.
 */
router.get("/detections/stream", (req: Request, res: Response) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  const recent = eventHub.getDetections(10);
  res.write(
    `data: ${JSON.stringify({ type: "connected", timestamp: new Date().toISOString(), detections: recent })}\n\n`,
  );

  const clientId = eventHub.addSSEClient((data: string) => {
    try {
      res.write(data);
    } catch {
      eventHub.removeSSEClient(clientId);
    }
  }, ["detections"]);

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
 * GET /api/detections/:id
 * Retrieve a single detection with its ancestry, related detections and
 * current process context.
 */
router.get("/detections/:id", (req: Request, res: Response) => {
  const id = String(req.params.id);
  const detection = eventHub.getDetection(id);
  if (!detection) {
    res.status(404).json({ error: "Detection not found" });
    return;
  }

  const related = eventHub.getRelatedDetections(detection.pid, id);
  const process =
    detectionEngine.getProcessContext(detection.pid) ??
    (eventHub.getSnapshot()?.processes.find((p) => p.pid === detection.pid) ?? null);

  const ancestry: Detection["ancestry"] =
    detection.ancestry && detection.ancestry.length > 0
      ? detection.ancestry
      : detectionEngine.getAncestry(detection.pid);

  res.json({ detection, related, process, ancestry });
});

/**
 * PATCH /api/detections/:id
 * Update the lifecycle status of a detection.
 */
router.patch("/detections/:id", (req: Request, res: Response) => {
  const id = String(req.params.id);
  const body = req.body;

  if (!body || typeof body !== "object" || typeof body.status !== "string") {
    res.status(400).json({
      error: "Invalid request body",
      detail: "Expected a JSON body with a 'status' string.",
    });
    return;
  }

  if (!VALID_STATUSES.includes(body.status as DetectionStatus)) {
    res.status(400).json({
      error: "Invalid status",
      detail: `status must be one of: ${VALID_STATUSES.join(", ")}`,
    });
    return;
  }

  const updated = eventHub.updateDetectionStatus(id, body.status as DetectionStatus);
  if (!updated) {
    res.status(404).json({ error: "Detection not found" });
    return;
  }

  res.json({ detection: updated });
});

export default router;