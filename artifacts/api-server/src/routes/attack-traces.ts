/**
 * ARGUS Attack Trace API Routes.
 *
 * Exposes correlated incident attack chains, timeline events, graph nodes/edges,
 * file impact assessments, affected files tables, and real-time SSE stream updates.
 */

import { Router, type Request, type Response } from "express";
import { attackCorrelationEngine } from "../lib/attack-correlation";
import { eventHub } from "../lib/event-hub";

const router = Router();

/**
 * GET /api/attack-traces
 * List all active correlated attack trace incidents.
 */
router.get("/attack-traces", (_req: Request, res: Response) => {
  const incidents = attackCorrelationEngine.getCorrelatedIncidents();
  res.json({
    timestamp: new Date().toISOString(),
    count: incidents.length,
    incidents,
  });
});

/**
 * GET /api/attack-traces/stream
 * Server-Sent Events stream for live attack trace updates.
 */
router.get("/attack-traces/stream", (req: Request, res: Response) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");

  const send = (data: string) => res.write(data);
  const clientId = eventHub.addSSEClient(send, ["detections", "process", "telemetry", "files.scan"]);

  const initialIncidents = attackCorrelationEngine.getCorrelatedIncidents();
  res.write(`data: ${JSON.stringify({ type: "attack_trace.snapshot", timestamp: new Date().toISOString(), count: initialIncidents.length, incidents: initialIncidents })}\n\n`);

  req.on("close", () => {
    eventHub.removeSSEClient(clientId);
  });
});

/**
 * GET /api/attack-traces/:id
 * Get single correlated incident trace by ID.
 */
router.get("/attack-traces/:id", (req: Request, res: Response) => {
  const id = String(req.params.id);
  const incidents = attackCorrelationEngine.getCorrelatedIncidents();
  const incident = incidents.find((i) => i.incidentId.toLowerCase() === id.toLowerCase());

  if (!incident) {
    res.status(404).json({ error: "Incident trace not found", incidentId: id });
    return;
  }

  res.json(incident);
});

/**
 * GET /api/attack-traces/:id/timeline
 * Get timeline events for an incident trace.
 */
router.get("/attack-traces/:id/timeline", (req: Request, res: Response) => {
  const id = String(req.params.id);
  const incidents = attackCorrelationEngine.getCorrelatedIncidents();
  const incident = incidents.find((i) => i.incidentId.toLowerCase() === id.toLowerCase());

  if (!incident) {
    res.status(404).json({ error: "Incident trace not found", incidentId: id });
    return;
  }

  res.json({
    incidentId: incident.incidentId,
    count: incident.timeline.length,
    timeline: incident.timeline,
  });
});

/**
 * GET /api/attack-traces/:id/graph
 * Get node and edge graph representation for an incident trace.
 */
router.get("/attack-traces/:id/graph", (req: Request, res: Response) => {
  const id = String(req.params.id);
  const incidents = attackCorrelationEngine.getCorrelatedIncidents();
  const incident = incidents.find((i) => i.incidentId.toLowerCase() === id.toLowerCase());

  if (!incident) {
    res.status(404).json({ error: "Incident trace not found", incidentId: id });
    return;
  }

  res.json({
    incidentId: incident.incidentId,
    graph: incident.graph,
  });
});

/**
 * GET /api/attack-traces/:id/files
 * Get list of affected files for an incident trace.
 */
router.get("/attack-traces/:id/files", (req: Request, res: Response) => {
  const id = String(req.params.id);
  const incidents = attackCorrelationEngine.getCorrelatedIncidents();
  const incident = incidents.find((i) => i.incidentId.toLowerCase() === id.toLowerCase());

  if (!incident) {
    res.status(404).json({ error: "Incident trace not found", incidentId: id });
    return;
  }

  res.json({
    incidentId: incident.incidentId,
    affectedFilesCount: incident.affectedFiles.length,
    affectedFiles: incident.affectedFiles,
  });
});

/**
 * GET /api/attack-traces/:id/impact
 * Get detailed impact assessment breakdown and conceptual data flow for an incident trace.
 */
router.get("/attack-traces/:id/impact", (req: Request, res: Response) => {
  const id = String(req.params.id);
  const incidents = attackCorrelationEngine.getCorrelatedIncidents();
  const incident = incidents.find((i) => i.incidentId.toLowerCase() === id.toLowerCase());

  if (!incident) {
    res.status(404).json({ error: "Incident trace not found", incidentId: id });
    return;
  }

  res.json({
    incidentId: incident.incidentId,
    impactAssessment: incident.impactAssessment,
    dataFlowChain: incident.dataFlowChain,
  });
});

/**
 * GET /api/attack-traces/:id/backtrace
 * Get 3D Backtrace & Network Intelligence model for an incident trace.
 */
router.get("/attack-traces/:id/backtrace", async (req: Request, res: Response) => {
  const id = String(req.params.id);
  const { backtraceEngine } = await import("../lib/backtrace-engine");
  const data = backtraceEngine.generateUnifiedBacktrace(id);

  if (!data) {
    res.status(404).json({ error: "Backtrace data unavailable for incident", incidentId: id });
    return;
  }

  res.json(data);
});

/**
 * GET /api/network-intelligence/lookup
 * Query passive network intelligence for an IP address.
 */
router.get("/network-intelligence/lookup", async (req: Request, res: Response) => {
  const ip = typeof req.query.ip === "string" ? req.query.ip : "185.199.110.27";
  const port = typeof req.query.port === "string" ? parseInt(req.query.port, 10) : 443;
  const protocol = typeof req.query.protocol === "string" ? req.query.protocol : "TCP";

  const { lookupNetworkIntelligence } = await import("../lib/backtrace-engine");
  const intel = lookupNetworkIntelligence(ip, port, protocol);

  res.json(intel);
});

export default router;
