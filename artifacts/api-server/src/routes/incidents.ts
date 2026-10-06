/**
 * ARGUS Incident Response & Recovery Orchestration API Routes.
 *
 * Exposes endpoints for managing incident lifecycle state transitions,
 * executing process containment with post-action verification, running verified data recovery,
 * closing incidents, and inspecting immutable audit trails.
 */

import { Router, type Request, type Response } from "express";
import { responseOrchestrator } from "../lib/response-orchestrator";

const router = Router();

/**
 * GET /api/incidents
 * List all active orchestrated incidents with state machine, response level,
 * containment status, recovery statistics, and audit logs.
 */
router.get("/incidents", (_req: Request, res: Response) => {
  const incidents = responseOrchestrator.getOrchestratedIncidents();
  res.json({
    timestamp: new Date().toISOString(),
    count: incidents.length,
    incidents,
  });
});

/**
 * GET /api/incidents/:id
 * Retrieve single orchestrated incident by ID.
 */
router.get("/incidents/:id", (req: Request, res: Response) => {
  const id = String(req.params.id);
  const incident = responseOrchestrator.getIncidentById(id);

  if (!incident) {
    res.status(404).json({ error: "Orchestrated incident not found", incidentId: id });
    return;
  }

  res.json(incident);
});

/**
 * GET /api/incidents/:id/timeline
 * Get extended lifecycle timeline for an incident.
 */
router.get("/incidents/:id/timeline", (req: Request, res: Response) => {
  const id = String(req.params.id);
  const incident = responseOrchestrator.getIncidentById(id);

  if (!incident) {
    res.status(404).json({ error: "Orchestrated incident not found", incidentId: id });
    return;
  }

  res.json({
    incidentId: incident.incidentId,
    state: incident.state,
    timeline: incident.correlatedTrace.timeline,
  });
});

/**
 * GET /api/incidents/:id/audit
 * Get immutable audit log trail for an incident.
 */
router.get("/incidents/:id/audit", (req: Request, res: Response) => {
  const id = String(req.params.id);
  const incident = responseOrchestrator.getIncidentById(id);

  if (!incident) {
    res.status(404).json({ error: "Orchestrated incident not found", incidentId: id });
    return;
  }

  res.json({
    incidentId: incident.incidentId,
    auditTrailCount: incident.auditTrail.length,
    auditTrail: incident.auditTrail,
  });
});

/**
 * POST /api/incidents/:id/contain
 * Trigger process containment execution and post-action verification.
 */
router.post("/incidents/:id/contain", async (req: Request, res: Response) => {
  const id = String(req.params.id);
  const actor = typeof req.body?.actor === "string" ? req.body.actor : "USER";

  try {
    const result = await responseOrchestrator.orchestrateContainment(id, {
      force: true,
      actor: actor as any,
    });

    res.status(result.success ? 200 : 422).json({
      incidentId: id,
      ...result,
    });
  } catch (error: any) {
    res.status(500).json({ error: "Containment execution failed", detail: error?.message });
  }
});

/**
 * POST /api/incidents/:id/recovery
 * Trigger verified data recovery for affected files in the incident.
 */
router.post("/incidents/:id/recovery", async (req: Request, res: Response) => {
  const id = String(req.params.id);
  const actor = typeof req.body?.actor === "string" ? req.body.actor : "USER";

  try {
    const result = await responseOrchestrator.orchestrateRecovery(id, {
      actor: actor as any,
    });

    res.status(result.success ? 200 : 422).json({
      incidentId: id,
      ...result,
    });
  } catch (error: any) {
    res.status(500).json({ error: "Recovery execution failed", detail: error?.message });
  }
});

/**
 * POST /api/incidents/:id/close
 * Request incident closure.
 */
router.post("/incidents/:id/close", (req: Request, res: Response) => {
  const id = String(req.params.id);
  const actor = typeof req.body?.actor === "string" ? req.body.actor : "USER";
  const reason = typeof req.body?.reason === "string" ? req.body.reason : undefined;

  const result = responseOrchestrator.orchestrateClosure(id, {
    actor: actor as any,
    reason,
  });

  res.status(result.success ? 200 : 422).json({
    incidentId: id,
    ...result,
  });
});

export default router;
