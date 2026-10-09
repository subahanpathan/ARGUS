import { Router, type IRouter, type Request, type Response } from "express";
import { adaptiveDefenseEngine } from "../lib/adaptive-defense";
import { logger } from "../lib/logger";

const router: IRouter = Router();

/**
 * GET /api/adaptive-defense/snapshot
 * Full snapshot of rule metrics, regression history and aggregate counts.
 */
router.get("/adaptive-defense/snapshot", (_req: Request, res: Response) => {
  try {
    res.json(adaptiveDefenseEngine.getSnapshot());
  } catch (error) {
    logger.error({ scope: "adaptive-defense", err: error }, "failed to build snapshot");
    res.status(500).json({ error: "Adaptive defense snapshot unavailable" });
  }
});

/**
 * GET /api/adaptive-defense/rules
 * Array of per-rule metrics, sorted by total firings descending.
 */
router.get("/adaptive-defense/rules", (_req: Request, res: Response) => {
  try {
    const { ruleMetrics } = adaptiveDefenseEngine.getSnapshot();
    const sorted = [...ruleMetrics].sort((a, b) => b.totalFirings - a.totalFirings);
    res.json({ count: sorted.length, rules: sorted });
  } catch (error) {
    logger.error({ scope: "adaptive-defense", err: error }, "failed to list rule metrics");
    res.status(500).json({ error: "Rule metrics unavailable" });
  }
});

/**
 * POST /api/adaptive-defense/regression
 * Record a regression test run and return its result.
 *
 * Body: { scenarioName: string, expectedRules: string[], firedRules: string[] }
 */
router.post("/adaptive-defense/regression", (req: Request, res: Response) => {
  const { scenarioName, expectedRules, firedRules } = req.body ?? {};

  if (typeof scenarioName !== "string" || !scenarioName.trim()) {
    res.status(400).json({ error: "scenarioName is required" });
    return;
  }
  if (!Array.isArray(expectedRules) || !expectedRules.every((r) => typeof r === "string")) {
    res.status(400).json({ error: "expectedRules must be an array of strings" });
    return;
  }
  if (!Array.isArray(firedRules) || !firedRules.every((r) => typeof r === "string")) {
    res.status(400).json({ error: "firedRules must be an array of strings" });
    return;
  }

  try {
    const result = adaptiveDefenseEngine.recordRegressionRun(scenarioName, expectedRules, firedRules);
    res.status(201).json(result);
  } catch (error) {
    logger.error({ scope: "adaptive-defense", err: error }, "failed to record regression run");
    res.status(500).json({ error: "Failed to record regression run" });
  }
});

/**
 * POST /api/adaptive-defense/incident-closure
 * Update rule metrics after a human closes an incident.
 *
 * Body: { incidentId: string, firedRules: string[], outcome: 'CONFIRMED_THREAT' | 'FALSE_POSITIVE' | 'INCONCLUSIVE' }
 */
router.post("/adaptive-defense/incident-closure", (req: Request, res: Response) => {
  const { incidentId, firedRules, outcome } = req.body ?? {};

  if (typeof incidentId !== "string" || !incidentId.trim()) {
    res.status(400).json({ error: "incidentId is required" });
    return;
  }
  if (!Array.isArray(firedRules) || !firedRules.every((r) => typeof r === "string")) {
    res.status(400).json({ error: "firedRules must be an array of strings" });
    return;
  }
  const validOutcomes = ["CONFIRMED_THREAT", "FALSE_POSITIVE", "INCONCLUSIVE"] as const;
  if (!validOutcomes.includes(outcome)) {
    res.status(400).json({ error: `outcome must be one of: ${validOutcomes.join(", ")}` });
    return;
  }

  try {
    adaptiveDefenseEngine.recordIncidentClosure(incidentId, firedRules, outcome);
    res.status(204).end();
  } catch (error) {
    logger.error({ scope: "adaptive-defense", err: error }, "failed to record incident closure");
    res.status(500).json({ error: "Failed to record incident closure" });
  }
});

export default router;
