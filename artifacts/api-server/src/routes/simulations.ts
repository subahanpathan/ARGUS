/**
 * ARGUS Controlled Simulation Lifecycle API Routes.
 *
 * Implements Phase 1 endpoints:
 * - GET  /api/simulations/scenarios  — list approved simulation scenarios
 * - GET  /api/simulations            — list all simulation runs
 * - POST /api/simulations            — validate and start an approved scenario
 * - GET  /api/simulations/:id        — retrieve job status, progress and metrics
 * - GET  /api/simulations/:id/events — retrieve tagged events for a simulation
 * - POST /api/simulations/:id/stop   — request safe cancellation and cleanup
 */

import { Router, type Request, type Response } from "express";
import { simulationEngine } from "../lib/simulation-engine";

const router = Router();

/**
 * GET /api/simulations/scenarios
 * Returns the allowlist of approved safe simulation scenarios.
 */
router.get("/simulations/scenarios", (_req: Request, res: Response) => {
  res.json({ scenarios: simulationEngine.getScenarioAllowlist() });
});

/**
 * GET /api/simulations
 * Returns all recorded simulation runs.
 */
router.get("/simulations", (_req: Request, res: Response) => {
  res.json({ simulations: simulationEngine.getAllSimulationRuns() });
});

/**
 * POST /api/simulations
 * Validates scenario parameter and starts a new simulation run.
 */
router.post("/simulations", async (req: Request, res: Response) => {
  const { scenarioId } = req.body || {};

  if (!scenarioId || typeof scenarioId !== "string") {
    res.status(400).json({
      error: "BAD_REQUEST",
      message: "Field 'scenarioId' is required and must be a string.",
    });
    return;
  }

  try {
    const run = await simulationEngine.startSimulation(scenarioId);
    res.status(201).json({ simulation: run });
  } catch (err: any) {
    const msg = err.message || String(err);
    if (msg.startsWith("INVALID_SCENARIO")) {
      res.status(400).json({ error: "INVALID_SCENARIO", message: msg });
    } else if (msg.startsWith("CONCURRENT_SIMULATION")) {
      res.status(409).json({ error: "CONCURRENT_SIMULATION", message: msg });
    } else {
      res.status(500).json({ error: "INTERNAL_ERROR", message: msg });
    }
  }
});

/**
 * GET /api/simulations/:id
 * Retrieves status, phase progress, ground truth, and detection metrics for a simulation.
 */
router.get("/simulations/:id", (req: Request, res: Response) => {
  const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const run = simulationEngine.getSimulationRun(id);

  if (!run) {
    res.status(404).json({
      error: "NOT_FOUND",
      message: `Simulation '${id}' was not found.`,
    });
    return;
  }

  res.json({ simulation: run });
});

/**
 * GET /api/simulations/:id/events
 * Retrieves events generated during a specific simulation run.
 */
router.get("/simulations/:id/events", (req: Request, res: Response) => {
  const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const run = simulationEngine.getSimulationRun(id);

  if (!run) {
    res.status(404).json({
      error: "NOT_FOUND",
      message: `Simulation '${id}' was not found.`,
    });
    return;
  }

  const events = simulationEngine.getSimulationEvents(id);
  res.json({
    simulationId: id,
    events,
    count: events.length,
  });
});

/**
 * POST /api/simulations/:id/stop
 * Requests cancellation and safe cleanup of a running simulation.
 */
router.post("/simulations/:id/stop", (req: Request, res: Response) => {
  const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;

  try {
    const run = simulationEngine.stopSimulation(id);
    res.json({ success: true, simulation: run });
  } catch (err: any) {
    const msg = err.message || String(err);
    if (msg.startsWith("NOT_FOUND")) {
      res.status(404).json({ error: "NOT_FOUND", message: msg });
    } else {
      res.status(500).json({ error: "INTERNAL_ERROR", message: msg });
    }
  }
});

/**
 * POST /api/simulations/:id/recover
 * Restores synthetic lab test files from trusted backup staging directory and verifies SHA-256 baseline hashes.
 */
router.post("/simulations/:id/recover", (req: Request, res: Response) => {
  const id = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;

  try {
    const run = simulationEngine.recoverLabFiles(id);
    res.json({ success: true, simulation: run });
  } catch (err: any) {
    const msg = err.message || String(err);
    if (msg.startsWith("NOT_FOUND")) {
      res.status(404).json({ error: "NOT_FOUND", message: msg });
    } else {
      res.status(500).json({ error: "INTERNAL_ERROR", message: msg });
    }
  }
});

/**
 * POST /api/simulations/adaptive-memory/reset
 * Resets adaptive defense memory so previously blocked simulation scenarios can be re-executed from scratch.
 */
router.post("/simulations/adaptive-memory/reset", (_req: Request, res: Response) => {
  simulationEngine.resetAdaptiveMemory();
  res.json({ success: true, message: "Adaptive defense memory reset successfully." });
});

export default router;
