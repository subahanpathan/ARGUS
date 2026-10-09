/**
 * ARGUS Detection Accuracy Benchmark & Evaluation Routes.
 *
 * Exposes deterministic evaluation metrics (Precision, Recall, F1, Latency, FP Rate,
 * Top-1/Top-3 Prediction Accuracy, Evidence Coverage) per rule and per scenario.
 */

import { Router, type IRouter, type Request, type Response } from "express";
import { benchmarkEvaluationEngine } from "../detection/benchmark";
import { logger } from "../lib/logger";

const router: IRouter = Router();

/**
 * GET /api/benchmark/results
 * Returns quantitative benchmark metrics over the deterministic ground-truth dataset.
 */
router.get("/benchmark/results", (_req: Request, res: Response) => {
  try {
    const results = benchmarkEvaluationEngine.evaluateBenchmark();
    res.json(results);
  } catch (err) {
    logger.error({ scope: "benchmark", err }, "failed to evaluate benchmark");
    res.status(500).json({ error: "Failed to evaluate benchmark metrics" });
  }
});

/**
 * POST /api/benchmark/run
 * Triggers a fresh evaluation cycle of the benchmark regression suite.
 */
router.post("/benchmark/run", (_req: Request, res: Response) => {
  try {
    const results = benchmarkEvaluationEngine.evaluateBenchmark();
    res.json(results);
  } catch (err) {
    logger.error({ scope: "benchmark", err }, "failed to run benchmark suite");
    res.status(500).json({ error: "Failed to run benchmark suite" });
  }
});

export default router;
