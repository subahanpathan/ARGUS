/**
 * ARGUS Prediction Engine API Route.
 *
 * Exposes a single read-only endpoint that runs the deterministic prediction
 * engine against live EventHub state and returns structured, uncertainty-
 * quantified forward-looking attack-stage predictions.
 *
 * All returned predictions are explicitly flagged as predicted (isPredicted=true)
 * and are never claimed to be confirmed observations.
 */

import { Router, type Request, type Response } from "express";
import { generatePredictions } from "../lib/prediction-engine";
import { attackCorrelationEngine } from "../lib/attack-correlation";
import { eventHub } from "../lib/event-hub";

const router = Router();

/**
 * GET /api/predictions
 *
 * Returns a ranked list of likely next attack stages derived from currently
 * correlated incidents and live detections in the EventHub.
 *
 * Response shape:
 * ```json
 * {
 *   "predictions": [ { stage, mitreId, confidence, uncertainty, evidenceRefs, explanation, isPredicted, basis } ],
 *   "generatedAt": "ISO-8601",
 *   "incidentCount": 3
 * }
 * ```
 */
router.get("/predictions", (_req: Request, res: Response) => {
  const incidents = attackCorrelationEngine.getCorrelatedIncidents();
  const detections = eventHub.getDetections(200);

  const predictions = generatePredictions(incidents, detections);

  res.json({
    predictions,
    generatedAt: new Date().toISOString(),
    incidentCount: incidents.length,
  });
});

export default router;
