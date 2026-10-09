import { test, describe, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { simulationEngine } from "../../lib/simulation-engine";
import { eventHub } from "../../lib/event-hub";
import { detectionEngine } from "../engine";
import { responseOrchestrator } from "../../lib/response-orchestrator";
import { generatePredictions } from "../../lib/prediction-engine";

describe("ARGUS Phase 2 — End-to-End Integration Verification (reverse_shell_exfiltration)", () => {
  beforeEach(() => {
    simulationEngine.reset();
    eventHub.reset();
    detectionEngine.reset();
  });

  after(() => {
    simulationEngine.reset();
    eventHub.reset();
    detectionEngine.reset();
  });

  test("Step 1 to 4: Simulation events -> Detections -> Correlated Incident -> Predictions with Evidence", async () => {
    // 1. Start harmless allowlisted simulation scenario
    const run = await simulationEngine.startSimulation("reverse_shell_exfiltration");
    assert.ok(run.simulationId.startsWith("sim-"));
    assert.equal(run.scenarioId, "reverse_shell_exfiltration");
    assert.equal(run.is_simulation, true);

    // Poll for simulation to complete
    let completedRun = simulationEngine.getSimulationRun(run.simulationId);
    let attempts = 0;
    while (completedRun && (completedRun.status === "starting" || completedRun.status === "running") && attempts < 40) {
      await new Promise((r) => setTimeout(r, 200));
      completedRun = simulationEngine.getSimulationRun(run.simulationId);
      attempts++;
    }

    assert.ok(completedRun, "Simulation run record must exist");
    assert.equal(completedRun.status, "completed", "Simulation run must complete successfully");

    // 2. Verify Simulation Events carry explicit simulation metadata
    const simEvents = simulationEngine.getSimulationEvents(run.simulationId);
    assert.ok(simEvents.length > 0, "Simulation must generate events");
    for (const evt of simEvents) {
      assert.equal(evt.is_simulation, true, "Event must carry is_simulation: true");
      assert.equal(evt.simulation_id, run.simulationId, "Event must carry simulation_id");
      assert.equal(evt.scenario_id, "reverse_shell_exfiltration", "Event must carry scenario_id");
      assert.equal(evt.source, "simulation", "Event source must be 'simulation'");
    }

    // 3. Verify Detections triggered and tagged with simulation metadata
    const detections = eventHub.getDetections();
    const simDetections = detections.filter((d) => d.simulation_id === run.simulationId);
    assert.ok(simDetections.length > 0, "Detections must be triggered for simulation run");

    for (const det of simDetections) {
      assert.equal(det.is_simulation, true, "Detection must carry is_simulation: true");
      assert.equal(det.simulation_id, run.simulationId, "Detection must carry simulation_id");
      assert.equal(det.scenario_id, "reverse_shell_exfiltration", "Detection must carry scenario_id");
      assert.ok(det.rule_id, "Detection must specify rule_id");
      assert.ok(det.evidence.length > 0, "Detection must include evidence");
    }

    const ruleIds = simDetections.map((d) => d.rule_id);
    assert.ok(ruleIds.some((r) => r.includes("NET-008")), "Must trigger NET-008 reverse shell detection");
    assert.ok(ruleIds.some((r) => r.includes("PROC")), "Must trigger PROC process detection");

    // 4. Verify Attack Trace / Correlated Incident grouping
    const incidents = responseOrchestrator.getOrchestratedIncidents();
    assert.ok(incidents.length > 0, "Incident correlation must group detections into orchestrated incident");

    const simIncident = incidents.find(
      (i: any) => i.primaryProcess?.pid === 9914 || i.incidentId?.includes("9914") || i.timeline?.some((e: any) => e.pid === 9914 || e.pid === 9912)
    );
    assert.ok(simIncident, "Must correlate events into incident for target PID 9914");
    const timeline = (simIncident as any).timeline ?? (simIncident as any).correlatedTrace?.timeline ?? [];
    assert.ok(timeline.length >= 1, "Incident timeline must contain correlated events");

    // 5. Verify Forward-Looking Predictions with Evidence
    const predictions = generatePredictions(incidents as any, detections);
    assert.ok(predictions.length > 0, "Prediction engine must generate predicted attack stages");

    for (const pred of predictions) {
      assert.equal(pred.isPredicted, true, "Prediction must explicitly set isPredicted: true");
      assert.ok(pred.stage, "Prediction must specify target stage");
      assert.ok(pred.confidence > 0, "Prediction must have positive confidence score");
      assert.ok(pred.evidenceRefs.length > 0, "Prediction must link to supporting evidence references");
      assert.ok(pred.explanation.length > 0, "Prediction must include human-readable explanation");
    }

    // Verify expected predicted stages for reverse shell sequence
    const predictedStages = predictions.map((p) => p.stage);
    assert.ok(
      predictedStages.includes("EXECUTION") ||
      predictedStages.includes("PERSISTENCE") ||
      predictedStages.includes("DEFENSE_EVASION"),
      "Must predict plausible next attack stages (EXECUTION / PERSISTENCE / DEFENSE_EVASION)"
    );
  });
});
