import { test, describe, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { simulationEngine, ALLOWED_SCENARIOS } from "../../lib/simulation-engine";
import { eventHub } from "../../lib/event-hub";
import { detectionEngine } from "../engine";

describe("ARGUS Phase 1 — Controlled Simulation Framework Lifecycle & Isolation", () => {
  beforeEach(() => {
    simulationEngine.reset();
    eventHub.reset();
    detectionEngine.reset();
  });

  after(() => {
    simulationEngine.reset();
  });

  test("Test 1: Scenario allowlist is defined and rejected for unknown scenarios", () => {
    const allowlist = simulationEngine.getScenarioAllowlist();
    assert.ok(Array.isArray(allowlist));
    assert.ok(allowlist.length >= 4);

    const ids = allowlist.map((s) => s.id);
    assert.ok(ids.includes("reverse_shell_exfiltration"));
    assert.ok(ids.includes("suspicious_process_spawn"));
    assert.ok(ids.includes("test_file_integrity"));
    assert.ok(ids.includes("benign_browser_activity"));
  });

  test("Test 2: Starting an allowed scenario generates unique simulation_id and initial state", async () => {
    const run1 = await simulationEngine.startSimulation("suspicious_process_spawn");
    assert.ok(run1.simulationId.startsWith("sim-"));
    assert.equal(run1.scenarioId, "suspicious_process_spawn");
    assert.equal(run1.is_simulation, true);
    assert.ok(["starting", "running", "completed"].includes(run1.status));

    // Poll for run to complete
    let completedRun1 = simulationEngine.getSimulationRun(run1.simulationId);
    let attempts = 0;
    while (completedRun1 && (completedRun1.status === "starting" || completedRun1.status === "running") && attempts < 30) {
      await new Promise((r) => setTimeout(r, 200));
      completedRun1 = simulationEngine.getSimulationRun(run1.simulationId);
      attempts++;
    }

    assert.ok(completedRun1);
    assert.equal(completedRun1.status, "completed");

    // Second run produces unique simulationId
    const run2 = await simulationEngine.startSimulation("benign_browser_activity");
    assert.notEqual(run1.simulationId, run2.simulationId);
    assert.ok(run2.simulationId.startsWith("sim-"));
  });

  test("Test 3: Duplicate concurrent starts are rejected", async () => {
    const run1 = await simulationEngine.startSimulation("reverse_shell_exfiltration");

    // Attempting a second start immediately should fail
    await assert.rejects(
      async () => {
        await simulationEngine.startSimulation("test_file_integrity");
      },
      (err: any) => {
        return err.message.includes("CONCURRENT_SIMULATION");
      }
    );

    // Stop run1 so future tests can proceed
    simulationEngine.stopSimulation(run1.simulationId);
  });

  test("Test 4: Simulation events carry explicit metadata (is_simulation, simulation_id, scenario_id)", async () => {
    const run = await simulationEngine.startSimulation("reverse_shell_exfiltration");

    let attempts = 0;
    while (attempts < 30) {
      await new Promise((r) => setTimeout(r, 200));
      const evts = simulationEngine.getSimulationEvents(run.simulationId);
      if (evts.length > 0) break;
      attempts++;
    }

    const events = simulationEngine.getSimulationEvents(run.simulationId);
    assert.ok(events.length > 0, "Simulation should generate events");

    for (const evt of events) {
      assert.equal(evt.is_simulation, true, "Event must carry is_simulation: true");
      assert.equal(evt.simulation_id, run.simulationId, "Event must carry simulation_id");
      assert.equal(evt.scenario_id, "reverse_shell_exfiltration", "Event must carry scenario_id");
      assert.equal(evt.source, "simulation", "Event source must be 'simulation'");
    }
  });

  test("Test 5: Live events retain live telemetry source and non-simulated classification", () => {
    eventHub.addEvent({
      id: "evt-live-101",
      event_type: "PROCESS_STARTED",
      timestamp: new Date().toISOString(),
      pid: 1234,
      process_name: "explorer.exe",
      source: "windows_process_monitor",
      observed: true,
    });

    const events = eventHub.getEvents();
    const liveEvt = events.find((e) => e.id === "evt-live-101");
    assert.ok(liveEvt);
    assert.equal(liveEvt.source, "windows_process_monitor");
    assert.notEqual(liveEvt.is_simulation, true, "Live event must NOT be classified as simulation");
  });

  test("Test 6: Simulation event ingestion triggers detections tagged with simulation metadata", async () => {
    const run = await simulationEngine.startSimulation("reverse_shell_exfiltration");

    let attempts = 0;
    while (attempts < 30) {
      await new Promise((r) => setTimeout(r, 200));
      const detections = eventHub.getDetections();
      const simDetections = detections.filter((d) => d.simulation_id === run.simulationId);
      if (simDetections.length > 0) break;
      attempts++;
    }

    const detections = eventHub.getDetections();
    const simDetections = detections.filter((d) => d.simulation_id === run.simulationId);

    assert.ok(simDetections.length > 0, "Simulation must trigger detections in EventHub");
    for (const det of simDetections) {
      assert.equal(det.is_simulation, true);
      assert.equal(det.simulation_id, run.simulationId);
      assert.equal(det.scenario_id, "reverse_shell_exfiltration");
    }
  });

  test("Test 7: Stop simulation cancels active run and performs safe workspace cleanup", async () => {
    const run = await simulationEngine.startSimulation("reverse_shell_exfiltration");
    assert.ok(["starting", "running"].includes(run.status));

    const stoppedRun = simulationEngine.stopSimulation(run.simulationId);
    assert.equal(stoppedRun.status, "cancelled");
    assert.ok(stoppedRun.completedAt);
  });

  test("Test 8: Test files are isolated within var/argus-lab-workspace/", async () => {
    const run = await simulationEngine.startSimulation("test_file_integrity");
    await new Promise((r) => setTimeout(r, 1600));

    const workspaceDir = path.resolve(process.cwd(), "var", "argus-lab-workspace");
    assert.ok(fs.existsSync(workspaceDir), "Workspace directory must exist");

    // Verify test files are created inside workspace directory
    const credFile = path.join(workspaceDir, "lab_credentials.txt");
    assert.ok(fs.existsSync(credFile), "Test file must be isolated in lab workspace");

    const content = fs.readFileSync(credFile, "utf-8");
    assert.ok(content.includes("ARGUS_LAB_SYNTHETIC"), "Test file must contain synthetic marker");

    // Cleanup simulation
    simulationEngine.stopSimulation(run.simulationId);
  });
});
