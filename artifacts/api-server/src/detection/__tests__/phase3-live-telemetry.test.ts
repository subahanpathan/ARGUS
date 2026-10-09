/**
 * Phase 3 Focused Verification Test Suite:
 * - Live System Telemetry Ingestion & Normalization
 * - Source Labeling (LIVE vs SIMULATION)
 * - Agent Liveness & Stale-Data Detection
 * - Real-Time Process & Network Telemetry Pipeline
 * - Live Threat Detection & Benign Event Separation
 */

import test, { describe } from "node:test";
import assert from "assert/strict";
import { eventHub, type SystemTelemetry } from "../../lib/event-hub";
import { detectionEngine } from "../engine";

describe("ARGUS Phase 3 — Live Windows Telemetry & Monitoring Test Suite", () => {
  test("1. Verify System Telemetry Ingestion and Normalization", () => {
    eventHub.reset();

    const sampleTelemetry: SystemTelemetry = {
      timestamp: new Date().toISOString(),
      source: "windows_system_monitor",
      observed: true,
      cpu: { percent: 24.5, count: 8, physical_count: 4 },
      memory: { total_bytes: 17179869184, available_bytes: 8589934592, used_bytes: 8589934592, percent: 50.0 },
      processes: { running: 195 },
      system: { uptime_seconds: 43200, boot_time: Date.now() / 1000 - 43200, hostname: "DEMO-WIN11-PC", platform: "Windows 11 Pro" },
      network: {
        interfaces: [
          { name: "Ethernet", is_up: true, speed: 1000, addresses: ["10.0.115.65"], bytes_sent: 1048576, bytes_recv: 5242880 },
        ],
        active_count: 1,
        total_count: 2,
      },
    };

    eventHub.setTelemetry(sampleTelemetry);

    const retrieved = eventHub.getTelemetry();
    assert.ok(retrieved, "Telemetry must be retrievable from EventHub");
    assert.equal(retrieved.source, "windows_system_monitor", "Source must be windows_system_monitor");
    assert.equal(retrieved.cpu?.percent, 24.5, "CPU percent must match ingested telemetry");
    assert.equal(retrieved.memory?.percent, 50.0, "Memory percent must match ingested telemetry");
    assert.equal(retrieved.processes?.running, 195, "Running process count must match");
  });

  test("2. Verify Agent Liveness and Stale-Data Warnings", () => {
    eventHub.reset();

    // Before any heartbeat or telemetry, isAgentLive should return false
    assert.equal(eventHub.isAgentLive(5000), false, "Agent must be offline when no heartbeat or telemetry has arrived");

    // Send a fresh telemetry snapshot
    eventHub.setTelemetry({
      timestamp: new Date().toISOString(),
      source: "windows_system_monitor",
      observed: true,
      cpu: { percent: 12.0 },
    });

    assert.equal(eventHub.isAgentLive(15000), true, "Agent must be marked LIVE when telemetry arrives within TTL");

    // Test stale telemetry (older than TTL)
    const staleTime = new Date(Date.now() - 30000).toISOString();
    eventHub.setTelemetry({
      timestamp: staleTime,
      source: "windows_system_monitor",
      observed: true,
      cpu: { percent: 12.0 },
    });

    assert.equal(eventHub.isAgentLive(15000), false, "Agent must be marked STALE when last update exceeds TTL");
  });

  test("3. Verify Live Process Event Ingestion & Threat Detection Pipeline", () => {
    eventHub.reset();
    detectionEngine.reset();

    // Ingest a live process event (powershell running encoded command)
    const liveProcEvt = {
      id: `live-proc-${Date.now()}`,
      event_type: "PROCESS_STARTED",
      timestamp: new Date().toISOString(),
      pid: 4892,
      process_name: "powershell.exe",
      executable_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      command_line: "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4AdAA...",
      parent_pid: 1000,
      parent_process_name: "explorer.exe",
      source: "windows_process_monitor",
      observed: true,
    };

    eventHub.addEvent(liveProcEvt);
    const detections = detectionEngine.ingestEvent(liveProcEvt);

    assert.ok(detections.length > 0, "Must detect PROC-002 on encoded PowerShell command line");
    assert.equal(detections[0].rule_id, "PROC-002-ENCODED-COMMAND-LINE", "Rule ID must match PROC-002");
    assert.equal(detections[0].pid, 4892, "PID must match target process");

    // Verify detection is buffered in EventHub
    for (const det of detections) {
      eventHub.addDetection(det);
    }

    const bufferedDetections = eventHub.getDetections();
    assert.ok(bufferedDetections.length > 0, "Detection must be retrievable from EventHub");
  });

  test("4. Verify Live vs Simulation Tagging Isolation", () => {
    eventHub.reset();

    const liveEvt = {
      id: "live-evt-100",
      event_type: "PROCESS_STARTED",
      timestamp: new Date().toISOString(),
      pid: 1234,
      process_name: "notepad.exe",
      source: "windows_process_monitor",
      observed: true,
    };

    const simEvt = {
      id: "sim-evt-200",
      event_type: "PROCESS_STARTED",
      timestamp: new Date().toISOString(),
      pid: 9914,
      process_name: "powershell.exe",
      source: "simulation",
      observed: true,
      is_simulation: true,
      simulation_id: "sim-12345",
      scenario_id: "reverse_shell_exfiltration",
    };

    eventHub.addEvent(liveEvt);
    eventHub.addEvent(simEvt as any);

    const events = eventHub.getEvents();
    const live = events.find((e) => e.id === "live-evt-100");
    const sim = events.find((e) => e.id === "sim-evt-200");

    assert.ok(live, "Live event must be present");
    assert.ok(sim, "Simulation event must be present");
    assert.equal((live as any).is_simulation, undefined, "Live event must NOT have is_simulation flag");
    assert.equal((sim as any).is_simulation, true, "Simulation event MUST have is_simulation: true flag");
  });
});
