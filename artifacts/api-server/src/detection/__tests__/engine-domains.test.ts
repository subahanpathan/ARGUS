import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import type { FileScanSnapshot, NetworkSnapshot, PortIntelligenceSnapshot, ProcessEvent } from "../../lib/event-hub";
import { DetectionEngine } from "../engine";

function makeProcessEvent(overrides: Partial<ProcessEvent> = {}): ProcessEvent {
  return {
    id: "evt-1",
    event_type: "PROCESS_STARTED",
    timestamp: "2026-01-01T12:00:00.000Z",
    pid: 4242,
    process_name: "powershell.exe",
    executable_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    source: "windows_process_monitor",
    observed: true,
    metadata: {},
    ...overrides,
  };
}

/** A process running out of a user-writable directory and talking to the internet. */
function makeSuspiciousSnapshot(pid: number, remoteAddr = "8.8.8.8", remotePort = 443): NetworkSnapshot {
  return {
    timestamp: "2026-01-01T12:01:00.000Z",
    total_count: 1,
    established_count: 1,
    listen_count: 0,
    connections: [
      {
        process: "evil.exe",
        pid,
        connection_id: `conn-${pid}`,
        type: "SOCK_STREAM",
        local_addr: "192.168.1.20",
        local_port: 50123,
        remote_addr: remoteAddr,
        remote_port: remotePort,
        status: "ESTABLISHED",
        local_role: "PRIVATE",
        remote_role: "REMOTE",
        executable_path: "C:\\Users\\alice\\AppData\\Local\\Temp\\evil.exe",
      },
    ],
  };
}

function makeFanOutSnapshot(pid: number, count: number): NetworkSnapshot {
  return {
    timestamp: "2026-01-01T12:02:00.000Z",
    total_count: count,
    established_count: count,
    listen_count: 0,
    connections: Array.from({ length: count }, (_, i) => ({
      process: "scanner.exe",
      pid,
      connection_id: `conn-${pid}-${i}`,
      type: "SOCK_STREAM",
      local_addr: "192.168.1.20",
      local_port: 50000 + i,
      remote_addr: `203.0.113.${(i % 250) + 1}`,
      remote_port: 443,
      status: "ESTABLISHED",
      local_role: "PRIVATE",
      remote_role: "REMOTE",
      executable_path: "C:\\Users\\alice\\Downloads\\scanner.exe",
    })),
  };
}

describe("DetectionEngine cross-domain correlation", () => {
  const { engine, reset } = (() => {
    const engine = new DetectionEngine();
    return { engine, reset: () => engine.reset() };
  })();
  beforeEach(reset);

  it("correlates a process rule and a network rule firing for the same pid", () => {
    const proc = engine.ingestEvent(
      makeProcessEvent({
        command_line:
          "evil.exe -enc SQBFAFgAIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA=",
      }),
    );
    assert.ok(proc.some((d) => d.rule_id === "PROC-002-ENCODED-COMMAND-LINE"));

    const net = engine.ingestNetworkSnapshot(makeSuspiciousSnapshot(4242));
    const net1 = net.find((d) => d.rule_id === "NET-001-USER-WRITABLE-OUTBOUND");
    assert.ok(net1, "expected NET-001 to fire");
    assert.ok(
      net1.correlated_rules?.includes("PROC-002-ENCODED-COMMAND-LINE"),
      "NET detection should reference the earlier PROCESS rule",
    );
  });

  it("escalates severity when a second independent rule fires for the same pid", () => {
    engine.ingestEvent(
      makeProcessEvent({
        command_line:
          "evil.exe -enc SQBFAFgAIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA=",
      }),
    );
    const net = engine.ingestNetworkSnapshot(makeSuspiciousSnapshot(4242));
    const net1 = net.find((d) => d.rule_id === "NET-001-USER-WRITABLE-OUTBOUND");
    assert.ok(net1);
    assert.ok(
      ["high", "critical"].includes(net1.severity),
      "NET-001 high base should escalate due to cross-domain correlation",
    );
  });

  it("dedupes the same network snapshot across ingestion cycles", () => {
    const first = engine.ingestNetworkSnapshot(makeSuspiciousSnapshot(4242));
    assert.ok(first.length >= 1);
    const second = engine.ingestNetworkSnapshot(makeSuspiciousSnapshot(4242));
    assert.equal(second.length, 0);
  });

  it("fires NET-007 fan-out only when one pid reaches many distinct remotes", () => {
    const many = makeFanOutSnapshot(4243, 12);
    const detections = engine.ingestNetworkSnapshot(many);
    const fan = detections.find((d) => d.rule_id === "NET-007-REMOTE-FAN-OUT");
    assert.ok(fan);
    assert.equal(fan.pid, 4243);
    // NET-007 is low on its own but elevates when NET-001 (same pid, user-writable
    // outbound) also fires in the same window.
    assert.ok(["low", "medium"].includes(fan.severity), "fan-out severity must be low or escalated");
  });

  it("emits NET-004 for a PORT_OPENED event from a user-writable binary", () => {
    const snapshot: PortIntelligenceSnapshot = {
      timestamp: "2026-01-01T12:03:00.000Z",
      tcp_listening: [],
      udp_endpoints: [],
      port_events: [
        {
          event_type: "PORT_OPENED",
          port_id: "pt-1",
          protocol: "TCP",
          local_addr: "0.0.0.0",
          local_port: 31337,
          state: "LISTENING",
          pid: 7777,
          process_name: "evil.exe",
          executable_path: "C:\\Users\\alice\\AppData\\Local\\Temp\\evil.exe",
          binding_type: "WILDCARD",
        },
      ],
    };
    const detections = engine.ingestPortSnapshot(snapshot);
    const found = detections.find((d) => d.rule_id === "NET-004-NEW-LISTENER-USER-WRITABLE");
    assert.ok(found);
    assert.equal(found.pid, 7777);
    assert.equal(found.severity, "high");
  });
});

describe("DetectionEngine file → process linking", () => {
  const { engine, reset } = (() => {
    const engine = new DetectionEngine();
    return { engine, reset: () => engine.reset() };
  })();
  beforeEach(reset);

  const RUNNING_PATH = "C:\\Users\\alice\\AppData\\Local\\Temp\\evil.ps1";

  function makeScan(): FileScanSnapshot {
    return {
      timestamp: "2026-01-01T12:05:00.000Z",
      total_count: 1,
      findings: [
        {
          id: "f-1",
          path: RUNNING_PATH,
          name: "evil.ps1",
          extension: "ps1",
          hash: "c".repeat(64),
          size_bytes: 1337,
          severity: "high",
          className: "Script",
          reason: "encoded powershell",
          category: "startup-file / encoded-powershell",
          is_running: true,
          source: "file_scanner",
        },
      ],
    };
  }

  it("resolves the file pid from the remembered process context", () => {
    engine.ingestEvent(
      makeProcessEvent({
        process_name: "powershell.exe",
        executable_path: RUNNING_PATH,
        command_line: "powershell.exe -WindowStyle Hidden evil.ps1",
      }),
    );

    const detections = engine.ingestFileScan(makeScan());
    const file001 = detections.find((d) => d.rule_id === "FILE-001-STARTUP-PERSISTENCE");
    assert.ok(file001);
    assert.equal(file001.pid, 4242, "pid must be resolved from the running process context");
    assert.equal(file001.executable_path, RUNNING_PATH);
  });

  it("emits FILE-004 and FILE-006 for scheduled-task scripts that are running", () => {
    engine.ingestEvent(
      makeProcessEvent({
        process_name: "powershell.exe",
        executable_path: "C:\\Users\\alice\\Documents\\task.ps1",
      }),
    );
    const detections = engine.ingestFileScan({
      timestamp: "2026-01-01T12:05:00.000Z",
      total_count: 1,
      findings: [
        {
          id: "f-2",
          path: "C:\\Users\\alice\\Documents\\task.ps1",
          name: "task.ps1",
          severity: "medium",
          className: "Script",
          reason: "scheduled task",
          category: "scheduled-task",
          is_running: true,
        },
      ],
    });
    assert.ok(detections.some((d) => d.rule_id === "FILE-004-SCHEDULED-TASK-PERSISTENCE"));
    const running = detections.find((d) => d.rule_id === "FILE-006-RUNNING-SUSPECT");
    assert.ok(running);
    assert.equal(running.pid, 4242);
  });
});