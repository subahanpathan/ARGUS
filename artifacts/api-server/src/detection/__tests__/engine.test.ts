import { describe, it, beforeEach } from "node:test";
import assert from "node:assert/strict";
import type { ProcessEvent, ProcessSnapshot } from "../../lib/event-hub";
import { DetectionEngine } from "../engine";

function makeEvent(overrides: Partial<ProcessEvent> = {}): ProcessEvent {
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

const ENCODED_CMD =
  'powershell.exe -nop -enc SQBFAFgAIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA=';

function makeEngine(): { engine: DetectionEngine; reset: () => void } {
  const engine = new DetectionEngine();
  return {
    engine,
    reset: () => engine.reset(),
  };
}

describe("DetectionEngine.ingestEvent", () => {
  const { engine, reset } = makeEngine();
  beforeEach(reset);

  it("produces a well-formed detection for an encoded PowerShell launch", () => {
    const detections = engine.ingestEvent(
      makeEvent({ command_line: ENCODED_CMD, parent_pid: 100, parent_process_name: "winword.exe" }),
    );
    assert.ok(detections.length >= 1);

    const encoded = detections.find((d) => d.rule_id === "PROC-002-ENCODED-COMMAND-LINE");
    assert.ok(encoded, "expected an encoded-command detection");
    assert.match(encoded.id, /^det-\d+$/);
    assert.equal(encoded.rule_id, "PROC-002-ENCODED-COMMAND-LINE");
    assert.equal(encoded.rule_name.length > 0, true);
    assert.equal(encoded.status, "detected");
    assert.equal(encoded.pid, 4242);
    assert.equal(encoded.entity, "powershell.exe");
    assert.ok(encoded.hostname && encoded.hostname.length > 0, "real hostname stamped");
    assert.equal(encoded.event_timestamp, "2026-01-01T12:00:00.000Z");
    assert.ok(encoded.timestamp, "timestamp present");
    assert.ok(encoded.evidence.length >= 1, "evidence present");
    assert.ok(encoded.explanation.length > 0);
    assert.ok(encoded.recommended_action.length > 0);
    assert.ok(Array.isArray(encoded.ancestry));
    assert.equal(encoded.related_event_id, "evt-1");
    assert.ok(encoded.confidence >= 0.1 && encoded.confidence <= 0.95, "confidence clamped");
    assert.ok(["low", "medium", "high", "critical"].includes(encoded.severity));
  });

  it("de-duplicates the exact same event on re-ingest", () => {
    const event = makeEvent({ command_line: ENCODED_CMD });
    const first = engine.ingestEvent(event);
    assert.ok(first.length >= 1);
    const second = engine.ingestEvent(event);
    assert.equal(second.length, 0);
  });

  it("de-duplicates the same pid+rule within the hourly window", () => {
    const first = engine.ingestEvent(makeEvent({ id: "evt-a", pid: 999, command_line: ENCODED_CMD }));
    assert.ok(first.some((d) => d.rule_id === "PROC-002-ENCODED-COMMAND-LINE"));
    const second = engine.ingestEvent(makeEvent({ id: "evt-b", pid: 999, command_line: ENCODED_CMD }));
    assert.equal(
      second.some((d) => d.rule_id === "PROC-002-ENCODED-COMMAND-LINE"),
      false,
      "same pid+rule should not re-fire within the window",
    );
  });

  it("returns no detections for terminated events", () => {
    const out = engine.ingestEvent(
      makeEvent({ event_type: "PROCESS_TERMINATED", command_line: ENCODED_CMD }),
    );
    assert.deepEqual(out, []);
  });

  it("returns [] for invalid events", () => {
    assert.deepEqual(engine.ingestEvent(null as unknown as ProcessEvent), []);
    assert.deepEqual(engine.ingestEvent({} as ProcessEvent), []);
  });
});

describe("DetectionEngine scoring & correlation", () => {
  const { engine, reset } = makeEngine();
  beforeEach(reset);

  it("applies base + evidence + command_line confidence modifiers", () => {
    const [det] = engine.ingestEvent(makeEvent({ command_line: ENCODED_CMD }));
    // PROC-002 base 0.7 +0.03 command_line = 0.73 (single evidence -> no +0.02)
    assert.equal(det.confidence, 0.73);
  });

  it("correlates distinct rules firing for the same pid and escalates", () => {
    // One event: winword -> powershell -enc  fires PROC-001 and PROC-002.
    const detections = engine.ingestEvent(
      makeEvent({ pid: 6000, command_line: ENCODED_CMD, parent_pid: 6100, parent_process_name: "winword.exe" }),
    );
    const proc001 = detections.find((d) => d.rule_id === "PROC-001-SUSPICIOUS-PARENT-CHILD");
    const proc002 = detections.find((d) => d.rule_id === "PROC-002-ENCODED-COMMAND-LINE");
    assert.ok(proc001 && proc002);

    assert.equal(proc001.correlated_rules, undefined, "first rule seeds the window");
    assert.ok(proc002.correlated_rules && proc002.correlated_rules.includes("PROC-001-SUSPICIOUS-PARENT-CHILD"));
    assert.equal(proc002.severity, "critical", "second distinct rule escalates severity");
  });

  it("caps confidence at 0.95 for highly evidenced detections", () => {
    const [det] = engine.ingestEvent(
      makeEvent({
        pid: 7000,
        command_line: ENCODED_CMD,
        parent_pid: 7100,
        parent_process_name: "winword.exe",
      }),
    );
    assert.ok(det.confidence <= 0.95);
  });
});

describe("DetectionEngine snapshots", () => {
  const { engine, reset } = makeEngine();
  beforeEach(reset);

  const snapshot: ProcessSnapshot = {
    timestamp: "2026-01-01T12:00:00.000Z",
    total_count: 3,
    access_denied_count: 0,
    processes: [
      { pid: 300, name: "explorer.exe", executable_path: "C:\\Windows\\explorer.exe" },
      {
        pid: 301,
        name: "powershell.exe",
        executable_path: "C:\\Users\\mira\\Downloads\\powershell.exe",
      },
      { pid: 302, name: "winword.exe", executable_path: "C:\\Program Files\\Microsoft Office\\winword.exe" },
      { pid: 303, name: "powershell.exe", parent_pid: 302, parent_name: "winword.exe" },
    ],
  };

  it("evaluates snapshot processes while skipping spawn-relationship rules", () => {
    const detections = engine.ingestSnapshot(snapshot);
    const ruleIds = new Set(detections.map((d) => d.rule_id));

    assert.ok(ruleIds.has("PROC-004-UNUSUAL-LOCATION"), "unusual location fires from snapshot");
    assert.ok(!ruleIds.has("PROC-001-SUSPICIOUS-PARENT-CHILD"), "parent-child must be skipped for snapshots");
    assert.ok(!ruleIds.has("PROC-005-INTERPRETER-CHAIN"), "interpreter chain must be skipped for snapshots");
  });

  it("applies the snapshot confidence penalty", () => {
    const dets = engine.ingestSnapshot(snapshot);
    const proc004 = dets.find((d) => d.rule_id === "PROC-004-UNUSUAL-LOCATION");
    assert.ok(proc004);
    assert.equal(proc004.confidence, 0.65);
  });

  it("ignores re-ingestion of the same snapshot timestamp", () => {
    engine.ingestSnapshot(snapshot);
    const again = engine.ingestSnapshot({ ...snapshot });
    assert.deepEqual(again, []);
  });
});

describe("DetectionEngine context & ancestry", () => {
  const { engine, reset } = makeEngine();
  beforeEach(reset);

  it("remembers process context with command_line", () => {
    engine.ingestEvent(makeEvent({ pid: 8000, command_line: ENCODED_CMD }));
    const context = engine.getProcessContext(8000);
    assert.ok(context);
    assert.equal(context.process_name, "powershell.exe");
    assert.equal(context.command_line, ENCODED_CMD);
    assert.equal(engine.getProcessContext(999999), null);
  });

  it("walks the parent chain in root-to-leaf order", () => {
    engine.ingestEvent(makeEvent({ id: "p1", pid: 10, process_name: "cmd.exe" }));
    engine.ingestEvent(
      makeEvent({ id: "p2", pid: 20, process_name: "powershell.exe", command_line: ENCODED_CMD, parent_pid: 10, parent_process_name: "cmd.exe" }),
    );
    const ancestry = engine.getAncestry(20);
    assert.deepEqual(
      ancestry.map((n) => n.pid),
      [10, 20],
    );
    assert.equal(ancestry[0].process_name, "cmd.exe");
    assert.equal(ancestry[1].process_name, "powershell.exe");
    assert.equal(ancestry[1].command_line, ENCODED_CMD);
  });

  it("caps ancestry at MAX_ANCESTRY_DEPTH and breaks pid cycles", () => {
    for (let i = 1; i <= 15; i++) {
      engine.ingestEvent(
        makeEvent({ id: `gen-${i}`, pid: 1000 + i, process_name: "cmd.exe", parent_pid: i > 1 ? 1000 + i - 1 : undefined }),
      );
    }
    const leaf = engine.ingestEvent(
      makeEvent({ id: "leaf", pid: 2000, process_name: "powershell.exe", parent_pid: 1015, parent_process_name: "cmd.exe", command_line: ENCODED_CMD }),
    )[0];
    assert.ok(leaf);
    assert.ok(leaf.ancestry.length <= 8, "ancestry depth capped");
    assert.equal(leaf.ancestry[leaf.ancestry.length - 1].pid, 2000);
  });

  it("reset clears detection sequence", () => {
    engine.ingestEvent(makeEvent({ command_line: ENCODED_CMD }));
    engine.reset();
    const [det] = engine.ingestEvent(makeEvent({ command_line: ENCODED_CMD }));
    assert.equal(det.id, "det-1");
  });
});