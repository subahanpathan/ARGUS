import { describe, it } from "node:test";
import assert from "node:assert/strict";
import type { ProcessEvent, ProcessSnapshot } from "../../lib/event-hub";
import {
  HOSTNAME,
  normalizeProcessEvent,
  normalizeSnapshotProcesses,
} from "../normalize";

function makeEvent(overrides: Partial<ProcessEvent> = {}): ProcessEvent {
  return {
    id: "evt-1",
    event_type: "PROCESS_STARTED",
    timestamp: "2026-01-01T12:00:00.000Z",
    pid: 4242,
    process_name: "powershell.exe",
    source: "windows_process_monitor",
    observed: true,
    metadata: {},
    ...overrides,
  };
}

describe("normalizeProcessEvent", () => {
  it("returns null for non-object / missing required fields", () => {
    assert.equal(normalizeProcessEvent(null as unknown as ProcessEvent), null);
    assert.equal(normalizeProcessEvent(undefined as unknown as ProcessEvent), null);
    assert.equal(
      normalizeProcessEvent({ id: "x", process_name: "cmd.exe" } as unknown as ProcessEvent),
      null,
    );
  });

  it("returns null for SNAPSHOT-type events (handled via snapshot endpoint)", () => {
    assert.equal(
      normalizeProcessEvent(makeEvent({ event_type: "SNAPSHOT" })),
      null,
    );
  });

  it("maps PROCESS_STARTED to created origin with command_line preserved", () => {
    const sec = normalizeProcessEvent(
      makeEvent({
        command_line: 'powershell -e QQBjAGIAaQ...',
        executable_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        parent_pid: 100,
        parent_process_name: "winword.exe",
        metadata: { username: "mira" },
      }),
    );
    assert.ok(sec);
    assert.equal(sec.type, "PROCESS_CREATED");
    assert.equal(sec.origin, "created");
    assert.equal(sec.pid, 4242);
    assert.equal(sec.process_name, "powershell.exe");
    assert.equal(sec.command_line, 'powershell -e QQBjAGIAaQ...');
    assert.equal(sec.executable_path, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    assert.equal(sec.parent_pid, 100);
    assert.equal(sec.parent_process_name, "winword.exe");
    assert.equal(sec.username, "mira");
    assert.equal(sec.hostname, HOSTNAME);
    assert.equal(sec.id, "evt-1");
  });

  it("maps PROCESS_TERMINATED and defaults missing optional fields", () => {
    const sec = normalizeProcessEvent(makeEvent({ event_type: "PROCESS_TERMINATED" }));
    assert.ok(sec);
    assert.equal(sec.type, "PROCESS_TERMINATED");
    assert.equal(sec.origin, "created");
    assert.equal(sec.command_line, null);
    assert.equal(sec.executable_path, null);
    assert.equal(sec.parent_pid, null);
    assert.equal(sec.username, null);
  });
});

describe("normalizeSnapshotProcesses", () => {
  it("returns [] for invalid input", () => {
    assert.deepEqual(
      normalizeSnapshotProcesses(null as unknown as ProcessSnapshot),
      [],
    );
    assert.deepEqual(
      normalizeSnapshotProcesses({ processes: [] } as unknown as ProcessSnapshot),
      [],
    );
  });

  it("maps each process to a snapshot-origin event", () => {
    const snapshot: ProcessSnapshot = {
      timestamp: "2026-01-01T12:00:00.000Z",
      total_count: 2,
      access_denied_count: 0,
      processes: [
        {
          pid: 10,
          name: "explorer.exe",
          executable_path: "C:\\Windows\\explorer.exe",
          command_line: "C:\\Windows\\explorer.exe",
          parent_pid: 4,
          parent_name: "System",
          username: "DESKTOP\\mira",
        },
        {
          pid: 20,
          name: "cmd.exe",
        },
      ],
    };
    const events = normalizeSnapshotProcesses(snapshot);
    assert.equal(events.length, 2);
    assert.equal(events[0].origin, "snapshot");
    assert.equal(events[0].type, "PROCESS_SNAPSHOT");
    assert.equal(events[0].process_name, "explorer.exe");
    assert.equal(events[0].parent_process_name, "System");
    assert.equal(events[0].command_line, "C:\\Windows\\explorer.exe");
    assert.equal(events[0].id, "snap:10:2026-01-01T12:00:00.000Z");
    assert.equal(events[1].command_line, null);
    assert.equal(events[1].username, null);
  });
});