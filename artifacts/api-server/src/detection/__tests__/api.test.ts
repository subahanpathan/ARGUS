import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import type { Express } from "express";
import type { Detection, DetectionStatus } from "../types";
import type { DetectionEngine } from "../engine";
import type { EventHubType } from "../../lib/event-hub";

const ENCODED_CMD =
  'powershell.exe -nop -enc SQBFAFgAIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA=';

type ListBody = { detections: Detection[]; count: number; rules: Array<{ rule_id: string; rule_name: string; description: string }> };
type DetailBody = { detection: Detection; related: Detection[]; ancestry: Detection["ancestry"]; process: unknown };
type AcceptedBody = { accepted: number; rejected: number };
type ApiErrorBody = { error: string; detail?: string; details?: Array<{ index: number; error: string }> };

let app: Express;
let eventHub: EventHubType;
let detectionEngine: DetectionEngine;
let server: Server;
let base: string;

async function startServer(): Promise<void> {
  process.env.LOG_LEVEL = "silent";
  ({ default: app } = await import("../../app"));
  ({ eventHub } = await import("../../lib/event-hub"));
  ({ detectionEngine } = await import("../engine"));

  await new Promise<void>((resolve) => {
    server = app.listen(0, () => resolve());
  });
  const addr = server.address() as AddressInfo;
  base = `http://127.0.0.1:${addr.port}/api`;
}

function postEvent(overrides: Record<string, unknown> = {}) {
  return fetch(`${base}/events/process`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      id: "evt-test-1",
      event_type: "PROCESS_STARTED",
      timestamp: "2026-01-01T12:00:00.000Z",
      pid: 4242,
      process_name: "powershell.exe",
      executable_path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      parent_pid: null,
      parent_process_name: null,
      source: "windows_process_monitor",
      observed: true,
      metadata: {},
      ...overrides,
    }),
  });
}

function postSnapshot(processes: Array<Record<string, unknown>>) {
  return fetch(`${base}/processes`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ timestamp: "2026-01-01T12:00:00.000Z", processes }),
  });
}

before(async () => {
  await startServer();
});

after(() => {
  server?.close();
});

beforeEach(() => {
  eventHub.reset();
  detectionEngine.reset();
});

describe("GET /api/detections/rules", () => {
  it("returns the full rule catalog", async () => {
    const res = await fetch(`${base}/detections/rules`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as { rules: Array<{ rule_id: string; rule_name: string; description: string }> };
    assert.ok(Array.isArray(body.rules));
    assert.equal(body.rules.length, 21);
    for (const rule of body.rules) {
      assert.ok(rule.rule_id && rule.rule_name && rule.description);
    }
  });
});

describe("process event ingestion -> detection pipeline", () => {
  it("creates, lists, filters and details a detection", async () => {
    const res = await postEvent({
      command_line: ENCODED_CMD,
      parent_pid: 100,
      parent_process_name: "winword.exe",
    });
    assert.equal(res.status, 201);
    const body = (await res.json()) as AcceptedBody;
    assert.equal(body.accepted, 1);

    const listRes = await fetch(`${base}/detections`);
    const list = (await listRes.json()) as ListBody;
    assert.equal(listRes.status, 200);
    assert.ok(list.count >= 2, "PROC-001 + PROC-002 should have fired");
    assert.ok(Array.isArray(list.rules));
    assert.equal(list.rules.length, 21);

    const detection = list.detections.find(
      (d: Detection) => d.rule_id === "PROC-002-ENCODED-COMMAND-LINE",
    );
    assert.ok(detection && detection.hostname && detection.hostname.length > 0);

    const filterRes = await fetch(`${base}/detections?rule_id=PROC-002-ENCODED-COMMAND-LINE`);
    const filtered = (await filterRes.json()) as ListBody;
    assert.equal(
      filtered.detections.every((d: Detection) => d.rule_id === "PROC-002-ENCODED-COMMAND-LINE"),
      true,
    );

    const detailRes = await fetch(`${base}/detections/${detection.id}`);
    const detail = (await detailRes.json()) as DetailBody;
    assert.equal(detailRes.status, 200);
    assert.equal(detail.detection.id, detection.id);
    assert.ok(Array.isArray(detail.related));
    assert.ok(Array.isArray(detail.ancestry));
    assert.ok(detail.process === null || typeof detail.process === "object");
  });

  it("validates the POST event payload", async () => {
    const res = await postEvent({ pid: "not-a-number" });
    assert.equal(res.status, 422);
    const body = (await res.json()) as ApiErrorBody;
    assert.equal(body.error, "Validation failed");
  });

  it("rejects malformed POST bodies", async () => {
    const res = await fetch(`${base}/events/process`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    assert.equal(res.status, 422);
  });
});

describe("snapshot ingestion -> detections", () => {
  it("accepts a snapshot and produces unusual-location detection without spawning rules", async () => {
    const res = await postSnapshot([
      { pid: 300, name: "explorer.exe", executable_path: "C:\\Windows\\explorer.exe" },
      { pid: 301, name: "powershell.exe", executable_path: "C:\\Users\\mira\\Downloads\\powershell.exe" },
      { pid: 302, name: "winword.exe", executable_path: "C:\\Program Files\\Microsoft Office\\winword.exe" },
      { pid: 303, name: "powershell.exe", parent_pid: 302, parent_name: "winword.exe" },
    ]);
    assert.equal(res.status, 201);

    const list = (await (await fetch(`${base}/detections`)).json()) as ListBody;
    const ruleIds = new Set(list.detections.map((d: Detection) => d.rule_id));
    assert.ok(ruleIds.has("PROC-004-UNUSUAL-LOCATION"));
    assert.ok(!ruleIds.has("PROC-001-SUSPICIOUS-PARENT-CHILD"));
    assert.ok(!ruleIds.has("PROC-005-INTERPRETER-CHAIN"));
  });
});

describe("detection lifecycle", () => {
  it("updates detection status via PATCH and broadcasts", async () => {
    await postEvent({ command_line: ENCODED_CMD });
    const list = (await (await fetch(`${base}/detections`)).json()) as ListBody;
    const detection = list.detections[0] as Detection;

    const res = await fetch(`${base}/detections/${detection.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: "investigated" }),
    });
    assert.equal(res.status, 200);
    const body = (await res.json()) as { detection: Detection };
    assert.equal(body.detection.status, "investigated");

    const detail = (await (await fetch(`${base}/detections/${detection.id}`)).json()) as DetailBody;
    assert.equal(detail.detection.status, "investigated");
  });

  it("rejects invalid statuses and bodies", async () => {
    await postEvent({ command_line: ENCODED_CMD });
    const list = (await (await fetch(`${base}/detections`)).json()) as ListBody;
    const id = list.detections[0].id as string;

    const badStatus = await fetch(`${base}/detections/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: "nuked" }),
    });
    assert.equal(badStatus.status, 400);

    const badBody = await fetch(`${base}/detections/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    assert.equal(badBody.status, 400);
  });

  it("returns 404 for unknown ids", async () => {
    const res = await fetch(`${base}/detections/nope`);
    assert.equal(res.status, 404);

    const patch = await fetch(`${base}/detections/nope`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: "resolved" as DetectionStatus }),
    });
    assert.equal(patch.status, 404);
  });
});

describe("SSE detection stream", () => {
  it("emits connected then a live detection", { timeout: 15000 }, async () => {
    const res = await fetch(`${base}/detections/stream`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("content-type"), "text/event-stream");
    const reader = res.body!.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    const nextEvent = async (): Promise<{ type?: string; detection?: Detection } | null> => {
      const timeout = new Promise<null>((resolve) => setTimeout(() => resolve(null), 5000));
      const read = (async () => {
        while (buffer.indexOf("\n\n") === -1) {
          const { value, done } = await reader.read();
          if (done) return null;
          buffer += decoder.decode(value, { stream: true });
        }
        const raw = buffer.slice(0, buffer.indexOf("\n\n"));
        buffer = buffer.slice(buffer.indexOf("\n\n") + 2);
        if (raw.startsWith(":")) return null; // heartbeat comment
        return JSON.parse(raw.replace(/^data: /, "")) as { type?: string; detection?: Detection };
      })();
      return (await Promise.race([read, timeout])) as { type?: string; detection?: Detection } | null;
    };

    try {
      const connected = await nextEvent();
      assert.equal(connected?.type, "connected");

      await postEvent({ id: "evt-sse-1", command_line: ENCODED_CMD });

      let found: { type?: string; detection?: Detection } | null = null;
      for (let i = 0; i < 5 && !found; i++) {
        found = await nextEvent();
        if (found?.type === "detection") break;
      }
      assert.ok(found && found.type === "detection", "expected a detection broadcast");
      assert.match(found.detection!.rule_id, /^PROC-/);
    } finally {
      reader.cancel().catch(() => undefined);
    }
  });
});