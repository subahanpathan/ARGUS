import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import fs from "node:fs/promises";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import type { Server } from "node:http";
import type { Express } from "express";

import type { RecoverySnapshot, ImpactIncident } from "../../recovery/types";

let app: Express;
let server: Server;
let base: string;
let root: string;
let workspace: string;
let victimDir: string;
let backupDir: string;

async function get<T>(route: string): Promise<{ status: number; body: T }> {
  const response = await fetch(`${base}${route}`);
  const text = await response.text();
  return { status: response.status, body: (text ? JSON.parse(text) : null) as T };
}

async function post<T>(route: string, body?: unknown): Promise<{ status: number; body: T }> {
  const response = await fetch(`${base}${route}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  const text = await response.text();
  return { status: response.status, body: (text ? JSON.parse(text) : null) as T };
}

/** Drive a full investigation through the public service, as the trigger would. */
async function investigate(detectionId: string, files: Array<{ target: string; kind?: string }>): Promise<ImpactIncident | null> {
  const { eventHub } = await import("../../lib/event-hub");
  const { recoveryService } = await import("../../recovery/service");

  for (const [index, file] of files.entries()) {
    eventHub.addMonitoringEvents([
      {
        eventId: `${detectionId}-fs-${index}`,
        timestamp: new Date().toISOString(),
        eventType: file.kind ?? "FILE_MODIFIED",
        source: "filesystem_watch",
        entity: { kind: "file", id: file.target, name: path.basename(file.target) },
        severity: "info",
        evidence: { path: file.target, is_directory: false, size_bytes: 2048 },
        metadata: {},
        correlationId: null,
      },
    ]);
  }

  const at = new Date().toISOString();
  return recoveryService.investigate({
    id: detectionId,
    rule_id: "PROC-002-ENCODED-COMMAND-LINE",
    rule_name: "Encoded PowerShell command line",
    title: "Encoded PowerShell",
    severity: "high",
    confidence: 0.8,
    status: "detected",
    timestamp: at,
    event_timestamp: at,
    entity: "powershell.exe",
    pid: 9001,
    hostname: "TEST-HOST",
    evidence: [],
    explanation: "",
    recommended_action: "",
    ancestry: [],
  });
}

before(async () => {
  process.env.LOG_LEVEL = "silent";

  root = await fs.mkdtemp(path.join(os.tmpdir(), "argus-recovery-api-"));
  victimDir = path.join(root, "victim");
  backupDir = path.join(root, "backup");
  workspace = path.join(root, "workspace");
  await fs.mkdir(victimDir, { recursive: true });
  await fs.mkdir(backupDir, { recursive: true });

  const { setRecoveryRoot } = await import("../../recovery/paths");
  setRecoveryRoot(workspace);
  process.env.ARGUS_RECOVERY_BACKUP_ROOTS = backupDir;

  ({ default: app } = await import("../../app"));
  const { recoveryService } = await import("../../recovery/service");
  recoveryService.setEnabled(true);

  await new Promise<void>((resolve) => {
    server = app.listen(0, () => resolve());
  });
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api`;
});

after(async () => {
  delete process.env.ARGUS_RECOVERY_BACKUP_ROOTS;
  await new Promise<void>((resolve) => {
    server.close(() => resolve());
  });
  await fs.rm(root, { recursive: true, force: true });
});

beforeEach(async () => {
  const { eventHub } = await import("../../lib/event-hub");
  const { recoveryStore } = await import("../../recovery/store");
  eventHub.reset();
  recoveryStore.reset();
});

describe("GET /api/recovery", () => {
  it("returns an honest empty snapshot before anything is observed", async () => {
    const { status, body } = await get<RecoverySnapshot>("/recovery");
    assert.equal(status, 200);
    assert.equal(body.observed, false);
    assert.equal(body.summary.affectedFiles, 0);
    assert.equal(body.incidents.length, 0);
    assert.deepEqual(
      body.stages.map((stage) => stage.reached),
      [false, false, false, false, false],
    );
    // Source support is probed even with no data, and every row explains itself.
    assert.equal(body.sources.length, 4);
    for (const source of body.sources) {
      assert.ok(source.reason.length > 0, `${source.kind} must report a reason`);
    }
    assert.ok(body.recoveryRoot);
  });
});

describe("GET /api/recovery/catalog", () => {
  it("exposes the shared vocabularies", async () => {
    const { status, body } = await get<{ stages: string[]; damage: unknown[]; recoveryStates: unknown[] }>(
      "/recovery/catalog",
    );
    assert.equal(status, 200);
    assert.equal(body.stages.length, 5);
    assert.equal(body.damage.length, 6);
    assert.equal(body.recoveryStates.length, 8);
  });
});

describe("GET /api/recovery/config", () => {
  it("reports the effective limits, root and parsed backup roots", async () => {
    const { status, body } = await get<{
      enabled: boolean;
      recoveryRoot: string;
      limits: Record<string, number>;
      configuredBackupRoots: string[];
      environment: Record<string, string>;
    }>("/recovery/config");
    assert.equal(status, 200);
    assert.equal(body.enabled, true);
    assert.equal(body.recoveryRoot, workspace);
    assert.ok(body.limits.maxAffectedFilesPerIncident > 0);
    assert.deepEqual(body.configuredBackupRoots, [backupDir]);
    assert.equal(body.environment.backupRoots, "ARGUS_RECOVERY_BACKUP_ROOTS");
  });
});

describe("incidents and files", () => {
  it("404s for an unknown incident", async () => {
    assert.equal((await get("/recovery/incidents/inc_missing")).status, 404);
    assert.equal((await get("/recovery/incidents/inc_missing/files")).status, 404);
    assert.equal((await get("/recovery/incidents/inc_missing/files/rec_missing")).status, 404);
  });

  it("exposes a reconstructed incident with its affected files", async () => {
    const target = path.join(victimDir, "api-report.docx");
    await fs.writeFile(target, randomBytes(2048));
    await investigate("det-api-1", [{ target }]);

    const list = await get<{ count: number; incidents: Array<{ incident_id: string; detection_id: string }> }>(
      "/recovery/incidents",
    );
    assert.equal(list.status, 200);
    assert.equal(list.body.count, 1);
    const incidentId = list.body.incidents[0].incident_id;

    const detail = await get<{ incident: ImpactIncident }>(`/recovery/incidents/${incidentId}`);
    assert.equal(detail.status, 200);
    assert.equal(detail.body.incident.detection_id, "det-api-1");
    assert.equal(detail.body.incident.affected_files.length, 1);
    assert.equal(detail.body.incident.affected_files[0].path, target);

    const files = await get<{ count: number; files: Array<{ record_id: string }> }>(
      `/recovery/incidents/${incidentId}/files`,
    );
    assert.equal(files.body.count, 1);

    const recordId = files.body.files[0].record_id;
    const record = await get<{ record: { damage_signals: unknown[]; recovery_sources: unknown[] } }>(
      `/recovery/incidents/${incidentId}/files/${recordId}`,
    );
    assert.equal(record.status, 200);
    assert.ok(record.body.record.damage_signals.length > 0);
    assert.ok(record.body.record.recovery_sources.length > 0);
  });

  it("filters affected files by damage and attribution strength", async () => {
    const encrypted = path.join(victimDir, "api-encrypted.docx");
    const intact = path.join(victimDir, "api-intact.docx");
    await fs.writeFile(encrypted, randomBytes(2048));
    await fs.writeFile(intact, Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), randomBytes(512)]));

    await investigate("det-api-2", [{ target: encrypted }, { target: intact }]);

    const incidents = await get<{ incidents: Array<{ incident_id: string }> }>("/recovery/incidents");
    const incidentId = incidents.body.incidents[0].incident_id;

    const encryptedOnly = await get<{ count: number }>(
      `/recovery/incidents/${incidentId}/files?damage=ENCRYPTED_OR_CORRUPTED_SUSPECTED`,
    );
    assert.equal(encryptedOnly.body.count, 1);

    const inferred = await get<{ count: number }>(
      `/recovery/incidents/${incidentId}/files?attribution_strength=INFERRED`,
    );
    assert.equal(inferred.body.count, 2);

    const searched = await get<{ count: number }>(`/recovery/incidents/${incidentId}/files?search=intact`);
    assert.equal(searched.body.count, 1);
  });

  it("404s the file route for an unknown record", async () => {
    const target = path.join(victimDir, "api-404.docx");
    await fs.writeFile(target, randomBytes(512));
    await investigate("det-api-3", [{ target }]);
    const incidents = await get<{ incidents: Array<{ incident_id: string }> }>("/recovery/incidents");
    const incidentId = incidents.body.incidents[0].incident_id;
    assert.equal((await get(`/recovery/incidents/${incidentId}/files/rec_nope`)).status, 404);
  });
});

describe("POST .../recover", () => {
  it("recovers from a pre-incident backup without touching the original", async () => {
    const target = path.join(victimDir, "api-recover.docx");
    // A real ZIP container, so the `.docx` extension and the magic bytes agree.
    const original = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), randomBytes(512)]);
    await fs.writeFile(target, randomBytes(2048));

    const backup = path.join(backupDir, "api-recover.docx");
    await fs.writeFile(backup, original);
    const old = new Date(Date.now() - 7_200_000);
    await fs.utimes(backup, old, old);

    await investigate("det-api-4", [{ target }]);

    const incidents = await get<{ incidents: Array<{ incident_id: string }> }>("/recovery/incidents");
    const incidentId = incidents.body.incidents[0].incident_id;
    const files = await get<{ files: Array<{ record_id: string }> }>(`/recovery/incidents/${incidentId}/files`);
    const recordId = files.body.files[0].record_id;

    const before = await fs.readFile(target);
    const result = await post<{
      record: { recovery_state: string; attempts: Array<{ verified: boolean; destructive: boolean }> };
      destructive: boolean;
    }>(`/recovery/incidents/${incidentId}/files/${recordId}/recover`);
    assert.equal(result.status, 200);
    assert.equal(result.body.destructive, false);
    assert.equal(result.body.record.recovery_state, "VERIFIED");
    assert.equal(result.body.record.attempts.at(-1)!.verified, true);

    const after = await fs.readFile(target);
    assert.deepEqual(after, before, "the original must be byte-identical after recovery");
  });

  it("refuses honestly when no restorable source exists", async () => {
    const target = path.join(victimDir, "api-nosource.docx");
    await fs.writeFile(target, randomBytes(512));
    await investigate("det-api-5", [{ target }]);

    const incidents = await get<{ incidents: Array<{ incident_id: string }> }>("/recovery/incidents");
    const incidentId = incidents.body.incidents[0].incident_id;
    const files = await get<{ files: Array<{ record_id: string }> }>(`/recovery/incidents/${incidentId}/files`);
    const recordId = files.body.files[0].record_id;

    const result = await post<{ error: string; sources: Array<{ probe_detail: string }> }>(
      `/recovery/incidents/${incidentId}/files/${recordId}/recover`,
    );
    assert.equal(result.status, 409);
    assert.match(result.body.error, /No restorable recovery source/);
    assert.ok(result.body.sources.length > 0);
    assert.ok(result.body.sources.every((source) => source.probe_detail.length > 0));
  });

  it("404s for an unknown record", async () => {
    assert.equal((await post("/recovery/incidents/inc_nope/files/rec_nope/recover")).status, 404);
  });
});

describe("POST /api/recovery/incidents/:id/rescan-sources", () => {
  it("picks up a backup that only becomes available afterwards", async () => {
    const target = path.join(victimDir, "api-late.docx");
    await fs.writeFile(target, randomBytes(1024));
    await investigate("det-api-6", [{ target }]);

    const incidents = await get<{ incidents: Array<{ incident_id: string }> }>("/recovery/incidents");
    const incidentId = incidents.body.incidents[0].incident_id;

    const before = await get<{ summary: { recoverySourcesFound: number } }>("/recovery/summary");
    const beforeRestorable = before.body.summary.recoverySourcesFound;

    // The backup appears only now.
    const backup = path.join(backupDir, "api-late.docx");
    await fs.writeFile(backup, Buffer.from("late but valid"));
    const old = new Date(Date.now() - 7_200_000);
    await fs.utimes(backup, old, old);

    const rescan = await post<{ files_rescanned: number; results: Array<{ restorable: number }> }>(
      `/recovery/incidents/${incidentId}/rescan-sources`,
    );
    assert.equal(rescan.status, 200);
    assert.equal(rescan.body.files_rescanned, 1);
    assert.ok(rescan.body.results[0].restorable >= 1);
    assert.ok(beforeRestorable >= 0);

    const files = await get<{ files: Array<{ recovery_state: string }> }>(`/recovery/incidents/${incidentId}/files`);
    assert.equal(files.body.files[0].recovery_state, "RECOVERY_SOURCE_FOUND");
  });

  it("404s for an unknown incident", async () => {
    assert.equal((await post("/recovery/incidents/inc_nope/rescan-sources")).status, 404);
  });
});

describe("GET /api/recovery/summary", () => {
  it("reports zeroed, non-fabricated counts when nothing happened", async () => {
    const { status, body } = await get<{
      observed: boolean;
      summary: Record<string, number>;
      stages: Array<{ reached: boolean }>;
    }>("/recovery/summary");
    assert.equal(status, 200);
    assert.equal(body.observed, false);
    for (const key of [
      "affectedFiles",
      "modifiedFiles",
      "deletedFiles",
      "recovered",
      "verified",
      "unrecoverable",
      "incidents",
      "recoverySourcesFound",
    ]) {
      assert.equal(body.summary[key], 0, `${key} must be 0, not fabricated`);
    }
    assert.equal(body.stages.every((stage) => !stage.reached), true);
  });
});

describe("GET /api/recovery/sources", () => {
  it("reports real platform/configuration support per source kind", async () => {
    const { status, body } = await get<{
      sources: Array<{ kind: string; supported: boolean; reason: string }>;
      configuredBackupRoots: string[];
    }>("/recovery/sources");
    assert.equal(status, 200);
    const byKind = new Map(body.sources.map((source) => [source.kind, source]));
    assert.equal(byKind.get("CONFIGURED_BACKUP_ROOT")!.supported, true);
    assert.match(byKind.get("CONFIGURED_BACKUP_ROOT")!.reason, /1 root\(s\) configured/);
    // The shadow-copy row states the platform fact either way.
    assert.ok(byKind.get("WINDOWS_SHADOW_COPY")!.reason.length > 0);
    assert.deepEqual(body.configuredBackupRoots, [backupDir]);
  });
});

describe("GET /api/recovery/stream", () => {
  it("opens an SSE stream that reports the current state", async () => {
    const controller = new AbortController();
    const response = await fetch(`${base}/recovery/stream`, {
      headers: { Accept: "text/event-stream" },
      signal: controller.signal,
    });
    assert.equal(response.status, 200);
    assert.match(String(response.headers.get("content-type")), /text\/event-stream/);

    const reader = response.body!.getReader();
    const { value } = await reader.read();
    const chunk = new TextDecoder().decode(value);
    assert.match(chunk, /"type":"connected"/);
    controller.abort();
  });
});
