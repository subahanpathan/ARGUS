/**
 * Observability and resume behaviour for the automatic recovery pipeline.
 *
 * These two concerns are grouped because they are both about what an operator
 * can see and what survives a restart: the event stream has to be complete and
 * machine-readable, and an interrupted incident has to finish the work rather
 * than start over or double-count it.
 */

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { after, before, beforeEach, describe, it } from "node:test";

process.env.LOG_LEVEL = "silent";

const { eventHub } = await import("../../lib/event-hub");
const { recoveryStore } = await import("../store");
const { recoveryService } = await import("../service");
const { setRecoveryEventSink } = await import("../observability");
type RecoveryEventName = import("../observability").RecoveryEventName;
type RecoveryEventFields = import("../observability").RecoveryEventFields;
type Detection = import("../../detection/types").Detection;
type MonitoringEvent = import("../../lib/event-hub").MonitoringEvent;

let root: string;
let victimDir: string;
let backupDir: string;
let toolDir: string;
let workspace: string;

const ORIGINAL_CONTENT = Buffer.concat([
  Buffer.from([0x50, 0x4b, 0x03, 0x04]),
  Buffer.alloc(18),
  Buffer.from("PK\x03\x04rest of the original document body"),
]);
const CORRUPTED_CONTENT = randomBytes(4096);

/** Every event the pipeline emitted, in order, for assertions. */
let events: Array<{ name: RecoveryEventName; fields: RecoveryEventFields }>;

function names(): RecoveryEventName[] {
  return events.map((entry) => entry.name);
}

function eventsFor(name: RecoveryEventName): Array<RecoveryEventFields> {
  return events.filter((entry) => entry.name === name).map((entry) => entry.fields);
}

/** Build a detection shaped exactly like a real `DetectionEngine` product. */
function detection(overrides: Partial<Detection> = {}): Detection {
  const at = new Date().toISOString();
  return {
    id: "det-observability",
    rule_id: "PROC-002-ENCODED-COMMAND-LINE",
    rule_name: "Encoded command line",
    title: "Process executed with an encoded command line",
    severity: "high",
    confidence: 0.82,
    status: "detected",
    timestamp: at,
    event_timestamp: at,
    entity: "toolhost.exe",
    pid: 40000,
    executable_path: path.join(toolDir, "toolhost.exe"),
    command_line: "toolhost.exe -enc " + "A".repeat(64),
    parent_pid: 1200,
    parent_process_name: "explorer.exe",
    username: "SYNTHETIC\\victim",
    hostname: "SYNTHETIC-HOST",
    evidence: [
      { key: "command_line", description: "Encoded command line", source: "command_line" },
      { key: "executable_path", description: "Non-shell binary", source: "executable_path" },
    ],
    explanation: "A base64-encoded command line was observed on a non-shell binary.",
    recommended_action: "Inspect the decoded command.",
    correlated_rules: [],
    ancestry: [
      { pid: 40000, process_name: "toolhost.exe", executable_path: path.join(toolDir, "toolhost.exe") },
      { pid: 1200, process_name: "explorer.exe", executable_path: null },
    ],
    related_event_id: null,
    ...overrides,
  };
}

function fileEvent(eventId: string, eventType: string, target: string, oldPath?: string): MonitoringEvent {
  return {
    eventId,
    timestamp: new Date().toISOString(),
    eventType,
    source: "filesystem_watch",
    entity: { kind: "file", id: target, name: path.basename(target) },
    severity: "info",
    evidence: {
      path: target,
      old_path: oldPath ?? null,
      root: path.dirname(target),
      is_directory: false,
      size_bytes: CORRUPTED_CONTENT.length,
      extension: path.extname(target),
      created_at: null,
      modified_at: new Date().toISOString(),
    },
    metadata: { contents_read: false },
    correlationId: null,
  };
}

before(async () => {
  process.env.LOG_LEVEL = "silent";
  root = await fs.mkdtemp(path.join(os.tmpdir(), "argus-observability-"));
  victimDir = path.join(root, "victim documents");
  toolDir = path.join(root, "tool");
  backupDir = path.join(root, "backup");
  workspace = path.join(root, "workspace");
  await fs.mkdir(victimDir, { recursive: true });
  await fs.mkdir(toolDir, { recursive: true });
  await fs.mkdir(backupDir, { recursive: true });
  await fs.writeFile(path.join(toolDir, "toolhost.exe"), Buffer.from("MZstub"));

  // The recovery workspace has to be a *sibling* of the data under attack. If it
  // wrapped the victim directory, every real affected file would be excluded as
  // "inside ARGUS's own workspace" and discovery would silently find nothing.
  const { setRecoveryRoot } = await import("../paths");
  setRecoveryRoot(workspace);
  process.env.ARGUS_RECOVERY_BACKUP_ROOTS = backupDir;
  recoveryService.registerTrigger();
});

after(async () => {
  delete process.env.ARGUS_RECOVERY_BACKUP_ROOTS;
  const { setRecoveryRoot } = await import("../paths");
  setRecoveryRoot(null);
  setRecoveryEventSink(null);
  await fs.rm(root, { recursive: true, force: true });
});

/** Drive the real automatic funnel and wait for it to finish on its own. */
async function runAutomaticPipeline(det: Detection): Promise<NonNullable<ReturnType<typeof recoveryStore.getIncidentByDetection>>> {
  eventHub.addDetection(det);
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const incident = recoveryStore.getIncidentByDetection(det.id);
    if (incident?.phase === "COMPLETE") return incident;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("the automatic pipeline did not reach COMPLETE");
}

beforeEach(() => {
  events = [];
  setRecoveryEventSink((name, fields) => {
    events.push({ name, fields });
  });
  eventHub.reset();
  recoveryStore.reset();
  recoveryService.setEnabled(true);
});

describe("recovery observability and resume", () => {
  it("emits a complete, timestamped, machine-readable event stream for one incident", async () => {
    const target = path.join(victimDir, "report.docx");
    await fs.writeFile(target, CORRUPTED_CONTENT);

    const backup = path.join(backupDir, "report.docx");
    await fs.writeFile(backup, ORIGINAL_CONTENT);
    const longAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    await fs.utimes(backup, longAgo, longAgo);

    eventHub.addMonitoringEvents([fileEvent("obs-fs-1", "FILE_MODIFIED", target)]);
    const incident = await runAutomaticPipeline(detection({ id: "det-events" }));
    assert.ok(incident);

    const emitted = new Set(names());
    for (const required of [
      "RECOVERY_TRIGGERED",
      "IMPACT_DISCOVERY_STARTED",
      "IMPACT_FILE_DISCOVERED",
      "RECOVERY_SOURCE_SEARCH_STARTED",
      "RECOVERY_SOURCE_FOUND",
      "RECOVERY_ATTEMPT_STARTED",
      "RECOVERY_ATTEMPT_COMPLETED",
      "RECOVERY_VERIFICATION_STARTED",
      "RECOVERY_VERIFICATION_COMPLETED",
      "RECOVERY_COMPLETED",
    ] as RecoveryEventName[]) {
      assert.ok(emitted.has(required), `the pipeline must emit ${required}`);
    }

    // Every event carries an identifier and a timestamp, so an operator can join
    // the stream back to the incident without guessing.
    for (const entry of events) {
      assert.ok(
        typeof entry.fields.timestamp === "string" && !Number.isNaN(Date.parse(entry.fields.timestamp as string)),
        `${entry.name} must carry a parseable timestamp`,
      );
      assert.ok(entry.fields.detection_id === "det-events", `${entry.name} must name the detection`);
    }

    // Per-file events carry the identifiers needed to locate the record. Both
    // the watched file and the detected process's own image are discovered.
    const discovered = eventsFor("IMPACT_FILE_DISCOVERED");
    const forTarget = discovered.filter((fields) => fields.path === target);
    assert.equal(forTarget.length, 1, "exactly one discovery event per affected file");
    assert.equal(forTarget[0].incident_id, incident!.incident_id);
    assert.ok(forTarget[0].record_id);

    const attemptStarted = eventsFor("RECOVERY_ATTEMPT_STARTED");
    assert.equal(attemptStarted.length, 1);
    assert.ok(attemptStarted[0].source, "an attempt must name the source it is using");

    const completed = eventsFor("RECOVERY_ATTEMPT_COMPLETED");
    assert.equal(completed.length, 1);
    assert.equal(completed[0].result, "VERIFIED", "a verified copy reports VERIFIED, not a bare success");
    assert.ok(completed[0].detail);

    const verification = eventsFor("RECOVERY_VERIFICATION_COMPLETED");
    assert.equal(verification.length, 1);
    assert.equal(verification[0].result, "VERIFIED");

    const finish = eventsFor("RECOVERY_COMPLETED");
    assert.equal(finish.length, 1);
    assert.equal(finish[0].result, "COMPLETE");

    // The log stream must never carry file contents, only fingerprints.
    const serialized = JSON.stringify(events);
    assert.ok(!serialized.includes(CORRUPTED_CONTENT.toString("latin1").slice(0, 64)));
    assert.ok(!serialized.includes(ORIGINAL_CONTENT.toString("latin1")));
  });

  it("resumes an interrupted incident instead of starting a new one or repeating finished work", async () => {
    const recovered = path.join(victimDir, "recovered.docx");
    await fs.writeFile(recovered, CORRUPTED_CONTENT);

    const unrecoverable = path.join(victimDir, "gone.docx");
    await fs.writeFile(unrecoverable, CORRUPTED_CONTENT);

    const backup = path.join(backupDir, "recovered.docx");
    await fs.writeFile(backup, ORIGINAL_CONTENT);
    const longAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    await fs.utimes(backup, longAgo, longAgo);

    eventHub.addMonitoringEvents([
      fileEvent("resume-fs-1", "FILE_MODIFIED", recovered),
      fileEvent("resume-fs-2", "FILE_MODIFIED", unrecoverable),
    ]);

    const first = await runAutomaticPipeline(detection({ id: "det-resume" }));
    assert.ok(first);
    assert.equal(first!.phase, "COMPLETE");

    const record = first!.affected_files.find((file) => file.path === recovered);
    assert.ok(record, `expected ${recovered} to be discovered as affected`);
    const attemptsAfterFirst = record!.attempts.length;
    const filesAfterFirst = first!.affected_files.length;
    assert.ok(attemptsAfterFirst >= 1);
    assert.equal(record!.recovery_state, "VERIFIED");

    // Simulate a restart mid-incident: the process died after one file was
    // verified, so the incident is rewound to an in-progress phase.
    recoveryStore.setPhase(first!.incident_id, "RECOVERING");

    events = [];
    // The same detection arrives again, exactly as it would after a restart.
    eventHub.addDetection(detection({ id: "det-resume" }));
    const resumed = await (async () => {
      const deadline = Date.now() + 30_000;
      while (Date.now() < deadline) {
        const current = recoveryStore.getIncidentByDetection("det-resume");
        if (current?.phase === "COMPLETE" && current.updated_at !== first!.updated_at) return current;
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
      throw new Error("the resumed pipeline did not reach COMPLETE");
    })();

    assert.equal(resumed!.incident_id, first!.incident_id, "resume must reuse the existing incident");
    assert.equal(resumed!.phase, "COMPLETE", "resume must drive the incident back to completion");
    assert.equal(
      resumed!.affected_files.length,
      filesAfterFirst,
      "resuming must not discover the same files a second time",
    );
    assert.equal(
      resumed!.affected_files.find((file) => file.path === recovered)!.attempts.length,
      attemptsAfterFirst,
      "work that already succeeded must not be repeated",
    );

    // The one genuinely unfinished file still gets its own honest verdict.
    const stillMissing = resumed!.affected_files.find((file) => file.path === unrecoverable)!;
    assert.equal(stillMissing.recovery_state, "NO_RECOVERY_SOURCE");

    // Resume emits a fresh trigger, joined by detection_id because the incident
    // row already exists but is deliberately reused rather than recreated.
    const triggers = eventsFor("RECOVERY_TRIGGERED");
    assert.equal(triggers.length, 1);
    assert.equal(triggers[0].detection_id, "det-resume");
  });
});
