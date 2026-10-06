/**
 * End-to-end: real detection event -> automatic recovery, with no human involved.
 *
 * This is the test that proves the Phase 3 objective. Nothing here calls
 * `recoveryService.investigate()` and nothing constructs a `Detection` by hand.
 * Every detection is produced by the real detection engine evaluating a real
 * process event posted to the real ingest route, and recovery starts purely
 * because that detection reached the hub.
 *
 * The threat is synthetic and harmless: a real child process (`node`) performs
 * ordinary file modifications, a delete and a rename inside a temp directory.
 * There is no malware, no obfuscated payload that does anything, and nothing
 * outside the temp directory is touched.
 */

import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs/promises";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import type { Express } from "express";

import type { Detection } from "../../detection/types";
import type { RecoverySnapshot } from "../types";

let app: Express;
let server: Server;
let base: string;

/** The synthetic world. Everything lives under one temp root. */
let root: string;
let victimDir: string;
let toolDir: string;
let backupDir: string;
let workspace: string;
let toolBinary: string;
let parentBinary: string;
let sidecar: string;

/* ------------------------------------------------------------------ */
/* Real, valid file containers                                          */
/* ------------------------------------------------------------------ */

/** A genuine ZIP local-file-header, so `.docx`/`.xlsx` fixtures carry real magic bytes. */
function zipContainer(entryName: string, contents: string): Buffer {
  const name = Buffer.from(entryName, "latin1");
  const body = Buffer.from(contents, "latin1");
  const header = Buffer.alloc(30);
  header.writeUInt32LE(0x04034b50, 0);
  header.writeUInt16LE(20, 4);
  header.writeUInt16LE(0, 6);
  header.writeUInt16LE(0, 8);
  header.writeUInt16LE(0, 10);
  header.writeUInt16LE(0, 12);
  header.writeUInt32LE(body.length, 14);
  header.writeUInt32LE(body.length, 18);
  header.writeUInt32LE(body.length, 22);
  header.writeUInt16LE(name.length, 26);
  header.writeUInt16LE(0, 28);
  return Buffer.concat([header, name, body]);
}

/** A genuine PNG signature header, so `.png` fixtures carry real magic bytes. */
function pngContainer(): Buffer {
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    Buffer.from([0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52]),
    randomBytes(256),
  ]);
}

/** A minimal but genuine `MZ` stub, so the tool binary is a valid PE by signature. */
function peStub(): Buffer {
  return Buffer.concat([Buffer.from("MZ", "latin1"), Buffer.from([0x90, 0x00, 0x03, 0x00]), randomBytes(512)]);
}

const GOOD_REPORT = zipContainer("word/document.xml", "the original quarterly report, untouched");
const GOOD_LEDGER = zipContainer("xl/workbook.xml", "the original ledger, untouched");
const GOOD_PHOTO = pngContainer();
const GOOD_NOTES = Buffer.from("plain notes, no container signature is claimed for .txt\n", "latin1");

/** What the synthetic process leaves behind: random bytes, i.e. real corruption. */
function corrupt(): Buffer {
  return randomBytes(2048);
}

async function sha256(target: string): Promise<string> {
  return createHash("sha256").update(await fs.readFile(target)).digest("hex");
}

/* ------------------------------------------------------------------ */
/* HTTP helpers against the real app                                    */
/* ------------------------------------------------------------------ */

async function post<T>(route: string, body: unknown): Promise<{ status: number; body: T }> {
  const response = await fetch(`${base}${route}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, body: (text ? JSON.parse(text) : null) as T };
}

async function get<T>(route: string): Promise<{ status: number; body: T }> {
  const response = await fetch(`${base}${route}`);
  const text = await response.text();
  return { status: response.status, body: (text ? JSON.parse(text) : null) as T };
}

async function waitFor(predicate: () => boolean, label: string, timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`timed out waiting for ${label}`);
}

/* ------------------------------------------------------------------ */
/* The synthetic attack, performed by a real OS process                 */
/* ------------------------------------------------------------------ */

/**
 * Run the destructive half of the scenario in a genuinely separate process and
 * return its real OS pid. Using a real pid means the detection that follows
 * refers to a process that actually existed, and the mutations are real
 * filesystem operations rather than in-process bookkeeping.
 */
function runSyntheticAttack(): Promise<{ pid: number }> {
  const script = `
    const fs = require("node:fs");
    const path = require("node:path");
    const victim = process.argv[1];
    const tool = process.argv[2];
    const rand = (n) => require("node:crypto").randomBytes(n);
    const pe = (n) => Buffer.concat([Buffer.from("MZ", "latin1"), Buffer.from([0x90, 0x00, 0x03, 0x00]), rand(n)]);
    // Modify in place, keeping the container signature intact.
    fs.writeFileSync(path.join(victim, "report.docx"), Buffer.concat([Buffer.from([0x50,0x4b,0x03,0x04]), rand(512)]));
    // Modify with the signature destroyed: real corruption.
    fs.writeFileSync(path.join(victim, "ledger.xlsx"), rand(2048));
    fs.writeFileSync(path.join(victim, "notes.txt"), "rewritten by the synthetic process\\n");
    fs.writeFileSync(path.join(victim, "photo.png"), rand(1024));
    // Delete outright.
    fs.rmSync(path.join(victim, "old.docx"));
    // Rename, so the watcher reports a destination plus an origin.
    fs.renameSync(path.join(victim, "draft.docx"), path.join(victim, "draft-final.docx"));
    // Touch the tool's own image, and its parent's image, for real: these are the
    // exact-executable-path cases. No watcher event is ever invented for a write
    // this process did not actually perform.
    fs.writeFileSync(path.join(tool, "toolhost.exe"), pe(512));
    fs.writeFileSync(path.join(tool, "winword.exe"), pe(512));
    // Drop a sidecar next to them: same directory, no shared identifier.
    fs.writeFileSync(path.join(tool, "sidecar.dat"), rand(256));
  `;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["-e", script, victimDir, toolDir], { stdio: "ignore" });
    const pid = child.pid;
    if (typeof pid !== "number") {
      reject(new Error("could not start the synthetic process"));
      return;
    }
    child.on("error", reject);
    child.on("exit", (code) =>
      code === 0 ? resolve({ pid }) : reject(new Error(`synthetic process exited with ${code}`)),
    );
  });
}

/** A filesystem watcher event, exactly the shape the endpoint agent posts. */
function watcherEvent(
  eventId: string,
  eventType: string,
  target: string,
  extra: Record<string, unknown> = {},
) {
  return {
    eventId,
    timestamp: new Date().toISOString(),
    eventType,
    source: "filesystem_watch",
    entity: { kind: "file", id: target, name: path.basename(target) },
    severity: "info",
    evidence: {
      path: target,
      old_path: null,
      root: path.dirname(target),
      is_directory: false,
      size_bytes: 2048,
      extension: path.extname(target),
      created_at: null,
      modified_at: new Date().toISOString(),
      ...extra,
    },
    metadata: { contents_read: false, observation: "filesystem metadata only" },
    correlationId: null,
  };
}

/**
 * Post a process event that the real detection engine will flag, then return the
 * detection the engine actually produced. Nothing about the detection is
 * asserted in advance beyond the rule the engine is documented to raise.
 */
async function triggerRealDetection(pid: number): Promise<Detection> {
  const { eventHub } = await import("../../lib/event-hub");
  const before = new Set(eventHub.getDetections(1000).map((entry) => entry.id));
  await post("/events/process", {
    id: `evt-parent-${pid}`,
    event_type: "PROCESS_STARTED",
    timestamp: new Date().toISOString(),
    hostname: "SYNTHETIC-HOST",
    pid: pid - 1,
    process_name: "winword.exe",
    executable_path: path.join(toolDir, "winword.exe"),
    command_line: "winword.exe /n report.docx",
    parent_pid: 4,
    parent_process_name: "explorer.exe",
    username: "SYNTHETIC\\victim",
  });

  // The child: an encoded, hidden, policy-bypassing command line, which is what
  // PROC-002 is written to catch.
  await post("/events/process", {
    id: `evt-child-${pid}`,
    event_type: "PROCESS_STARTED",
    timestamp: new Date().toISOString(),
    hostname: "SYNTHETIC-HOST",
    pid,
    process_name: "toolhost.exe",
    executable_path: toolBinary,
    command_line:
      "toolhost.exe -nop -w hidden -ep bypass -enc " +
      "VGhpcyBpcyBhIHN5bnRoZXRpYyBibG9iIHRoYXQgaW5jcnlwdGVkIG5vdGhpbmcgYW55dGhpbmcu",
    parent_pid: pid - 1,
    parent_process_name: "winword.exe",
    username: "SYNTHETIC\\victim",
  });


  await waitFor(
    () => eventHub.getDetections(1000).some((entry) => !before.has(entry.id) && entry.pid === pid),
    "the detection engine to produce a detection for the synthetic process",
  );

  const produced = eventHub
    .getDetections(1000)
    .find((entry) => !before.has(entry.id) && entry.pid === pid);
  assert.ok(produced, "the real detection pipeline must produce a detection");
  return produced;
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                            */
/* ------------------------------------------------------------------ */

before(async () => {
  process.env.LOG_LEVEL = "silent";

  root = await fs.mkdtemp(path.join(os.tmpdir(), "argus-auto-pipeline-"));
  victimDir = path.join(root, "victim documents");
  toolDir = path.join(root, "tool");
  backupDir = path.join(root, "backup");
  workspace = path.join(root, "workspace");
  // A space in the path proves the pipeline is not doing naive string splitting.
  await fs.mkdir(victimDir, { recursive: true });
  await fs.mkdir(toolDir, { recursive: true });
  await fs.mkdir(backupDir, { recursive: true });

  toolBinary = path.join(toolDir, "toolhost.exe");  await fs.writeFile(toolBinary, peStub());
  // The suspected parent runs from the same directory, so its image is also a
  // real, pre-existing file that the synthetic process overwrites later.
  parentBinary = path.join(toolDir, "winword.exe");
  await fs.writeFile(parentBinary, peStub());
  sidecar = path.join(toolDir, "sidecar.dat");

  // Known-good copies, all deliberately older than the incident window so they
  // are legitimately restorable.
  const longAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  for (const [name, content] of [
    ["report.docx", GOOD_REPORT],
    ["ledger.xlsx", GOOD_LEDGER],
    ["photo.png", GOOD_PHOTO],
  ] as const) {
    const target = path.join(backupDir, name);
    await fs.writeFile(target, content);
    await fs.utimes(target, longAgo, longAgo);
  }
  // `notes.txt` deliberately has NO known-good copy, and `old.docx` is deleted
  // outright. Those must end as NO_RECOVERY_SOURCE, not as a silent success.

  const { setRecoveryRoot } = await import("../paths");
  setRecoveryRoot(workspace);
  process.env.ARGUS_RECOVERY_BACKUP_ROOTS = backupDir;

  ({ default: app } = await import("../../app"));
  const { recoveryService } = await import("../service");
  recoveryService.setEnabled(true);

  await new Promise<void>((resolve) => {
    server = app.listen(0, () => resolve());
  });
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api`;
});

after(async () => {
  delete process.env.ARGUS_RECOVERY_BACKUP_ROOTS;
  const { setRecoveryRoot } = await import("../paths");
  setRecoveryRoot(null);
  await new Promise<void>((resolve) => {
    server.close(() => resolve());
  });
  await fs.rm(root, { recursive: true, force: true });
});

beforeEach(async () => {
  const { eventHub } = await import("../../lib/event-hub");
  const { recoveryStore } = await import("../store");
  eventHub.reset();
  recoveryStore.reset();
});

/* ------------------------------------------------------------------ */
/* The scenario                                                         */
/* ------------------------------------------------------------------ */

describe("automatic detection-to-recovery pipeline", () => {
  it("starts recovery on its own from a real detection and recovers what it can", async () => {
    /* 1. Lay down the user's files, and record exactly what they contain. */
    const report = path.join(victimDir, "report.docx");
    const ledger = path.join(victimDir, "ledger.xlsx");
    const notes = path.join(victimDir, "notes.txt");
    const photo = path.join(victimDir, "photo.png");
    const oldDoc = path.join(victimDir, "old.docx");
    const draft = path.join(victimDir, "draft.docx");
    const renamed = path.join(victimDir, "draft-final.docx");

    await fs.writeFile(report, GOOD_REPORT);
    await fs.writeFile(ledger, GOOD_LEDGER);
    await fs.writeFile(notes, GOOD_NOTES);
    await fs.writeFile(photo, GOOD_PHOTO);
    await fs.writeFile(oldDoc, zipContainer("word/document.xml", "about to be deleted"));
    await fs.writeFile(draft, zipContainer("word/document.xml", "about to be renamed"));

    /* 2. A real process performs the destructive work. */
    const { pid } = await runSyntheticAttack();

    /* 3. Report it to ARGUS the way the endpoint agent would, in two real calls. */
    const watcherBatch = [
      watcherEvent("auto-fs-1", "FILE_MODIFIED", report),
      watcherEvent("auto-fs-2", "FILE_MODIFIED", ledger),
      watcherEvent("auto-fs-3", "FILE_MODIFIED", notes),
      watcherEvent("auto-fs-4", "FILE_MODIFIED", photo),
      watcherEvent("auto-fs-5", "FILE_DELETED", oldDoc),
      watcherEvent("auto-fs-6", "FILE_RENAMED", renamed, { old_path: draft }),
      // The tool's own image, its parent's image, and a sidecar beside them. Each
      // of these three files really was overwritten by the synthetic process in
      // step 2; these events only report what already happened.
      watcherEvent("auto-fs-7", "FILE_MODIFIED", toolBinary),
      watcherEvent("auto-fs-8", "FILE_MODIFIED", parentBinary),
      watcherEvent("auto-fs-9", "FILE_CREATED", sidecar),
    ];
    const ingest = await post<{ accepted: number; rejected: number }>("/monitoring/events", { events: watcherBatch });
    assert.equal(ingest.status, 202);
    assert.equal(ingest.body.accepted, watcherBatch.length, "every watcher event must be ingested");

    /* 4. The real detection pipeline produces the detection. */
    const detection = await triggerRealDetection(pid);
    assert.equal(detection.pid, pid);
    assert.equal(detection.severity, "high", "the gate's threshold input comes from the real engine");
    assert.ok(
      detection.rule_id.startsWith("PROC-"),
      `expected a process rule, got ${detection.rule_id}`,
    );

    /* 5. Nobody calls investigate(). Recovery must start by itself. */
    const { recoveryStore } = await import("../store");
    await waitFor(
      () => recoveryStore.getIncidentByDetection(detection.id)?.phase === "COMPLETE",
      "the automatic investigation to run to completion",
    );

    const incident = recoveryStore.getIncidentByDetection(detection.id);
    assert.ok(incident, "an incident must exist for the detection, created automatically");
    assert.equal(incident!.detection_id, detection.id);
    assert.equal(incident!.process.pid, pid, "the incident must name the real offending pid");

    /* 6. Affected data was discovered, and the damage is classified from real bytes. */
    const byPath = new Map(incident!.affected_files.map((file) => [file.path, file]));
    for (const target of [report, ledger, notes, photo, oldDoc, renamed]) {
      assert.ok(byPath.has(target), `expected ${path.basename(target)} to be discovered as affected`);
    }

    const ledgerRecord = byPath.get(ledger)!;
    assert.equal(
      ledgerRecord.damage,
      "ENCRYPTED_OR_CORRUPTED_SUSPECTED",
      "a container whose signature was destroyed is real measured corruption",
    );
    assert.ok(ledgerRecord.damage_signals.some((signal) => signal.kind === "SIGNATURE_MISMATCH"));

    assert.equal(byPath.get(report)!.damage, "MODIFIED");
    assert.equal(byPath.get(oldDoc)!.damage, "DELETED");
    assert.equal(byPath.get(renamed)!.damage, "RENAMED");
    assert.equal(byPath.get(renamed)!.previous_path, draft, "the rename origin must be preserved");

    /* 7. Telemetry correlation graded the attribution, and never overclaimed. */
    // The detected process's own image: an exact executable-path match.
    const toolRecord = byPath.get(toolBinary)!;
    assert.equal(toolRecord.attribution_strength, "ATTRIBUTED");
    assert.equal(toolRecord.attribution, "PROCESS_EXECUTABLE_PATH");

    // The suspected parent's image: exact path, but a different process, so it
    // must be graded as ancestry rather than as the offending binary itself.
    const parentRecord = byPath.get(parentBinary)!;
    assert.equal(parentRecord.attribution_strength, "ATTRIBUTED");
    assert.equal(parentRecord.attribution, "PROCESS_ANCESTRY_PATH");

    // Same directory as the tool, but no shared identifier. Co-location is
    // circumstantial, so it must be reported as uncertain and never as ATTRIBUTED.
    const sidecarRecord = byPath.get(sidecar)!;
    assert.equal(
      sidecarRecord.attribution_strength,
      "ATTRIBUTION_UNCERTAIN",
      "sharing a directory with the tool is not proof of authorship",
    );
    assert.equal(sidecarRecord.attribution, "PROCESS_LINEAGE_DIRECTORY");

    // Files that share nothing with the process at all fall back to the window.
    for (const target of [report, ledger, notes, photo]) {
      const record = byPath.get(target)!;
      assert.notEqual(record.attribution_strength, "ATTRIBUTED", `${path.basename(target)} shares no identifier with the process`);
      assert.ok(
        ["ATTRIBUTION_UNCERTAIN", "INFERRED"].includes(record.attribution_strength),
        `unexpected strength ${record.attribution_strength}`,
      );
      assert.ok(
        record.notes.some((note) => note.includes("ATTRIBUTION_UNCERTAIN") || note.includes("incident time window")),
        "a weakly attributed record must say so on its face",
      );
    }
    // Nothing anywhere may be graded higher than its evidence supports.
    for (const record of incident!.affected_files) {
      if (record.attribution_strength === "ATTRIBUTED") {
        assert.ok(
          ["SECURITY_PROVIDER_RESOURCE", "PROCESS_EXECUTABLE_PATH", "PROCESS_ANCESTRY_PATH", "ENGINE_FILE_DETECTION"].includes(
            record.attribution,
          ),
          `${record.attribution} must be backed by an exact identifier`,
        );
      }
    }

    /* 8. Recovery source discovery ran for every record, against real sources. */
    for (const record of incident!.affected_files) {
      assert.ok(record.recovery_sources.length > 0, "source discovery must probe every record");
      for (const source of record.recovery_sources) {
        assert.ok(source.probe_detail.length > 0, "every source must carry a real probe reason");
        // A source is only ever restorable when it was really found and really
        // predates the incident.
        if (source.restorable) {
          assert.equal(source.available, true);
          assert.ok(Date.parse(source.modified_at!) < Date.parse(incident!.window.start));
        }
      }
    }

    /* 9. Recovery ran, staged copies, and verified them. */
    const recovered = incident!.affected_files.filter((file) => file.recovery_state === "VERIFIED");
    assert.ok(recovered.length >= 3, `expected the three backed-up files to verify, got ${recovered.length}`);
    for (const file of recovered) {
      const attempt = file.attempts.at(-1)!;
      assert.equal(attempt.outcome, "SUCCEEDED");
      assert.equal(attempt.verified, true);
      assert.equal(attempt.destructive, false);
      assert.ok(attempt.recovered_path!.startsWith(workspace), "a staged copy must live inside the recovery workspace");
      assert.ok(
        attempt.checks.some((check) => check.name === "ORIGINAL_UNTOUCHED" && check.passed),
        "the original-untouched invariant must be an asserted, passing check",
      );
      assert.ok(
        attempt.checks.some((check) => check.name === "BYTE_IDENTICAL" && check.passed),
        "a verified copy must be proven byte-identical to its source",
      );
      // The staged copy really is the known-good content.
      assert.equal(await sha256(attempt.recovered_path!), await sha256(path.join(backupDir, path.basename(file.path))));
    }

    // The file with no known-good copy must be reported as unrecoverable, not
    // quietly called recovered.
    assert.equal(byPath.get(notes)!.recovery_state, "NO_RECOVERY_SOURCE");
    assert.equal(byPath.get(oldDoc)!.recovery_state, "NO_RECOVERY_SOURCE");
    assert.ok(
      byPath.get(notes)!.notes.some((note) => note.includes("no pre-incident copy")),
      "an unrecoverable file must explain itself",
    );

    /* 10. Progress counts came from real state, and the pipeline ran end to end. */
    assert.deepEqual(incident!.stages_reached, [
      "THREAT_DETECTED",
      "IMPACT_DISCOVERY",
      "RECOVERY_SOURCE_SEARCH",
      "SAFE_RECOVERY",
      "VERIFICATION",
    ]);
    assert.equal(incident!.progress.total, incident!.affected_files.length);
    assert.equal(incident!.progress.verified, recovered.length);
    assert.ok(incident!.progress.stage_percent === 100);

    /* 11. The originals were never overwritten, renamed back or deleted. */
    assert.notEqual(await sha256(report), await sha256(path.join(backupDir, "report.docx")), "the damaged original must still be damaged");
    assert.ok((await fs.readFile(report)).length < 2048, "report.docx must still hold the attacker's content, not the backup");
    assert.ok((await fs.readFile(ledger)).length === 2048);
    await assert.rejects(fs.access(oldDoc), "a deleted file must stay deleted; recovery never resurrects originals");
    await assert.rejects(fs.access(draft), "the rename origin must stay gone");

    /* 12. Evidence was preserved before any recovery decision. */
    const withEvidence = incident!.affected_files.filter((file) =>
      file.notes.some((note) => note.includes("as-found copy preserved")),
    );
    assert.ok(withEvidence.length > 0, "as-found evidence must be captured for surviving files");

    /* 13. The API serves the whole thing, with no invented numbers. */
    const snapshot = await get<RecoverySnapshot>("/recovery");
    assert.equal(snapshot.status, 200);
    assert.equal(snapshot.body.incidents.length, 1);
    assert.equal(snapshot.body.summary.affectedFiles, incident!.affected_files.length);
    assert.equal(snapshot.body.summary.verified, recovered.length);
    assert.equal(
      snapshot.body.summary.affectedFiles -
        snapshot.body.summary.modifiedFiles -
        snapshot.body.summary.deletedFiles -
        snapshot.body.summary.renamedFiles -
        snapshot.body.summary.createdFiles -
        snapshot.body.summary.encryptedSuspectedFiles -
        snapshot.body.summary.unknownDamageFiles,
      0,
      "the damage counters must partition the affected files exactly",
    );
  });

  it("produces the same incident no matter how many times the detection is replayed", async () => {
    const target = path.join(victimDir, "replay.docx");
    await fs.writeFile(target, GOOD_REPORT);
    const backup = path.join(backupDir, "replay.docx");
    await fs.writeFile(backup, GOOD_REPORT);
    const longAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    await fs.utimes(backup, longAgo, longAgo);

    const { pid } = await corruptFromChildProcess(target);

    await post("/monitoring/events", {
      events: [watcherEvent("replay-fs-1", "FILE_MODIFIED", target)],
    });
    const detection = await triggerRealDetection(pid);

    const { recoveryStore } = await import("../store");
    await waitFor(
      () => recoveryStore.getIncidentByDetection(detection.id)?.phase === "COMPLETE",
      "the automatic investigation to complete",
    );

    const incidentId = recoveryStore.getIncidentByDetection(detection.id)!.incident_id;
    const attemptsAfterFirst = recoveryStore.getIncidentByDetection(detection.id)!.affected_files[0].attempts.length;
    assert.ok(attemptsAfterFirst >= 1);

    // Replay the identical process event. The engine's own dedup means no second
    // detection is produced, so no second investigation can start.
    await post("/events/process", {
      id: `evt-child-${pid}`,
      event_type: "PROCESS_STARTED",
      timestamp: new Date().toISOString(),
      hostname: "SYNTHETIC-HOST",
      pid,
      process_name: "toolhost.exe",
      executable_path: toolBinary,
      command_line: "toolhost.exe -nop -w hidden -ep bypass -enc " + "V".repeat(60),
      parent_pid: pid - 1,
      parent_process_name: "winword.exe",
    });
    await new Promise((resolve) => setTimeout(resolve, 300));

    // And drive the service directly with the very same detection, which is the
    // idempotency guarantee the store is responsible for.
    const { recoveryService } = await import("../service");
    const again = await recoveryService.investigate(detection);
    assert.equal(again!.incident_id, incidentId, "the same detection must resolve to the same incident");
    assert.equal(recoveryStore.listIncidents().length, 1, "no second incident may be created");
    assert.equal(
      again!.affected_files[0].attempts.length,
      attemptsAfterFirst,
      "a replayed detection must not produce another recovery attempt",
    );
    assert.equal(again!.affected_files[0].recovery_state, "VERIFIED", "a verified recovery must not be downgraded");
  });

  it("deduplicates redelivered filesystem events instead of inflating impact", async () => {
    const target = path.join(victimDir, "dedupe.docx");
    await fs.writeFile(target, GOOD_REPORT);
    const { pid } = await corruptFromChildProcess(target);

    const batch = { events: [watcherEvent("dedupe-fs-1", "FILE_MODIFIED", target)] };
    const first = await post<{ accepted: number; duplicates: number }>("/monitoring/events", batch);
    assert.equal(first.body.accepted, 1);

    const second = await post<{ accepted: number; duplicates: number }>("/monitoring/events", batch);
    assert.equal(second.body.accepted, 0, "a redelivered event id must not be accepted twice");
    assert.equal(second.body.duplicates, 1);

    const detection = await triggerRealDetection(pid);
    const { recoveryStore } = await import("../store");
    await waitFor(
      () => recoveryStore.getIncidentByDetection(detection.id)?.phase === "COMPLETE",
      "the automatic investigation to complete",
    );

    const incident = recoveryStore.getIncidentByDetection(detection.id)!;
    assert.equal(
      incident.affected_files.filter((file) => file.path === target).length,
      1,
      "a redelivered event must not create a second impact record for the same file",
    );
    assert.equal(incident.affected_files[0].observation_count, 1);
  });

  it("does not open an investigation for a detection below the threat threshold", async () => {
    const target = path.join(victimDir, "benign.docx");
    await fs.writeFile(target, GOOD_REPORT);
    await fs.writeFile(target, corrupt());
    await post("/monitoring/events", {
      events: [watcherEvent("benign-fs-1", "FILE_MODIFIED", target)],
    });

    // NET-002 is a medium-severity, 0.6-confidence network observation with no
    // file evidence: real telemetry, but nothing to reconstruct.
    const { eventHub } = await import("../../lib/event-hub");
    const at = new Date().toISOString();
    eventHub.addDetection({
      id: "det-benign-net",
      rule_id: "NET-002-KNOWN-TOOL-PORT",
      rule_name: "Known tool listening on a remote port",
      title: "chrome.exe listening on 4444",
      severity: "medium",
      confidence: 0.6,
      status: "detected",
      timestamp: at,
      event_timestamp: at,
      entity: "chrome.exe",
      pid: 31337,
      hostname: "SYNTHETIC-HOST",
      evidence: [],
      explanation: "",
      recommended_action: "",
      ancestry: [],
      related_event_id: null,
    });

    await new Promise((resolve) => setTimeout(resolve, 400));

    const { recoveryStore } = await import("../store");
    assert.equal(recoveryStore.getIncidentByDetection("det-benign-net"), null, "a sub-threshold detection must not open an incident");

    // The decision must remain visible rather than looking like nothing happened.
    const { recoveryService } = await import("../service");
    assert.ok(recoveryService.getTriggerSkipStats().skipped >= 1);

    const config = await get<{ automaticTrigger: { skippedDetections: number; lastSkipReason: string | null } }>(
      "/recovery/config",
    );
    assert.equal(config.status, 200);
    assert.ok(config.body.automaticTrigger.skippedDetections >= 1);
    assert.match(config.body.automaticTrigger.lastSkipReason!, /below the automatic recovery threshold/);

    // It is still investigable on demand: the gate applies to automation only.
    const forced = await recoveryService.investigate({
      id: "det-benign-net",
      rule_id: "NET-002-KNOWN-TOOL-PORT",
      rule_name: "Known tool listening on a remote port",
      title: "chrome.exe listening on 4444",
      severity: "medium",
      confidence: 0.6,
      status: "detected",
      timestamp: at,
      event_timestamp: at,
      entity: "chrome.exe",
      pid: 31337,
      hostname: "SYNTHETIC-HOST",
      evidence: [],
      explanation: "",
      recommended_action: "",
      ancestry: [],
      related_event_id: null,
    });
    assert.ok(forced, "an operator must still be able to force an investigation");
    assert.equal(forced!.detection_id, "det-benign-net");
  });
});

/* ------------------------------------------------------------------ */
/* Helpers for the focused cases                                        */
/* ------------------------------------------------------------------ */

/**
 * Corrupt one file from a real separate process and return its real pid.
 *
 * Each focused case gets its own distinct pid on purpose: the engine
 * deduplicates detections per process per hour, so reusing a pid would make a
 * later case silently produce no detection at all and the test would pass for
 * the wrong reason.
 */
function corruptFromChildProcess(target: string): Promise<{ pid: number }> {
  const script = `
    const fs = require("node:fs");
    const file = process.argv[1];
    fs.writeFileSync(file, require("node:crypto").randomBytes(1024));
  `;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["-e", script, target], { stdio: "ignore" });
    const pid = child.pid;
    if (typeof pid !== "number") {
      reject(new Error("could not start the synthetic process"));
      return;
    }
    child.on("error", reject);
    child.on("exit", (code) =>
      code === 0 ? resolve({ pid }) : reject(new Error(`synthetic process exited with ${code}`)),
    );
  });
}
