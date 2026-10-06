import { describe, it, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import type { Detection } from "../../detection/types";
import type { EventHubType } from "../../lib/event-hub";
import type { RecoveryService } from "../service";
import type { RecoveryStore } from "../store";
import type { ImpactIncident } from "../types";

process.env.LOG_LEVEL = "silent";

let eventHub: EventHubType;
let recoveryService: RecoveryService;
let recoveryStore: RecoveryStore;

let root: string;
let victimDir: string;
let backupDir: string;
let workspace: string;

/**
 * Build a real ZIP local-file-header container so a `.docx` fixture actually
 * carries the signature its extension claims. Signature verification compares
 * magic bytes, so a text buffer pretending to be a document would (correctly)
 * be rejected.
 */
function zipContainer(entryName: string, contents: string): Buffer {
  const name = Buffer.from(entryName, "latin1");
  const body = Buffer.from(contents, "latin1");
  const header = Buffer.alloc(30);
  header.writeUInt32LE(0x04034b50, 0); // local file header signature
  header.writeUInt16LE(20, 4); // version needed to extract
  header.writeUInt16LE(0, 6); // general purpose flags
  header.writeUInt16LE(0, 8); // compression method: stored
  header.writeUInt16LE(0, 10); // last mod time
  header.writeUInt16LE(0, 12); // last mod date
  header.writeUInt32LE(0, 14); // crc32 (unchecked by the container check)
  header.writeUInt32LE(body.length, 18); // compressed size
  header.writeUInt32LE(body.length, 22); // uncompressed size
  header.writeUInt16LE(name.length, 26); // file name length
  header.writeUInt16LE(0, 28); // extra field length
  return Buffer.concat([header, name, body]);
}

const ORIGINAL_CONTENT = zipContainer("word/document.xml", "the original, untouched document contents");
const ENCRYPTED_CONTENT = Buffer.concat([Buffer.from("SOMETHING"), randomBytes(2048)]);

/** Build a detection that looks like a real engine product. */
function detection(overrides: Partial<Detection> = {}): Detection {
  const at = new Date().toISOString();
  return {
    id: "det-test-1",
    rule_id: "PROC-002-ENCODED-COMMAND-LINE",
    rule_name: "Encoded PowerShell command line",
    title: "PowerShell executed with an encoded command",
    severity: "high",
    confidence: 0.82,
    status: "detected",
    timestamp: at,
    event_timestamp: at,
    entity: "powershell.exe",
    pid: 4242,
    executable_path: null,
    command_line: "powershell.exe -enc SQBFAFgA",
    parent_pid: 1200,
    parent_process_name: "explorer.exe",
    username: "CORP\\analyst",
    hostname: "WORKSTATION-01",
    evidence: [],
    explanation: "A base64-encoded PowerShell command was observed.",
    recommended_action: "Inspect the decoded command.",
    correlated_rules: [],
    ancestry: [
      { pid: 4242, process_name: "powershell.exe", executable_path: null },
      { pid: 1200, process_name: "explorer.exe", executable_path: null },
    ],
    related_event_id: null,
    ...overrides,
  };
}

/** One filesystem watcher event, exactly as the endpoint agent sends it. */
function fileEvent(id: string, kind: string, target: string, extra: Record<string, unknown> = {}) {
  return {
    eventId: id,
    timestamp: new Date().toISOString(),
    eventType: kind,
    source: "filesystem_watch",
    entity: { kind: "file", id: target, name: path.basename(target) },
    severity: "info",
    evidence: {
      path: target,
      old_path: null,
      root: path.dirname(target),
      is_directory: false,
      size_bytes: ENCRYPTED_CONTENT.length,
      extension: path.extname(target),
      created_at: null,
      modified_at: new Date().toISOString(),
      ...extra,
    },
    metadata: { contents_read: false, observation: "filesystem metadata only" },
    correlationId: null,
  };
}

async function waitFor(
  predicate: () => boolean,
  timeoutMs = 20_000,
  label = "condition",
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`timed out waiting for ${label}`);
}

before(async () => {
  ({ eventHub } = await import("../../lib/event-hub"));
  ({ recoveryService } = await import("../service"));
  ({ recoveryStore } = await import("../store"));
  const { setRecoveryRoot } = await import("../paths");

  root = await fs.mkdtemp(path.join(os.tmpdir(), "argus-recovery-e2e-"));
  victimDir = path.join(root, "victim");
  backupDir = path.join(root, "backup");
  workspace = path.join(root, "workspace");
  await fs.mkdir(victimDir, { recursive: true });
  await fs.mkdir(backupDir, { recursive: true });

  setRecoveryRoot(workspace);
  process.env.ARGUS_RECOVERY_BACKUP_ROOTS = backupDir;
  recoveryService.setEnabled(true);
  recoveryService.registerTrigger();
});

after(async () => {
  delete process.env.ARGUS_RECOVERY_BACKUP_ROOTS;
  const { setRecoveryRoot } = await import("../paths");
  setRecoveryRoot(null);
  await fs.rm(root, { recursive: true, force: true });
});

beforeEach(() => {
  eventHub.reset();
  recoveryStore.reset();
});

describe("impact reconstruction", () => {
  it("reports zero impact honestly when no telemetry names a file", async () => {
    const incident = await recoveryService.investigate(detection({ id: "det-empty" }));
    assert.ok(incident);
    assert.equal(incident!.affected_files.length, 0);
    assert.equal(incident!.phase, "COMPLETE");
    assert.equal(incident!.skipped_reason, null);

    const summary = recoveryStore.buildSummary();
    assert.equal(summary.affectedFiles, 0);
    assert.equal(recoveryStore.hasObservedAnything(), true);
  });

  it("attributes a window-only change as INFERRED and says why", async () => {
    const target = path.join(victimDir, "inferred.docx");
    await fs.writeFile(target, ENCRYPTED_CONTENT);
    eventHub.addMonitoringEvents([fileEvent("fs-1", "FILE_MODIFIED", target)]);

    const incident = await recoveryService.investigate(detection({ id: "det-inferred" }));
    const record = incident!.affected_files[0];
    assert.ok(record, "expected one affected file");
    assert.equal(record!.attribution, "INCIDENT_TIME_WINDOW");
    assert.equal(record!.attribution_strength, "INFERRED");
    assert.ok(record!.notes.some((note) => note.includes("no owning pid")));
    assert.ok(record!.evidence.some((item) => item.source === "monitoring_event"));
  });

  it("attributes a provider-named resource as ATTRIBUTED", async () => {
    const target = path.join(victimDir, "attributed.docx");
    await fs.writeFile(target, ENCRYPTED_CONTENT);
    eventHub.addMonitoringEvents([fileEvent("fs-2", "FILE_MODIFIED", target)]);
    eventHub.setSecurityProviders({
      timestamp: new Date().toISOString(),
      source: "agent",
      observed: true,
      discovery_state: "complete",
      provider_count: 1,
      providers: [],
      alerts: [
        {
          alert_id: "alert-1",
          provider_id: "p1",
          provider_name: "TestAV",
          kind: "DETECTION",
          timestamp: new Date().toISOString(),
          title: "Suspicious activity",
          severity: "high",
          resources: [target],
          process_name: "powershell.exe",
        },
      ],
      errors: [],
    });

    const incident = await recoveryService.investigate(detection({ id: "det-attributed" }));
    const record = incident!.affected_files[0];
    assert.equal(record!.attribution, "SECURITY_PROVIDER_RESOURCE");
    assert.equal(record!.attribution_strength, "ATTRIBUTED");
    assert.ok(record!.evidence.some((item) => item.source === "security_provider"));
  });

  it("escalates to suspected encryption only with a real signal", async () => {
    const target = path.join(victimDir, "mangled.docx");
    // Random bytes in a .docx: the container signature is gone. Real signal.
    await fs.writeFile(target, randomBytes(4096));
    eventHub.addMonitoringEvents([fileEvent("fs-3", "FILE_MODIFIED", target)]);

    const incident = await recoveryService.investigate(detection({ id: "det-encrypted" }));
    const record = incident!.affected_files[0];
    assert.equal(record!.damage, "ENCRYPTED_OR_CORRUPTED_SUSPECTED");
    assert.ok(record!.damage_signals.some((entry) => entry.kind === "SIGNATURE_MISMATCH"));
  });

  it("leaves an intact container as MODIFIED, not as suspected encryption", async () => {
    const target = path.join(victimDir, "intact.docx");
    await fs.writeFile(target, Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), randomBytes(2048)]));
    eventHub.addMonitoringEvents([fileEvent("fs-4", "FILE_MODIFIED", target)]);

    const incident = await recoveryService.investigate(detection({ id: "det-intact" }));
    const record = incident!.affected_files[0];
    assert.equal(record!.damage, "MODIFIED");
  });

  it("reports a deleted file as DELETED and unfindable for recovery", async () => {
    const target = path.join(victimDir, "gone.docx");
    eventHub.addMonitoringEvents([fileEvent("fs-5", "FILE_DELETED", target)]);

    const incident = await recoveryService.investigate(detection({ id: "det-deleted" }));
    const record = incident!.affected_files[0];
    assert.equal(record!.damage, "DELETED");
    assert.equal(record!.current_metadata.exists, false);
    assert.equal(record!.recovery_state, "NO_RECOVERY_SOURCE");
  });

  it("records a rename with its original path", async () => {
    const target = path.join(victimDir, "renamed.docx");
    // An intact container, so the only damage signal is the rename itself.
    await fs.writeFile(target, Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), randomBytes(1024)]));
    eventHub.addMonitoringEvents([
      fileEvent("fs-6", "FILE_RENAMED", target, { old_path: path.join(victimDir, "before.docx") }),
    ]);

    const incident = await recoveryService.investigate(detection({ id: "det-renamed" }));
    const record = incident!.affected_files[0];
    assert.equal(record!.damage, "RENAMED");
    assert.equal(record!.previous_path, path.join(victimDir, "before.docx"));
  });

  it("never counts its own workspace as impact", async () => {
    const insideWorkspace = path.join(workspace, "staging", "whatever.docx");
    eventHub.addMonitoringEvents([fileEvent("fs-7", "FILE_MODIFIED", insideWorkspace)]);

    const incident = await recoveryService.investigate(detection({ id: "det-workspace" }));
    assert.equal(incident!.affected_files.length, 0);
  });
});

describe("safe recovery", () => {
  it("recovers a file from a pre-incident backup and leaves the original untouched", async () => {
    const target = path.join(victimDir, "recoverable.docx");
    await fs.writeFile(target, ENCRYPTED_CONTENT);

    // A backup copy that genuinely predates the incident.
    const backup = path.join(backupDir, "recoverable.docx");
    await fs.writeFile(backup, ORIGINAL_CONTENT);
    const anHourAgo = new Date(Date.now() - 3_600_000);
    await fs.utimes(backup, anHourAgo, anHourAgo);

    eventHub.addMonitoringEvents([fileEvent("fs-8", "FILE_MODIFIED", target)]);

    const originalBefore = createHash("sha256").update(await fs.readFile(target)).digest("hex");
    const incident = await recoveryService.investigate(detection({ id: "det-recover" }));
    const record = incident!.affected_files[0];

    assert.equal(record!.damage, "ENCRYPTED_OR_CORRUPTED_SUSPECTED");
    assert.equal(record!.recovery_state, "VERIFIED", JSON.stringify(record!.notes));

    const attempt = record!.attempts[0];
    assert.equal(attempt.outcome, "SUCCEEDED");
    assert.equal(attempt.destructive, false);
    assert.equal(attempt.recovered_sha256, createHash("sha256").update(ORIGINAL_CONTENT).digest("hex"));

    // Every required verification check genuinely passed.
    for (const check of attempt.checks.filter((entry) => entry.required)) {
      assert.equal(check.passed, true, `${check.name} should pass: ${check.detail}`);
    }

    // The staged copy holds the ORIGINAL bytes, not the damaged ones.
    const staged = await fs.readFile(attempt.recovered_path!);
    assert.deepEqual(staged, ORIGINAL_CONTENT);

    // The non-destructive guarantee, asserted on the real bytes.
    const originalAfter = createHash("sha256").update(await fs.readFile(target)).digest("hex");
    assert.equal(originalAfter, originalBefore, "the original file must not be modified by recovery");
    assert.ok(attempt.recovered_path!.startsWith(workspace), "staged copy must live in the workspace");
    assert.notEqual(path.resolve(attempt.recovered_path!), path.resolve(target));
  });

  it("refuses a backup copy taken after the incident opened", async () => {
    const target = path.join(victimDir, "late-backup.docx");
    await fs.writeFile(target, ENCRYPTED_CONTENT);

    const backup = path.join(backupDir, "late-backup.docx");
    await fs.writeFile(backup, ORIGINAL_CONTENT);
    // Backup is NEWER than the incident: restoring it would return bad content.
    const future = new Date(Date.now() + 3_600_000);
    await fs.utimes(backup, future, future);

    eventHub.addMonitoringEvents([fileEvent("fs-9", "FILE_MODIFIED", target)]);

    const incident = await recoveryService.investigate(detection({ id: "det-late" }));
    const record = incident!.affected_files[0];
    assert.equal(record!.recovery_state, "NO_RECOVERY_SOURCE");
    assert.equal(record!.attempts.length, 0);
    const source = record!.recovery_sources.find((entry) => entry.kind === "CONFIGURED_BACKUP_ROOT");
    assert.ok(source);
    assert.equal(source!.restorable, false);
    assert.match(source!.probe_detail, /NOT older than the incident window/);
  });

  it("honestly reports when no source exists anywhere", async () => {
    const target = path.join(victimDir, "no-source.docx");
    await fs.writeFile(target, ENCRYPTED_CONTENT);
    eventHub.addMonitoringEvents([fileEvent("fs-10", "FILE_MODIFIED", target)]);

    const incident = await recoveryService.investigate(detection({ id: "det-nosource" }));
    const record = incident!.affected_files[0];
    assert.equal(record!.recovery_state, "NO_RECOVERY_SOURCE");
    assert.ok(record!.recovery_sources.length > 0, "every source kind should still report a reason");

    for (const source of record!.recovery_sources) {
      // Nothing is restorable — that is why recovery was refused.
      assert.equal(source.restorable, false, `${source.kind} must not be restorable`);
      assert.ok(source.probe_detail.length > 0, `${source.kind} must explain itself`);
    }
    // Only the evidence copy ARGUS itself just wrote can be present, and it is
    // preservation-only because it was captured during the incident.
    const evidence = record!.recovery_sources.find((entry) => entry.kind === "ARGUS_EVIDENCE_COPY")!;
    assert.equal(evidence.available, true);
    assert.equal(evidence.role, "EVIDENCE_PRESERVATION");
    for (const kind of ["ARGUS_KNOWN_GOOD_COPY", "CONFIGURED_BACKUP_ROOT"] as const) {
      assert.equal(record!.recovery_sources.find((entry) => entry.kind === kind)!.available, false, `${kind} must be unavailable`);
    }
  });

  it("does not repeat a recovery attempt for the same incident, file and source", async () => {
    const target = path.join(victimDir, "idempotent-recovery.docx");
    await fs.writeFile(target, ENCRYPTED_CONTENT);

    const backup = path.join(backupDir, "idempotent-recovery.docx");
    await fs.writeFile(backup, ORIGINAL_CONTENT);
    const old = new Date(Date.now() - 3_600_000);
    await fs.utimes(backup, old, old);

    eventHub.addMonitoringEvents([fileEvent("fs-17", "FILE_MODIFIED", target)]);

    const incident = await recoveryService.investigate(detection({ id: "det-idem-recovery" }));
    const first = incident!.affected_files[0];
    assert.equal(first.recovery_state, "VERIFIED");
    const attemptsAfterFirstRun = first.attempts.length;
    assert.equal(attemptsAfterFirstRun, 1);

    const source = first.recovery_sources.find((entry) => entry.source_id === first.selected_source_id)!;
    const record = recoveryStore.findRecord(incident!.incident_id, first.record_id)!;
    const again = await recoveryService.recoverRecord(record, source, 2);

    assert.equal(again!.recovery_state, "VERIFIED", "a re-run must not downgrade a verified recovery");
    assert.equal(
      again!.attempts.length,
      attemptsAfterFirstRun,
      "a source that already succeeded must not be attempted again for the same incident and file",
    );

    // Re-triggering the whole detection must not add attempts either.
    const retriggered = await recoveryService.investigate(detection({ id: "det-idem-recovery" }));
    assert.equal(retriggered!.incident_id, incident!.incident_id);
    assert.equal(retriggered!.affected_files[0].attempts.length, attemptsAfterFirstRun);
  });

  it("keeps a successful attempt recorded even after the failure history is trimmed", async () => {
    const target = path.join(victimDir, "durable-dedupe.docx");
    await fs.writeFile(target, ENCRYPTED_CONTENT);

    const backup = path.join(backupDir, "durable-dedupe.docx");
    await fs.writeFile(backup, ORIGINAL_CONTENT);
    const old = new Date(Date.now() - 3_600_000);
    await fs.utimes(backup, old, old);

    eventHub.addMonitoringEvents([fileEvent("fs-dedupe", "FILE_MODIFIED", target)]);

    const incident = await recoveryService.investigate(detection({ id: "det-durable-dedupe" }));
    const record = recoveryStore.findRecord(incident!.incident_id, incident!.affected_files[0].record_id)!;
    const succeeded = record.attempts.filter((attempt) => attempt.outcome === "SUCCEEDED");
    assert.equal(succeeded.length, 1);
    const successfulSourceId = succeeded[0].source_id;

    // Pad the history with more failures than the cap allows. A success must
    // survive the trim, otherwise this source becomes eligible again and the
    // duplicate-attempt guarantee silently lapses.
    const noisy = {
      ...record,
      attempts: [
        ...Array.from({ length: 6 }, (_unused, index) => ({
          ...succeeded[0],
          attempt_id: `noise-${index}`,
          source_id: `NOISY-SOURCE-${index}`,
          outcome: "FAILED" as const,
          verified: false,
          error: "synthetic noise standing in for many trimmed failures",
        })),
        ...record.attempts,
      ],
    };

    const source = record.recovery_sources.find((entry) => entry.source_id === successfulSourceId)!;
    const rerun = await recoveryService.recoverRecord(noisy, source, 2);

    assert.ok(
      rerun!.attempts.some((attempt) => attempt.source_id === successfulSourceId && attempt.outcome === "SUCCEEDED"),
      "the recorded success must survive trimming, so the source is never retried",
    );
    assert.equal(
      rerun!.attempts.filter((attempt) => attempt.source_id === successfulSourceId).length,
      1,
      "no duplicate attempt may be recorded for the same incident, file and source",
    );
    assert.equal(rerun!.recovery_state, "VERIFIED");
  });

  it("verifies an already-staged copy instead of rewriting it", async () => {
    const target = path.join(victimDir, "staged-reuse.docx");
    await fs.writeFile(target, ENCRYPTED_CONTENT);

    const backup = path.join(backupDir, "staged-reuse.docx");
    await fs.writeFile(backup, ORIGINAL_CONTENT);
    const old = new Date(Date.now() - 3_600_000);
    await fs.utimes(backup, old, old);

    eventHub.addMonitoringEvents([fileEvent("fs-18", "FILE_MODIFIED", target)]);

    const incident = await recoveryService.investigate(detection({ id: "det-staged-reuse" }));
    const first = incident!.affected_files[0];
    const stagedPath = first.attempts[0].recovered_path!;
    const stagedBefore = await fs.stat(stagedPath);

    // `recoverRecord` bounds only the failure history, so a success normally
    // blocks the source permanently. Clearing the history by hand is the way to
    // reach the copy step for a source that already produced a staged file, and
    // that path must verify what is on disk rather than overwrite it.
    const record = recoveryStore.findRecord(incident!.incident_id, first.record_id)!;
    const pruned = await recoveryService.recoverRecord({ ...record, attempts: [] }, first.recovery_sources.find((entry) => entry.source_id === first.selected_source_id)!, 2);

    assert.equal(pruned!.recovery_state, "VERIFIED");
    const latest = pruned!.attempts.at(-1)!;
    assert.equal(latest.outcome, "SUCCEEDED");
    assert.equal(latest.verified, true);
    assert.equal(latest.recovered_path, stagedPath);
    assert.ok(latest.checks.some((check) => check.name === "STAGED_COPY_REUSED" && check.passed));

    // The staged file was reused, not rewritten.
    const stagedAfter = await fs.stat(stagedPath);
    assert.equal(stagedAfter.size, stagedBefore.size);
    assert.equal(stagedAfter.mtimeMs, stagedBefore.mtimeMs);
  });

  it("refuses to call a byte-identical but corrupt source verified", async () => {
    const target = path.join(victimDir, "corrupt-source.docx");
    await fs.writeFile(target, ENCRYPTED_CONTENT);

    // The backup genuinely predates the incident and the staged copy will be
    // byte-identical to it, but the "document" never had a ZIP container.
    const backup = path.join(backupDir, "corrupt-source.docx");
    await fs.writeFile(backup, randomBytes(1024));
    const old = new Date(Date.now() - 3_600_000);
    await fs.utimes(backup, old, old);

    eventHub.addMonitoringEvents([fileEvent("fs-19", "FILE_MODIFIED", target)]);

    const incident = await recoveryService.investigate(detection({ id: "det-corrupt-source" }));
    const record = incident!.affected_files[0];
    const attempt = record!.attempts[0];

    assert.equal(attempt.outcome, "SUCCEEDED", "the copy itself did succeed");
    const signature = attempt.checks.find((check) => check.name === "SIGNATURE_OK");
    assert.ok(signature, "a signature check must be recorded for a .docx");
    assert.equal(signature.passed, false, signature.detail);
    assert.equal(signature.required, true);
    assert.match(signature.detail, /ZIP container/);

    // Hash equality alone must not be enough to declare the recovery verified.
    const byteIdentical = attempt.checks.find((check) => check.name === "BYTE_IDENTICAL");
    assert.equal(byteIdentical!.passed, true, "the copy really is byte-identical to the source");
    assert.equal(attempt.verified, false, "verification must fail while the signature check fails");
    assert.equal(record!.recovery_state, "RECOVERED", "the copy is staged but not verified");
  });

  it("preserves an as-found evidence copy of the damaged file", async () => {
    const target = path.join(victimDir, "evidence.docx");
    await fs.writeFile(target, ENCRYPTED_CONTENT);
    eventHub.addMonitoringEvents([fileEvent("fs-11", "FILE_MODIFIED", target)]);

    const incident = await recoveryService.investigate(detection({ id: "det-evidence" }));
    const record = incident!.affected_files[0];
    const preserved = record!.notes.find((note) => note.includes("as-found copy preserved"));
    assert.ok(preserved, `expected an evidence copy note, got: ${record!.notes.join(" | ")}`);

    const evidenceSource = record!.recovery_sources.find((entry) => entry.kind === "ARGUS_EVIDENCE_COPY");
    assert.ok(evidenceSource);
    assert.equal(evidenceSource!.available, true);
    // The as-found copy is preservation-only: it was taken during the incident.
    assert.equal(evidenceSource!.restorable, false);
    assert.equal(evidenceSource!.role, "EVIDENCE_PRESERVATION");
  });
});

describe("automatic triggering", () => {
  it("reconstructs impact without anyone calling investigate()", async () => {
    const target = path.join(victimDir, "auto.docx");
    await fs.writeFile(target, ENCRYPTED_CONTENT);
    eventHub.addMonitoringEvents([fileEvent("fs-12", "FILE_MODIFIED", target)]);

    eventHub.addDetection(detection({ id: "det-auto" }));

    await waitFor(
      () => recoveryStore.getIncidentByDetection("det-auto")?.phase === "COMPLETE",
      20_000,
      "the automatic investigation to complete",
    );

    const incident = recoveryStore.getIncidentByDetection("det-auto");
    assert.equal(incident?.affected_files.length, 1);
    assert.equal(incident?.affected_files[0].path, target);
  });

  it("is idempotent for the same detection", async () => {
    const target = path.join(victimDir, "idempotent.docx");
    await fs.writeFile(target, ENCRYPTED_CONTENT);
    eventHub.addMonitoringEvents([fileEvent("fs-13", "FILE_MODIFIED", target)]);

    const first = await recoveryService.investigate(detection({ id: "det-idem" }));
    const second = await recoveryService.investigate(detection({ id: "det-idem" }));
    assert.equal(first!.incident_id, second!.incident_id);
    assert.equal(recoveryStore.listIncidents().length, 1);
    assert.equal(second!.affected_files[0].attempts.length, first!.affected_files[0].attempts.length);
  });

  it("does nothing when recovery is disabled", async () => {
    const target = path.join(victimDir, "disabled.docx");
    await fs.writeFile(target, ENCRYPTED_CONTENT);
    eventHub.addMonitoringEvents([fileEvent("fs-14", "FILE_MODIFIED", target)]);

    recoveryService.setEnabled(false);
    try {
      assert.equal(await recoveryService.investigate(detection({ id: "det-off" })), null);
      eventHub.addDetection(detection({ id: "det-off2" }));
      await new Promise((resolve) => setTimeout(resolve, 150));
      assert.equal(recoveryStore.getIncidentByDetection("det-off2"), null);
    } finally {
      recoveryService.setEnabled(true);
    }
  });
});

describe("summary aggregation", () => {
  it("counts only real records and separates the encrypted subset", async () => {
    const recoverTarget = path.join(victimDir, "sum-a.docx");
    await fs.writeFile(recoverTarget, randomBytes(2048));
    const backup = path.join(backupDir, "sum-a.docx");
    await fs.writeFile(backup, ORIGINAL_CONTENT);
    const old = new Date(Date.now() - 7_200_000);
    await fs.utimes(backup, old, old);

    const intactTarget = path.join(victimDir, "sum-b.docx");
    await fs.writeFile(intactTarget, Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), randomBytes(512)]));

    eventHub.addMonitoringEvents([
      fileEvent("fs-15", "FILE_MODIFIED", recoverTarget),
      fileEvent("fs-16", "FILE_MODIFIED", intactTarget),
    ]);

    await recoveryService.investigate(detection({ id: "det-sum" }));
    const summary = recoveryStore.buildSummary();

    assert.equal(summary.affectedFiles, 2);
    assert.equal(summary.encryptedSuspectedFiles, 1);
    assert.equal(summary.modifiedFiles, 1, "the encrypted file is counted only under the encryption class");
    assert.equal(summary.verified, 1);
    assert.equal(summary.inferredAttribution, 2);
    assert.equal(summary.evidenceCompleteness.hashed, 2);

    // The six damage counters are mutually exclusive and partition the records.
    assert.equal(
      summary.modifiedFiles +
        summary.deletedFiles +
        summary.renamedFiles +
        summary.createdFiles +
        summary.encryptedSuspectedFiles +
        summary.unknownDamageFiles,
      summary.affectedFiles,
    );
    assert.match(summary.damageClassificationTotals, /mutually exclusive/);
  });
});

describe("incident window", () => {
  it("brackets the detection time rather than using unbounded time", async () => {
    const incident: ImpactIncident | null = await recoveryService.investigate(detection({ id: "det-window" }));
    assert.ok(incident);
    const start = Date.parse(incident!.window.start);
    const end = Date.parse(incident!.window.end);
    assert.ok(start < end);
    assert.equal(incident!.window.pre_ms, 5 * 60 * 1000);
    assert.equal(incident!.window.post_ms, 10 * 60 * 1000);
    assert.equal(incident!.window.widened, false);
    assert.deepEqual(incident!.stages_reached, [
      "THREAT_DETECTED",
      "IMPACT_DISCOVERY",
      "RECOVERY_SOURCE_SEARCH",
      "SAFE_RECOVERY",
      "VERIFICATION",
    ]);
  });
});
