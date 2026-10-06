import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import {
  analyzeAffectedFile,
  classifyDamage,
  detectSignature,
  expectedSignaturesFor,
  mentionsRansomware,
  readPrefix,
  sha256File,
  shannonEntropy,
} from "../file-analysis";
import type { DamageSignal } from "../types";

let dir: string;

before(async () => {
  dir = await fs.mkdtemp(path.join(os.tmpdir(), "argus-analysis-"));
});

after(async () => {
  await fs.rm(dir, { recursive: true, force: true });
});

async function write(name: string, data: Buffer | string): Promise<string> {
  const target = path.join(dir, name);
  await fs.writeFile(target, data);
  return target;
}

const signal = (kind: DamageSignal["kind"], detail = "test signal"): DamageSignal => ({
  kind,
  detail,
  source: "test",
});

describe("shannonEntropy", () => {
  it("is zero for empty input and minimal for repetition", () => {
    assert.equal(shannonEntropy(Buffer.alloc(0)), 0);
    assert.ok(shannonEntropy(Buffer.alloc(1024, 0x41)) < 0.01);
  });

  it("approaches 8 bits/byte for random data", () => {
    assert.ok(shannonEntropy(randomBytes(8192)) > 7.9);
  });
});

describe("detectSignature", () => {
  it("recognises real container magic bytes", () => {
    assert.equal(detectSignature(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])), "PNG image");
    assert.equal(detectSignature(Buffer.from("%PDF-1.7\n...")), "PDF document");
    assert.equal(detectSignature(Buffer.from([0x4d, 0x5a, 0x90, 0x00])), "Portable executable (PE/MZ)");
    assert.equal(detectSignature(Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x14])), "ZIP container");
  });

  it("returns null for unrecognized bytes", () => {
    assert.equal(detectSignature(randomBytes(64)), null);
  });
});

describe("expectedSignaturesFor", () => {
  it("maps extensions to the containers they imply", () => {
    assert.ok(expectedSignaturesFor("report.docx").includes("ZIP container"));
    assert.ok(expectedSignaturesFor("photo.PNG").includes("PNG image"));
    assert.ok(expectedSignaturesFor("setup.exe").includes("Portable executable (PE/MZ)"));
  });

  it("returns an empty list for an unknown extension rather than guessing", () => {
    assert.deepEqual(expectedSignaturesFor("data.weirdext"), []);
  });
});

describe("mentionsRansomware", () => {
  it("accepts explicit encryption claims", () => {
    assert.equal(mentionsRansomware("Ransomware detected"), true);
    assert.equal(mentionsRansomware("files were encrypted"), true);
    assert.equal(mentionsRansomware("LockBit payload"), true);
  });

  it("does not promote ordinary findings", () => {
    assert.equal(mentionsRansomware("Suspicious PowerShell encoded command"), false);
    assert.equal(mentionsRansomware("Startup folder persistence"), false);
    assert.equal(mentionsRansomware(""), false);
  });
});

describe("classifyDamage", () => {
  it("does NOT escalate a plain modification", () => {
    assert.equal(
      classifyDamage({ operation: "MODIFIED", exists: true, signals: [] }),
      "MODIFIED",
    );
  });

  it("escalates only when an explicit signal is present", () => {
    assert.equal(
      classifyDamage({ operation: "MODIFIED", exists: true, signals: [signal("SIGNATURE_MISMATCH")] }),
      "ENCRYPTED_OR_CORRUPTED_SUSPECTED",
    );
    assert.equal(
      classifyDamage({ operation: "MODIFIED", exists: true, signals: [signal("HIGH_ENTROPY_UNRECOGNIZED_CONTENT")] }),
      "ENCRYPTED_OR_CORRUPTED_SUSPECTED",
    );
    assert.equal(
      classifyDamage({ operation: "MODIFIED", exists: true, signals: [signal("PROVIDER_RANSOMWARE_REPORT")] }),
      "ENCRYPTED_OR_CORRUPTED_SUSPECTED",
    );
  });

  it("does not escalate on a non-escalating signal", () => {
    assert.equal(
      classifyDamage({ operation: "MODIFIED", exists: true, signals: [signal("READ_FAILED")] }),
      "MODIFIED",
    );
  });

  it("maps operations to damage classes", () => {
    assert.equal(classifyDamage({ operation: "DELETED", exists: false, signals: [] }), "DELETED");
    assert.equal(classifyDamage({ operation: "RENAMED", exists: true, signals: [] }), "RENAMED");
    assert.equal(classifyDamage({ operation: "CREATED", exists: true, signals: [] }), "CREATED");
    assert.equal(classifyDamage({ operation: "UNKNOWN", exists: true, signals: [] }), "UNKNOWN");
  });

  it("reports a vanished file as DELETED even when the event said MODIFIED", () => {
    assert.equal(classifyDamage({ operation: "MODIFIED", exists: false, signals: [] }), "DELETED");
  });
});

describe("sha256File", () => {
  it("matches the digest of the same bytes", async () => {
    const data = Buffer.from("the quick brown fox jumps over the lazy dog");
    const target = await write("hash-a.txt", data);
    const result = await sha256File(target);
    assert.equal(result.bytes_read, data.length);
    // Cross-checked against an independent digest rather than a magic constant.
    assert.equal(result.sha256, createHash("sha256").update(data).digest("hex"));
    assert.equal(result.error, null);
  });

  it("refuses to hash a file above the limit instead of returning a partial digest", async () => {
    const target = await write("hash-large.bin", randomBytes(4096));
    const result = await sha256File(target, 1024);
    assert.equal(result.sha256, null);
    assert.equal(result.truncated, true);
    assert.match(String(result.skipped_reason), /above the 1024 byte analysis limit/);
  });

  it("reports an unreadable path instead of throwing", async () => {
    const result = await sha256File(path.join(dir, "does-not-exist"));
    assert.equal(result.sha256, null);
    assert.match(String(result.error), /ENOENT/);
  });
});

describe("analyzeAffectedFile", () => {
  it("measures an intact file and produces no corruption signal", async () => {
    const target = await write("intact.png", Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4]));
    const analysis = await analyzeAffectedFile(target, { previous: null });
    assert.equal(analysis.metadata.exists, true);
    assert.equal(analysis.metadata.size_bytes, 12);
    assert.match(String(analysis.metadata.sha256), /^[0-9a-f]{64}$/);
    assert.equal(analysis.detected_signature, "PNG image");
    assert.deepEqual(
      analysis.signals.filter((entry) => entry.kind !== "READ_FAILED"),
      [],
    );
  });

  it("raises SIGNATURE_MISMATCH when a container has the wrong magic bytes", async () => {
    const target = await write("disguised.docx", Buffer.from("this is plain text pretending to be a docx"));
    const analysis = await analyzeAffectedFile(target, { previous: null });
    const mismatch = analysis.signals.find((entry) => entry.kind === "SIGNATURE_MISMATCH");
    assert.ok(mismatch, "expected a SIGNATURE_MISMATCH signal");
    assert.match(mismatch!.detail, /ZIP container/);
    assert.equal(
      classifyDamage({ operation: "MODIFIED", exists: true, signals: analysis.signals }),
      "ENCRYPTED_OR_CORRUPTED_SUSPECTED",
    );
  });

  it("raises HIGH_ENTROPY_UNRECOGNIZED_CONTENT for random bytes in an unknown format", async () => {
    const target = await write("blob.unknown", randomBytes(16 * 1024));
    const analysis = await analyzeAffectedFile(target, { previous: null });
    const entropySignal = analysis.signals.find((entry) => entry.kind === "HIGH_ENTROPY_UNRECOGNIZED_CONTENT");
    assert.ok(entropySignal, "expected an entropy signal");
    assert.ok((analysis.entropy ?? 0) > 7.9);
  });

  it("does not raise an entropy finding for a recognised high-entropy container", async () => {
    // A real PNG header followed by incompressible payload: high entropy, but a
    // known container, so it must not be flagged as suspected encryption.
    const target = await write("noise.png", Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), randomBytes(16 * 1024)]));
    const analysis = await analyzeAffectedFile(target, { previous: null });
    assert.equal(analysis.detected_signature, "PNG image");
    assert.equal(analysis.signals.some((entry) => entry.kind === "HIGH_ENTROPY_UNRECOGNIZED_CONTENT"), false);
  });

  it("detects truncation against an earlier observation", async () => {
    const target = await write("truncated.bin", Buffer.alloc(0));
    const analysis = await analyzeAffectedFile(target, {
      previous: {
        exists: true,
        size_bytes: 4096,
        modified_at: "2026-01-01T00:00:00.000Z",
        created_at: null,
        sha256: "a".repeat(64),
        sha256_computed_at: null,
        sha256_skipped_reason: null,
      },
    });
    const truncation = analysis.signals.find((entry) => entry.kind === "TELEMETRY_SIZE_DROPPED_TO_ZERO");
    assert.ok(truncation, "expected a truncation signal");
    assert.match(truncation!.detail, /recorded 4096 bytes/);
  });

  it("records a provider encryption claim as a signal with its source", async () => {
    const target = await write("claimed.docx", Buffer.from("whatever"));
    const analysis = await analyzeAffectedFile(target, {
      previous: null,
      provider_encryption_reports: ["CrowdStrike: Ransomware detected — files were encrypted"],
    });
    const provider = analysis.signals.find((entry) => entry.kind === "PROVIDER_RANSOMWARE_REPORT");
    assert.ok(provider);
    assert.equal(provider!.source, "security_provider");
  });

  it("reports a missing path as absent without inventing metadata", async () => {
    const analysis = await analyzeAffectedFile(path.join(dir, "gone.docx"), { previous: null });
    assert.equal(analysis.metadata.exists, false);
    assert.equal(analysis.metadata.sha256, null);
    assert.equal(analysis.metadata.modified_at, null);
    assert.ok(analysis.notes.some((note) => note.includes("does not exist")));
  });

  it("refuses to classify a directory as a regular file", async () => {
    const analysis = await analyzeAffectedFile(dir, { previous: null });
    assert.equal(analysis.metadata.exists, null);
    assert.ok(analysis.notes.some((note) => note.includes("could not be read")));
  });
});

describe("readPrefix", () => {
  it("returns at most the requested number of bytes", async () => {
    const target = await write("prefix.bin", Buffer.from("0123456789"));
    const prefix = await readPrefix(target, 4);
    assert.equal(prefix?.length, 4);
    assert.equal(prefix?.toString(), "0123");
  });

  it("returns null for a missing file", async () => {
    assert.equal(await readPrefix(path.join(dir, "nope"), 4), null);
  });
});
