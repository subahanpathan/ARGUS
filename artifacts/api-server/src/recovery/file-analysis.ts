/**
 * Read-only file analysis used for impact reconstruction and verification.
 *
 * Everything in this module is *read* only. Nothing here opens a file for
 * writing, truncates, renames, or deletes, and the reads are bounded so that a
 * hostile 40 GB file cannot stall an investigation.
 *
 * The only inference this module performs is `classifyDamage`, and it will only
 * escalate to `ENCRYPTED_OR_CORRUPTED_SUSPECTED` when one of the explicitly
 * enumerated, independently checkable signals is present.
 */

import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

import { describeError, statReadable } from "./paths";
import type { DamageClassification, DamageSignal, FileMetadataSnapshot, FileOperation } from "./types";

/** Above this size a full hash is skipped rather than burning investigation time. */
export const DEFAULT_MAX_HASH_BYTES = 256 * 1024 * 1024;

/** Bytes sampled for entropy measurement. */
const ENTROPY_SAMPLE_BYTES = 64 * 1024;

/** Minimum sampled bytes before entropy is considered meaningful. */
const ENTROPY_MIN_SAMPLE = 4096;

/** Shannon entropy above which *unrecognized* content is worth flagging. */
const ENTROPY_SUSPICION_THRESHOLD = 7.9;

/* -------------------------------------------------------------------------- */
/* Hashing                                                                    */
/* -------------------------------------------------------------------------- */

export type HashResult = {
  sha256: string | null;
  bytes_read: number;
  truncated: boolean;
  /** Populated when `sha256` is null, so a missing hash is never ambiguous. */
  skipped_reason: string | null;
  error: string | null;
};

/**
 * SHA-256 of a file, read in bounded chunks.
 *
 * A file larger than `maxBytes` is not hashed at all rather than half-hashed:
 * a partial digest would be misleading if it ever reached verification.
 */
export async function sha256File(target: string, maxBytes = DEFAULT_MAX_HASH_BYTES): Promise<HashResult> {
  let handle: Awaited<ReturnType<typeof fs.open>> | null = null;
  try {
    const stats = await fs.stat(target);
    if (!stats.isFile()) {
      return { sha256: null, bytes_read: 0, truncated: false, skipped_reason: "not a regular file", error: null };
    }
    if (stats.size > maxBytes) {
      return {
        sha256: null,
        bytes_read: 0,
        truncated: true,
        skipped_reason: `file is ${stats.size} bytes, above the ${maxBytes} byte analysis limit`,
        error: null,
      };
    }

    handle = await fs.open(target, "r");
    const hash = createHash("sha256");
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    let bytesRead = 0;
    for (;;) {
      const { bytesRead: read } = await handle.read(buffer, 0, buffer.length, bytesRead);
      if (read <= 0) break;
      hash.update(buffer.subarray(0, read));
      bytesRead += read;
    }
    return { sha256: hash.digest("hex"), bytes_read: bytesRead, truncated: false, skipped_reason: null, error: null };
  } catch (error) {
    return { sha256: null, bytes_read: 0, truncated: false, skipped_reason: null, error: describeError(error) };
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

/** Best-effort read of the first `maxBytes`. Returns null on any failure. */
export async function readPrefix(target: string, maxBytes: number): Promise<Buffer | null> {
  let handle: Awaited<ReturnType<typeof fs.open>> | null = null;
  try {
    const stats = await fs.stat(target);
    if (!stats.isFile() || stats.size === 0) return Buffer.alloc(0);
    handle = await fs.open(target, "r");
    const length = Math.min(maxBytes, stats.size);
    const buffer = Buffer.allocUnsafe(length);
    const { bytesRead } = await handle.read(buffer, 0, length, 0);
    return buffer.subarray(0, bytesRead);
  } catch {
    return null;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

/* -------------------------------------------------------------------------- */
/* Content signals                                                            */
/* -------------------------------------------------------------------------- */

/** Shannon entropy in bits per byte, 0..8. */
export function shannonEntropy(buffer: Buffer): number {
  if (buffer.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (const byte of buffer) counts[byte] += 1;
  let entropy = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const probability = count / buffer.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

type SignatureMatcher = {
  name: string;
  extensions: readonly string[];
  test: (buffer: Buffer) => boolean;
};

const startsWith = (...bytes: number[]) => (buffer: Buffer) =>
  buffer.length >= bytes.length && bytes.every((byte, index) => buffer[index] === byte);

const asciiStartsWith = (text: string) => (buffer: Buffer) =>
  buffer.length >= text.length && buffer.subarray(0, text.length).toString("latin1") === text;

const riffWith = (form: string) => (buffer: Buffer) =>
  buffer.length >= 12 &&
  buffer.subarray(0, 4).toString("latin1") === "RIFF" &&
  buffer.subarray(8, 12).toString("latin1") === form;

/**
 * Magic-byte signatures ARGUS can actually check.
 *
 * This is deliberately a modest, verifiable set covering common document, image,
 * archive, media and executable containers. An extension absent from this table
 * simply yields "unknown signature" and never a mismatch finding.
 */
const SIGNATURES: readonly SignatureMatcher[] = [
  {
    name: "ZIP container",
    extensions: [
      ".zip", ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".jar", ".apk", ".odt", ".ods", ".odp",
      ".epub", ".whl", ".nupkg", ".vsix", ".aar", ".ipa", ".crx", ".cbz", ".xpi", ".apkm",
    ],
    test: startsWith(0x50, 0x4b),
  },
  { name: "OLE2 compound document", extensions: [".doc", ".xls", ".ppt", ".msi", ".msg", ".xlsb"], test: startsWith(0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1) },
  { name: "Portable executable (PE/MZ)", extensions: [".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".efi"], test: startsWith(0x4d, 0x5a) },
  { name: "PDF document", extensions: [".pdf"], test: asciiStartsWith("%PDF-") },
  { name: "PNG image", extensions: [".png", ".apng"], test: startsWith(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a) },
  { name: "JPEG image", extensions: [".jpg", ".jpeg", ".jpe"], test: startsWith(0xff, 0xd8, 0xff) },
  { name: "GIF image", extensions: [".gif"], test: (buffer) => buffer.length >= 6 && /^(GIF8[79]a?)$/.test(buffer.subarray(0, 6).toString("latin1")) },
  { name: "BMP image", extensions: [".bmp", ".dib"], test: startsWith(0x42, 0x4d) },
  { name: "TIFF image", extensions: [".tif", ".tiff"], test: (buffer) => buffer.length >= 4 && ((buffer[0] === 0x49 && buffer[1] === 0x49) || (buffer[0] === 0x4d && buffer[1] === 0x4d)) },
  { name: "RIFF/WAVE audio", extensions: [".wav", ".wave"], test: riffWith("WAVE") },
  { name: "RIFF/AVI video", extensions: [".avi"], test: riffWith("AVI ") },
  { name: "ISO base media (MP4/MOV/HEIF)", extensions: [".mp4", ".m4a", ".mov", ".heic", ".heif", ".m4v"], test: (buffer) => buffer.length >= 12 && buffer.subarray(4, 8).toString("latin1") === "ftyp" },
  { name: "MPEG audio", extensions: [".mp3"], test: (buffer) => asciiStartsWith("ID3")(buffer) || (buffer.length >= 2 && buffer[0] === 0xff && (buffer[1] & 0xe0) === 0xe0) },
  { name: "Ogg container", extensions: [".ogg", ".oga", ".ogv"], test: asciiStartsWith("OggS") },
  { name: "FLAC audio", extensions: [".flac"], test: asciiStartsWith("fLaC") },
  { name: "7-Zip archive", extensions: [".7z"], test: startsWith(0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c) },
  { name: "RAR archive", extensions: [".rar"], test: (buffer) => asciiStartsWith("Rar!")(buffer) },
  { name: "Gzip stream", extensions: [".gz", ".tgz", ".svgz"], test: startsWith(0x1f, 0x8b) },
  { name: "Bzip2 stream", extensions: [".bz2", ".tbz2"], test: asciiStartsWith("BZh") },
  { name: "XZ stream", extensions: [".xz", ".txz"], test: startsWith(0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00) },
  { name: "zstd stream", extensions: [".zst"], test: startsWith(0x28, 0xb5, 0x2f, 0xfd) },
  { name: "tar archive", extensions: [".tar"], test: (buffer) => buffer.length >= 262 && buffer.subarray(257, 262).toString("latin1") === "ustar" },
  { name: "SQLite database", extensions: [".sqlite", ".sqlite3", ".db"], test: asciiStartsWith("SQLite format 3\u0000") },
  { name: "RTF document", extensions: [".rtf"], test: (buffer) => buffer.length >= 5 && buffer.subarray(0, 5).toString("latin1") === "{\\rtf" },
  { name: "Photoshop image", extensions: [".psd"], test: asciiStartsWith("8BPS") },
  { name: "PCAP capture", extensions: [".pcap", ".pcapng"], test: (buffer) => startsWith(0xd4, 0xc3, 0xb2, 0xa1)(buffer) || startsWith(0xa1, 0xb2, 0xc3, 0xd4)(buffer) || startsWith(0x0a, 0x0d, 0x0d, 0x0a)(buffer) },
];

/** Signature names that are legitimate for a given file extension. */
export function expectedSignaturesFor(filePath: string): string[] {
  const extension = path.extname(filePath).toLowerCase();
  return SIGNATURES.filter((matcher) => matcher.extensions.includes(extension)).map((matcher) => matcher.name);
}

/** Name of the container actually detected from magic bytes, or null. */
export function detectSignature(buffer: Buffer): string | null {
  return SIGNATURES.find((matcher) => matcher.test(buffer))?.name ?? null;
}

/* -------------------------------------------------------------------------- */
/* Damage classification                                                      */
/* -------------------------------------------------------------------------- */

/** Signals that are independently sufficient to suspect encryption/corruption. */
const ESCALATING_SIGNALS = new Set([
  "TELEMETRY_SIZE_DROPPED_TO_ZERO",
  "SIGNATURE_MISMATCH",
  "HIGH_ENTROPY_UNRECOGNIZED_CONTENT",
  "PROVIDER_RANSOMWARE_REPORT",
]);

/**
 * Terms that make a security provider's own finding an encryption claim.
 *
 * Kept narrow and explicit on purpose: a provider saying "suspicious" must not
 * be promoted to "ransomware".
 *
 * Note the deliberate absence of a trailing word boundary — alternatives such as
 * `file encrypt` must still match inside "files were encrypted", which a closing
 * `\b` would prevent.
 */
const RANSOMWARE_INDICATORS =
  /(?:\bransom ?ware|\bransom ?note|\bcrypto ?locker|\bfile encrypt|\bfiles (?:were|have been) encrypt|\block ?bit|\bconti|\bblack ?cat|\balphv|\bclop|\bryuk|\brevil|\bblack ?byte|\bwanna ?cry|\bnot ?petya|\bdark ?side|\broyal ?ransom|\bplay ?ransom|\bakira|\bmedusa ?lock|\brhysida|\bblack ?basta|\bqilin|\bstorm-?\d+)/i;

export function mentionsRansomware(text: string): boolean {
  return RANSOMWARE_INDICATORS.test(text);
}

export type ClassifyInput = {
  operation: FileOperation;
  /** Whether the path exists on disk right now (null = could not determine). */
  exists: boolean | null;
  signals: readonly DamageSignal[];
};

/**
 * Map observed operation + measured signals to a damage classification.
 *
 * Escalation to `ENCRYPTED_OR_CORRUPTED_SUSPECTED` requires an escalating
 * signal. A `MODIFIED` event alone stays `MODIFIED`.
 */
export function classifyDamage({ operation, exists, signals }: ClassifyInput): DamageClassification {
  if (signals.some((signal) => ESCALATING_SIGNALS.has(signal.kind))) {
    return "ENCRYPTED_OR_CORRUPTED_SUSPECTED";
  }
  if (exists === false && operation !== "CREATED") return "DELETED";
  switch (operation) {
    case "DELETED":
      return "DELETED";
    case "RENAMED":
      return "RENAMED";
    case "MODIFIED":
      return "MODIFIED";
    case "CREATED":
      return "CREATED";
    case "DIRECTORY_CHANGED":
      return exists === true ? "MODIFIED" : "UNKNOWN";
    case "UNKNOWN":
    default:
      return "UNKNOWN";
  }
}

/* -------------------------------------------------------------------------- */
/* Whole-file analysis                                                        */
/* -------------------------------------------------------------------------- */

export type FileAnalysis = {
  metadata: FileMetadataSnapshot;
  signals: DamageSignal[];
  notes: string[];
  /** Shannon entropy of the sampled prefix, or null when it could not be read. */
  entropy: number | null;
  detected_signature: string | null;
  expected_signature: string[];
};

export type AnalyzeOptions = {
  /** Metadata from earlier in the incident, used for truncation detection. */
  previous: FileMetadataSnapshot | null;
  maxHashBytes?: number;
  /**
   * Verification details from security providers that reported *encryption or
   * ransomware* against this exact path. Supplied by the caller because only it
   * has access to provider telemetry.
   */
  provider_encryption_reports?: string[];
};

/**
 * Measure what is actually true about a file on disk right now.
 *
 * Never throws: an unreadable or missing path becomes metadata plus a note.
 */
export async function analyzeAffectedFile(target: string, options: AnalyzeOptions): Promise<FileAnalysis> {
  const { previous, maxHashBytes = DEFAULT_MAX_HASH_BYTES } = options;
  const notes: string[] = [];
  const signals: DamageSignal[] = [];

  for (const report of options.provider_encryption_reports ?? []) {
    signals.push({ kind: "PROVIDER_RANSOMWARE_REPORT", detail: report, source: "security_provider" });
  }

  const probe = await statReadable(target);
  if (!probe.ok) {
    const missing = probe.reason?.startsWith("ENOENT") ?? false;
    notes.push(missing ? "path does not exist on this host (deleted or moved)" : `path could not be read: ${probe.reason}`);
    if (!missing) {
      signals.push({ kind: "READ_FAILED", detail: `stat/access failed: ${probe.reason}`, source: "safe_file_analysis" });
    }
    return {
      metadata: {
        exists: missing ? false : null,
        size_bytes: missing ? 0 : null,
        modified_at: null,
        created_at: null,
        sha256: null,
        sha256_computed_at: null,
        sha256_skipped_reason: probe.reason,
      },
      signals,
      notes,
      entropy: null,
      detected_signature: null,
      expected_signature: [],
    };
  }

  const size = probe.size ?? 0;
  const expected = expectedSignaturesFor(target);

  // Truncation: a file that previously had content and is now empty. This is a
  // real measured comparison against telemetry ARGUS already holds.
  if (previous && previous.size_bytes !== null && previous.size_bytes > 0 && size === 0) {
    signals.push({
      kind: "TELEMETRY_SIZE_DROPPED_TO_ZERO",
      detail: `telemetry recorded ${previous.size_bytes} bytes at ${previous.modified_at ?? "an earlier observation"}, current size is 0`,
      source: previous.sha256 ? "file_scan" : "filesystem_activity",
    });
  }

  const prefix = await readPrefix(target, Math.max(ENTROPY_SAMPLE_BYTES, 512));
  const detected = prefix ? detectSignature(prefix) : null;
  const entropy = prefix && prefix.length > 0 ? shannonEntropy(prefix) : null;

  if (prefix === null && size > 0) {
    notes.push("could not read a content prefix; signature and entropy checks were skipped");
    signals.push({ kind: "READ_FAILED", detail: "content prefix read failed", source: "safe_file_analysis" });
  }

  if (size > 0 && expected.length > 0 && detected === null && prefix !== null) {
    signals.push({
      kind: "SIGNATURE_MISMATCH",
      detail: `extension ${path.extname(target) || "(none)"} expects ${expected.join(" or ")}, but no such magic bytes are present`,
      source: "safe_file_analysis",
    });
  }

  if (
    size > 0 &&
    detected === null &&
    prefix !== null &&
    prefix.length >= ENTROPY_MIN_SAMPLE &&
    entropy !== null &&
    entropy >= ENTROPY_SUSPICION_THRESHOLD
  ) {
    signals.push({
      kind: "HIGH_ENTROPY_UNRECOGNIZED_CONTENT",
      detail: `shannon entropy ${entropy.toFixed(2)} bits/byte over ${prefix.length} sampled bytes with no recognized container signature`,
      source: "safe_file_analysis",
    });
  }

  const hash = await sha256File(target, maxHashBytes);
  if (hash.sha256 === null) {
    notes.push(hash.skipped_reason ?? `sha256 unavailable: ${hash.error}`);
  }

  return {
    metadata: {
      exists: true,
      size_bytes: size,
      modified_at: probe.modifiedAt,
      created_at: null,
      sha256: hash.sha256,
      sha256_computed_at: new Date().toISOString(),
      sha256_skipped_reason: hash.skipped_reason ?? hash.error,
    },
    signals,
    notes,
    entropy,
    detected_signature: detected,
    expected_signature: expected,
  };
}
