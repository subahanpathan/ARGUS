/**
 * Isolated recovery workspace: layout, validation and containment.
 *
 * Two invariants are enforced here rather than trusted to callers:
 *
 *  1. **Containment** — every path ARGUS writes must resolve inside the
 *     configured recovery root. A traversal attempt throws instead of escaping.
 *  2. **Isolation** — the recovery root is never a legitimate recovery target
 *     and never a source. It is also excluded from impact discovery, so copying
 *     evidence can never feed back into the incident that produced it.
 *
 * Layout (all relative to the recovery root):
 *
 *   evidence/<incidentId>/<recordId>/<name>   chain-of-custody copy, taken as found
 *   staging/<incidentId>/<recordId>/<name>    recovered copy, never overwrites
 *   known-good/<recordId>/<name>              pre-incident baseline, if one exists
 */

import { constants } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { logger } from "../lib/logger";

/** Environment override for the whole workspace. */
const ROOT_ENV = "ARGUS_RECOVERY_ROOT";

/**
 * Default workspace location, kept beside the API server and named so it is
 * obviously ARGUS-owned. Ignored by git via `.gitignore`.
 */
const DEFAULT_ROOT_SEGMENTS = ["var", "argus-recovery"];

let cachedRoot: string | null = null;

/**
 * Absolute, normalized recovery root. Created lazily and only when something
 * actually needs to be written.
 */
export function getRecoveryRoot(): string {
  if (cachedRoot) return cachedRoot;
  const configured = process.env[ROOT_ENV]?.trim();
  const base = configured && configured.length > 0 ? configured : path.resolve(process.cwd(), ...DEFAULT_ROOT_SEGMENTS);
  cachedRoot = path.resolve(base);
  return cachedRoot;
}

/** Test seam: force a specific root, or clear the cache with `null`. */
export function setRecoveryRoot(value: string | null): void {
  cachedRoot = value ? path.resolve(value) : null;
}

/** Create the recovery root if needed. Returns null when it cannot be created. */
export async function ensureRecoveryRoot(): Promise<string | null> {
  const root = getRecoveryRoot();
  try {
    await fs.mkdir(root, { recursive: true });
    return root;
  } catch (error) {
    logger.error({ scope: "recovery", root, err: describeError(error) }, "could not create recovery root");
    return null;
  }
}

/**
 * Reduce an arbitrary string to a single safe path segment.
 *
 * Separators, drive colons, traversal dots and control characters are removed,
 * so a hostile file name cannot escape its directory. Non-ASCII is preserved so
 * real user file names stay recognizable.
 */
export function safeSegment(value: string, fallback = "unnamed"): string {
  const cleaned = value
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .replace(/[\\/]+/g, "_")
    .replace(/[:*?"<>|]/g, "_")
    .replace(/^\.+/, "_")
    .replace(/[. ]+$/g, "")
    .trim();
  if (!cleaned || cleaned === "." || cleaned === "..") return fallback;
  return cleaned.length > 120 ? cleaned.slice(0, 120) : cleaned;
}

/** Normalize an id (incident/record) into a safe single segment. */
function safeId(value: string): string {
  return safeSegment(value.replace(/[^A-Za-z0-9._-]/g, "-"), "unknown");
}

/**
 * Resolve `candidate` and prove it stays inside `root`.
 *
 * Throws when the resolved path escapes, which is the traversal guard for every
 * write the recovery engine performs.
 */
export function resolveInside(root: string, candidate: string): string {
  const resolvedRoot = path.resolve(root);
  const resolved = path.resolve(resolvedRoot, candidate);
  const relative = path.relative(resolvedRoot, resolved);
  // `relative === ""` means the candidate *is* the root, which is a valid base
  // for a join. Anything that walks upward or re-roots is a traversal attempt.
  if (relative !== "" && (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative))) {
    throw new Error(`path escapes the recovery root: ${candidate}`);
  }
  return resolved;
}

export type WorkspaceArea = "evidence" | "staging" | "known-good";

/** Absolute directory for one affected file's workspace area. */
export function areaDir(area: WorkspaceArea, incidentId: string, recordId: string, name: string): string {
  return resolveInside(
    getRecoveryRoot(),
    path.join(area, safeId(incidentId), safeId(recordId), safeSegment(name)),
  );
}

/** Absolute target path for a recovered copy inside staging. */
export function stagingPathFor(incidentId: string, recordId: string, name: string): string {
  return areaDir("staging", incidentId, recordId, name);
}

/** Absolute target path for a preserved evidence copy. */
export function evidencePathFor(incidentId: string, recordId: string, name: string): string {
  return areaDir("evidence", incidentId, recordId, name);
}

/** Absolute target path for a pre-incident known-good baseline copy. */
export function knownGoodPathFor(recordId: string, name: string): string {
  return areaDir("known-good", recordId, recordId, name);
}

/** True when a path lies inside the recovery workspace (or is the root). */
export function isInsideRecoveryRoot(candidate: string): boolean {
  try {
    const root = getRecoveryRoot();
    const resolved = path.resolve(candidate);
    if (resolved.toLowerCase() === root.toLowerCase()) return true;
    const relative = path.relative(root, resolved);
    return relative.length > 0 && !relative.startsWith("..") && !path.isAbsolute(relative);
  } catch {
    return false;
  }
}

/**
 * Reject any attempt to use the recovery workspace as a source or a target.
 *
 * Staging into the workspace is fine; recovering *from* it, or writing an
 * affected original back into it, would make the audit trail self-referential.
 */
export function assertNotWorkspacePath(candidate: string, reason: string): void {
  if (isInsideRecoveryRoot(candidate)) {
    throw new Error(`${reason}: ${candidate} is inside the ARGUS recovery workspace`);
  }
}

/**
 * Canonical form used for deduplication and comparison.
 *
 * Case-folded, forward-slashed, no trailing separator — so `C:\Users\A\x.docx`
 * and `c:/users/a/x.docx` are the same file.
 */
export function normalizePathKey(value: string): string {
  if (!value) return "";
  return value
    .trim()
    .replace(/\//g, "\\")
    .replace(/\\{2,}/g, "\\")
    .replace(/\\+$/, "")
    .toLowerCase();
}

/** Case-folded equality on canonical paths. */
export function samePath(a: string, b: string): boolean {
  const left = normalizePathKey(a);
  const right = normalizePathKey(b);
  return left.length > 0 && left === right;
}

/** The Windows volume a path lives on (`c:`), or null when undeterminable. */
export function volumeOf(target: string): string | null {
  const match = /^([A-Za-z]:)\\/.exec(target.trim());
  return match ? match[1].toLowerCase() : null;
}

/**
 * Canonical volume form for comparison, e.g. `c:`.
 *
 * VSS reports volumes as `C:\`, configuration often as `C:`; both normalize here
 * so volume matching cannot silently fail on a trailing separator.
 */
export function normalizeVolume(value: string): string | null {
  const match = /^([A-Za-z]:)/.exec(value.trim());
  return match ? match[1].toLowerCase() : null;
}

/** Path relative to its volume root, e.g. `C:\a\b` -> `a\b`. Null if not on a volume. */
export function relativeToVolume(target: string): string | null {
  const volume = volumeOf(target);
  if (!volume) return null;
  // Skip `volume.length + 1` to consume the drive letter, colon and separator.
  return target.slice(volume.length + 1);
}

/** True when the path looks absolute for the current platform. */
export function isAbsolutePath(value: string): boolean {
  if (!value) return false;
  return path.isAbsolute(value) || /^[A-Za-z]:[\\/]/.test(value);
}

/**
 * Validate a path received from telemetry before it is used.
 *
 * Telemetry is trusted enough to act on but not enough to write with: a null
 * byte, a relative fragment, or an empty value is refused outright.
 */
export function validateObservedPath(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 4096) return null;
  if (trimmed.includes("\u0000")) return null;
  if (!isAbsolutePath(trimmed)) return null;
  return trimmed;
}

/** Readable + regular-file check that never throws. */
export async function statReadable(target: string): Promise<{ ok: boolean; size: number | null; modifiedAt: string | null; reason: string | null }> {
  try {
    const stats = await fs.stat(target);
    if (!stats.isFile()) {
      return { ok: false, size: null, modifiedAt: null, reason: "not a regular file" };
    }
    await fs.access(target, constants.R_OK);
    return {
      ok: true,
      size: stats.size,
      modifiedAt: stats.mtime.toISOString(),
      reason: null,
    };
  } catch (error) {
    return { ok: false, size: null, modifiedAt: null, reason: describeError(error) };
  }
}

/** Human-readable errno/reason for a filesystem rejection. */
export function describeError(error: unknown): string {
  if (error && typeof error === "object") {
    const code = (error as NodeJS.ErrnoException).code;
    if (code) {
      const message = (error as NodeJS.ErrnoException).message;
      return code === "ENOENT" ? "ENOENT (path does not exist)" : `${code}: ${message}`;
    }
    if ("message" in error && typeof (error as Error).message === "string") {
      return (error as Error).message;
    }
  }
  return String(error);
}