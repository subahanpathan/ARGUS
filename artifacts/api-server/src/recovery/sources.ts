/**
 * Recovery source resolvers.
 *
 * Each resolver answers one question with a real filesystem probe: *does a
 * legitimate pre-incident copy of this file exist somewhere reachable on this
 * host, and can it be read right now?*
 *
 * The rules that keep this module honest:
 *
 *  - No resolver invents a path, a hash, a size or a timestamp. If a probe fails,
 *    the reason is reported verbatim (usually an errno) and `available` is false.
 *  - `restorable` is stricter than `available`. An ARGUS evidence copy of a file
 *    that was already encrypted is readable but useless, so it is reported as
 *    available-for-preservation and *not* restorable.
 *  - The recovery workspace is never a source. Recovering evidence out of the
 *    workspace would make the audit trail self-referential.
 *  - Every probe is bounded (subprocess timeout, result cap, hash size cap).
 */

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

import { sha256File } from "./file-analysis";
import {
  assertNotWorkspacePath,
  describeError,
  getRecoveryRoot,
  isInsideRecoveryRoot,
  normalizeVolume,
  relativeToVolume,
  volumeOf,
} from "./paths";
import type { RecoverySource, RecoverySourceKind, RecoverySourceRole, RecoverySourceSupport } from "./types";
import { RECOVERY_SOURCE_PRIORITY } from "./types";

const execFileAsync = promisify(execFile);

/** Environment variable holding `;`-separated (Windows) / `:`-separated (POSIX) backup roots. */
const BACKUP_ROOTS_ENV = "ARGUS_RECOVERY_BACKUP_ROOTS";

/** How long a shadow-copy enumeration subprocess may run. */
const SHADOW_PROBE_TIMEOUT_MS = 8000;

/** Most shadow copies inspected for a single file. */
const MAX_SHADOW_COPIES = 16;

/** Most backup-root candidates inspected for a single file. */
const MAX_BACKUP_CANDIDATES = 8;

/** Shadow-copy enumeration is cached this long to avoid spawning per file. */
const SHADOW_CACHE_MS = 30_000;

/* -------------------------------------------------------------------------- */
/* Probe helpers                                                              */
/* -------------------------------------------------------------------------- */

/** Stable identifier so the same source is not listed twice across probes. */
function sourceId(kind: RecoverySourceKind, sourcePath: string): string {
  return `${kind.toLowerCase()}:${createHash("sha1").update(`${kind}\u0000${sourcePath.toLowerCase()}`).digest("hex").slice(0, 12)}`;
}

/** A source that does not exist, carrying the real reason why. */
function absentSource(
  kind: RecoverySourceKind,
  label: string,
  probeDetail: string,
  sourcePath: string | null = null,
): RecoverySource {
  const priority = RECOVERY_SOURCE_PRIORITY.find((entry) => entry.kind === kind)?.priority ?? 99;
  return {
    source_id: sourceId(kind, sourcePath ?? label),
    kind,
    priority,
    label,
    path: sourcePath,
    available: false,
    restorable: false,
    role: "RESTORATION_CANDIDATE",
    size_bytes: null,
    modified_at: null,
    sha256: null,
    probe_detail: probeDetail,
    discovered_at: new Date().toISOString(),
  };
}

/**
 * Turn a real candidate file into a `RecoverySource` verdict.
 *
 * `predatesIncident` decides `restorable`; a copy captured after the incident
 * opened is preservation-only, no matter how readable it is.
 */
async function describeCandidate(
  kind: RecoverySourceKind,
  label: string,
  candidatePath: string,
  incidentWindowStart: string,
  role: RecoverySourceRole,
  maxHashBytes: number,
): Promise<RecoverySource> {
  const priority = RECOVERY_SOURCE_PRIORITY.find((entry) => entry.kind === kind)?.priority ?? 99;
  const base: RecoverySource = {
    source_id: sourceId(kind, candidatePath),
    kind,
    priority,
    label,
    path: candidatePath,
    available: false,
    restorable: false,
    role,
    size_bytes: null,
    modified_at: null,
    sha256: null,
    probe_detail: "",
    discovered_at: new Date().toISOString(),
  };

  let stats: Awaited<ReturnType<typeof fs.stat>>;
  try {
    stats = await fs.stat(candidatePath);
  } catch (error) {
    return { ...base, probe_detail: describeError(error) };
  }
  if (!stats.isFile()) {
    return { ...base, probe_detail: "candidate exists but is not a regular file" };
  }

  const modifiedAt = stats.mtime.toISOString();
  let sha256: string | null = null;
  let hashNote = "";
  if (stats.size <= maxHashBytes) {
    const hash = await sha256File(candidatePath, maxHashBytes);
    sha256 = hash.sha256;
    if (!hash.sha256) hashNote = ` sha256 unavailable (${hash.error ?? hash.skipped_reason}).`;
  } else {
    hashNote = ` sha256 skipped: ${stats.size} bytes exceeds the ${maxHashBytes} byte limit.`;
  }

  const predates = stats.mtime.getTime() < new Date(incidentWindowStart).getTime();
  const predatesNote = predates
    ? `copy mtime ${modifiedAt} predates the incident window`
    : `copy mtime ${modifiedAt} is NOT older than the incident window (${incidentWindowStart}), so it is not a known-good original`;

  return {
    ...base,
    available: true,
    restorable: predates,
    role: predates ? "RESTORATION_CANDIDATE" : "EVIDENCE_PRESERVATION",
    size_bytes: stats.size,
    modified_at: modifiedAt,
    sha256,
    probe_detail: `readable (${stats.size} bytes); ${predatesNote}.${hashNote}`.trim(),
  };
}

/* -------------------------------------------------------------------------- */
/* Resolver 1: ARGUS evidence store                                           */
/* -------------------------------------------------------------------------- */

/**
 * The chain-of-custody copy ARGUS preserved while investigating.
 *
 * Written by the impact engine via `preserveEvidenceCopy`. It contains the file
 * *as found*, so it is only a restoration candidate when it was captured before
 * the incident window — which, for a copy taken during investigation, it never is.
 */
async function resolveArgusEvidence(input: SourceLookupInput): Promise<RecoverySource[]> {
  const candidate = path.join(
    getRecoveryRoot(),
    "evidence",
    safeIncident(input.incidentId),
    safeRecord(input.recordId),
    path.basename(input.originalPath),
  );
  if (isInsideRecoveryRoot(input.originalPath)) {
    return [absentSource("ARGUS_EVIDENCE_COPY", "ARGUS evidence copy", "the affected path is itself inside the ARGUS recovery workspace")];
  }
  try {
    await fs.access(candidate);
  } catch {
    return [
      absentSource(
        "ARGUS_EVIDENCE_COPY",
        "ARGUS evidence copy",
        `no evidence copy has been preserved for this file yet (expected at ${candidate})`,
        candidate,
      ),
    ];
  }
  return [
    await describeCandidate(
      "ARGUS_EVIDENCE_COPY",
      "ARGUS evidence copy (as found)",
      candidate,
      input.incidentWindowStart,
      "EVIDENCE_PRESERVATION",
      input.maxHashBytes,
    ),
  ];
}

/* -------------------------------------------------------------------------- */
/* Resolver 2: ARGUS known-good baseline                                      */
/* -------------------------------------------------------------------------- */

/**
 * Baseline copies captured before the incident.
 *
 * ARGUS does not silently populate this: a baseline must have been captured
 * ahead of time by the operator, otherwise the resolver reports exactly that.
 */
async function resolveKnownGood(input: SourceLookupInput): Promise<RecoverySource[]> {
  const base = path.join(getRecoveryRoot(), "known-good");
  const candidates = [
    path.join(base, "by-path", ...input.originalPath.split(/[\\/]/).filter(Boolean)),
    path.join(base, safeRecord(input.recordId), path.basename(input.originalPath)),
  ];

  const found: RecoverySource[] = [];
  for (const candidate of candidates) {
    if (isInsideRecoveryRoot(input.originalPath)) break;
    try {
      await fs.access(candidate);
    } catch {
      continue;
    }
    found.push(
      await describeCandidate(
        "ARGUS_KNOWN_GOOD_COPY",
        "ARGUS pre-incident baseline copy",
        candidate,
        input.incidentWindowStart,
        "RESTORATION_CANDIDATE",
        input.maxHashBytes,
      ),
    );
    if (found.length >= input.maxSources) break;
  }

  if (found.length === 0) {
    return [
      absentSource(
        "ARGUS_KNOWN_GOOD_COPY",
        "ARGUS pre-incident baseline copy",
        `no baseline copy exists for this path under ${base}; a baseline must be captured before an incident to be usable`,
        base,
      ),
    ];
  }
  return found;
}

/* -------------------------------------------------------------------------- */
/* Resolver 3: Windows Volume Shadow Copy Service                             */
/* -------------------------------------------------------------------------- */

type ShadowCopy = {
  deviceObject: string;
  volumeName: string;
  installDate: string | null;
};

let shadowCache: { at: number; shadows: ShadowCopy[]; reason: string } | null = null;

/**
 * Enumerate shadow copies through CIM.
 *
 * Results are cached briefly because this spawns a subprocess and recovery runs
 * once per affected file. A failure is cached too, so a missing VSS service does
 * not cause one PowerShell launch per file.
 */
async function enumerateShadowCopies(): Promise<{ shadows: ShadowCopy[]; reason: string }> {
  if (process.platform !== "win32") {
    return { shadows: [], reason: "Volume Shadow Copy Service is only available on Windows" };
  }
  if (shadowCache && Date.now() - shadowCache.at < SHADOW_CACHE_MS) {
    return { shadows: shadowCache.shadows, reason: shadowCache.reason };
  }

  let shadows: ShadowCopy[] = [];
  let reason = "no shadow copies exist on this host";
  try {
    const script =
      "Get-CimInstance -ClassName Win32_ShadowCopy | " +
      "Select-Object -Property DeviceObject,VolumeName,InstallDate | ConvertTo-Json -Compress";
    // `-NonLogo` is deliberately omitted: some powershell.exe hosts (including
    // constrained ones) reject it and then report every later argument as a
    // cmdlet name, which made VSS look permanently unavailable.
    const { stdout } = await execFileAsync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script],
      { timeout: SHADOW_PROBE_TIMEOUT_MS, windowsHide: true, maxBuffer: 1024 * 1024 },
    );
    const trimmed = stdout.trim();
    if (trimmed.length > 0) {
      const parsed: unknown = JSON.parse(trimmed);
      const rows = Array.isArray(parsed) ? parsed : [parsed];
      shadows = rows
        .filter((row): row is Record<string, unknown> => typeof row === "object" && row !== null)
        .map((row) => ({
          deviceObject: typeof row.DeviceObject === "string" ? row.DeviceObject : "",
          volumeName: typeof row.VolumeName === "string" ? row.VolumeName : "",
          installDate: typeof row.InstallDate === "string" ? row.InstallDate : null,
        }))
        .filter((shadow) => shadow.deviceObject.length > 0);
      reason = shadows.length === 0 ? "the VSS query returned no shadow copies" : `${shadows.length} shadow copy/copies enumerated`;
    }
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    reason = code === "ENOENT" ? "powershell.exe is not available to query the VSS service" : describeError(error);
  }

  shadowCache = { at: Date.now(), shadows, reason };
  return { shadows, reason };
}

async function resolveShadowCopy(input: SourceLookupInput): Promise<RecoverySource[]> {
  const { shadows, reason } = await enumerateShadowCopies();
  const volume = volumeOf(input.originalPath);
  const relative = relativeToVolume(input.originalPath);

  if (!volume) {
    return [absentSource("WINDOWS_SHADOW_COPY", "Windows shadow copy", `cannot determine the volume for ${input.originalPath}`)];
  }
  if (relative === null) {
    return [absentSource("WINDOWS_SHADOW_COPY", "Windows shadow copy", `cannot determine a volume-relative path for ${input.originalPath}`)];
  }
  if (shadows.length === 0) {
    return [absentSource("WINDOWS_SHADOW_COPY", "Windows shadow copy", reason)];
  }

  const onVolume = shadows.filter((shadow) => normalizeVolume(shadow.volumeName) === volume);
  if (onVolume.length === 0) {
    const volumes = [...new Set(shadows.map((shadow) => shadow.volumeName.trim().toLowerCase()))].join(", ");
    return [
      absentSource(
        "WINDOWS_SHADOW_COPY",
        "Windows shadow copy",
        `no shadow copy exists for volume ${volume} (available volumes: ${volumes || "none reported"})`,
      ),
    ];
  }

  // Oldest first: the earliest snapshot that still contains the file is the
  // closest legitimate pre-incident state.
  onVolume.sort((a, b) => (a.installDate ?? "").localeCompare(b.installDate ?? ""));

  const found: RecoverySource[] = [];
  for (const shadow of onVolume.slice(0, MAX_SHADOW_COPIES)) {
    if (found.length >= input.maxSources) break;
    const candidate = `${shadow.deviceObject.replace(/[\\/]+$/, "")}\\${relative}`;
    try {
      await fs.access(candidate);
    } catch {
      continue;
    }
    found.push(
      await describeCandidate(
        "WINDOWS_SHADOW_COPY",
        `Windows shadow copy (${shadow.deviceObject.split("\\").pop() ?? "snapshot"})`,
        candidate,
        input.incidentWindowStart,
        "RESTORATION_CANDIDATE",
        input.maxHashBytes,
      ),
    );
  }

  if (found.length === 0) {
    return [
      absentSource(
        "WINDOWS_SHADOW_COPY",
        "Windows shadow copy",
        `${onVolume.length} shadow copy/copies exist for volume ${volume}, but none contains ${relative}`,
      ),
    ];
  }
  return found;
}

/* -------------------------------------------------------------------------- */
/* Resolver 4: operator-configured backup roots                               */
/* -------------------------------------------------------------------------- */

/** Backup roots from the environment, validated to be absolute directories. */
export function configuredBackupRoots(): string[] {
  const raw = process.env[BACKUP_ROOTS_ENV];
  if (!raw || raw.trim().length === 0) return [];
  return raw
    .split(path.delimiter)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0)
    .map((entry) => path.resolve(entry));
}

/**
 * Look for an exact mirror of the path, then for versioned siblings.
 *
 * Versioned names (`report.docx.1`, `report (2026-01-02).docx`, `report.docx.bak`)
 * are matched on the base name only, and every match is still individually
 * stat'd and date-checked, so a wrong file can never be presented as the original.
 */
async function resolveBackupRoots(input: SourceLookupInput): Promise<RecoverySource[]> {
  const roots = configuredBackupRoots();
  if (roots.length === 0) {
    return [
      absentSource(
        "CONFIGURED_BACKUP_ROOT",
        "Configured backup root",
        `${BACKUP_ROOTS_ENV} is not set, so no operator backup location is known`,
      ),
    ];
  }
  if (isInsideRecoveryRoot(input.originalPath)) {
    return [absentSource("CONFIGURED_BACKUP_ROOT", "Configured backup root", "the affected path is inside the ARGUS recovery workspace")];
  }

  const volume = volumeOf(input.originalPath);
  const relative = relativeToVolume(input.originalPath);
  const baseName = path.basename(input.originalPath);
  const extension = path.extname(baseName);
  const stem = extension ? baseName.slice(0, -extension.length) : baseName;

  const found: RecoverySource[] = [];
  for (const root of roots) {
    if (found.length >= Math.min(input.maxSources, MAX_BACKUP_CANDIDATES)) break;

    const exact: string[] = [];
    if (relative) exact.push(path.join(root, ...relative.split(/[\\/]/)));
    exact.push(path.join(root, ...input.originalPath.split(/[\\/]/).filter(Boolean)));
    exact.push(path.join(root, baseName));

    for (const candidate of exact) {
      try {
        await fs.access(candidate);
        found.push(
          await describeCandidate(
            "CONFIGURED_BACKUP_ROOT",
            `Backup root ${root} (exact mirror)`,
            candidate,
            input.incidentWindowStart,
            "RESTORATION_CANDIDATE",
            input.maxHashBytes,
          ),
        );
        break;
      } catch {
        continue;
      }
    }

    // Versioned siblings, newest-first discovery but oldest-first preference is
    // applied by the caller's priority sort.
    const searchDirs = [path.join(root, ...(relative ? relative.split(/[\\/]/).slice(0, -1) : [])), root];
    for (const dir of new Set(searchDirs)) {
      if (found.length >= Math.min(input.maxSources, MAX_BACKUP_CANDIDATES)) break;
      let entries: string[];
      try {
        entries = await fs.readdir(dir);
      } catch {
        continue;
      }
      const siblings = entries
        .filter((entry) => entry !== baseName && entry.startsWith(stem) && entry.toLowerCase().endsWith(extension.toLowerCase()))
        .slice(0, MAX_BACKUP_CANDIDATES);
      for (const sibling of siblings) {
        if (found.length >= Math.min(input.maxSources, MAX_BACKUP_CANDIDATES)) break;
        const candidate = path.join(dir, sibling);
        found.push(
          await describeCandidate(
            "CONFIGURED_BACKUP_ROOT",
            `Backup root ${root} (versioned sibling ${sibling})`,
            candidate,
            input.incidentWindowStart,
            "RESTORATION_CANDIDATE",
            input.maxHashBytes,
          ),
        );
      }
    }
  }

  if (found.length === 0) {
    return [
      absentSource(
        "CONFIGURED_BACKUP_ROOT",
        "Configured backup root",
        `${roots.length} backup root(s) configured (${roots.join(", ")}) but none holds a copy of ${baseName}${volume ? "" : " (volume undetermined)"}`,
      ),
    ];
  }
  return found;
}

/* -------------------------------------------------------------------------- */
/* Orchestration                                                              */
/* -------------------------------------------------------------------------- */

export type SourceLookupInput = {
  originalPath: string;
  incidentId: string;
  recordId: string;
  incidentWindowStart: string;
  maxSources: number;
  timeoutMs: number;
  maxHashBytes: number;
};

function safeIncident(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]/g, "-");
}

function safeRecord(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]/g, "-");
}

const RESOLVERS: ReadonlyArray<{
  kind: RecoverySourceKind;
  resolve: (input: SourceLookupInput) => Promise<RecoverySource[]>;
}> = [
  { kind: "ARGUS_EVIDENCE_COPY", resolve: resolveArgusEvidence },
  { kind: "ARGUS_KNOWN_GOOD_COPY", resolve: resolveKnownGood },
  { kind: "WINDOWS_SHADOW_COPY", resolve: resolveShadowCopy },
  { kind: "CONFIGURED_BACKUP_ROOT", resolve: resolveBackupRoots },
];

/**
 * Run every resolver for one file.
 *
 * A resolver that throws is reported as an unavailable source rather than
 * failing the investigation: an unreachable backup share must not hide a shadow
 * copy that would have worked.
 */
export async function findRecoverySources(input: SourceLookupInput): Promise<RecoverySource[]> {
  assertNotWorkspacePath(input.originalPath, "cannot search for a recovery source");
  const collected: RecoverySource[] = [];
  for (const resolver of RESOLVERS) {
    try {
      collected.push(...(await resolver.resolve(input)));
    } catch (error) {
      collected.push(absentSource(resolver.kind, resolver.kind, `resolver failed: ${describeError(error)}`));
    }
  }

  const restorable = collected.filter((source) => source.restorable);
  const fallback = collected.filter((source) => !source.restorable);
  const restorableBudget = Math.min(input.maxSources, restorable.length);
  return [...restorable.slice(0, restorableBudget), ...fallback].slice(0, input.maxSources + 1);
}

/**
 * Support matrix for `GET /api/recovery/config`.
 *
 * Reports what can *actually* run on this host right now, from the platform and
 * configuration — never from an assumption that a resolver will find something.
 */
export async function recoverySourceSupport(): Promise<RecoverySourceSupport> {
  const rows: RecoverySourceSupport = RECOVERY_SOURCE_PRIORITY.map((entry) => ({
    kind: entry.kind,
    priority: entry.priority,
    description: entry.description,
    supported: false,
    reason: "",
  }));
  const byKind = new Map(rows.map((row) => [row.kind, row]));

  byKind.get("ARGUS_EVIDENCE_COPY")!.supported = true;
  byKind.get("ARGUS_EVIDENCE_COPY")!.reason =
    `evidence copies are written to ${path.join(getRecoveryRoot(), "evidence")} while investigating`;

  byKind.get("ARGUS_KNOWN_GOOD_COPY")!.supported = true;
  byKind.get("ARGUS_KNOWN_GOOD_COPY")!.reason =
    `baseline copies are read from ${path.join(getRecoveryRoot(), "known-good")} and must be captured before an incident`;

  const shadow = byKind.get("WINDOWS_SHADOW_COPY")!;
  if (process.platform !== "win32") {
    shadow.reason = `not supported on ${process.platform}`;
  } else {
    const { shadows, reason } = await enumerateShadowCopies();
    shadow.supported = shadows.length > 0;
    shadow.reason = reason;
  }

  const backup = byKind.get("CONFIGURED_BACKUP_ROOT")!;
  const roots = configuredBackupRoots();
  backup.supported = roots.length > 0;
  backup.reason =
    roots.length === 0
      ? `${BACKUP_ROOTS_ENV} is not set`
      : `${roots.length} root(s) configured: ${roots.join("; ")}`;

  return rows;
}