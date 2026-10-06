/**
 * Impact Reconstruction & Safe Recovery — domain types.
 *
 * Every shape here describes something ARGUS actually observed. Fields that a
 * source cannot support are `null`, never a plausible-looking placeholder, and
 * every classification carries the evidence that produced it.
 *
 * Two vocabularies are kept deliberately distinct:
 *
 *  - **Damage classification** — what happened to the file, derived from the
 *    observed operation plus, when real evidence exists, corruption signals.
 *  - **Recovery state** — where the file currently stands in the recovery
 *    pipeline, derived from sources actually found and attempts actually made.
 *
 * Nothing in this file may be populated from a simulation, a seed, or a guess.
 */

/* -------------------------------------------------------------------------- */
/* Damage                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * What the observed evidence says happened to a file.
 *
 * `ENCRYPTED_OR_CORRUPTED_SUSPECTED` is only ever assigned from an explicit
 * signal (see `DAMAGE_SIGNALS`) — never merely because a file changed.
 */
export type DamageClassification =
  | "MODIFIED"
  | "DELETED"
  | "RENAMED"
  | "CREATED"
  | "ENCRYPTED_OR_CORRUPTED_SUSPECTED"
  | "UNKNOWN";

/** The filesystem operation the evidence actually reported. */
export type FileOperation =
  | "CREATED"
  | "MODIFIED"
  | "DELETED"
  | "RENAMED"
  | "DIRECTORY_CHANGED"
  | "UNKNOWN";

/** Catalog used by the API and the UI so both agree on meaning. */
export const DAMAGE_CATALOG: ReadonlyArray<{
  classification: DamageClassification;
  meaning: string;
}> = [
  {
    classification: "MODIFIED",
    meaning: "Content or metadata of an existing file was reported changed.",
  },
  {
    classification: "DELETED",
    meaning: "The watcher reported the file was removed.",
  },
  {
    classification: "RENAMED",
    meaning: "The watcher reported a rename; the original path is recorded.",
  },
  {
    classification: "CREATED",
    meaning: "A file appeared that the watcher had not previously reported.",
  },
  {
    classification: "ENCRYPTED_OR_CORRUPTED_SUSPECTED",
    meaning:
      "An explicit corruption/encryption signal was measured. Requires a listed signal; a plain change is never enough.",
  },
  {
    classification: "UNKNOWN",
    meaning: "The operation was observed but its effect on content is unknown.",
  },
];

/**
 * Named, individually checkable corruption signals.
 *
 * Every one of these is derived from real telemetry or from a bounded, read-only
 * analysis of the file. There is deliberately no "looks wrong" signal.
 */
export type DamageSignalKind =
  | "TELEMETRY_SIZE_DROPPED_TO_ZERO"
  | "SIGNATURE_MISMATCH"
  | "HIGH_ENTROPY_UNRECOGNIZED_CONTENT"
  | "PROVIDER_RANSOMWARE_REPORT"
  | "READ_FAILED";

export type DamageSignal = {
  kind: DamageSignalKind;
  detail: string;
  /** Where the signal came from. Never "heuristic guesswork". */
  source: string;
};

/* -------------------------------------------------------------------------- */
/* Recovery                                                                   */
/* -------------------------------------------------------------------------- */

/** Evidence-based position of an affected file in the recovery pipeline. */
export type RecoveryState =
  | "DISCOVERED"
  | "RECOVERY_CANDIDATE"
  | "RECOVERY_SOURCE_FOUND"
  | "RECOVERY_ATTEMPTED"
  | "RECOVERED"
  | "VERIFIED"
  | "UNRECOVERABLE"
  | "NO_RECOVERY_SOURCE";

export const RECOVERY_STATE_CATALOG: ReadonlyArray<{
  state: RecoveryState;
  meaning: string;
}> = [
  { state: "DISCOVERED", meaning: "Observed as affected; nothing attempted yet." },
  { state: "RECOVERY_CANDIDATE", meaning: "Worth searching for a source, per the incident." },
  {
    state: "RECOVERY_SOURCE_FOUND",
    meaning: "At least one real recovery source was located and stat'd.",
  },
  { state: "RECOVERY_ATTEMPTED", meaning: "A copy into staging is in flight or failed." },
  { state: "RECOVERED", meaning: "A copy exists in staging but has not been verified." },
  {
    state: "VERIFIED",
    meaning: "Every required verification check passed on the staged copy.",
  },
  { state: "UNRECOVERABLE", meaning: "Recovery was attempted and could not succeed." },
  {
    state: "NO_RECOVERY_SOURCE",
    meaning: "The search finished and no legitimate source exists on this host.",
  },
];

/** Terminal states: automatic triggering never re-runs these. */
export const TERMINAL_RECOVERY_STATES: ReadonlySet<RecoveryState> = new Set<RecoveryState>([
  "VERIFIED",
  "UNRECOVERABLE",
]);

/**
 * Legitimate recovery sources ARGUS knows how to look for.
 *
 * The order below is the selection priority. Sources that are not implemented
 * (raw-disk/file carving, cloud backup providers) are deliberately absent rather
 * than simulated: `GET /api/recovery/config` reports what is actually supported.
 */
export type RecoverySourceKind =
  | "ARGUS_EVIDENCE_COPY"
  | "ARGUS_KNOWN_GOOD_COPY"
  | "WINDOWS_SHADOW_COPY"
  | "CONFIGURED_BACKUP_ROOT";

export const RECOVERY_SOURCE_PRIORITY: ReadonlyArray<{
  kind: RecoverySourceKind;
  priority: number;
  description: string;
}> = [
  {
    kind: "ARGUS_EVIDENCE_COPY",
    priority: 10,
    description:
      "A copy ARGUS itself preserved under its evidence store. Only a pre-incident copy can restore content; a copy taken at detection time is evidence, not a known-good original.",
  },
  {
    kind: "ARGUS_KNOWN_GOOD_COPY",
    priority: 20,
    description:
      "A baseline copy ARGUS holds for this exact path from before the incident window.",
  },
  {
    kind: "WINDOWS_SHADOW_COPY",
    priority: 30,
    description:
      "Windows Volume Shadow Copy Service snapshot of the volume holding the file (what Previous Versions reads). Requires a shadow copy to exist and be readable by this process.",
  },
  {
    kind: "CONFIGURED_BACKUP_ROOT",
    priority: 40,
    description:
      "An operator-configured backup directory, probed for an exact mirrored path and for versioned siblings of the same file.",
  },
];

/**
 * Why a source is or is not usable.
 *
 * `restorable` is the honest gate: a source can be `available` (the bytes are
 * readable right now) and still not be a valid restoration source, because it
 * was captured after the incident window opened.
 */
export type RecoverySourceRole = "EVIDENCE_PRESERVATION" | "RESTORATION_CANDIDATE";

export type RecoverySource = {
  source_id: string;
  kind: RecoverySourceKind;
  priority: number;
  label: string;
  /** Real, resolved path, or null when the source does not exist. */
  path: string | null;
  /** True only when the path was stat'd and is a readable regular file. */
  available: boolean;
  /** True only when `available` and the source predates the incident window. */
  restorable: boolean;
  role: RecoverySourceRole;
  size_bytes: number | null;
  modified_at: string | null;
  sha256: string | null;
  /** The real reason for the verdict (probe output, errno, elevation error). */
  probe_detail: string;
  discovered_at: string;
};

/** One named, pass/fail verification check on a staged copy. */
export type VerificationCheck = {
  name: string;
  passed: boolean;
  detail: string;
  /** Required checks must all pass before a copy may be called VERIFIED. */
  required: boolean;
};

export type RecoveryAttemptOutcome = "SUCCEEDED" | "FAILED";

/** One attempt to stage a copy of an affected file from a real source. */
export type RecoveryAttempt = {
  attempt_id: string;
  record_id: string;
  incident_id: string;
  source_id: string;
  source_kind: RecoverySourceKind;
  started_at: string;
  completed_at: string | null;
  outcome: RecoveryAttemptOutcome;
  /** Path inside the isolated ARGUS staging area. Never the original path. */
  recovered_path: string | null;
  recovered_size_bytes: number | null;
  recovered_sha256: string | null;
  source_sha256: string | null;
  error: string | null;
  checks: VerificationCheck[];
  /** True only when every required check passed. */
  verified: boolean;
  /**
   * Design invariant, recorded so the audit trail is self-describing.
   * This phase never opens an affected file for writing.
   */
  destructive: false;
};

/* -------------------------------------------------------------------------- */
/* Attribution                                                                */
/* -------------------------------------------------------------------------- */

/** How an affected file was tied to the detection. */
export type AttributionBasis =
  | "SECURITY_PROVIDER_RESOURCE"
  | "PROCESS_EXECUTABLE_PATH"
  | "ENGINE_FILE_DETECTION"
  | "PROCESS_ANCESTRY_PATH"
  | "PROCESS_LINEAGE_DIRECTORY"
  | "INCIDENT_TIME_WINDOW";

/**
 * `ATTRIBUTED` means an exact identifier matched (a provider named this path,
 * or the path is the binary of the detected process or of one of its ancestors).
 *
 * `ATTRIBUTION_UNCERTAIN` means a real, non-exact link to the detected process
 * exists: the changed path sits inside the directory the process or one of its
 * ancestors was loaded from. That is circumstantial. It is reported as uncertain
 * rather than promoted, because co-location is not causation.
 *
 * `INFERRED` means only the incident time window matched — a real observation,
 * but no link to the detected process at all.
 *
 * The three levels exist so the product can never state that a malware process
 * modified a file without an exact identifier behind the claim.
 */
export type AttributionStrength = "ATTRIBUTED" | "ATTRIBUTION_UNCERTAIN" | "INFERRED";

export const ATTRIBUTION_CATALOG: ReadonlyArray<{
  basis: AttributionBasis;
  strength: AttributionStrength;
  description: string;
}> = [
  {
    basis: "SECURITY_PROVIDER_RESOURCE",
    strength: "ATTRIBUTED",
    description: "A security product reported this exact resource path.",
  },
  {
    basis: "PROCESS_EXECUTABLE_PATH",
    strength: "ATTRIBUTED",
    description: "The changed path is the detected process's own executable path.",
  },
  {
    basis: "PROCESS_ANCESTRY_PATH",
    strength: "ATTRIBUTED",
    description:
      "The changed path is the executable of an ancestor of the detected process, matched exactly against the recorded process lineage.",
  },
  {
    basis: "ENGINE_FILE_DETECTION",
    strength: "ATTRIBUTED",
    description: "The detection engine produced a file finding for this exact path.",
  },
  {
    basis: "PROCESS_LINEAGE_DIRECTORY",
    strength: "ATTRIBUTION_UNCERTAIN",
    description:
      "The changed path sits in the directory the detected process or one of its ancestors was loaded from. Circumstantial, and reported as uncertain rather than as attribution.",
  },
  {
    basis: "INCIDENT_TIME_WINDOW",
    strength: "INFERRED",
    description:
      "The change fell inside the incident time window. Real, but not proof of attribution.",
  },
];

/* -------------------------------------------------------------------------- */
/* Affected files                                                             */
/* -------------------------------------------------------------------------- */

/** One reference to the telemetry that justified an impact record. */
export type ImpactEvidenceRef = {
  /** Which real subsystem produced it. */
  source:
    | "monitoring_event"
    | "filesystem_activity"
    | "file_scan"
    | "security_provider"
    | "detection"
    | "process_snapshot"
    | "safe_file_analysis";
  /** The identifier the source itself assigned. */
  ref: string;
  at: string;
  detail: string;
};

/** File metadata as observed at one point in time. */
export type FileMetadataSnapshot = {
  /** null when the path did not exist when observed. */
  exists: boolean | null;
  size_bytes: number | null;
  modified_at: string | null;
  created_at: string | null;
  /** Real SHA-256, only when the file was small enough to hash safely. */
  sha256: string | null;
  sha256_computed_at: string | null;
  /** Why a hash is missing, when it is. */
  sha256_skipped_reason: string | null;
};

export type AffectedFile = {
  record_id: string;
  incident_id: string;
  detection_id: string;

  path: string;
  name: string;
  operation: FileOperation;
  /** The pre-rename path reported by the watcher, for renames. */
  previous_path: string | null;

  /** When the evidence was observed. */
  observed_at: string;
  first_seen_at: string;
  last_seen_at: string;
  /** Every observation timestamp that contributed to this record. */
  observation_count: number;

  pid: number | null;
  process_name: string | null;
  process_ancestry: Array<{
    pid: number;
    process_name: string;
    executable_path: string | null;
  }>;

  attribution: AttributionBasis;
  attribution_strength: AttributionStrength;

  evidence_source: string;
  evidence: ImpactEvidenceRef[];

  previous_metadata: FileMetadataSnapshot | null;
  current_metadata: FileMetadataSnapshot;

  damage: DamageClassification;
  damage_signals: DamageSignal[];

  recovery_state: RecoveryState;
  recovery_sources: RecoverySource[];
  selected_source_id: string | null;
  attempts: RecoveryAttempt[];
  /** Honest operational notes (permission denied, locked, missing, truncated). */
  notes: string[];
};

/* -------------------------------------------------------------------------- */
/* Incidents                                                                  */
/* -------------------------------------------------------------------------- */

/** The five stages the UI renders, in order. */
export const RECOVERY_PIPELINE_STAGES = [
  "THREAT_DETECTED",
  "IMPACT_DISCOVERY",
  "RECOVERY_SOURCE_SEARCH",
  "SAFE_RECOVERY",
  "VERIFICATION",
] as const;

export type RecoveryPipelineStage = (typeof RECOVERY_PIPELINE_STAGES)[number];

export type RecoveryPhase =
  | "QUEUED"
  | "DISCOVERING"
  | "SOURCE_SEARCH"
  | "RECOVERING"
  | "VERIFYING"
  | "COMPLETE"
  | "FAILED";

export type IncidentWindow = {
  start: string;
  end: string;
  /** How far before the detection's own event time the window was widened. */
  pre_ms: number;
  /** How far past detection the window was widened. */
  post_ms: number;
  /** True when an explicit source is missing and the window had to be widened. */
  widened: boolean;
};

export type IncidentProcess = {
  pid: number | null;
  name: string | null;
  executable_path: string | null;
  command_line: string | null;
  parent_pid: number | null;
  parent_process_name: string | null;
  username: string | null;
  ancestry: Array<{
    pid: number;
    process_name: string;
    executable_path: string | null;
  }>;
};

export type IncidentDetectionRef = {
  id: string;
  rule_id: string;
  rule_name: string;
  title: string;
  severity: string;
  confidence: number;
  status: string;
  timestamp: string;
  event_timestamp: string;
  entity: string;
  pid: number;
  executable_path: string | null;
  hostname: string | null;
};

export type RecoveryProgress = {
  total: number;
  discovered: number;
  sources_found: number;
  attempted: number;
  recovered: number;
  verified: number;
  unrecoverable: number;
  /** 0..100 over the pipeline stages, not over files. */
  stage_percent: number;
};

export type IncidentError = {
  at: string;
  stage: string;
  message: string;
};

export type ImpactIncident = {
  incident_id: string;
  detection_id: string;
  detection: IncidentDetectionRef;
  created_at: string;
  updated_at: string;
  window: IncidentWindow;
  process: IncidentProcess;
  phase: RecoveryPhase;
  /** Which pipeline stages have actually been reached. */
  stages_reached: RecoveryPipelineStage[];
  progress: RecoveryProgress;
  affected_files: AffectedFile[];
  /** True when the affected-file cap was hit and the list is not complete. */
  affected_files_truncated: boolean;
  /** Detections that did not trigger recovery, with the reason. */
  skipped_reason: string | null;
  errors: IncidentError[];
};

/* -------------------------------------------------------------------------- */
/* Aggregates                                                                */
/* -------------------------------------------------------------------------- */

/**
 * The counts the Recovery API and UI show. Every field is a count over real
 * records; nothing here is a projection or an estimate.
 */
export type RecoverySummary = {
  generatedAt: string;
  /** Total impact records across all retained incidents. */
  affectedFiles: number;
  modifiedFiles: number;
  deletedFiles: number;
  renamedFiles: number;
  createdFiles: number;
  encryptedSuspectedFiles: number;
  unknownDamageFiles: number;
  recoveryCandidates: number;
  recoverySourceFound: number;
  recoveryAttempted: number;
  recovered: number;
  verified: number;
  unrecoverable: number;
  noRecoverySource: number;
  /** Recovery sources that were actually located on disk. */
  recoverySourcesFound: number;
  incidents: number;
  incidentsInvestigating: number;
  /** Records whose attribution rests only on the incident time window. */
  inferredAttribution: number;
  /** Records linked to the process only by directory co-location. */
  uncertainAttribution: number;
  /**
   * Stated explicitly because it is easy to misread: the six damage counters are
   * mutually exclusive. Every affected file falls into exactly one damage class,
   * so the six of them sum to `affectedFiles`. A file classified as suspected
   * encryption is counted there and *not* also under `modifiedFiles`.
   */
  damageClassificationTotals: string;
  evidenceCompleteness: {
    hashed: number;
    hashSkipped: number;
    missingOnDisk: number;
    unreadable: number;
  };
};

export type RecoverySnapshot = {
  generatedAt: string;
  /** True once an incident has actually been created. */
  observed: boolean;
  enabled: boolean;
  /** Pipeline stage -> whether it has been reached at least once. */
  stages: Array<{ stage: RecoveryPipelineStage; reached: boolean }>;
  summary: RecoverySummary;
  incidents: ImpactIncident[];
  /** Support matrix for the recovery source resolvers, from real probes/config. */
  sources: RecoverySourceSupport;
  recoveryRoot: string | null;
  limits: RecoveryLimits;
  lastError: string | null;
};

/** Whether each source resolver can run here, and why. */
export type RecoverySourceSupport = Array<{
  kind: RecoverySourceKind;
  priority: number;
  description: string;
  supported: boolean;
  /** Real reason: platform, configuration, or a probe result. */
  reason: string;
}>;

export type RecoveryLimits = {
  maxAffectedFilesPerIncident: number;
  maxSourcesPerFile: number;
  maxAttemptsPerFile: number;
  maxHashBytes: number;
  /** Evidence references retained per affected file. */
  maxEvidenceRefsPerFile: number;
  sourceSearchTimeoutMs: number;
  maxIncidentHistory: number;
};