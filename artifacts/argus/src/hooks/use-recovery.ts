/**
 * useRecovery — React hook for impact reconstruction and recovery state.
 *
 * Fetches `/api/recovery` and subscribes to `/api/recovery/stream` for live
 * incident and affected-file updates.
 *
 * The hook never synthesizes data. When the API is unreachable, `available` is
 * false; when nothing has been observed, `observed` is false and the UI shows an
 * explicit empty state rather than placeholder numbers.
 */

import { useCallback, useEffect, useRef, useState } from "react";

export type DamageClassification =
  | "MODIFIED"
  | "DELETED"
  | "RENAMED"
  | "CREATED"
  | "ENCRYPTED_OR_CORRUPTED_SUSPECTED"
  | "UNKNOWN";

export type RecoveryState =
  | "DISCOVERED"
  | "RECOVERY_CANDIDATE"
  | "RECOVERY_SOURCE_FOUND"
  | "RECOVERY_ATTEMPTED"
  | "RECOVERED"
  | "VERIFIED"
  | "UNRECOVERABLE"
  | "NO_RECOVERY_SOURCE";

export type RecoveryPipelineStage =
  | "THREAT_DETECTED"
  | "IMPACT_DISCOVERY"
  | "RECOVERY_SOURCE_SEARCH"
  | "SAFE_RECOVERY"
  | "VERIFICATION";

export type AttributionStrength = "ATTRIBUTED" | "INFERRED";

export type RecoverySourceKind =
  | "ARGUS_EVIDENCE_COPY"
  | "ARGUS_KNOWN_GOOD_COPY"
  | "WINDOWS_SHADOW_COPY"
  | "CONFIGURED_BACKUP_ROOT";

export type VerificationCheck = {
  name: string;
  passed: boolean;
  detail: string;
  required: boolean;
};

export type RecoveryAttempt = {
  attempt_id: string;
  source_kind: RecoverySourceKind;
  started_at: string;
  completed_at: string | null;
  outcome: "SUCCEEDED" | "FAILED";
  recovered_path: string | null;
  recovered_sha256: string | null;
  source_sha256: string | null;
  error: string | null;
  checks: VerificationCheck[];
  verified: boolean;
  destructive: false;
};

export type RecoverySource = {
  source_id: string;
  kind: RecoverySourceKind;
  priority: number;
  label: string;
  path: string | null;
  available: boolean;
  restorable: boolean;
  role: "EVIDENCE_PRESERVATION" | "RESTORATION_CANDIDATE";
  size_bytes: number | null;
  modified_at: string | null;
  sha256: string | null;
  probe_detail: string;
};

export type DamageSignal = {
  kind: string;
  detail: string;
  source: string;
};

export type AffectedFile = {
  record_id: string;
  incident_id: string;
  path: string;
  name: string;
  operation: string;
  previous_path: string | null;
  observed_at: string;
  first_seen_at: string;
  last_seen_at: string;
  observation_count: number;
  pid: number | null;
  process_name: string | null;
  attribution: string;
  attribution_strength: AttributionStrength;
  evidence_source: string;
  evidence: Array<{ source: string; ref: string; at: string; detail: string }>;
  current_metadata: {
    exists: boolean | null;
    size_bytes: number | null;
    modified_at: string | null;
    sha256: string | null;
    sha256_skipped_reason: string | null;
  };
  previous_metadata: { size_bytes: number | null; sha256: string | null } | null;
  damage: DamageClassification;
  damage_signals: DamageSignal[];
  recovery_state: RecoveryState;
  recovery_sources: RecoverySource[];
  selected_source_id: string | null;
  attempts: RecoveryAttempt[];
  notes: string[];
};

export type IncidentDetectionRef = {
  id: string;
  rule_id: string;
  rule_name: string;
  title: string;
  severity: string;
  confidence: number;
  status: string;
  event_timestamp: string;
  entity: string;
  pid: number;
  hostname: string | null;
};

export type RecoveryProgress = {
  total: number;
  sources_found: number;
  attempted: number;
  recovered: number;
  verified: number;
  unrecoverable: number;
  stage_percent: number;
};

export type ImpactIncident = {
  incident_id: string;
  detection_id: string;
  detection: IncidentDetectionRef;
  created_at: string;
  updated_at: string;
  window: { start: string; end: string; pre_ms: number; post_ms: number; widened: boolean };
  process: {
    pid: number | null;
    name: string | null;
    executable_path: string | null;
    command_line: string | null;
    username: string | null;
    ancestry: Array<{ pid: number; process_name: string; executable_path: string | null }>;
  };
  phase: string;
  stages_reached: RecoveryPipelineStage[];
  progress: RecoveryProgress;
  affected_files: AffectedFile[];
  affected_files_truncated: boolean;
  errors: Array<{ at: string; stage: string; message: string }>;
};

export type RecoverySummary = {
  generatedAt: string;
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
  recoverySourcesFound: number;
  incidents: number;
  incidentsInvestigating: number;
  inferredAttribution: number;
  damageClassificationTotals: string;
  evidenceCompleteness: { hashed: number; hashSkipped: number; missingOnDisk: number; unreadable: number };
};

export type RecoverySourceSupport = {
  kind: RecoverySourceKind;
  priority: number;
  description: string;
  supported: boolean;
  reason: string;
};

export type RecoverySnapshot = {
  generatedAt: string;
  observed: boolean;
  enabled: boolean;
  stages: Array<{ stage: RecoveryPipelineStage; reached: boolean }>;
  summary: RecoverySummary;
  incidents: ImpactIncident[];
  sources: RecoverySourceSupport[];
  recoveryRoot: string | null;
  limits: Record<string, number>;
  lastError: string | null;
};

export type RecoveryFileFilters = {
  damage?: DamageClassification;
  recovery_state?: RecoveryState;
  attribution_strength?: AttributionStrength;
  search?: string;
};

export type RecoveryState_ = {
  /** False when the API could not be reached. */
  available: boolean;
  /** True once the API has answered at least once. */
  loaded: boolean;
  /** True once an incident actually exists. */
  observed: boolean;
  connected: boolean;
  enabled: boolean;
  snapshot: RecoverySnapshot | null;
  /** Incident currently expanded in the UI. */
  selectedIncident: ImpactIncident | null;
  filters: RecoveryFileFilters;
  lastUpdateTime: string | null;
  error: string | null;
  selectIncident: (incidentId: string | null) => void;
  setFilter: (next: RecoveryFileFilters) => void;
  refresh: () => Promise<void>;
  /** Re-run source discovery for an incident's files. Non-destructive. */
  rescanSources: (incidentId: string) => Promise<boolean>;
  /** Stage a verified copy of one file. Non-destructive: the original is untouched. */
  recoverFile: (incidentId: string, recordId: string, sourceId?: string) => Promise<boolean>;
  busyRecordId: string | null;
};

const RECONNECT_DELAY_MS = 3000;
const POLL_MS = 10000;

function applyRecords(
  incidents: ImpactIncident[],
  incidentId: string,
  record: AffectedFile,
): ImpactIncident[] {
  return incidents.map((incident) => {
    if (incident.incident_id !== incidentId) return incident;
    const index = incident.affected_files.findIndex((file) => file.record_id === record.record_id);
    if (index === -1) return { ...incident, affected_files: [...incident.affected_files, record] };
    const files = [...incident.affected_files];
    files[index] = record;
    return { ...incident, affected_files: files };
  });
}

export function useRecovery(): RecoveryState_ {
  const [available, setAvailable] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [connected, setConnected] = useState(false);
  const [snapshot, setSnapshot] = useState<RecoverySnapshot | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [filters, setFilters] = useState<RecoveryFileFilters>({});
  const [lastUpdateTime, setLastUpdateTime] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyRecordId, setBusyRecordId] = useState<string | null>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const refresh = useCallback(async () => {
    try {
      const response = await fetch("/api/recovery");
      if (!response.ok) {
        setAvailable(false);
        return;
      }
      const data = (await response.json()) as RecoverySnapshot;
      setSnapshot(data);
      setAvailable(true);
      setLoaded(true);
      setError(data.lastError ?? null);
    } catch {
      // API not reachable — expected when the engine is not running.
      setAvailable(false);
      setLoaded(true);
    }
  }, []);

  const selectIncident = useCallback((incidentId: string | null) => {
    setSelectedIncidentId(incidentId);
  }, []);

  const setFilter = useCallback((next: RecoveryFileFilters) => {
    setFilters((current) => {
      const merged = { ...current, ...next };
      for (const key of Object.keys(merged) as Array<keyof RecoveryFileFilters>) {
        if (!merged[key]) delete merged[key];
      }
      return merged;
    });
  }, []);

  const rescanSources = useCallback(
    async (incidentId: string) => {
      try {
        const response = await fetch(`/api/recovery/incidents/${encodeURIComponent(incidentId)}/rescan-sources`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
        });
        if (!response.ok) return false;
        await refresh();
        return true;
      } catch {
        return false;
      }
    },
    [refresh],
  );

  const recoverFile = useCallback(
    async (incidentId: string, recordId: string, sourceId?: string) => {
      setBusyRecordId(recordId);
      try {
        const response = await fetch(
          `/api/recovery/incidents/${encodeURIComponent(incidentId)}/files/${encodeURIComponent(recordId)}/recover`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(sourceId ? { source_id: sourceId } : {}),
          },
        );
        const data = await response.json().catch(() => null);
        if (!response.ok) {
          setError(typeof data?.error === "string" ? data.error : `Recovery failed (HTTP ${response.status})`);
          await refresh();
          return false;
        }
        await refresh();
        return true;
      } catch {
        setError("Recovery request could not be sent");
        return false;
      } finally {
        setBusyRecordId(null);
      }
    },
    [refresh],
  );

  useEffect(() => {
    let cancelled = false;

    function connect() {
      if (cancelled) return;
      try {
        const source = new EventSource("/api/recovery/stream");

        source.onopen = () => {
          if (!cancelled) setConnected(true);
        };

        source.onmessage = (message) => {
          if (cancelled) return;
          try {
            const data = JSON.parse(message.data);

            if (data.type === "connected") {
              setAvailable(true);
              setLoaded(true);
              return;
            }

            if (data.type === "recovery.incident" && data.incident) {
              const incident = data.incident as ImpactIncident;
              setSnapshot((current) => {
                if (!current) return current;
                const index = current.incidents.findIndex((entry) => entry.incident_id === incident.incident_id);
                const incidents =
                  index === -1
                    ? [incident, ...current.incidents]
                    : current.incidents.map((entry) =>
                        entry.incident_id === incident.incident_id ? incident : entry,
                      );
                return { ...current, incidents, summary: { ...current.summary } };
              });
              setLastUpdateTime(new Date().toISOString());
              return;
            }

            if (data.type === "recovery.record" && data.record) {
              const record = data.record as AffectedFile;
              setSnapshot((current) =>
                current
                  ? { ...current, incidents: applyRecords(current.incidents, record.incident_id, record) }
                  : current,
              );
              setLastUpdateTime(new Date().toISOString());
            }
          } catch {
            // Ignore heartbeat lines and malformed frames.
          }
        };

        source.onerror = () => {
          if (!cancelled) {
            setConnected(false);
            source.close();
            reconnectTimerRef.current = setTimeout(connect, RECONNECT_DELAY_MS);
          }
        };

        eventSourceRef.current = source;
      } catch {
        if (!cancelled) reconnectTimerRef.current = setTimeout(connect, RECONNECT_DELAY_MS);
      }
    }

    connect();
    void refresh();
    const pollInterval = setInterval(() => void refresh(), POLL_MS);

    return () => {
      cancelled = true;
      eventSourceRef.current?.close();
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      clearInterval(pollInterval);
    };
  }, [refresh]);

  const selectedIncident =
    snapshot?.incidents.find((incident) => incident.incident_id === selectedIncidentId) ?? null;

  return {
    available,
    loaded,
    observed: snapshot?.observed ?? false,
    connected,
    enabled: snapshot?.enabled ?? false,
    snapshot,
    selectedIncident,
    filters,
    lastUpdateTime,
    error,
    selectIncident,
    setFilter,
    refresh,
    rescanSources,
    recoverFile,
    busyRecordId,
  };
}
