/**
 * Recovery panels — impact reconstruction and non-destructive recovery view.
 *
 * Everything rendered here comes from the ARGUS recovery API. When the API is
 * unreachable or nothing has been observed, the panels say so explicitly
 * instead of showing placeholder counts.
 */

import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  AlertTriangle, CheckCircle2, ClipboardCheck, FileSearch, FolderOpen,
  HardDriveDownload, Inbox, RefreshCw, Search, ShieldCheck, XCircle,
} from "lucide-react";
import {
  useRecovery,
  type AffectedFile,
  type AttributionStrength,
  type DamageClassification,
  type ImpactIncident,
  type RecoveryAttempt,
  type RecoveryFileFilters,
  type RecoveryPipelineStage,
  type RecoverySource,
  type RecoverySourceKind,
  type RecoveryState,
  type VerificationCheck,
} from "@/hooks/use-recovery";

type Toast = (title: string, body: string) => void;

const DAMAGE_TONE: Record<DamageClassification, string> = {
  MODIFIED: "badge-medium",
  DELETED: "badge-critical",
  RENAMED: "badge-high",
  CREATED: "badge-low",
  ENCRYPTED_OR_CORRUPTED_SUSPECTED: "badge-critical",
  UNKNOWN: "badge-muted",
};

const STATE_TONE: Record<RecoveryState, string> = {
  DISCOVERED: "badge-muted",
  RECOVERY_CANDIDATE: "badge-medium",
  RECOVERY_SOURCE_FOUND: "badge-medium",
  RECOVERY_ATTEMPTED: "badge-high",
  RECOVERED: "badge-low",
  VERIFIED: "badge-low",
  UNRECOVERABLE: "badge-critical",
  NO_RECOVERY_SOURCE: "badge-muted",
};

const DAMAGE_ORDER: DamageClassification[] = [
  "MODIFIED",
  "DELETED",
  "RENAMED",
  "CREATED",
  "ENCRYPTED_OR_CORRUPTED_SUSPECTED",
  "UNKNOWN",
];

const STATE_ORDER: RecoveryState[] = [
  "DISCOVERED",
  "RECOVERY_CANDIDATE",
  "RECOVERY_SOURCE_FOUND",
  "RECOVERY_ATTEMPTED",
  "RECOVERED",
  "VERIFIED",
  "UNRECOVERABLE",
  "NO_RECOVERY_SOURCE",
];

const SOURCE_LABEL: Record<RecoverySourceKind, string> = {
  ARGUS_EVIDENCE_COPY: "ARGUS evidence copy",
  ARGUS_KNOWN_GOOD_COPY: "ARGUS known-good copy",
  WINDOWS_SHADOW_COPY: "Windows shadow copy",
  CONFIGURED_BACKUP_ROOT: "Configured backup root",
};

function Badge({ value, tone }: { value: string; tone: string }) {
  return <span className={`badge ${tone}`}>{value}</span>;
}

function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[unit]}`;
}

function formatTime(value: string | null | undefined): string {
  if (!value) return "—";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

function shortHash(hash: string | null | undefined): string {
  if (!hash) return "—";
  if (hash.length <= 14) return hash;
  return `${hash.slice(0, 6)}…${hash.slice(-6)}`;
}

function Metric({ label, value, note, tone }: { label: string; value: string | number; note?: string; tone?: string }) {
  return (
    <section className="card metric">
      <div className="metric-label">{label}</div>
      <div className={tone ? `metric-value ${tone}` : "metric-value"}>{value}</div>
      {note && <div className="metric-note">{note}</div>}
    </section>
  );
}

function EmptyState({ title, body, icon }: { title: string; body: string; icon: ReactNode }) {
  return (
    <div className="empty" data-testid="recovery-empty-state">
      {icon}
      <h3>{title}</h3>
      <p>{body}</p>
    </div>
  );
}

function StageStrip({ stages }: { stages: Array<{ stage: RecoveryPipelineStage; reached: boolean }> }) {
  return (
    <div className="recov-stages" data-testid="recovery-stage-strip">
      {stages.map((entry, index) => (
        <div key={entry.stage} className={entry.reached ? "recov-stage on" : "recov-stage"}>
          <span className="recov-stage-index">{String(index + 1).padStart(2, "0")}</span>
          <span className="recov-stage-name">{entry.stage.replace(/_/g, " ")}</span>
        </div>
      ))}
    </div>
  );
}

function SourceSupportPanel({ sources }: { sources: Array<{ kind: RecoverySourceKind; supported: boolean; reason: string; priority: number }> }) {
  if (sources.length === 0) return null;
  return (
    <section className="card card-pad">
      <div className="panel-title">
        <h2>Recovery source availability</h2>
        <span>probed on demand</span>
      </div>
      <div className="recov-source-list">
        {sources.map((source) => (
          <div key={source.kind} className="recov-source" data-testid={`recovery-source-${source.kind}`}>
            <div className="recov-source-head">
              {source.supported ? <CheckCircle2 size={13} className="signal-good" /> : <XCircle size={13} className="signal-danger" />}
              <b>{SOURCE_LABEL[source.kind]}</b>
              <span className="mono muted">priority {source.priority}</span>
              <span style={{ marginLeft: "auto" }}>
                <Badge value={source.supported ? "AVAILABLE" : "UNAVAILABLE"} tone={source.supported ? "badge-low" : "badge-muted"} />
              </span>
            </div>
            <div className="mono muted recov-source-reason">{source.reason}</div>
          </div>
        ))}
      </div>
    </section>
  );
}

function VerificationChecks({ checks }: { checks: VerificationCheck[] }) {
  if (checks.length === 0) return null;
  return (
    <div className="recov-checks">
      {checks.map((check) => (
        <div key={check.name} className="recov-check" data-testid={`recovery-check-${check.name}`}>
          {check.passed ? <CheckCircle2 size={12} className="signal-good" /> : <XCircle size={12} className="signal-danger" />}
          <b>{check.name}</b>
          {check.required ? <Badge value="required" tone="badge-high" /> : <Badge value="optional" tone="badge-muted" />}
          <span className="mono muted">{check.detail}</span>
        </div>
      ))}
    </div>
  );
}

function AttemptRow({ attempt }: { attempt: RecoveryAttempt }) {
  return (
    <div className="recov-attempt" data-testid={`recovery-attempt-${attempt.attempt_id}`}>
      <div className="recov-source-head">
        {attempt.outcome === "SUCCEEDED" ? <CheckCircle2 size={13} className="signal-good" /> : <XCircle size={13} className="signal-danger" />}
        <b>{SOURCE_LABEL[attempt.source_kind]}</b>
        <Badge value={attempt.outcome} tone={attempt.outcome === "SUCCEEDED" ? "badge-low" : "badge-critical"} />
        {attempt.verified && <Badge value="VERIFIED" tone="badge-low" />}
        <Badge value="non-destructive" tone="badge-muted" />
        <span className="mono muted" style={{ marginLeft: "auto" }}>{formatTime(attempt.started_at)}</span>
      </div>
      {attempt.recovered_path && <div className="mono recov-attempt-line">staged copy: {attempt.recovered_path}</div>}
      <div className="mono muted recov-attempt-line">
        recovered {shortHash(attempt.recovered_sha256)} · source {shortHash(attempt.source_sha256)}
      </div>
      {attempt.error && <div className="mono recov-attempt-line" style={{ color: "hsl(var(--destructive))" }}>{attempt.error}</div>}
      <VerificationChecks checks={attempt.checks} />
    </div>
  );
}

function FileSources({ sources }: { sources: RecoverySource[] }) {
  if (sources.length === 0) {
    return <div className="mono muted">No recovery source located for this file yet.</div>;
  }
  return (
    <div className="recov-source-list">
      {sources.map((source) => (
        <div key={source.source_id} className="recov-source">
          <div className="recov-source-head">
            <FolderOpen size={13} className={source.restorable ? "signal-good" : "signal-warn"} />
            <b>{SOURCE_LABEL[source.kind]}</b>
            <Badge value={source.role === "RESTORATION_CANDIDATE" ? "restoration candidate" : "evidence only"} tone={source.role === "RESTORATION_CANDIDATE" ? "badge-medium" : "badge-muted"} />
            {source.restorable ? <Badge value="RESTORABLE" tone="badge-low" /> : <Badge value="NOT RESTORABLE" tone="badge-muted" />}
          </div>
          <div className="mono muted recov-source-reason">
            {source.path ?? "path unavailable"} · {formatBytes(source.size_bytes)} · modified {formatTime(source.modified_at)} · {shortHash(source.sha256)}
          </div>
          <div className="mono muted recov-source-reason">{source.probe_detail}</div>
        </div>
      ))}
    </div>
  );
}

function FileDetail({ file, incidentId, onRecover, busy }: {
  file: AffectedFile;
  incidentId: string;
  onRecover: (incidentId: string, recordId: string, sourceId?: string) => Promise<boolean>;
  busy: boolean;
}) {
  const restorable = file.recovery_sources.find((source) => source.restorable);
  const canRecover = file.recovery_state !== "VERIFIED" && file.recovery_state !== "RECOVERED" && Boolean(restorable);

  return (
    <div className="recov-file-detail">
      <div className="recov-detail-grid">
        <div>
          <div className="metric-label">Original path</div>
          <div className="mono recov-path">{file.path}</div>
          {file.previous_path && (
            <>
              <div className="metric-label" style={{ marginTop: 10 }}>Previous path</div>
              <div className="mono recov-path">{file.previous_path}</div>
            </>
          )}
        </div>
        <div>
          <div className="metric-label">Current metadata</div>
          <div className="mono muted">
            {file.current_metadata.exists === null
              ? "existence not probed"
              : file.current_metadata.exists
                ? `${formatBytes(file.current_metadata.size_bytes)} · modified ${formatTime(file.current_metadata.modified_at)}`
                : "file no longer present on disk"}
          </div>
          <div className="mono muted">sha256 {shortHash(file.current_metadata.sha256)}</div>
          {file.current_metadata.sha256_skipped_reason && (
            <div className="mono muted">hash skipped: {file.current_metadata.sha256_skipped_reason}</div>
          )}
          {file.previous_metadata && (
            <div className="mono muted">
              pre-incident sha256 {shortHash(file.previous_metadata.sha256)} · {formatBytes(file.previous_metadata.size_bytes)}
            </div>
          )}
        </div>
        <div>
          <div className="metric-label">Attribution</div>
          <div className="mono muted">{file.attribution}</div>
          <div style={{ marginTop: 6 }}>
            <Badge
              value={file.attribution_strength}
              tone={file.attribution_strength === "ATTRIBUTED" ? "badge-low" : "badge-high"}
            />
          </div>
          <div className="mono muted" style={{ marginTop: 6 }}>observations {file.observation_count}</div>
          <div className="mono muted">first {formatTime(file.first_seen_at)} · last {formatTime(file.last_seen_at)}</div>
        </div>
        <div>
          <div className="metric-label">Evidence ({file.evidence.length})</div>
          {file.evidence.length === 0 && <div className="mono muted">No evidence references recorded.</div>}
          {file.evidence.map((entry) => (
            <div key={`${entry.source}-${entry.ref}-${entry.at}`} className="mono muted recov-evidence-line">
              <b>{entry.source}</b> {entry.ref} · {formatTime(entry.at)} · {entry.detail}
            </div>
          ))}
          {file.notes.length > 0 && (
            <div className="mono muted recov-evidence-line">
              {file.notes.map((note) => <div key={note}>note: {note}</div>)}
            </div>
          )}
        </div>
      </div>

      {file.damage_signals.length > 0 && (
        <>
          <div className="metric-label" style={{ margin: "14px 0 6px" }}>Damage signals</div>
          <div className="recov-checks">
            {file.damage_signals.map((signal) => (
              <div key={`${signal.kind}-${signal.detail}`} className="recov-check">
                <AlertTriangle size={12} className="signal-warn" />
                <b>{signal.kind}</b>
                <span className="mono muted">{signal.source}: {signal.detail}</span>
              </div>
            ))}
          </div>
        </>
      )}

      <div className="metric-label" style={{ margin: "14px 0 6px" }}>Recovery sources</div>
      <FileSources sources={file.recovery_sources} />

      {file.attempts.length > 0 && (
        <>
          <div className="metric-label" style={{ margin: "14px 0 6px" }}>Recovery attempts</div>
          {file.attempts.map((attempt) => <AttemptRow key={attempt.attempt_id} attempt={attempt} />)}
        </>
      )}

      <div className="recov-actions">
        <button
          type="button"
          className="btn btn-primary btn-sm"
          disabled={!canRecover || busy}
          data-testid={`button-recover-${file.record_id}`}
          onClick={() => void onRecover(incidentId, file.record_id, restorable?.source_id)}
        >
          <HardDriveDownload size={13} /> Stage verified copy
        </button>
        <span className="mono muted">
          {canRecover
            ? "Copies a verified source into the recovery workspace. The original file is never modified."
            : file.recovery_state === "VERIFIED" || file.recovery_state === "RECOVERED"
              ? "Already staged and verified."
              : "No pre-incident recovery source located for this file."}
        </span>
      </div>
    </div>
  );
}

function IncidentDetail({ incident, onRecover, onRescan, busyRecordId, filters, setFilter }: {
  incident: ImpactIncident;
  onRecover: (incidentId: string, recordId: string, sourceId?: string) => Promise<boolean>;
  onRescan: (incidentId: string) => Promise<boolean>;
  busyRecordId: string | null;
  filters: RecoveryFileFilters;
  setFilter: (next: RecoveryFileFilters) => void;
}) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const [rescanBusy, setRescanBusy] = useState(false);

  return (
    <div className="grid" style={{ marginTop: 14 }}>
      <section className="card card-pad">
        <div className="panel-title">
          <h2>{incident.detection.title}</h2>
          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <span className="mono muted">{incident.detection.id}</span>
            <button
              type="button"
              className="btn btn-sm"
              disabled={rescanBusy}
              data-testid="button-rescan-sources"
              onClick={() => {
                setRescanBusy(true);
                void onRescan(incident.incident_id).finally(() => setRescanBusy(false));
              }}
            >
              <RefreshCw size={13} /> Rescan sources
            </button>
          </div>
        </div>

        <div className="recov-detail-grid">
          <div>
            <div className="metric-label">Detection</div>
            <div className="mono muted">{incident.detection.rule_name}</div>
            <div className="mono muted">severity {incident.detection.severity} · confidence {incident.detection.confidence}</div>
            <div className="mono muted">event {formatTime(incident.detection.event_timestamp)}</div>
          </div>
          <div>
            <div className="metric-label">Impact window</div>
            <div className="mono muted">{formatTime(incident.window.start)} → {formatTime(incident.window.end)}</div>
            <div className="mono muted">
              ±{incident.window.pre_ms / 1000}s / +{incident.window.post_ms / 1000}s
              {incident.window.widened ? " · widened by telemetry coverage" : ""}
            </div>
          </div>
          <div>
            <div className="metric-label">Process</div>
            <div className="mono muted">{incident.process.name ?? "unknown"} {incident.process.pid ?? ""}</div>
            <div className="mono recov-path">{incident.process.executable_path ?? "executable path not recorded"}</div>
            {incident.process.ancestry.map((link) => (
              <div key={link.pid} className="mono muted">{link.process_name} ({link.pid})</div>
            ))}
          </div>
          <div>
            <div className="metric-label">Progress</div>
            <div className="mono muted">
              {incident.progress.recovered}/{incident.progress.total} recovered · {incident.progress.verified} verified · {incident.progress.unrecoverable} unrecoverable
            </div>
            <div className="progress" style={{ marginTop: 8 }}>
              <i style={{ width: `${Math.max(0, Math.min(100, incident.progress.stage_percent))}%` }} />
            </div>
            <div className="mono muted" style={{ marginTop: 6 }}>
              phase {incident.phase} · {incident.progress.stage_percent}% of pipeline
            </div>
          </div>
        </div>

        {incident.errors.length > 0 && (
          <div className="recov-errors" data-testid="recovery-incident-errors">
            {incident.errors.map((entry) => (
              <div key={`${entry.at}-${entry.stage}`} className="mono">
                <b>{entry.stage}</b> {formatTime(entry.at)} — {entry.message}
              </div>
            ))}
          </div>
        )}
      </section>

      <AffectedFilesTable
        incident={incident}
        expanded={expanded}
        setExpanded={setExpanded}
        onRecover={onRecover}
        busyRecordId={busyRecordId}
        filters={filters}
        setFilter={setFilter}
      />
    </div>
  );
}

function AffectedFilesTable({ incident, expanded, setExpanded, onRecover, busyRecordId, filters, setFilter }: {
  incident: ImpactIncident;
  expanded: string | null;
  setExpanded: (recordId: string | null) => void;
  onRecover: (incidentId: string, recordId: string, sourceId?: string) => Promise<boolean>;
  busyRecordId: string | null;
  filters: RecoveryFileFilters;
  setFilter: (next: RecoveryFileFilters) => void;
}) {
  const [search, setSearch] = useState("");

  const rows = useMemo(() => {
    const term = (search || filters.search || "").trim().toLowerCase();
    return incident.affected_files.filter((file) => {
      if (filters.damage && file.damage !== filters.damage) return false;
      if (filters.recovery_state && file.recovery_state !== filters.recovery_state) return false;
      if (filters.attribution_strength && file.attribution_strength !== filters.attribution_strength) return false;
      if (term && !`${file.path} ${file.name} ${file.process_name ?? ""}`.toLowerCase().includes(term)) return false;
      return true;
    });
  }, [incident.affected_files, filters, search]);

  const damageCounts = useMemo(() => {
    const counts = new Map<DamageClassification, number>();
    for (const file of incident.affected_files) counts.set(file.damage, (counts.get(file.damage) ?? 0) + 1);
    return counts;
  }, [incident.affected_files]);

  return (
    <section className="card card-pad">
      <div className="panel-title">
        <h2>Affected files ({rows.length} of {incident.affected_files.length})</h2>
        <span>originals are read-only</span>
      </div>

      <div className="filterbar">
        <div className="search-wrap">
          <Search size={14} />
          <input
            className="search"
            placeholder="Search paths or processes"
            value={search}
            data-testid="input-recovery-search"
            onChange={(event) => setSearch(event.target.value)}
          />
        </div>
        <select
          className="select"
          value={filters.damage ?? ""}
          data-testid="select-recovery-damage"
          onChange={(event) => setFilter({ damage: (event.target.value || undefined) as DamageClassification | undefined })}
        >
          <option value="">All damage classes</option>
          {DAMAGE_ORDER.map((damage) => (
            <option key={damage} value={damage}>{damage.replace(/_/g, " ").toLowerCase()} ({damageCounts.get(damage) ?? 0})</option>
          ))}
        </select>
        <select
          className="select"
          value={filters.recovery_state ?? ""}
          data-testid="select-recovery-state"
          onChange={(event) => setFilter({ recovery_state: (event.target.value || undefined) as RecoveryState | undefined })}
        >
          <option value="">All recovery states</option>
          {STATE_ORDER.map((state) => (
            <option key={state} value={state}>{state.replace(/_/g, " ").toLowerCase()}</option>
          ))}
        </select>
        <select
          className="select"
          value={filters.attribution_strength ?? ""}
          data-testid="select-recovery-attribution"
          onChange={(event) => setFilter({ attribution_strength: (event.target.value || undefined) as AttributionStrength | undefined })}
        >
          <option value="">All attribution</option>
          <option value="ATTRIBUTED">attributed</option>
          <option value="INFERRED">inferred</option>
        </select>
      </div>

      {rows.length === 0 ? (
        <EmptyState
          title="No affected files discovered yet."
          body="The API reported no files matching the current filters for this incident."
          icon={<FileSearch size={22} />}
        />
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>File</th>
                <th>Operation</th>
                <th>Damage</th>
                <th>Attribution</th>
                <th>Recovery state</th>
                <th>Sources</th>
                <th>Last seen</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((file) => (
                <tr key={file.record_id} data-testid={`recovery-file-${file.record_id}`}>
                  <td>
                    <b>{file.name}</b>
                    <div className="mono muted">{file.path}</div>
                  </td>
                  <td>{file.operation}</td>
                  <td><Badge value={file.damage.replace(/_/g, " ").toLowerCase()} tone={DAMAGE_TONE[file.damage]} /></td>
                  <td>
                    <Badge value={file.attribution_strength} tone={file.attribution_strength === "ATTRIBUTED" ? "badge-low" : "badge-high"} />
                    <div className="mono muted">{file.process_name ?? `pid ${file.pid ?? "—"}`}</div>
                  </td>
                  <td><Badge value={file.recovery_state.replace(/_/g, " ").toLowerCase()} tone={STATE_TONE[file.recovery_state]} /></td>
                  <td>
                    <span className="mono">{file.recovery_sources.filter((source) => source.restorable).length}</span>
                    <span className="mono muted"> restorable / {file.recovery_sources.length} located</span>
                  </td>
                  <td className="mono muted">{formatTime(file.last_seen_at)}</td>
                  <td>
                    <button
                      type="button"
                      className="btn btn-sm"
                      data-testid={`button-expand-${file.record_id}`}
                      onClick={() => setExpanded(expanded === file.record_id ? null : file.record_id)}
                    >
                      {expanded === file.record_id ? "Hide" : "Inspect"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {incident.affected_files_truncated && (
        <div className="mono muted" style={{ marginTop: 12 }}>
          Result set truncated by the API observation limit. Increase the observation cap in the recovery service to widen the window.
        </div>
      )}

      {expanded && rows.some((file) => file.record_id === expanded) && (
        <FileDetail
          file={rows.find((file) => file.record_id === expanded)!}
          incidentId={incident.incident_id}
          onRecover={onRecover}
          busy={busyRecordId === expanded}
        />
      )}
    </section>
  );
}

export function RecoveryPage({ toast }: { toast?: Toast }) {
  const recovery = useRecovery();
  const { snapshot, selectedIncident, available, loaded, observed } = recovery;

  useEffect(() => {
    if (!selectedIncident && snapshot?.incidents.length) {
      recovery.selectIncident(snapshot.incidents[0].incident_id);
    }
    // Only auto-select the first incident when nothing is selected yet.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [snapshot?.incidents.length]);

  const summary = snapshot?.summary ?? null;

  const header = (
    <div className="page-heading">
      <div>
        <div className="eyebrow">impact reconstruction · non-destructive recovery</div>
        <h1 className="page-title">Impact &amp; recovery</h1>
        <p className="page-subtitle">
          Real telemetry only. Affected files are reconstructed from detections, filesystem events and provider evidence, and recovery never modifies an original.
        </p>
      </div>
      <div className="actions">
        <button type="button" className="btn btn-sm" onClick={() => void recovery.refresh()} data-testid="button-refresh-recovery">
          <RefreshCw size={13} /> Refresh
        </button>
      </div>
    </div>
  );

  if (!loaded) {
    return <div className="animate-rise">{header}<EmptyState title="Loading recovery state…" body="Querying the ARGUS recovery API." icon={<Inbox size={22} />} /></div>;
  }

  if (!available) {
    return (
      <div className="animate-rise">
        {header}
        <div className="scan-strip" style={{ marginBottom: 14, background: "hsl(var(--muted))" }} data-testid="recovery-offline-banner">
          <div className="scan-status" style={{ color: "hsl(var(--muted-foreground))" }}>
            <AlertTriangle size={15} />
            <div>
              <b>RECOVERY API UNAVAILABLE</b>
              <small> · Start the ARGUS API server to reconstruct impact from live telemetry.</small>
            </div>
          </div>
        </div>
        <EmptyState
          title="No recovery data available."
          body="The API did not respond, so no impact or recovery state can be shown. No values are estimated."
          icon={<XCircle size={22} />}
        />
      </div>
    );
  }

  if (!observed || !summary || snapshot!.incidents.length === 0) {
    return (
      <div className="animate-rise">
        {header}
        {!snapshot!.enabled && (
          <div className="scan-strip" style={{ marginBottom: 14 }} data-testid="recovery-disabled-banner">
            <div className="scan-status">
              <ShieldCheck size={15} />
              <div>
                <b>RECOVERY AUTOMATION DISABLED</b>
                <small> · Set ARGUS_RECOVERY_ENABLED=true to let ARGUS stage verified copies on its own.</small>
              </div>
            </div>
          </div>
        )}
        <EmptyState
          title="No affected files discovered yet."
          body="ARGUS has not reconstructed any impacted files from live telemetry. Incidents appear here automatically when a detection triggers an investigation."
          icon={<FileSearch size={22} />}
        />
      </div>
    );
  }

  return (
    <div className="animate-rise" data-testid="recovery-page">
      {header}

      <StageStrip stages={snapshot!.stages} />

      <div className="grid metrics" style={{ marginTop: 14 }}>
        <Metric label="Affected files" value={summary.affectedFiles} note={`${summary.incidents} incident(s) · ${summary.incidentsInvestigating} investigating`} />
        <Metric label="Deleted" value={summary.deletedFiles} tone={summary.deletedFiles > 0 ? "signal-danger" : undefined} note={`renamed ${summary.renamedFiles} · created ${summary.createdFiles}`} />
        <Metric
          label="Encrypted suspected"
          value={summary.encryptedSuspectedFiles}
          tone={summary.encryptedSuspectedFiles > 0 ? "signal-danger" : undefined}
          note={`modified ${summary.modifiedFiles} · unknown ${summary.unknownDamageFiles}`}
        />
        <Metric label="Attributed / inferred" value={`${summary.affectedFiles - summary.inferredAttribution} / ${summary.inferredAttribution}`} note="attributed to a process vs window-only inference" />
        <Metric label="Source found" value={summary.recoverySourcesFound} note={`candidates ${summary.recoveryCandidates} · no source ${summary.noRecoverySource}`} />
        <Metric label="Attempted" value={summary.recoveryAttempted} note={`recovered ${summary.recovered}`} />
        <Metric label="Verified" value={summary.verified} tone="signal-good" note="required checks passed" />
        <Metric label="Unrecoverable" value={summary.unrecoverable} tone={summary.unrecoverable > 0 ? "signal-warn" : undefined} note="no usable pre-incident source" />
      </div>

      <div className="grid dash-grid" style={{ marginTop: 14 }}>
        <section className="card card-pad">
          <div className="panel-title">
            <h2>Incidents</h2>
            <span>{recovery.connected ? "live" : "polling"}</span>
          </div>
          {snapshot!.incidents.map((incident) => {
            const active = selectedIncident?.incident_id === incident.incident_id;
            return (
              <button
                key={incident.incident_id}
                type="button"
                className={active ? "recov-incident on" : "recov-incident"}
                data-testid={`recovery-incident-${incident.incident_id}`}
                onClick={() => recovery.selectIncident(active ? null : incident.incident_id)}
              >
                <div className="recov-source-head">
                  <b>{incident.detection.title}</b>
                  <Badge value={incident.detection.severity} tone={incident.detection.severity === "critical" ? "badge-critical" : incident.detection.severity === "high" ? "badge-high" : "badge-medium"} />
                  <span className="mono muted" style={{ marginLeft: "auto" }}>{formatTime(incident.created_at)}</span>
                </div>
                <div className="mono muted">
                  {incident.progress.total} affected · {incident.progress.sources_found} with sources · {incident.progress.verified} verified
                </div>
                <div className="progress" style={{ marginTop: 8 }}>
                  <i style={{ width: `${Math.max(0, Math.min(100, incident.progress.stage_percent))}%` }} />
                </div>
                <div className="mono muted" style={{ marginTop: 6 }}>
                  {incident.stages_reached.map((stage) => stage.replace(/_/g, " ").toLowerCase()).join(" → ") || "no stage recorded"}
                </div>
              </button>
            );
          })}
        </section>

        <div className="grid">
          <SourceSupportPanel sources={snapshot!.sources} />
          <section className="card card-pad">
            <div className="panel-title">
              <h2>Evidence completeness</h2>
              <span>{summary.damageClassificationTotals}</span>
            </div>
            <div className="recov-completeness">
              <div><span className="mono">hashed</span><b>{summary.evidenceCompleteness.hashed}</b></div>
              <div><span className="mono">hash skipped</span><b>{summary.evidenceCompleteness.hashSkipped}</b></div>
              <div><span className="mono">missing on disk</span><b>{summary.evidenceCompleteness.missingOnDisk}</b></div>
              <div><span className="mono">unreadable</span><b>{summary.evidenceCompleteness.unreadable}</b></div>
            </div>
            <div className="mono muted" style={{ marginTop: 12 }}>
              recovery root: {snapshot!.recoveryRoot ?? "not configured"}
            </div>
            <div className="mono muted">last update: {formatTime(recovery.lastUpdateTime)}</div>
            {snapshot!.lastError && <div className="mono" style={{ color: "hsl(var(--destructive))", marginTop: 6 }}>{snapshot!.lastError}</div>}
          </section>
          {summary.evidenceCompleteness.hashSkipped > 0 && (
            <section className="card card-pad" data-testid="recovery-hash-skipped-notice">
              <div className="panel-title"><h2>Hash limits reached</h2><ClipboardCheck size={14} /></div>
              <div className="mono muted">
                {summary.evidenceCompleteness.hashSkipped} file(s) exceeded the per-file hashing cap. Their hashes are intentionally absent rather than guessed; raise the cap in the recovery service to hash them.
              </div>
            </section>
          )}
        </div>
      </div>

      {selectedIncident && (
        <IncidentDetail
          incident={selectedIncident}
          onRecover={async (incidentId, recordId, sourceId) => {
            const ok = await recovery.recoverFile(incidentId, recordId, sourceId);
            toast?.(
              ok ? "Recovery attempt finished" : "Recovery attempt failed",
              ok
                ? "A verified copy was staged in the recovery workspace. The original file was not modified."
                : recovery.error ?? "The recovery API rejected the attempt.",
            );
            return ok;
          }}
          onRescan={async (incidentId) => {
            const ok = await recovery.rescanSources(incidentId);
            toast?.(ok ? "Source scan complete" : "Source scan failed", ok ? "Recovery sources were re-probed. Originals untouched." : "The recovery API did not accept the rescan request.");
            return ok;
          }}
          busyRecordId={recovery.busyRecordId}
          filters={recovery.filters}
          setFilter={recovery.setFilter}
        />
      )}

      {!selectedIncident && snapshot!.incidents.length > 0 && (
        <div style={{ marginTop: 14 }}>
          <EmptyState title="Select an incident" body="Choose an incident to inspect its impact window, affected files, evidence and recovery attempts." icon={<Inbox size={22} />} />
        </div>
      )}
    </div>
  );
}
