/**
 * monitoring-panels.tsx — ARGUS Monitoring panels (scan activity, live
 * metrics, event feed). All values come from the real aggregated snapshot.
 * Progress bars render only when a real denominator is known; otherwise the
 * scan shows an indeterminate activity state — never a fabricated percent.
 */

import { useMemo } from "react";
import type {
  AggregatedMonitorEvent,
  MonitoringScanState,
  MonitoringSnapshot,
} from "@/hooks/use-monitoring-stream";
import { fmtBytes } from "../universe/universe-theme";

/* ------------------------------------------------------------------ */
/* Shared primitives                                                   */
/* ------------------------------------------------------------------ */

function Kpi({ label, value, tone = "", small }: { label: string; value: string; tone?: string; small?: boolean }) {
  return (
    <div className="moni-kpi">
      <div className="moni-kpi-label">{label}</div>
      <div className={`moni-kpi-value ${tone ? `sig-${tone}` : ""} ${small ? "moni-kpi-small" : ""}`}>{value}</div>
    </div>
  );
}

function PanelTitle({ title, detail, right }: { title: string; detail?: string; right?: React.ReactNode }) {
  return (
    <div className="panel-title">
      <h2>{title}</h2>
      <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
        {detail && <span>{detail}</span>}
        {right}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Scan activity panel                                                 */
/* ------------------------------------------------------------------ */

export function MonitoringScanPanel({ scan }: { scan: MonitoringScanState | null }) {
  const st = scan?.state ?? "idle";

  const toneOf = (s: string) =>
    s === "completed" ? "ok" : s === "partial" ? "warn" : s === "failed" ? "danger" : s === "cancelled" ? "muted" : s === "analyzing" ? "info" : "live";
  const labelOf = (s: string) =>
    s.toUpperCase();

  const scanned = scan?.files_scanned ?? 0;
  const discovered = scan?.files_discovered ?? 0;
  const foldersScanned = scan?.folders_scanned ?? 0;
  const foldersDiscovered = scan?.folders_discovered ?? 0;

  // Real progress only when a real denominator exists.
  const fileDenom = discovered > 0;
  const folderDenom = foldersDiscovered > 0;
  const filePct = fileDenom ? Math.min(100, (scanned / discovered) * 100) : null;
  const folderPct = folderDenom ? Math.min(100, (foldersScanned / foldersDiscovered) * 100) : null;
  const indeterminate = !fileDenom && !folderDenom && (st === "scanning" || st === "analyzing");

  const running = st === "scanning" || st === "analyzing" || st === "starting";

  return (
    <div className="card card-pad moni-card">
      <PanelTitle
        title="Scan activity"
        detail="REAL FILESYSTEM WALK"
        right={<span className={`moni-scan-state ${toneOf(st)}`}>{labelOf(st)}</span>}
      />
      {running && (
        <div className="moni-indeterminate">
          <span className="animate-pulse-line" />
          tracing filesystem entries…
        </div>
      )}
      {scan?.current_operation && (
        <div className="mono muted moni-scan-opn">{scan.current_operation}</div>
      )}
      {scan?.current_path && scan.current_path !== scan.current_operation && (
        <div className="mono muted moni-scan-path" title={scan.current_path}>{scan.current_path}</div>
      )}

      <div className="moni-scan-progress-wrap">
        <div className="moni-scan-progress-row">
          <span className="mono">FILES</span>
          <span className="mono muted">{filePct != null ? `${filePct.toFixed(1)}%` : "—"}</span>
        </div>
        <div className="progress"><i style={filePct != null ? { width: `${filePct}%`, background: "hsl(var(--accent))" } : running ? { width: "38%", background: "hsl(var(--primary))", animation: "indeterminate-slide 1.4s ease-in-out infinite" } : undefined} /></div>
        <div className="moni-scan-progress-row">
          <span className="mono">FOLDERS</span>
          <span className="mono muted">{folderPct != null ? `${folderPct.toFixed(1)}%` : "—"}</span>
        </div>
        <div className="progress"><i style={folderPct != null ? { width: `${folderPct}%`, background: "hsl(var(--primary))" } : running ? { width: "52%", background: "hsl(var(--primary))", animation: "indeterminate-slide 1.4s ease-in-out infinite" } : undefined} /></div>
      </div>

      <div className="moni-scan-stats">
        <Kpi label="Files scanned" value={`${scanned}`} tone="" />
        <Kpi label="Folders scanned" value={`${foldersScanned}`} tone="" />
        <Kpi label="Bytes scanned" value={fmtBytes(scan?.bytes_scanned ?? 0)} tone="" />
        <Kpi label="Discovered" value={discovered > 0 ? `${discovered}` : "—"} tone="" />
      </div>

      {(() => {
        const errs = scan?.errors ?? 0;
        const skips = scan?.skipped ?? 0;
        if (errs > 0 || skips > 0) {
          return (
            <div className="moni-scan-note">
              <span className="mono" data-tone="warn">{errs > 0 ? `${errs} errors` : ""}</span>
              {errs > 0 && skips > 0 && <span className="mono muted"> · </span>}
              <span className="mono" data-tone="muted">{skips > 0 ? `${skips} skipped` : ""}</span>
            </div>
          );
        }
        return null;
      })()}

      {scan?.roots && scan.roots.length > 0 && (
        <div className="moni-scan-roots">
          {scan.roots.map((r) => (
            <span className="mono muted" key={r}>{r}</span>
          ))}
        </div>
      )}

      {!scan && (
        <div className="empty">
          <h3>No scan has started</h3>
          <p>Filesystem scan state appears once the ARGUS engine begins its bounded walk of local volumes.</p>
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Live activity metrics card                                          */
/* ------------------------------------------------------------------ */

export function MonitoringLiveMetrics({ snapshot, hasData }: { snapshot: MonitoringSnapshot | null; hasData: boolean }) {
  const s = snapshot;

  const procsLive = !!s?.processes.observed;
  const netLive = !!s?.network.observed;
  const portsLive = !!s?.ports.observed;
  const svcLive = !!s?.services.observed;
  const fsLive = !!s?.files.observed;
  const disks = s?.disks ?? [];
  const diskTotal = disks.reduce((a, d) => a + (d.total_bytes ?? 0), 0);
  const diskUsed = disks.reduce((a, d) => a + (d.used_bytes ?? 0), 0);

  const rows: Array<{ label: string; value: string; note: string; listed: boolean; bar?: number }> = [
    {
      label: "PROCESS",
      value: procsLive ? String(s?.processes.total_count ?? 0) : "—",
      note: procsLive ? `${s?.processes.access_denied_count ?? 0} access-denied` : "SOURCE DOWN",
      listed: procsLive,
    },
    {
      label: "NETWORK",
      value: netLive ? String(s?.network.total_count ?? 0) : "—",
      note: netLive ? `${s?.network.established_count ?? 0} established · ${s?.network.interfaces ?? 0} ifaces` : "SOURCE DOWN",
      listed: netLive,
    },
    {
      label: "PORTS",
      value: portsLive ? String((s?.ports.tcp_listening ?? 0) + (s?.ports.udp_endpoints ?? 0)) : "—",
      note: portsLive ? `${s?.ports.tcp_listening ?? 0} tcp listen · ${s?.ports.udp_endpoints ?? 0} udp` : "SOURCE DOWN",
      listed: portsLive,
    },
    {
      label: "SERVICES",
      value: svcLive ? String(s?.services.total_count ?? 0) : "—",
      note: svcLive ? `${s?.services.running_count ?? 0} running · ${s?.services.stopped_count ?? 0} stopped` : "SOURCE DOWN",
      listed: svcLive,
    },
    {
      label: "FILES",
      value: fsLive ? String(s?.files.findings ?? 0) : "—",
      note: fsLive ? `${s?.files.files_hashed ?? 0} hashed · ${s?.files.directories_scanned ?? 0} dirs` : "SOURCE DOWN",
      listed: fsLive,
    },
    {
      label: "DISK",
      value: diskTotal > 0 ? fmtBytes(diskUsed) : "—",
      note: diskTotal > 0 ? `${fmtBytes(diskTotal)} · ${disks.length} volume${disks.length === 1 ? "" : "s"}` : "SOURCE DOWN",
      listed: diskTotal > 0,
      bar: diskTotal > 0 ? (diskUsed / diskTotal) * 100 : undefined,
    },
  ];

  return (
    <div className="card card-pad moni-card" data-testid="monitoring-live-metrics">
      <PanelTitle title="Live activity" detail={hasData ? "REAL OBSERVED VALUES" : "AWAITING FEED"} />
      <div className="moni-metric-grid">
        {rows.map((r) => (
          <div className="moni-metric-cell" key={r.label}>
            <div className="mono muted moni-metric-key">{r.label}</div>
            <div className={`moni-metric-value ${r.listed ? "sig-good" : "sig-muted"}`}>{r.value}</div>
            <div className="mono muted moni-metric-note">{r.note}</div>
            {r.bar != null && (
              <div className="progress" style={{ marginTop: 6 }}>
                <i style={{ width: `${Math.max(1, Math.min(100, r.bar))}%`, background: "hsl(var(--warn))" }} />
              </div>
            )}
          </div>
        ))}
      </div>
      <div className="moni-system-row">
        <Kpi label="CPU" value={s?.endpoint.cpu_percent != null ? `${s.endpoint.cpu_percent.toFixed(1)}%` : "—"} tone="info" />
        <Kpi label="Memory" value={s?.endpoint.memory_percent != null ? `${s.endpoint.memory_percent.toFixed(1)}%` : "—"} tone="info" />
        <Kpi label="Cores" value={s?.endpoint.cpu_count != null ? `${s.endpoint.cpu_count}` : "—"} tone="info" />
        <Kpi label="Uptime" value={fmtUptime(s?.endpoint.uptime_seconds)} tone="info" />
      </div>
    </div>
  );
}

function fmtUptime(seconds: number | null | undefined): string {
  if (seconds == null) return "—";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

/* ------------------------------------------------------------------ */
/* Bottom metrics bar (compact host stats strip)                       */
/* ------------------------------------------------------------------ */

export function MonitoringMetricsBar({ snapshot, scan, hasData }: { snapshot: MonitoringSnapshot | null; scan: MonitoringScanState | null; hasData: boolean }) {
  const s = snapshot;
  const disks = s?.disks ?? [];
  const diskTotal = disks.reduce((a, d) => a + (d.total_bytes ?? 0), 0);
  const diskUsed = disks.reduce((a, d) => a + (d.used_bytes ?? 0), 0);

  const items = useMemo(() => {
    return [
      { key: "HOST", value: s?.endpoint.hostname || "—" },
      { key: "CPU", value: s?.endpoint.cpu_percent != null ? `${s.endpoint.cpu_percent.toFixed(1)}%` : "—" },
      { key: "MEM", value: s?.endpoint.memory_percent != null ? `${s.endpoint.memory_percent.toFixed(1)}%` : "—" },
      { key: "DISK", value: diskTotal > 0 ? `${((diskUsed / diskTotal) * 100).toFixed(0)}%` : "—" },
      { key: "PROCS", value: s?.processes.observed ? String(s.processes.total_count) : "—" },
      { key: "CONNS", value: s?.network.observed ? String(s.network.total_count) : "—" },
      { key: "PORTS", value: s?.ports.observed ? String((s.ports.tcp_listening ?? 0) + (s.ports.udp_endpoints ?? 0)) : "—" },
      { key: "SVC", value: s?.services.observed ? String(s.services.total_count) : "—" },
      { key: "SCAN", value: scan ? `${scan.files_scanned ?? 0} files` : "idle" },
    ];
  }, [s, scan, diskTotal, diskUsed, hasData]);

  return (
    <div className="moni-metrics-bar" data-testid="monitoring-metrics-bar">
      {items.map((it) => (
        <div className="moni-metrics-item" key={it.key}>
          <span className="mono muted">{it.key}</span>
          <span className="mono moni-metrics-value">{it.value}</span>
        </div>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Live event feed                                                     */
/* ------------------------------------------------------------------ */

const TYPE_COLOR: Record<string, string> = {
  process_started: "hsl(var(--accent))",
  process_terminated: "hsl(var(--destructive))",
  network_connection: "hsl(280 60% 70%)",
  port_listening: "hsl(200 80% 60%)",
  service_change: "hsl(142 71% 60%)",
};

export function MonitoringEventFeed({ events, connected, hasData }: { events: AggregatedMonitorEvent[]; connected: boolean; hasData: boolean }) {
  const list = events.slice(-24).reverse();
  return (
    <div className="card card-pad moni-card" data-testid="monitoring-event-feed">
      <PanelTitle
        title="Event feed"
        detail={connected ? "STREAMING · SSE" : hasData ? "CACHED · RECONNECTING" : "AWAITING FEED"}
        right={connected ? <span className="badge badge-low" style={{ background: "hsl(142 71% 20%)", color: "hsl(142 71% 70%)", border: "1px solid hsl(142 71% 30%)" }}>LIVE</span> : <span className="badge badge-muted">OFFLINE</span>}
      />
      {list.length > 0 ? (
        <div className="moni-event-list">
          {list.map((e, i) => (
            <div className="event-row" key={`${e.timestamp}|${i}`}>
              <span className="event-dot" style={{ background: TYPE_COLOR[e.type] ?? "hsl(var(--chart-3))" }} />
              <div className="event-copy">
                <div>{e.title}</div>
                <div className="muted" style={{ fontSize: 10, marginTop: 2 }}>
                  <span className="mono">{e.source}</span>
                  {e.detail ? ` · ${e.detail}` : ""}
                </div>
              </div>
              <span className="event-time">{new Date(e.timestamp).toLocaleTimeString()}</span>
            </div>
          ))}
        </div>
      ) : (
        <div className="empty">
          <h3>No events yet</h3>
          <p>Aggregated monitoring events appear here as the engine observes process, network, port, and service changes on this host.</p>
        </div>
      )}
    </div>
  );
}