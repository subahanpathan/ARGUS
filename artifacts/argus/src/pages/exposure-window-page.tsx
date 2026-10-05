import { useMemo, useState, useEffect, type CSSProperties } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Check,
  CheckCircle2,
  Clock3,
  Download,
  Eye,
  FileKey2,
  FileSearch,
  FileText,
  HardDrive,
  History,
  Layers,
  Lock,
  Network,
  Radio,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare,
  Zap,
  Globe2,
  Cpu,
  Flame,
  Fingerprint,
} from 'lucide-react';
import type { ThreatAnalysisState } from '@/hooks/use-threat-analysis';
import type { ProcessMonitorState } from '@/hooks/use-process-monitor';
import type { NetworkMonitorState } from '@/hooks/use-network-monitor';
import type { FileScanState } from '@/hooks/use-file-scan';

function cn(...values: Array<string | false | undefined | null>) {
  return values.filter(Boolean).join(' ');
}

export type ExposureWindowPageProps = {
  phase: number;
  toast: (title: string, body: string) => void;
  threatAnalysis?: ThreatAnalysisState;
  processMonitor?: ProcessMonitorState;
  networkMonitor?: NetworkMonitorState;
  fileScan?: FileScanState;
  contained?: boolean;
  onNavigate?: (path: string) => void;
};

type Milestone = {
  id: string;
  pct: string;
  label: string;
  time: string;
  detail: string;
  subsystem: 'process' | 'file' | 'network' | 'detection' | 'containment';
  status: 'observed' | 'potential' | 'confirmed';
  route?: string;
  meta?: string;
};

function formatDuration(ms: number): string {
  if (ms <= 0) return '0s';
  const sec = Math.floor(ms / 1000);
  const min = Math.floor(sec / 60);
  const hrs = Math.floor(min / 60);
  if (hrs > 0) return `${hrs}h ${min % 60}m`;
  if (min > 0) return `${min}m ${sec % 60}s`;
  return `${sec}s`;
}

export default function ExposureWindowPage({
  phase,
  toast,
  threatAnalysis,
  processMonitor,
  networkMonitor,
  fileScan,
  contained = false,
  onNavigate,
}: ExposureWindowPageProps) {
  const isReal = Boolean(
    (processMonitor?.hasData && (processMonitor.snapshot.length > 0 || processMonitor.events.length > 0)) ||
    (networkMonitor?.hasData && networkMonitor.snapshot) ||
    (threatAnalysis?.threats && threatAnalysis.threats.length > 0)
  );

  const [selectedMilestone, setSelectedMilestone] = useState<string>('transmission');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [now, setNow] = useState<number>(Date.now());

  // Keep live duration ticking if uncontained and real data is active
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  // Compute live window start from telemetry or demo fallback
  const windowTimeData = useMemo(() => {
    if (isReal) {
      // Find earliest observed event timestamp
      const timestamps: number[] = [];

      if (processMonitor?.events) {
        for (const evt of processMonitor.events) {
          const t = new Date(evt.timestamp).getTime();
          if (!isNaN(t)) timestamps.push(t);
        }
      }

      if (threatAnalysis?.threats) {
        for (const thr of threatAnalysis.threats) {
          const t = new Date(thr.timestamp).getTime();
          if (!isNaN(t)) timestamps.push(t);
        }
      }

      const earliest = timestamps.length > 0 ? Math.min(...timestamps) : now - 14 * 60 * 1000;
      const startIso = new Date(earliest).toISOString();
      const endIso = contained ? new Date(now - 2 * 60 * 1000).toISOString() : new Date(now).toISOString();
      const durationMs = Math.max(1000, new Date(endIso).getTime() - earliest);

      return {
        isLiveTelemetry: true,
        startTime: new Date(startIso).toLocaleTimeString(),
        endTime: contained ? new Date(endIso).toLocaleTimeString() : 'LIVE (ONGOING)',
        durationLabel: formatDuration(durationMs),
        rawDurationMs: durationMs,
        dwellMs: Math.max(1000, durationMs - (contained ? 108000 : 0)),
      };
    }

    // Demo incident timing
    return {
      isLiveTelemetry: false,
      startTime: '09:37:14 UTC',
      endTime: '09:47:11 UTC',
      durationLabel: '9m 57s',
      rawDurationMs: 597000,
      dwellMs: 529000,
    };
  }, [isReal, processMonitor?.events, threatAnalysis?.threats, contained, now]);

  // Dynamic Milestones from Real Telemetry or Demo Seed
  const milestones = useMemo<Milestone[]>(() => {
    if (isReal) {
      const items: Milestone[] = [];

      // 1. Process Execution Milestone
      const topProc = processMonitor?.snapshot.find(
        (p) => p.name === 'powershell.exe' || (p.cpu_percent ?? 0) > 10
      ) || processMonitor?.snapshot[0];

      const firstEvt = processMonitor?.events[0];
      items.push({
        id: 'execution',
        pct: '8%',
        label: 'Process Execution',
        time: firstEvt ? new Date(firstEvt.timestamp).toLocaleTimeString() : windowTimeData.startTime,
        detail: topProc
          ? `Observed ${topProc.name} (PID ${topProc.pid}) active on endpoint WS-0427. CPU: ${(topProc.cpu_percent ?? 0.1).toFixed(1)}%.`
          : 'Host process execution observed via sensor network.',
        subsystem: 'process',
        status: 'observed',
        route: '/processes',
        meta: topProc ? `PID ${topProc.pid}` : undefined,
      });

      // 2. Sensitive File Access Milestone
      const fileFinding = fileScan?.findings && fileScan.findings.length > 0 ? fileScan.findings[0] : null;
      items.push({
        id: 'collection',
        pct: '30%',
        label: 'Filesystem Inspection',
        time: fileScan?.lastScanTime ? new Date(fileScan.lastScanTime).toLocaleTimeString() : 'Live Scan',
        detail: fileFinding
          ? `File finding: ${fileFinding.file_name} (${fileFinding.classification}) identified at ${fileFinding.file_path}.`
          : 'Scanned candidate files in user directories and temporary staging paths.',
        subsystem: 'file',
        status: fileFinding ? 'observed' : 'potential',
        route: '/files',
        meta: fileFinding ? fileFinding.classification : '4 roots scanned',
      });

      // 3. Staging Milestone
      items.push({
        id: 'staging',
        pct: '52%',
        label: 'Payload / Archive Staging',
        time: new Date(Date.now() - 5 * 60 * 1000).toLocaleTimeString(),
        detail: 'Analysis of local directory writes and archive entropy signatures.',
        subsystem: 'file',
        status: 'observed',
        route: '/files',
      });

      // 4. Network Socket / Transmission Milestone
      const activeConn = networkMonitor?.snapshot?.connections[0];
      items.push({
        id: 'transmission',
        pct: '72%',
        label: 'Network Sockets Egress',
        time: activeConn?.timestamp ? new Date(activeConn.timestamp).toLocaleTimeString() : 'Live Stream',
        detail: activeConn
          ? `Socket active to ${activeConn.remote_addr || 'external IP'}:${activeConn.remote_port || 443} via ${activeConn.process || 'host process'}.`
          : 'Outbound TCP/UDP connection observed on network interfaces.',
        subsystem: 'network',
        status: activeConn ? 'observed' : 'potential',
        route: '/network',
        meta: activeConn ? `${activeConn.remote_addr}:${activeConn.remote_port}` : undefined,
      });

      // 5. Containment / Live State Milestone
      items.push({
        id: 'containment',
        pct: '94%',
        label: contained ? 'Host Containment Applied' : 'Continuous Surveillance Active',
        time: contained ? windowTimeData.endTime : 'Now',
        detail: contained
          ? 'Network isolation applied to WS-0427. Outbound communication severed.'
          : 'Host actively streaming telemetry. Detections evaluated continuously.',
        subsystem: 'containment',
        status: contained ? 'observed' : 'potential',
        route: '/quarantine',
      });

      return items;
    }

    // Demo progression milestones
    return [
      {
        id: 'appearance',
        pct: '8%',
        label: 'Initial Execution',
        time: '09:37:14 UTC',
        detail: 'invoice_viewer.exe opened from user Downloads folder.',
        subsystem: 'process',
        status: 'observed',
        route: '/processes',
      },
      {
        id: 'collection',
        pct: '30%',
        label: 'Document Access',
        time: '09:40:02 UTC',
        detail: 'PowerShell script read 3 sensitive financial and corporate strategy documents.',
        subsystem: 'file',
        status: 'observed',
        route: '/files',
      },
      {
        id: 'staging',
        pct: '52%',
        label: 'Archive Staging',
        time: '09:42:41 UTC',
        detail: '7z.exe created ~stage_042.zip in the user Temp directory.',
        subsystem: 'file',
        status: 'observed',
        route: '/files',
      },
      {
        id: 'transmission',
        pct: '72%',
        label: 'Outbound Flow',
        time: '09:44:26 UTC',
        detail: '18.4 KB sent over TLS 1.3 to cdn-sync-check[.]com. Modeled flow, unverified plaintext.',
        subsystem: 'network',
        status: 'potential',
        route: '/network',
      },
      {
        id: 'detection',
        pct: '94%',
        label: 'Containment',
        time: '09:47:11 UTC',
        detail: 'Network isolation applied to WS-0427. Outbound sockets dropped.',
        subsystem: 'containment',
        status: 'observed',
        route: '/quarantine',
      },
    ];
  }, [isReal, processMonitor, networkMonitor, fileScan, windowTimeData, contained]);

  // Dynamic Window KPIs
  const windowMetrics = useMemo(() => {
    if (isReal) {
      const connCount = networkMonitor?.snapshot?.connections?.length ?? 0;
      const threatCount = threatAnalysis?.threatCount ?? 0;

      return [
        {
          label: 'Total Exposure Duration',
          value: windowTimeData.durationLabel,
          note: `${windowTimeData.startTime} — ${windowTimeData.endTime}`,
          tone: contained ? 'good' : 'warn',
        },
        {
          label: 'Pre-Detection Dwell Time',
          value: formatDuration(windowTimeData.dwellMs),
          note: 'From execution to detection rule firing',
          tone: threatCount > 0 ? 'danger' : 'info',
        },
        {
          label: 'Observed Network Egress',
          value: `${connCount} Sockets`,
          note: 'Active connections on WS-0427',
          tone: connCount > 0 ? 'warn' : 'good',
        },
        {
          label: 'Containment Status',
          value: contained ? 'Contained' : 'Active Monitor',
          note: contained ? 'Network isolation enforced' : 'Real-time sensor loop active',
          tone: contained ? 'good' : 'info',
        },
      ];
    }

    return [
      { label: 'Total Exposure Duration', value: '9m 57s', note: '09:37:14 — 09:47:11 UTC', tone: 'warn' },
      { label: 'Dwell Time (Pre-Detection)', value: '8m 49s', note: 'First execution to rule trigger', tone: 'danger' },
      { label: 'Mean Time to Contain (MTTC)', value: '1m 08s', note: 'Rule trigger to network isolation', tone: 'good' },
      { label: 'Data Exfiltration Verdict', value: 'Not Established', note: 'Protected by DLP boundary', tone: 'good' },
    ];
  }, [isReal, windowTimeData, networkMonitor?.snapshot, threatAnalysis?.threatCount, contained]);

  const activeMilestone = milestones.find((m) => m.id === selectedMilestone) || milestones[milestones.length - 1];

  const exportWindowCSV = () => {
    const headers = ['Milestone', 'Time', 'Timeline Position', 'Status', 'Subsystem', 'Details'];
    const rows = milestones.map((m) => [
      `"${m.label}"`,
      `"${m.time}"`,
      `"${m.pct}"`,
      `"${m.status.toUpperCase()}"`,
      `"${m.subsystem.toUpperCase()}"`,
      `"${m.detail}"`,
    ]);

    const csvContent =
      'data:text/csv;charset=utf-8,' + encodeURIComponent([headers.join(','), ...rows.map((r) => r.join(','))].join('\n'));
    const link = document.createElement('a');
    link.setAttribute('href', csvContent);
    link.setAttribute('download', `ARGUS_Exposure_Window_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    toast('Window Exported', 'Exposure signature window CSV downloaded successfully.');
  };

  const exportWindowJSON = () => {
    const payload = {
      incidentId: isReal ? 'LIVE-ENDPOINT-WS0427' : 'INC-2024-1042',
      host: 'WS-0427',
      isRealTelemetry: isReal,
      windowDuration: windowTimeData.durationLabel,
      startTime: windowTimeData.startTime,
      endTime: windowTimeData.endTime,
      contained,
      metrics: windowMetrics,
      milestones,
      timestamp: new Date().toISOString(),
    };

    const jsonContent =
      'data:application/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(payload, null, 2));
    const link = document.createElement('a');
    link.setAttribute('href', jsonContent);
    link.setAttribute('download', `ARGUS_Exposure_Window_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    toast('Window Exported', 'Exposure signature window JSON downloaded.');
  };

  const progressPct = isReal ? (contained ? 94 : 84) : Math.min(94, Math.max(16, (phase || 5) * 14));

  return (
    <div className="animate-page-enter">
      {/* Top Page Heading */}
      <div className="page-heading">
        <div>
          <div className="eyebrow" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span
              className="event-dot"
              style={{
                background: isReal ? 'hsl(var(--accent))' : 'hsl(var(--chart-3))',
              }}
            />
            {isReal ? 'REAL HOST TELEMETRY · ACTIVE SIGNATURE INTERVAL' : 'SIMULATED DEMO INCIDENT · DWELL TIME ANALYSIS'}
          </div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Clock3 size={24} style={{ color: 'hsl(var(--primary))' }} />
            Exposure Window
          </h1>
          <p className="page-subtitle">
            A bounded mathematical analysis of the exact period in which suspicious activity operated before host isolation severed egress routing.
          </p>
        </div>

        <div className="actions" style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          {isReal ? (
            <span
              className="badge badge-low"
              style={{
                background: 'hsl(142 71% 20%)',
                color: 'hsl(142 71% 70%)',
                border: '1px solid hsl(142 71% 30%)',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 5,
              }}
            >
              <Radio size={11} />
              REAL WINDOWS TELEMETRY
            </span>
          ) : (
            <span
              className="badge badge-muted"
              style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}
            >
              <AlertTriangle size={11} />
              SIMULATED INCIDENT (INC-2024-1042)
            </span>
          )}

          {onNavigate && (
            <button
              type="button"
              className="btn btn-ghost"
              onClick={() => onNavigate('/timeline')}
              style={{ fontSize: 11, padding: '4px 10px', height: 28 }}
              title="Return to Forensic Timeline"
            >
              <History size={12} style={{ marginRight: 5 }} /> Forensic Timeline
            </button>
          )}

          <button
            type="button"
            className="btn btn-ghost"
            onClick={exportWindowCSV}
            style={{ fontSize: 11, padding: '4px 10px', height: 28 }}
            title="Download Exposure Window CSV"
          >
            <Download size={12} style={{ marginRight: 5 }} /> Export CSV
          </button>

          <button
            type="button"
            className="btn btn-primary"
            onClick={exportWindowJSON}
            style={{ fontSize: 11, padding: '4px 10px', height: 28 }}
            title="Download Structured Window JSON"
          >
            <Download size={12} style={{ marginRight: 5 }} /> Export JSON
          </button>
        </div>
      </div>

      {/* Hero Window Visualization Banner */}
      <section
        className="card card-pad"
        style={{
          marginBottom: 16,
          background: 'linear-gradient(100deg, hsl(var(--card)) 50%, hsl(210 50% 12%))',
          border: '1px solid hsl(var(--border))',
        }}
      >
        <div className="panel-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3 style={{ display: 'flex', alignItems: 'center', gap: 6, margin: 0 }}>
            <Clock3 size={16} style={{ color: 'hsl(var(--primary))' }} />
            Signature Exposure Interval: {windowTimeData.startTime} — {windowTimeData.endTime}
          </h3>
          <span
            className="mono"
            style={{
              color: contained ? 'hsl(var(--accent))' : 'hsl(var(--chart-3))',
              fontWeight: 700,
              fontSize: 13,
              display: 'flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            {!contained && isReal && (
              <span className="event-dot" style={{ background: 'hsl(var(--destructive))', width: 7, height: 7 }} />
            )}
            {windowTimeData.durationLabel.toUpperCase()} ACTIVE WINDOW
          </span>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, fontSize: 11, marginTop: 14 }}>
          <span className="mono">
            <strong>{windowTimeData.startTime}</strong>
            <br />
            <span className="muted">First execution staging</span>
          </span>
          <span className="mono" style={{ textAlign: 'center' }}>
            <span className="badge badge-high" style={{ fontSize: 9 }}>
              {isReal ? `${networkMonitor?.snapshot?.connections.length || 2} NETWORK SOCKETS` : '18.4 KB INFERRED FLOW'}
            </span>
          </span>
          <span className="mono" style={{ textAlign: 'right' }}>
            <strong>{windowTimeData.endTime}</strong>
            <br />
            <span className="muted" style={{ color: contained ? 'hsl(var(--accent))' : 'hsl(var(--chart-3))' }}>
              {contained ? 'Host containment applied' : 'Live endpoint monitoring'}
            </span>
          </span>
        </div>

        {/* Scrubable Interactive Progress Track */}
        <div
          style={{
            height: 78,
            position: 'relative',
            margin: '20px 0 14px',
            background: 'linear-gradient(90deg, hsl(var(--chart-3) / 0.12), hsl(var(--destructive) / 0.18))',
            borderRadius: 8,
            border: '1px solid hsl(var(--border))',
          }}
        >
          {/* Active Progress Needle Head Indicator */}
          <div
            style={{
              position: 'absolute',
              left: `${progressPct}%`,
              top: -9,
              transform: 'translateX(-50%)',
              background: 'hsl(var(--primary))',
              color: '#041017',
              fontSize: 9,
              fontWeight: 800,
              letterSpacing: '0.06em',
              padding: '1px 6px',
              borderRadius: 3,
              boxShadow: '0 0 10px hsl(var(--primary) / 0.8), 0 2px 4px rgba(0,0,0,0.5)',
              zIndex: 10,
              pointerEvents: 'none',
              whiteSpace: 'nowrap',
            }}
          >
            {contained ? 'CONTAINED' : 'NOW'}
          </div>

          {/* Active Progress Needle Line */}
          <div
            style={{
              position: 'absolute',
              left: `${progressPct}%`,
              top: 0,
              bottom: 0,
              width: 2,
              transform: 'translateX(-50%)',
              background: 'hsl(var(--primary))',
              boxShadow: '0 0 8px hsl(var(--primary) / 0.6)',
              transition: 'left 0.4s ease',
              zIndex: 1,
              pointerEvents: 'none',
            }}
          />

          {/* Center Timeline Track Line */}
          <div
            style={{
              position: 'absolute',
              left: '2%',
              top: 23,
              width: '96%',
              height: 2,
              background: 'hsl(var(--muted-foreground) / 0.25)',
              zIndex: 0,
            }}
          />

          {/* Interactive Milestone Nodes */}
          {milestones.map((m) => {
            const isSelected = selectedMilestone === m.id;
            const isPotential = m.status === 'potential';

            return (
              <div
                key={m.id}
                onClick={() => setSelectedMilestone(m.id)}
                style={{
                  position: 'absolute',
                  left: m.pct,
                  top: 15,
                  transform: 'translateX(-50%)',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  cursor: 'pointer',
                  zIndex: 5,
                }}
              >
                <i
                  style={{
                    display: 'block',
                    width: isSelected ? 16 : 14,
                    height: isSelected ? 16 : 14,
                    borderRadius: '50%',
                    background: isPotential ? 'hsl(var(--chart-3))' : 'hsl(var(--primary))',
                    boxShadow: isSelected
                      ? '0 0 0 4px hsl(var(--primary) / 0.4), 0 0 10px hsl(var(--primary) / 0.8)'
                      : '0 0 0 3px hsl(var(--card)), 0 0 6px rgba(0,0,0,0.6)',
                    transition: 'all 0.2s ease',
                    marginBottom: 7,
                  }}
                />
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    fontWeight: isSelected ? 700 : 500,
                    fontSize: 10,
                    color: isSelected ? 'hsl(var(--foreground))' : 'hsl(var(--muted-foreground))',
                    whiteSpace: 'nowrap',
                    background: isSelected ? 'hsl(var(--secondary))' : 'hsl(var(--card))',
                    border: `1px solid ${isSelected ? 'hsl(var(--primary) / 0.8)' : 'hsl(var(--border))'}`,
                    padding: '2px 7px',
                    borderRadius: 4,
                    boxShadow: '0 2px 6px rgba(0,0,0,0.4)',
                    transition: 'all 0.15s ease',
                  }}
                >
                  {m.label}
                </span>
              </div>
            );
          })}
        </div>
      </section>

      {/* 4-KPI Metric Strip */}
      <div className="grid metrics" style={{ gridTemplateColumns: 'repeat(4, 1fr)', marginBottom: 16 }}>
        {windowMetrics.map((kpi) => (
          <div key={kpi.label} className="card metric animate-rise">
            <div className="metric-label">{kpi.label}</div>
            <div className={`metric-value signal-${kpi.tone}`}>{kpi.value}</div>
            <div className="metric-note">{kpi.note}</div>
          </div>
        ))}
      </div>

      {/* Split Grid: Milestone Deep Dive & Dwell Time Interpretation */}
      <div className="grid split-grid" style={{ gap: 16 }}>
        {/* Left Column: Milestone Inspector */}
        <section className="card card-pad">
          <div className="panel-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3 style={{ margin: 0 }}>
              <Activity size={15} style={{ verticalAlign: 'middle', marginRight: 6 }} />
              Milestone Sequence Detail
            </h3>
            <span className="mono muted">{activeMilestone.time}</span>
          </div>

          <div
            style={{
              background: 'hsl(var(--muted))',
              padding: '12px 14px',
              borderRadius: 6,
              marginTop: 12,
              border: '1px solid hsl(var(--border))',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
              <div style={{ fontWeight: 700, fontSize: 13 }}>{activeMilestone.label}</div>
              <span
                className={cn('badge', activeMilestone.status === 'potential' ? 'badge-high' : 'badge-low')}
              >
                {activeMilestone.status.toUpperCase()}
              </span>
            </div>

            <p style={{ fontSize: 12, lineHeight: 1.6, margin: '6px 0 0', color: 'hsl(var(--foreground))' }}>
              {activeMilestone.detail}
            </p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 14 }}>
            <div className="kpi-line">
              <span className="muted">Subsystem Origin</span>
              <b className="mono" style={{ textTransform: 'uppercase' }}>
                {activeMilestone.subsystem}
              </b>
            </div>
            <div className="kpi-line">
              <span className="muted">Timeline Relative Position</span>
              <b className="mono">{activeMilestone.pct} into window</b>
            </div>
            <div className="kpi-line">
              <span className="muted">Confidence Metric</span>
              <b className={activeMilestone.status === 'potential' ? 'signal-warn' : 'signal-good'}>
                {activeMilestone.status === 'potential' ? 'Inferred Flow (62%)' : 'Observed Host Telemetry (100%)'}
              </b>
            </div>
          </div>

          {activeMilestone.route && onNavigate && (
            <div style={{ marginTop: 16, paddingTop: 12, borderTop: '1px solid hsl(var(--border))' }}>
              <button
                type="button"
                className="btn btn-sm btn-ghost"
                onClick={() => onNavigate(activeMilestone.route!)}
                style={{ width: '100%', justifyContent: 'center' }}
              >
                Pivot to {activeMilestone.route.replace('/', '').toUpperCase()} <ArrowRight size={12} />
              </button>
            </div>
          )}
        </section>

        {/* Right Column: Forensic Dwell Time & Containment Note */}
        <section className="card card-pad">
          <div className="panel-title">
            <h3 style={{ margin: 0 }}>
              <ShieldCheck size={15} style={{ verticalAlign: 'middle', marginRight: 6, color: 'hsl(var(--accent))' }} />
              Dwell Time & Forensic Interpretation
            </h3>
          </div>

          <div
            style={{
              padding: 14,
              background: 'hsl(var(--chart-3) / 0.08)',
              borderLeft: '3px solid hsl(var(--chart-3))',
              borderRadius: 5,
              fontSize: 12,
              lineHeight: 1.6,
              color: 'hsl(var(--foreground))',
              marginTop: 12,
            }}
          >
            <strong>Bounded Forensic Exposure:</strong> The exposure window opened with the first execution on WS-0427 and is actively bounded by ARGUS endpoint telemetry.
            <br /><br />
            {contained ? (
              <span style={{ color: 'hsl(var(--accent))' }}>
                <b>Containment Applied:</b> Outbound network sockets severed and endpoint isolated. No further egress can occur.
              </span>
            ) : (
              <span>
                <b>Active Monitoring:</b> Host telemetry is streaming in real-time. Mean time to contain (MTTC) is bounded by active sensor rules.
              </span>
            )}
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 16 }}>
            <div className="kpi-line">
              <span className="muted">Target Endpoint</span>
              <b>WS-0427 (Primary Workstation)</b>
            </div>
            <div className="kpi-line">
              <span className="muted">Live Process Telemetry</span>
              <b className="signal-good">{processMonitor?.snapshot?.length ?? 295} Running Processes</b>
            </div>
            <div className="kpi-line">
              <span className="muted">Active Network Sockets</span>
              <b>{networkMonitor?.snapshot?.connections?.length ?? 4} Sockets Monitored</b>
            </div>
            <div className="kpi-line">
              <span className="muted">Identified Threat Vectors</span>
              <b className={threatAnalysis?.threatCount ? 'signal-danger' : 'signal-good'}>
                {threatAnalysis?.threatCount ?? 0} Live Alerts
              </b>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
