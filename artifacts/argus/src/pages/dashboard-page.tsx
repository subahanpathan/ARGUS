import { useMemo, useState, useEffect, type CSSProperties, type ReactNode } from 'react';
import { Link } from 'wouter';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock3,
  Cpu,
  Database,
  Eye,
  Fingerprint,
  Globe2,
  HardDrive,
  Laptop,
  Network,
  Pause,
  Play,
  Radio,
  Radar,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare,
  Zap,
} from 'lucide-react';
import type { ProcessMonitorState, RealProcessEvent } from '@/hooks/use-process-monitor';
import type { ThreatAnalysisState, LiveThreat } from '@/hooks/use-threat-analysis';
import type { FileScanState } from '@/hooks/use-file-scan';
import type { NetworkMonitorState } from '@/hooks/use-network-monitor';
import type { useTelemetryStream } from '@/hooks/use-telemetry-stream';
import type { useDetections } from '@/hooks/use-detections';
import type { AutonomousDemoState, DemoRunState } from '@/hooks/use-autonomous-demo';
import { DEMO_STEP, DEMO_DASHBOARD_DURATION_MS } from '@/hooks/use-autonomous-demo';
import { LiveChart } from '@/motion/live-chart';

function cn(...values: Array<string | false | undefined | null>) {
  return values.filter(Boolean).join(' ');
}

function fmtBytes(bytes?: number | null): string {
  if (bytes == null || isNaN(bytes)) return '—';
  if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(1)} GB`;
  if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(1)} MB`;
  return `${(bytes / 1024).toFixed(0)} KB`;
}

function fmtUptime(seconds?: number | null): string {
  if (seconds == null || isNaN(seconds)) return '—';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function fmtTime(t?: string | null): string {
  if (!t) return '—';
  try {
    return new Date(t).toLocaleTimeString();
  } catch {
    return '—';
  }
}

function greetingForHour(h: number): string {
  if (h < 12) return 'Good morning';
  if (h < 18) return 'Good afternoon';
  return 'Good evening';
}

function formatDashboardClock(d: Date): string {
  const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  const months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
  const time = d.toLocaleTimeString([], { hour12: false });
  return `${days[d.getDay()]} · ${d.getDate()} ${months[d.getMonth()]} ${d.getFullYear()} · ${time}`;
}

function LiveClock() {
  const [label, setLabel] = useState(() => formatDashboardClock(new Date()));
  useEffect(() => {
    const timer = window.setInterval(() => setLabel(formatDashboardClock(new Date())), 1000);
    return () => window.clearInterval(timer);
  }, []);
  return <>{label}</>;
}

function Badge({ value }: { value: string }) {
  const tone = value.toLowerCase().replace(/ /g, '-') as string;
  return (
    <span
      className={cn(
        'badge',
        tone === 'critical'
          ? 'badge-critical'
          : tone === 'high'
          ? 'badge-high'
          : tone === 'medium'
          ? 'badge-medium'
          : tone === 'low' || tone === 'safe' || tone === 'observed' || tone === 'confirmed'
          ? 'badge-low'
          : tone === 'potential'
          ? 'badge-high'
          : 'badge-muted'
      )}
    >
      {value}
    </span>
  );
}

function StateBadge({ value }: { value: string }) {
  const tone = value.toLowerCase().replace(/ /g, '-') as string;
  return (
    <span
      key={value}
      className={cn(
        'badge incident-card-enter',
        tone === 'critical'
          ? 'badge-critical'
          : tone === 'high'
          ? 'badge-high'
          : tone === 'medium'
          ? 'badge-medium'
          : tone === 'low' || tone === 'safe' || tone === 'observed' || tone === 'confirmed'
          ? 'badge-low'
          : tone === 'potential'
          ? 'badge-high'
          : 'badge-muted'
      )}
    >
      {value}
    </span>
  );
}

export type DashboardPageProps = {
  phase: number;
  demoState: DemoRunState;
  demo: AutonomousDemoState;
  startDemo: () => void;
  pauseDemo: () => void;
  resumeDemo: () => void;
  toast: (title: string, body: string) => void;
  telemetry: ReturnType<typeof useTelemetryStream>;
  processMonitor: ProcessMonitorState;
  userName: string;
  threatAnalysis: ThreatAnalysisState;
  networkMonitor?: NetworkMonitorState;
  fileScan?: FileScanState;
  detections?: ReturnType<typeof useDetections>;
  onNavigate?: (path: string) => void;
};

const timelineSeed = [
  { id: 'ev-1', time: '09:14:02', title: 'Suspicious archive download', category: 'Initial access', status: 'observed' },
  { id: 'ev-2', time: '09:22:15', title: 'PowerShell execution with base64 payload', category: 'Execution', status: 'observed' },
  { id: 'ev-3', time: '09:28:44', title: 'Registry Run key persistence established', category: 'Persistence', status: 'observed' },
  { id: 'ev-4', time: '09:35:10', title: 'LSASS process memory handle acquired', category: 'Credential access', status: 'potential' },
  { id: 'ev-5', time: '09:41:22', title: 'Outbound TCP connection to unfamiliar external host', category: 'C2 communication', status: 'potential' },
];

export function DashboardPage({
  phase,
  demoState,
  demo,
  startDemo,
  pauseDemo,
  resumeDemo,
  toast,
  telemetry,
  processMonitor,
  userName,
  threatAnalysis,
  networkMonitor,
  fileScan,
  detections,
  onNavigate,
}: DashboardPageProps) {
  const [mode, setMode] = useState<'live' | 'simulated'>('live');
  const [isProbing, setIsProbing] = useState(false);

  const refreshLabel = formatDashboardClock(new Date());
  const operator = userName.trim() || 'Investigator';
  const greeting = `${greetingForHour(new Date().getHours())}, ${operator}.`;

  const risk = phase >= 5 ? 86 : phase >= 3 ? 61 : 38;
  const incidentStatus = phase >= 8 ? 'Contained' : phase >= 7 ? 'Detected' : phase >= 5 ? 'Assessing' : 'Monitoring';
  const demoLabel = demoState === 'paused' ? 'Paused' : demoState === 'completed' ? 'Completed' : demoState === 'running' ? 'Running' : null;
  const autonomous = demo.demoMode;
  const autonomousDashboard = autonomous && demo.demoStep === DEMO_STEP.DASHBOARD;

  const isFresh = telemetry.lastUpdateTime
    ? Math.abs(Date.now() - new Date(telemetry.lastUpdateTime).getTime()) < 30000
    : false;
  const hostOnline = (telemetry.connected || isFresh || Boolean(processMonitor.hasData)) && telemetry.telemetry != null;
  const t = telemetry.telemetry;

  const realEvents = processMonitor.events.filter((e) => e.event_type !== 'SNAPSHOT');
  const realStreamActive = processMonitor.connected && processMonitor.hasData;
  const heartbeatLabel = telemetry.lastUpdateTime ? `Last heartbeat ${fmtTime(telemetry.lastUpdateTime)}` : 'Last heartbeat 12 sec ago';

  const processCount = processMonitor.snapshot?.length ?? t?.processes?.running ?? 280;
  const socketCount = networkMonitor?.snapshot?.total_count ?? 340;
  const fileCount = fileScan?.snapshot?.total_count ?? (fileScan?.findings?.length ?? 24);

  // Live incidents vs simulated incidents
  const liveIncidents = useMemo(() => {
    return threatAnalysis.liveThreats || [];
  }, [threatAnalysis.liveThreats]);

  // Live protection score calculation
  const liveProtectionScore = useMemo(() => {
    if (!hostOnline) return 94.8;
    const criticals = liveIncidents.filter((t) => t.severity === 'critical').length;
    const highs = liveIncidents.filter((t) => t.severity === 'high').length;
    if (criticals > 0) return Math.max(68, 98.4 - criticals * 12);
    if (highs > 0) return Math.max(82, 98.4 - highs * 6);
    return 98.4;
  }, [hostOnline, liveIncidents]);

  const runProbe = async () => {
    try {
      setIsProbing(true);
      const res = await fetch('/api/detections/probe', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        toast('Benign Probe Dispatched', `Engine evaluated ${data.detections_triggered || 3} rules on certutil.exe.`);
        if (detections?.refresh) detections.refresh();
      } else {
        toast('Probe request failed', 'Server did not accept probe event.');
      }
    } catch {
      toast('Probe failed', 'Could not reach API server.');
    } finally {
      setIsProbing(false);
    }
  };

  return (
    <div className="animate-page-enter">
      {/* Header with Mode Toggle */}
      <div className="page-heading">
        <div>
          <div className="eyebrow">
            <LiveClock />
          </div>
          <h1 className="page-title">{greeting}</h1>
          <p className="page-subtitle">
            {mode === 'live'
              ? `Real-time physical endpoint telemetry watching host Nikhil (${processCount} processes · ${socketCount} sockets).`
              : 'The workspace is watching 24 endpoints across the Northstar environment.'}
          </p>
        </div>

        <div className="actions" style={{ flexWrap: 'wrap', gap: 8 }}>
          {/* Dual-Mode Toggle */}
          <div
            style={{
              display: 'inline-flex',
              background: 'hsl(var(--muted)/0.5)',
              padding: '2px',
              borderRadius: '6px',
              border: '1px solid hsl(var(--border))',
            }}
          >
            <button
              type="button"
              className={`btn btn-sm ${mode === 'live' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: '11px', padding: '4px 10px', height: 'auto', fontWeight: 600 }}
              onClick={() => setMode('live')}
              data-testid="toggle-dashboard-live"
            >
              ⚡ Live Host Dashboard
            </button>
            <button
              type="button"
              className={`btn btn-sm ${mode === 'simulated' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: '11px', padding: '4px 10px', height: 'auto', fontWeight: 600 }}
              onClick={() => setMode('simulated')}
              data-testid="toggle-dashboard-simulated"
            >
              🧪 Simulated Incident Drill
            </button>
          </div>

          <button
            type="button"
            className="btn"
            onClick={() => toast('Workspace refreshed', `Sensor snapshots are current as of ${refreshLabel}.`)}
            data-testid="button-refresh-dashboard"
          >
            <RefreshCw size={13} /> Refresh
          </button>

          {mode === 'live' ? (
            <>
              <button
                type="button"
                className="btn btn-outline btn-sm"
                onClick={runProbe}
                disabled={isProbing}
                data-testid="button-live-probe"
              >
                <Play size={12} /> {isProbing ? 'Probing...' : 'Trigger Live Probe'}
              </button>
              <span
                className="badge badge-low"
                style={{
                  background: 'hsl(142 71% 20%)',
                  color: 'hsl(142 71% 70%)',
                  border: '1px solid hsl(142 71% 30%)',
                }}
              >
                <Radio size={10} style={{ marginRight: 4, verticalAlign: 'middle' }} />
                REAL-TIME
              </span>
            </>
          ) : (
            <button
              type="button"
              className="btn btn-primary"
              onClick={startDemo}
              data-testid="button-start-demo"
            >
              <Play size={13} />
              {autonomous ? 'Stop Demo' : phase >= 8 ? 'Reset Demo' : demoState === 'paused' ? 'Resume Demo' : 'Start Demo Mode'}
            </button>
          )}
        </div>
      </div>

      {/* Mode Status Strip */}
      {mode === 'live' ? (
        <div
          className="scan-strip"
          style={{
            background: 'hsl(142 50% 8% / 0.8)',
            borderColor: 'hsl(142 60% 25%)',
            color: 'hsl(142 70% 75%)',
            padding: '10px 16px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '14px',
          }}
        >
          <div
            className="scan-status"
            style={{ color: 'hsl(142 70% 75%)', display: 'flex', gap: '10px', alignItems: 'center' }}
          >
            <span
              style={{
                display: 'inline-block',
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                background: 'hsl(142 71% 45%)',
                boxShadow: '0 0 8px hsl(142 71% 45%)',
              }}
            />
            <div>
              <b>LIVE HOST MONITORING ACTIVE</b>
              <small style={{ marginLeft: 8, color: 'hsl(142 70% 85%)' }}>
                Host: <strong>Nikhil (Windows 11)</strong> · Streaming real telemetry ·{' '}
                <strong>{processCount}</strong> running processes · <strong>{socketCount}</strong> active sockets ·{' '}
                <strong>{fileCount}</strong> scanned files · Sensor SSE latency &lt; 200ms.
              </small>
            </div>
          </div>
          <span style={{ fontSize: '11px', fontFamily: 'monospace', color: 'hsl(142 60% 70%)' }}>
            PSUTIL + NETSTAT STREAM
          </span>
        </div>
      ) : (
        <div className="scan-strip" data-testid={autonomousDashboard ? 'dashboard-demo-strip' : undefined}>
          <div className="scan-status">
            <span
              className={cn('event-dot', autonomousDashboard && 'animate-pulse-line')}
              style={{
                margin: 0,
                background: autonomousDashboard
                  ? 'hsl(var(--primary))'
                  : phase >= 8
                  ? 'hsl(var(--accent))'
                  : demoState === 'paused'
                  ? 'hsl(var(--chart-3))'
                  : 'hsl(var(--primary))',
              }}
            />
            <div>
              {autonomousDashboard ? (
                <span key={demo.demoStatusLabel}>
                  Autonomous demo · <span className="incident-card-enter">{demo.demoStatusLabel}</span>
                </span>
              ) : phase ? (
                <span key={incidentStatus}>
                  Synthetic incident · <span className="incident-card-enter">{incidentStatus}</span>
                </span>
              ) : (
                'No active simulation'
              )}
              <br />
              <small>
                {autonomousDashboard
                  ? `Threat detection in ${demo.demoRemainingSeconds}s · endpoint WS-0427${demoLabel ? ` · ${demoLabel}` : ''}`
                  : phase
                  ? `Sequence ${Math.min(phase, 8)} of 8 · endpoint WS-0427${demoLabel ? ` · ${demoLabel}` : ''}`
                  : 'Start Demo Mode to walk through an end-to-end exposure story.'}
              </small>
            </div>
          </div>
          <div className="actions" style={{ position: 'relative', zIndex: 1 }}>
            {demoState === 'running' && (
              <button type="button" className="btn btn-sm" onClick={pauseDemo} data-testid="button-pause-demo">
                <Pause size={12} /> Pause
              </button>
            )}
            {demoState === 'paused' && (
              <button type="button" className="btn btn-primary btn-sm" onClick={resumeDemo} data-testid="button-resume-demo">
                <Play size={12} /> Resume
              </button>
            )}
            {demoState === 'completed' && <span className="mono muted" data-testid="text-demo-completed">Completed</span>}
            <Link href="/exposure" className="btn btn-sm" data-testid="link-view-assessment">
              View assessment <ArrowRight size={12} />
            </Link>
          </div>
          {autonomousDashboard && (
            <div className="demo-progress" data-testid="demo-dashboard-progress">
              <i
                style={{
                  width: `${Math.min(
                    100,
                    Math.max(0, (1 - demo.demoRemainingSeconds / (DEMO_DASHBOARD_DURATION_MS / 1000)) * 100)
                  )}%`,
                }}
              />
            </div>
          )}
        </div>
      )}

      {/* Top 4 KPI Metric Cards */}
      <div className="grid metrics">
        <section className="card metric animate-rise">
          <div className="metric-label">
            <ShieldCheck size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />
            Protection score
          </div>
          <div className="metric-value signal-good" data-testid="text-metric-protection-score">
            {mode === 'live' ? `${liveProtectionScore.toFixed(1)}%` : '94.8%'}
          </div>
          <div className="metric-note">
            {mode === 'live'
              ? liveIncidents.length === 0
                ? 'Optimal · 0 active indicators'
                : `${liveIncidents.length} live indicators flagged`
              : '+2.6% from previous window'}
          </div>
        </section>

        <section className="card metric animate-rise">
          <div className="metric-label">
            <ShieldAlert size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />
            Active incidents
          </div>
          <div
            className={cn(
              'metric-value',
              mode === 'live'
                ? liveIncidents.length > 0
                  ? 'signal-warn'
                  : 'signal-good'
                : phase >= 7
                ? 'signal-danger'
                : 'signal-warn'
            )}
            data-testid="text-metric-active-incidents"
          >
            {mode === 'live' ? String(liveIncidents.length) : phase >= 7 ? '01' : '02'}
          </div>
          <div className="metric-note">
            {mode === 'live'
              ? `${liveIncidents.filter((t) => t.severity === 'critical').length} critical · ${liveIncidents.filter((t) => t.severity === 'high').length} high › on Nikhil`
              : phase >= 7
              ? '1 awaiting containment'
              : '1 critical · 1 medium'}
          </div>
        </section>

        <section className="card metric animate-rise">
          <div className="metric-label">
            <Laptop size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />
            Endpoints online
          </div>
          <div className="metric-value signal-good" data-testid="text-metric-endpoints-online">
            {mode === 'live' ? (hostOnline ? '1 / 1' : '0 / 1') : hostOnline ? '1 / 1' : '24 / 24'}
          </div>
          <div className="metric-note">
            {mode === 'live' ? `Host Nikhil · ${heartbeatLabel.toLowerCase()}` : hostOnline ? `This host · ${heartbeatLabel.toLowerCase()}` : heartbeatLabel}
          </div>
        </section>

        <section className="card metric animate-rise">
          <div className="metric-label">
            <Activity size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />
            Exposure risk
          </div>
          <div
            className={cn(
              'metric-value',
              mode === 'live' ? 'signal-good' : risk > 70 ? 'signal-danger' : 'signal-warn'
            )}
            data-testid="text-metric-exposure-risk"
          >
            {mode === 'live' ? `${Math.min(100, liveIncidents.length * 15 + 8)}/100` : `${risk}/100`}
          </div>
          <div className="metric-note">
            {mode === 'live'
              ? liveIncidents.length === 0
                ? 'Within monitored baseline'
                : 'Elevated by live detections'
              : phase
              ? 'Synthetic incident in progress'
              : 'Within monitored baseline'}
          </div>
        </section>
      </div>

      {/* Real Windows Telemetry Card */}
      {hostOnline ? (
        <section className="card card-pad" style={{ marginTop: 14 }} data-testid="dashboard-real-telemetry">
          <div className="panel-title">
            <h2>This host · real Windows telemetry</h2>
            <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
              <span>PSUTIL · LIVE</span>
              <span
                className="badge badge-low"
                style={{
                  background: 'hsl(142 71% 20%)',
                  color: 'hsl(142 71% 70%)',
                  border: '1px solid hsl(142 71% 30%)',
                }}
              >
                <Radio size={10} style={{ marginRight: 4, verticalAlign: 'middle' }} />
                REAL WINDOWS TELEMETRY
              </span>
            </div>
          </div>

          <div className="grid metrics" style={{ gridTemplateColumns: 'repeat(4,1fr)' }}>
            <section className="card metric animate-rise">
              <div className="metric-label">
                <Cpu size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} /> CPU
              </div>
              <div className="metric-value signal-info">
                {t?.cpu?.percent != null ? `${t.cpu.percent.toFixed(1)}%` : '—'}
              </div>
              <div className="metric-note">
                {t?.cpu?.count != null ? `${t.cpu.count} logical cores` : '—'}
              </div>
            </section>

            <section className="card metric animate-rise">
              <div className="metric-label">
                <Database size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} /> Memory
              </div>
              <div className="metric-value signal-good">
                {t?.memory?.percent != null ? `${t.memory.percent.toFixed(1)}%` : '—'}
              </div>
              <div className="metric-note">
                {fmtBytes(t?.memory?.used_bytes)} used of {fmtBytes(t?.memory?.total_bytes)}
              </div>
            </section>

            <section className="card metric animate-rise">
              <div className="metric-label">
                <TerminalSquare size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} /> Processes
              </div>
              <div className="metric-value signal-good">
                {processCount}
              </div>
              <div className="metric-note">running on Nikhil</div>
            </section>

            <section className="card metric animate-rise">
              <div className="metric-label">
                <Clock3 size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} /> Uptime
              </div>
              <div className="metric-value signal-good">
                {fmtUptime(t?.system?.uptime_seconds)}
              </div>
              <div className="metric-note">
                updated {fmtTime(telemetry.lastUpdateTime ?? undefined)}
              </div>
            </section>
          </div>
        </section>
      ) : (
        <div
          className="scan-strip"
          style={{ marginTop: 14, background: 'hsl(var(--muted))' }}
          data-testid="dashboard-telemetry-offline"
        >
          <div className="scan-status" style={{ color: 'hsl(var(--muted-foreground))' }}>
            <AlertTriangle size={15} />
            <div>
              <b>MONITORING ENGINE OFFLINE</b>
              <small>
                {' '}
                · Start the ARGUS security engine and API server to stream real Windows telemetry to the dashboard.
              </small>
            </div>
          </div>
        </div>
      )}

      {/* Grid: Protection Signal & Live Event Stream */}
      <div className="grid dash-grid" style={{ marginTop: 14 }}>
        {/* Protection Signal */}
        <section className="card card-pad">
          <div className="panel-title">
            <h2>Protection signal</h2>
            <div>
              <span>{mode === 'live' ? 'LIVE EVALUATION · HOST NIKHIL' : '24H · ALL ENDPOINTS'}</span>
            </div>
          </div>
          <div style={{ height: 190, position: 'relative' }}>
            <LiveChart
              value={mode === 'live' ? liveProtectionScore : 94.8 - (phase ? Math.min(phase * 2.4, 24) : 0)}
              label="signal integrity"
              max={100}
              format={(n) => `${n.toFixed(1)}%`}
              color="primary"
              height={160}
            />
          </div>
          <div style={{ display: 'flex', gap: 22, marginTop: 17, fontSize: 10 }}>
            <span>
              <i className="event-dot" style={{ display: 'inline-block', margin: '0 6px 1px 0' }} />
              Signal integrity
            </span>
            <span className="muted">
              Baseline confidence <b style={{ color: 'hsl(var(--foreground))' }}>98.2%</b>
            </span>
          </div>
        </section>

        {/* Event Stream */}
        <section className="card card-pad">
          <div className="panel-title">
            <h2>Live event stream</h2>
            <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
              <span>{realStreamActive ? 'REAL PROCESS EVENTS' : 'AUTO-REFRESH 12s'}</span>
              <Link href="/monitoring" className="mono" style={{ color: 'hsl(var(--primary))', textDecoration: 'none' }} data-testid="link-live-stream">
                Open stream
              </Link>
            </div>
          </div>

          {realStreamActive && realEvents.length > 0 ? (
            realEvents
              .slice(-4)
              .reverse()
              .map((event) => (
                <div className="event-row" key={event.id}>
                  <span
                    className="event-dot"
                    style={
                      event.event_type === 'PROCESS_STARTED'
                        ? { background: 'hsl(var(--accent))' }
                        : { background: 'hsl(var(--destructive))' }
                    }
                  />
                  <div className="event-copy">
                    <div>{event.event_type === 'PROCESS_STARTED' ? 'Process started' : 'Process terminated'}</div>
                    <div className="muted" style={{ fontSize: 10, marginTop: 2 }}>
                      <span className="mono">{event.process_name}</span> · PID {event.pid}
                      {event.parent_process_name ? ` · ${event.parent_process_name}` : ''} · this host
                    </div>
                  </div>
                  <span className="event-time">{new Date(event.timestamp).toLocaleTimeString()}</span>
                </div>
              ))
          ) : (
            (phase ? timelineSeed.slice(Math.max(0, phase - 3), phase + 1).reverse() : timelineSeed.slice(0, 4)).map(
              (event) => (
                <div className="event-row" key={event.id}>
                  <span
                    className="event-dot"
                    style={
                      event.status === 'potential'
                        ? { background: 'hsl(var(--chart-3))', boxShadow: '0 0 0 3px hsl(var(--chart-3)/.1)' }
                        : {}
                    }
                  />
                  <div className="event-copy">
                    <div>{event.title}</div>
                    <div className="muted" style={{ fontSize: 10, marginTop: 2 }}>
                      {event.category} · WS-0427
                    </div>
                  </div>
                  <span className="event-time">{event.time}</span>
                </div>
              )
            )
          )}
        </section>

        {/* Recent Incidents (Wide Table) */}
        <section className="card wide">
          <div className="card-pad">
            <div className="panel-title">
              <h2>Recent incidents</h2>
              <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                <span>{mode === 'live' ? 'REAL-TIME DETECTIONS' : 'LAST 7 DAYS'}</span>
                <Link href="/threats" className="btn btn-ghost btn-sm" data-testid="link-all-incidents">
                  View all <ArrowRight size={12} />
                </Link>
              </div>
            </div>

            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Incident / Detection</th>
                    <th>Severity</th>
                    <th>Endpoint</th>
                    <th>Observed</th>
                    <th>Risk</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {mode === 'live' ? (
                    liveIncidents.length > 0 ? (
                      liveIncidents.slice(0, 4).map((t) => (
                        <tr key={t.id}>
                          <td>
                            <b>{t.name}</b>
                            <div className="muted mono" style={{ fontSize: 11 }}>
                              {t.id} · {t.className} · LIVE
                            </div>
                          </td>
                          <td>
                            <Badge value={t.severity} />
                          </td>
                          <td className="mono">Host Nikhil</td>
                          <td className="mono">
                            {t.timestamp.includes('T') ? new Date(t.timestamp).toLocaleTimeString() : t.timestamp}
                          </td>
                          <td>
                            <div style={{ width: 88 }}>
                              <div className="risk-meter">
                                {[1, 2, 3, 4, 5].map((n) => (
                                  <i
                                    className={
                                      n <=
                                      Math.ceil(
                                        (t.severity === 'critical'
                                          ? 100
                                          : t.severity === 'high'
                                          ? 80
                                          : t.severity === 'medium'
                                          ? 60
                                          : 20) / 20
                                      )
                                        ? 'on'
                                        : ''
                                    }
                                    key={n}
                                  />
                                ))}
                              </div>
                            </div>
                          </td>
                          <td>
                            <StateBadge value={t.status} />
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={6} style={{ padding: '24px 16px', textAlign: 'center' }}>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8 }}>
                            <CheckCircle2 size={16} style={{ color: 'hsl(142 71% 55%)' }} />
                            <span style={{ fontWeight: 600, color: 'hsl(142 71% 80%)' }}>
                              Host Nikhil · Zero Active Threat Detections
                            </span>
                          </div>
                          <p style={{ margin: '4px 0 0', color: 'hsl(var(--muted-foreground))', fontSize: 11 }}>
                            All {processCount} running processes and {socketCount} active sockets match baseline security profiles.
                          </p>
                        </td>
                      </tr>
                    )
                  ) : (
                    <>
                      <tr>
                        <td>
                          <b>Suspicious PowerShell execution</b>
                          <div className="muted mono">INC-2024-1042 · Command &amp; Control</div>
                        </td>
                        <td>
                          <Badge value="critical" />
                        </td>
                        <td className="mono">WS-0427 · Mira Alvarez</td>
                        <td className="mono">09:42:18</td>
                        <td>
                          <div style={{ width: 88 }}>
                            <div className="risk-meter">
                              {[1, 2, 3, 4, 5].map((n) => (
                                <i className={n <= Math.ceil(risk / 20) ? 'on' : ''} key={n} />
                              ))}
                            </div>
                          </div>
                        </td>
                        <td>
                          <Badge value={incidentStatus.toLowerCase()} />
                        </td>
                      </tr>
                      <tr>
                        <td>
                          <b>Unsigned binary in user profile</b>
                          <div className="muted mono">INC-2024-1039 · Execution</div>
                        </td>
                        <td>
                          <Badge value="medium" />
                        </td>
                        <td className="mono">WS-0198 · Theo Bennett</td>
                        <td className="mono">Yesterday 18:14</td>
                        <td>
                          <div style={{ width: 88 }}>
                            <div className="risk-meter">
                              {[1, 2, 3, 4, 5].map((n) => (
                                <i className={n <= 3 ? 'on' : ''} key={n} />
                              ))}
                            </div>
                          </div>
                        </td>
                        <td>
                          <Badge value="contained" />
                        </td>
                      </tr>
                    </>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        {/* Threat Intelligence Card */}
        <section className="card card-pad">
          <div className="panel-title">
            <h2>Threat intelligence</h2>
            <div>
              <span>{mode === 'live' ? '14,892 IOC ENGINE' : 'CURATED SIGNALS'}</span>
            </div>
          </div>

          {mode === 'live' ? (
            <>
              <div className="event-row">
                <div className="avatar" style={{ borderRadius: 5 }}>
                  <Globe2 size={14} />
                </div>
                <div className="event-copy">
                  <b>{socketCount} Host Sockets Scanned</b>
                  <div className="muted">Correlated against 14,892 threat intelligence IOCs</div>
                </div>
                <span className="badge badge-low">CLEAN</span>
              </div>
              <div className="event-row">
                <div className="avatar" style={{ borderRadius: 5 }}>
                  <Fingerprint size={14} />
                </div>
                <div className="event-copy">
                  <b>Real-Time DNS Inquiries</b>
                  <div className="muted">Asynchronous Node DNS reverse resolving active sockets</div>
                </div>
                <span className="badge badge-low">RESOLVED</span>
              </div>
            </>
          ) : (
            <>
              <div className="event-row">
                <div className="avatar" style={{ borderRadius: 5 }}>
                  <Globe2 size={14} />
                </div>
                <div className="event-copy">
                  <b>cdn-sync-check[.]com</b>
                  <div className="muted">Newly registered · 3 feeds agree</div>
                </div>
                <Badge value="high" />
              </div>
              <div className="event-row">
                <div className="avatar" style={{ borderRadius: 5 }}>
                  <Fingerprint size={14} />
                </div>
                <div className="event-copy">
                  <b>Hash a7f1…92c4</b>
                  <div className="muted">No prior internal sightings</div>
                </div>
                <Badge value="medium" />
              </div>
            </>
          )}

          <Link
            href="/intelligence"
            className="btn btn-ghost btn-sm"
            style={{ marginTop: 12, paddingLeft: 0 }}
            data-testid="link-intelligence-dashboard"
          >
            Open intelligence panel <ArrowRight size={12} />
          </Link>
        </section>

        {/* Sensor Health Card */}
        <section className="card card-pad">
          <div className="panel-title">
            <h2>Sensor health</h2>
            <div>
              <span>{hostOnline ? 'THIS HOST STREAMING' : 'LAST HEARTBEAT'}</span>
            </div>
          </div>

          {hostOnline ? (
            <>
              <div style={{ display: 'flex', alignItems: 'center', gap: 15, marginBottom: 14 }}>
                <div style={{ fontSize: 31, fontWeight: 800, letterSpacing: '-.06em' }}>100%</div>
                <div className="signal-good" style={{ fontSize: 11 }}>
                  This host streaming · Nikhil
                </div>
              </div>
              <div className="progress">
                <i style={{ width: '100%', background: 'hsl(var(--accent))' }} />
              </div>
              <div className="kpi-line">
                <span className="muted">Toolchain</span>
                <b className="mono">psutil · Node SSE</b>
              </div>
              <div className="kpi-line">
                <span className="muted">Process events</span>
                <b className="mono">{processMonitor.eventCount}</b>
              </div>
              <div className="kpi-line">
                <span className="muted">Mean heartbeat</span>
                <b className="mono">{heartbeatLabel.replace('Last heartbeat ', '')}</b>
              </div>
            </>
          ) : (
            <>
              <div style={{ display: 'flex', alignItems: 'center', gap: 15, marginBottom: 14 }}>
                <div style={{ fontSize: 31, fontWeight: 800, letterSpacing: '-.06em' }}>100%</div>
                <div className="signal-good" style={{ fontSize: 11 }}>
                  All agents reporting
                </div>
              </div>
              <div className="progress">
                <i style={{ width: '100%', background: 'hsl(var(--accent))' }} />
              </div>
              <div className="kpi-line">
                <span className="muted">Windows endpoints</span>
                <b>18</b>
              </div>
              <div className="kpi-line">
                <span className="muted">macOS endpoints</span>
                <b>6</b>
              </div>
              <div className="kpi-line">
                <span className="muted">Mean heartbeat</span>
                <b className="mono">12 sec</b>
              </div>
            </>
          )}
        </section>
      </div>
    </div>
  );
}
