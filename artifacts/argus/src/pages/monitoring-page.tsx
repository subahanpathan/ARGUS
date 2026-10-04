import { useEffect, useMemo, useRef, useState, type CSSProperties, type ReactNode } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  Cpu,
  Database,
  FolderOpen,
  Layers,
  Radio,
  RefreshCw,
  ShieldAlert,
  TerminalSquare,
  Wifi,
  ExternalLink,
} from 'lucide-react';
import { useTelemetryStream, type SystemTelemetry } from '@/hooks/use-telemetry-stream';
import type { RealProcessEvent, RealProcessInfo } from '@/hooks/use-process-monitor';
import { LiveChart } from '@/motion/live-chart';

function cn(...values: Array<string | false | undefined | null>) {
  return values.filter(Boolean).join(' ');
}

function fmtBytes(bytes?: number | null): string {
  if (bytes == null || isNaN(bytes)) return '—';
  if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(1)} GB`;
  if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${bytes} B`;
}

function fmtRate(bytesPerSec: number): string {
  if (bytesPerSec >= 1048576) return `${(bytesPerSec / 1048576).toFixed(2)} MB/s`;
  if (bytesPerSec >= 1024) return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
  return `${Math.round(bytesPerSec)} B/s`;
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

type CardProps = {
  children: ReactNode;
  className?: string;
  style?: CSSProperties;
  testId?: string;
};

function Card({ children, className = '', style, testId }: CardProps) {
  return (
    <section className={cn('card', className)} style={style} data-testid={testId}>
      {children}
    </section>
  );
}

function PanelTitle({
  title,
  detail,
  action,
}: {
  title: string;
  detail?: string;
  action?: ReactNode;
}) {
  return (
    <div className="panel-title">
      <h2>{title}</h2>
      <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
        {detail && <span>{detail}</span>}
        {action}
      </div>
    </div>
  );
}

function PageHeading({
  eyebrow,
  title,
  subtitle,
  actions,
}: {
  eyebrow: ReactNode;
  title: string;
  subtitle: string;
  actions?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1 className="page-title">{title}</h1>
        <p className="page-subtitle">{subtitle}</p>
      </div>
      {actions && <div className="actions">{actions}</div>}
    </div>
  );
}

function StatCard({
  label,
  value,
  note,
  tone = 'info',
  icon: Icon,
}: {
  label: string;
  value: string;
  note: string;
  tone?: string;
  icon?: typeof Activity;
}) {
  return (
    <Card className="metric animate-rise">
      <div className="metric-label">
        {Icon && <Icon size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />}
        {label}
      </div>
      <div
        className={cn('metric-value', `signal-${tone}`)}
        data-testid={`text-metric-${label.toLowerCase().replace(/ /g, '-')}`}
      >
        {value}
      </div>
      <div className="metric-note">{note}</div>
    </Card>
  );
}

export type ProcessMonitorData = {
  connected: boolean;
  hasData: boolean;
  events: RealProcessEvent[];
  snapshot: RealProcessInfo[];
  eventCount: number;
  lastEventTime: string | null;
};

export type MonitoringPageProps = {
  processMonitor?: ProcessMonitorData;
  onNavigate?: (path: string) => void;
};

// Fallback synthetic process list for demonstration when security engine is offline
const fallbackTopProcesses = [
  { pid: 8420, name: 'powershell.exe', cpu_percent: 14.8, memory_bytes: 88080384, username: 'SYSTEM', status: 'flagged' },
  { pid: 9136, name: 'rundll32.exe', cpu_percent: 8.2, memory_bytes: 32505856, username: 'SYSTEM', status: 'flagged' },
  { pid: 7124, name: 'outlook.exe', cpu_percent: 4.1, memory_bytes: 224395264, username: 'mira', status: 'normal' },
  { pid: 4908, name: 'explorer.exe', cpu_percent: 1.8, memory_bytes: 71303168, username: 'mira', status: 'normal' },
  { pid: 10544, name: 'invoice_viewer.exe', cpu_percent: 0.9, memory_bytes: 50331648, username: 'mira', status: 'contained' },
];

export default function MonitoringPage({ processMonitor, onNavigate }: MonitoringPageProps) {
  const telemetry = useTelemetryStream();
  const isFresh = telemetry.lastUpdateTime
    ? Math.abs(Date.now() - new Date(telemetry.lastUpdateTime).getTime()) < 35000
    : false;
  const isOnline =
    ((telemetry.connected && telemetry.hasData) || isFresh || Boolean(processMonitor?.hasData)) &&
    telemetry.telemetry != null;
  const latest = telemetry.telemetry;

  // Track network throughput rate (Upload/Download delta velocity)
  const prevNetRef = useRef<{ time: number; sent: number; recv: number } | null>(null);
  const [rates, setRates] = useState<{ upRate: number; downRate: number }>({ upRate: 0, downRate: 0 });

  // Simulated jitter for offline demonstration
  const [demoTick, setDemoTick] = useState(0);
  useEffect(() => {
    if (isOnline) return;
    const interval = window.setInterval(() => {
      setDemoTick((t) => t + 1);
    }, 2000);
    return () => window.clearInterval(interval);
  }, [isOnline]);

  // Compute live bandwidth deltas when telemetry arrives
  useEffect(() => {
    if (!latest?.network?.interfaces) return;
    const now = Date.now();
    let totalSent = 0;
    let totalRecv = 0;
    for (const iface of latest.network.interfaces) {
      totalSent += iface.bytes_sent ?? 0;
      totalRecv += iface.bytes_recv ?? 0;
    }

    if (prevNetRef.current) {
      const dt = Math.max(0.5, (now - prevNetRef.current.time) / 1000);
      const dSent = Math.max(0, totalSent - prevNetRef.current.sent);
      const dRecv = Math.max(0, totalRecv - prevNetRef.current.recv);
      setRates({
        upRate: dSent / dt,
        downRate: dRecv / dt,
      });
    }

    prevNetRef.current = { time: now, sent: totalSent, recv: totalRecv };
  }, [latest]);

  // Dynamic values (live vs smooth demo simulation)
  const displayCpu = isOnline
    ? latest?.cpu?.percent ?? 0
    : 18.5 + Math.sin(demoTick * 0.7) * 4.2;

  const displayMem = isOnline
    ? latest?.memory?.percent ?? 0
    : 43.8 + Math.cos(demoTick * 0.5) * 1.5;

  const displayDisk = isOnline
    ? latest?.disk?.percent ?? 0
    : 62.4;

  const displayUpRate = isOnline ? rates.upRate : 12400 + Math.sin(demoTick) * 3500;
  const displayDownRate = isOnline ? rates.downRate : 48200 + Math.cos(demoTick) * 12000;

  // Threshold anomaly evaluation
  const isCpuHigh = displayCpu > 80;
  const isMemHigh = displayMem > 85;
  const isDiskHigh = displayDisk > 90;
  const hasAnomaly = isCpuHigh || isMemHigh || isDiskHigh;

  // Sort top consumer processes
  const topProcesses = useMemo(() => {
    if (processMonitor?.hasData && processMonitor.snapshot.length > 0) {
      return [...processMonitor.snapshot]
        .sort((a, b) => (b.cpu_percent ?? 0) - (a.cpu_percent ?? 0))
        .slice(0, 5)
        .map((p) => ({
          pid: p.pid,
          name: p.name,
          cpu_percent: p.cpu_percent ?? 0,
          memory_bytes: p.memory_bytes ?? 0,
          username: p.username ?? '—',
          status: (p.cpu_percent ?? 0) > 10 ? 'elevated' : 'normal',
        }));
    }
    return fallbackTopProcesses;
  }, [processMonitor?.hasData, processMonitor?.snapshot]);

  const statusBadge = isOnline ? (
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
  ) : (
    <span
      className="badge badge-muted"
      style={{
        background: 'hsl(var(--muted))',
        color: 'hsl(var(--muted-foreground))',
        border: '1px solid hsl(var(--border))',
      }}
    >
      <AlertTriangle size={10} style={{ marginRight: 4, verticalAlign: 'middle' }} />
      SIMULATED TELEMETRY (ENGINE OFFLINE)
    </span>
  );

  const [showSensorModal, setShowSensorModal] = useState(false);
  const [copied, setCopied] = useState(false);

  const copyCommand = (cmd: string) => {
    navigator.clipboard.writeText(cmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="animate-page-enter">
      <PageHeading
        eyebrow="Host telemetry · real-time diagnostics"
        title="Live Monitoring"
        subtitle="Real-time host vitals, hardware resource metrics, interface bandwidth, and top consumer processes."
        actions={
          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            {statusBadge}
            <button
              type="button"
              className={cn('btn', isOnline ? 'btn-ghost' : 'btn-primary')}
              style={{ fontSize: 11, padding: '5px 10px' }}
              onClick={() => setShowSensorModal(true)}
            >
              <Radio size={11} style={{ marginRight: 5 }} />
              {isOnline ? 'Sensor Agent Setup' : 'Connect My PC Sensor'}
            </button>
          </div>
        }
      />

      {/* Anomaly warning strip */}
      {hasAnomaly && (
        <div
          className="scan-strip"
          style={{
            marginBottom: 14,
            background: 'hsl(var(--destructive) / 0.12)',
            borderColor: 'hsl(var(--destructive) / 0.3)',
          }}
          data-testid="telemetry-anomaly-banner"
        >
          <div className="scan-status" style={{ color: 'hsl(var(--destructive))' }}>
            <ShieldAlert size={16} />
            <div>
              <b>RESOURCE SATURATION ALERT:</b>
              <small>
                {isCpuHigh && ' High CPU saturation detected.'}
                {isMemHigh && ' Critical memory pressure.'}
                {isDiskHigh && ' Disk capacity near full.'} Check top processes below.
              </small>
            </div>
          </div>
        </div>
      )}

      {/* Offline guidance banner with 1-Click Connect Button */}
      {!isOnline && (
        <div
          className="scan-strip"
          style={{ marginBottom: 14, background: 'hsl(var(--muted))' }}
          data-testid="telemetry-offline-banner"
        >
          <div className="scan-status" style={{ color: 'hsl(var(--muted-foreground))' }}>
            <AlertTriangle size={15} />
            <div>
              <b>DEMO TELEMETRY ACTIVE:</b>
              <small>
                {' '}
                Browser security prevents webpages from reading your PC without an agent. To stream your actual Windows CPU, RAM, and processes, run the local sensor.
              </small>
            </div>
          </div>
          <button
            type="button"
            className="btn btn-primary"
            style={{ fontSize: 11, padding: '6px 12px', whiteSpace: 'nowrap' }}
            onClick={() => setShowSensorModal(true)}
          >
            <Radio size={12} style={{ marginRight: 6 }} />
            Connect My PC Sensor
          </button>
        </div>
      )}

      {/* Sensor Connection Modal */}
      {showSensorModal && (
        <div className="modal-backdrop" role="presentation" onClick={() => setShowSensorModal(false)}>
          <div
            className="modal"
            style={{ maxWidth: 540 }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <div className="eyebrow" style={{ margin: 0 }}>Endpoint Agent</div>
              <button
                type="button"
                className="btn btn-ghost"
                style={{ padding: 4 }}
                onClick={() => setShowSensorModal(false)}
              >
                <X size={15} />
              </button>
            </div>

            <h2 style={{ fontSize: 18, margin: '0 0 6px' }}>Connect Your Windows PC Sensor</h2>
            <p style={{ fontSize: 12, lineHeight: 1.5, color: 'hsl(var(--muted-foreground))', margin: '0 0 16px' }}>
              Web browsers run in a strict security sandbox and cannot read your PC's hardware or processes directly. Running the lightweight ARGUS sensor on your machine grants permission to stream your live telemetry.
            </p>

            <div style={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', borderRadius: 6, padding: 14, marginBottom: 12 }}>
              <div style={{ fontSize: 11, fontWeight: 700, marginBottom: 4 }}>Option 1: 1-Click Windows Launcher</div>
              <p style={{ fontSize: 11, color: 'hsl(var(--muted-foreground))', margin: '0 0 10px' }}>
                Self-contained launcher: downloads and runs the local Python sensor to stream this PC's live hardware and processes to this dashboard.
              </p>
              <a
                href="/start-sensor.bat"
                download="start-sensor.bat"
                className="btn btn-primary"
                style={{ textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11, padding: '7px 14px' }}
              >
                <Download size={13} /> Download start-sensor.bat
              </a>
            </div>

            <div style={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', borderRadius: 6, padding: 14, marginBottom: 12 }}>
              <div style={{ fontSize: 11, fontWeight: 700, marginBottom: 4 }}>Option 2: 1-Line PowerShell (Direct streaming)</div>
              <p style={{ fontSize: 11, color: 'hsl(var(--muted-foreground))', margin: '0 0 8px' }}>
                Paste into Windows PowerShell (no download needed):
              </p>
              <div
                style={{
                  background: 'hsl(var(--background))',
                  border: '1px solid hsl(var(--border))',
                  borderRadius: 4,
                  padding: '8px 12px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <code className="mono" style={{ fontSize: 10, color: 'hsl(var(--primary))', wordBreak: 'break-all' }}>
                  {typeof window !== 'undefined'
                    ? `powershell -ExecutionPolicy Bypass -Command "irm '${window.location.origin}/start-sensor.ps1' | iex"`
                    : `powershell -ExecutionPolicy Bypass -Command "irm 'http://localhost:5000/start-sensor.ps1' | iex"`}
                </code>
                <button
                  type="button"
                  className="btn btn-ghost"
                  style={{ padding: '3px 7px', fontSize: 10, marginLeft: 8 }}
                  onClick={() =>
                    copyCommand(
                      `powershell -ExecutionPolicy Bypass -Command "irm '${window.location.origin}/start-sensor.ps1' | iex"`
                    )
                  }
                  title="Copy command"
                >
                  {copied ? <Check size={12} className="signal-good" /> : <Copy size={12} />}
                </button>
              </div>
            </div>

            <div style={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', borderRadius: 6, padding: 14, marginBottom: 16 }}>
              <div style={{ fontSize: 11, fontWeight: 700, marginBottom: 4 }}>Option 3: Cloned Repository Terminal</div>
              <p style={{ fontSize: 11, color: 'hsl(var(--muted-foreground))', margin: '0 0 8px' }}>
                If you have cloned the project locally, run:
              </p>
              <div
                style={{
                  background: 'hsl(var(--background))',
                  border: '1px solid hsl(var(--border))',
                  borderRadius: 4,
                  padding: '8px 12px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <code className="mono" style={{ fontSize: 11, color: 'hsl(var(--primary))' }}>
                  python artifacts/security-engine/main.py --api --snapshot
                </code>
                <button
                  type="button"
                  className="btn btn-ghost"
                  style={{ padding: '3px 7px', fontSize: 10 }}
                  onClick={() => copyCommand('python artifacts/security-engine/main.py --api --snapshot')}
                >
                  {copied ? <Check size={12} className="signal-good" /> : <Copy size={12} />}
                </button>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: 10, borderTop: '1px solid hsl(var(--border))', flexWrap: 'wrap', gap: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11 }}>
                <span
                  className="event-dot"
                  style={{
                    margin: 0,
                    background: isOnline ? 'hsl(var(--accent))' : 'hsl(var(--chart-3))',
                  }}
                />
                <span className="mono muted">
                  {isOnline ? 'Sensor detected · streaming live' : 'Waiting for sensor data...'}
                </span>
                <button
                  type="button"
                  className="btn btn-ghost"
                  style={{ padding: '2px 8px', fontSize: 10, marginLeft: 4 }}
                  onClick={() => telemetry.refresh()}
                  title="Check sensor status now"
                >
                  <RefreshCw size={11} style={{ marginRight: 4 }} /> Check Status
                </button>
              </div>
              <button
                type="button"
                className="btn btn-ghost"
                onClick={() => setShowSensorModal(false)}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Core Vitals KPI Row */}
      <div className="grid metrics" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
        <StatCard
          label="CPU Load"
          value={`${displayCpu.toFixed(1)}%`}
          note={
            isOnline && latest?.cpu?.count != null
              ? `${latest.cpu.count} logical · ${latest.cpu.physical_count ?? '?'} physical cores`
              : '8 logical cores · baseline nominal'
          }
          tone={isCpuHigh ? 'danger' : 'info'}
          icon={Cpu}
        />
        <StatCard
          label="Memory Used"
          value={`${displayMem.toFixed(1)}%`}
          note={
            isOnline && latest?.memory
              ? `${fmtBytes(latest.memory.used_bytes)} of ${fmtBytes(latest.memory.total_bytes)}`
              : '7.1 GB of 16.0 GB used'
          }
          tone={isMemHigh ? 'danger' : 'good'}
          icon={Database}
        />
        <StatCard
          label="Disk Space"
          value={`${displayDisk.toFixed(1)}%`}
          note={
            isOnline && latest?.disk
              ? `${fmtBytes(latest.disk.free_bytes)} free on ${latest.disk.mount ?? 'C:'}`
              : '184.2 GB free on system drive'
          }
          tone={isDiskHigh ? 'warn' : 'good'}
          icon={FolderOpen}
        />
        <StatCard
          label="Active Processes"
          value={
            isOnline && latest?.processes?.running != null
              ? String(latest.processes.running)
              : String(processMonitor?.snapshot?.length || 184)
          }
          note={isOnline ? 'monitored processes on this host' : '184 monitored processes'}
          tone="good"
          icon={TerminalSquare}
        />
      </div>

      {/* Live Animated Rolling Sparkline Charts */}
      <div className="grid live-telemetry-grid" style={{ marginTop: 14 }}>
        <div className="live-telemetry-row">
          <Card className="card-pad live-telemetry-cell" style={{ overflow: 'hidden' }}>
            <LiveChart
              value={displayCpu}
              label="CPU utilization"
              max={100}
              format={(n) => `${n.toFixed(1)}%`}
              color={isCpuHigh ? 'warn' : 'primary'}
              height={130}
            />
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'hsl(var(--muted-foreground))', marginTop: 4, fontFamily: 'var(--app-font-mono)' }}>
              <span>{isOnline && latest?.cpu?.count ? `${latest.cpu.count} cores active` : 'Nominal baseline'}</span>
              <span>{isCpuHigh ? 'High load' : 'Normal'}</span>
            </div>
          </Card>
          <Card className="card-pad live-telemetry-cell" style={{ overflow: 'hidden' }}>
            <LiveChart
              value={displayMem}
              label="Memory pressure"
              max={100}
              format={(n) => `${n.toFixed(1)}%`}
              color={isMemHigh ? 'warn' : 'accent'}
              height={130}
            />
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'hsl(var(--muted-foreground))', marginTop: 4, fontFamily: 'var(--app-font-mono)' }}>
              <span>{isOnline && latest?.memory ? `${fmtBytes(latest.memory.free_bytes)} free` : '8.9 GB free'}</span>
              <span>{isMemHigh ? 'Elevated' : 'Normal'}</span>
            </div>
          </Card>
          <Card className="card-pad live-telemetry-cell" style={{ overflow: 'hidden' }}>
            <LiveChart
              value={Math.min(100, ((displayUpRate + displayDownRate) / (1024 * 1024)) * 10)}
              label="Network velocity"
              max={100}
              format={() => fmtRate(displayUpRate + displayDownRate)}
              color="primary"
              height={130}
            />
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'hsl(var(--muted-foreground))', marginTop: 4, fontFamily: 'var(--app-font-mono)' }}>
              <span>↑ {fmtRate(displayUpRate)} sent</span>
              <span>↓ {fmtRate(displayDownRate)} recv</span>
            </div>
          </Card>
        </div>
      </div>

      {/* Split Section: Top Resource Consuming Processes + System Details */}
      <div className="grid split-grid" style={{ marginTop: 14 }}>
        {/* Top Resource Consuming Processes */}
        <Card className="card-pad">
          <PanelTitle
            title="Top consumer processes"
            detail="BY CPU & MEMORY USAGE"
            action={
              onNavigate ? (
                <button
                  type="button"
                  className="btn btn-ghost"
                  style={{ fontSize: 11, padding: '3px 8px' }}
                  onClick={() => onNavigate('/processes')}
                >
                  Process explorer <ExternalLink size={11} style={{ marginLeft: 4 }} />
                </button>
              ) : undefined
            }
          />
          <div className="table-wrap" style={{ marginTop: 8 }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>PID</th>
                  <th>Process Name</th>
                  <th>User</th>
                  <th>CPU %</th>
                  <th>Memory</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {topProcesses.map((p) => (
                  <tr key={p.pid}>
                    <td className="mono">{p.pid}</td>
                    <td className="mono" style={{ fontWeight: 600 }}>{p.name}</td>
                    <td className="mono muted">{p.username}</td>
                    <td>
                      <span className={cn('mono', p.cpu_percent > 10 ? 'signal-warn' : 'signal-good')}>
                        {p.cpu_percent.toFixed(1)}%
                      </span>
                    </td>
                    <td className="mono">{fmtBytes(p.memory_bytes)}</td>
                    <td>
                      <span
                        className={cn(
                          'badge',
                          p.status === 'flagged' || p.status === 'elevated'
                            ? 'badge-high'
                            : p.status === 'contained'
                              ? 'badge-critical'
                              : 'badge-low'
                        )}
                        style={{ fontSize: 9, padding: '2px 6px' }}
                      >
                        {p.status.toUpperCase()}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        {/* Host Details & Network Interfaces */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* Host OS Metadata */}
          <Card className="card-pad">
            <PanelTitle title="Host configuration" detail="SYSTEM ARCHITECTURE" />
            <div className="kpi-line">
              <span className="muted">Host platform</span>
              <b className="mono">{isOnline ? 'Windows Host OS' : 'Demo Workstation (WS-0427)'}</b>
            </div>
            <div className="kpi-line">
              <span className="muted">Uptime</span>
              <b className="mono">
                {isOnline ? fmtUptime(latest?.system?.uptime_seconds) : '4d 11h 23m'}
              </b>
            </div>
            <div className="kpi-line">
              <span className="muted">Telemetry source</span>
              <b className="mono">{isOnline ? latest?.source ?? 'psutil' : 'Synthetic simulation'}</b>
            </div>
            <div className="kpi-line">
              <span className="muted">Last stream heartbeat</span>
              <b className="mono">
                {isOnline && telemetry.lastUpdateTime
                  ? fmtTime(telemetry.lastUpdateTime)
                  : 'Active (local-first)'}
              </b>
            </div>
          </Card>

          {/* Network Adapters */}
          <Card className="card-pad">
            <PanelTitle
              title="Network adapters"
              detail={
                isOnline
                  ? `${latest?.network?.active_count ?? 0} ACTIVE / ${latest?.network?.total_count ?? 0} TOTAL`
                  : '2 ACTIVE ADAPTERS'
              }
            />
            {isOnline && latest?.network?.interfaces?.length ? (
              latest.network.interfaces.slice(0, 4).map((iface) => (
                <div className="kpi-line" key={iface.name}>
                  <span>
                    <b style={{ fontSize: 11 }}>{iface.name}</b>
                    <br />
                    <span className="muted mono" style={{ fontSize: 10 }}>
                      {iface.addresses?.join(', ') || (iface.is_up ? 'link up · no IP' : 'link down')}
                    </span>
                  </span>
                  <span style={{ textAlign: 'right' }}>
                    <span className={iface.is_up ? 'signal-good' : 'signal-warn'}>
                      {iface.is_up ? 'UP' : 'DOWN'}
                    </span>
                    <br />
                    <span className="mono muted" style={{ fontSize: 10 }}>
                      {fmtBytes(iface.bytes_sent)} ↑ · {fmtBytes(iface.bytes_recv)} ↓
                    </span>
                  </span>
                </div>
              ))
            ) : (
              <>
                <div className="kpi-line">
                  <span>
                    <b style={{ fontSize: 11 }}>Ethernet (Primary)</b>
                    <br />
                    <span className="muted mono" style={{ fontSize: 10 }}>10.14.8.27 · 1 Gbps Full-Duplex</span>
                  </span>
                  <span style={{ textAlign: 'right' }}>
                    <span className="signal-good">UP</span>
                    <br />
                    <span className="mono muted" style={{ fontSize: 10 }}>2.4 MB ↑ · 14.8 MB ↓</span>
                  </span>
                </div>
                <div className="kpi-line">
                  <span>
                    <b style={{ fontSize: 11 }}>Loopback (Localhost)</b>
                    <br />
                    <span className="muted mono" style={{ fontSize: 10 }}>127.0.0.1, ::1</span>
                  </span>
                  <span style={{ textAlign: 'right' }}>
                    <span className="signal-good">UP</span>
                    <br />
                    <span className="mono muted" style={{ fontSize: 10 }}>412 KB ↑ · 412 KB ↓</span>
                  </span>
                </div>
              </>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}
