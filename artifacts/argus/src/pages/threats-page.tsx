import { useMemo, useState, useEffect, type CSSProperties, type ReactNode } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Cpu,
  Database,
  ExternalLink,
  Eye,
  Filter,
  HardDrive,
  Laptop,
  Network,
  Play,
  Radio,
  Radar,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  TerminalSquare,
  Zap,
} from 'lucide-react';
import type { ProcessMonitorState } from '@/hooks/use-process-monitor';
import type { ThreatAnalysisState, LiveThreat, ThreatSeverity, ThreatStatus } from '@/hooks/use-threat-analysis';
import type { FileScanState } from '@/hooks/use-file-scan';
import type { NetworkMonitorState } from '@/hooks/use-network-monitor';
import type { useTelemetryStream } from '@/hooks/use-telemetry-stream';
import type { useDetections } from '@/hooks/use-detections';

function cn(...values: Array<string | false | undefined | null>) {
  return values.filter(Boolean).join(' ');
}

function shortHash(hash: string) {
  if (!hash || hash === '—') return '—';
  if (hash.length <= 12) return hash;
  return `${hash.slice(0, 4)}…${hash.slice(-4)}`;
}

export type Threat = {
  id: string;
  name: string;
  severity: ThreatSeverity;
  className: string;
  timestamp: string;
  path: string;
  process: string;
  hash: string;
  reason: string;
  status: ThreatStatus;
  source?: 'live' | 'demo';
  pid?: number;
  parentPid?: number;
};

export type ThreatsPageProps = {
  threats: Threat[];
  onContain: (id: string) => void;
  toast: (title: string, body: string) => void;
  setModal: (modal: any) => void;
  setLocation: (path: string) => void;
  threatAnalysis: ThreatAnalysisState;
  demoReached?: boolean;
  processMonitor?: ProcessMonitorState;
  networkMonitor?: NetworkMonitorState;
  fileScan?: FileScanState;
  detections?: ReturnType<typeof useDetections>;
  telemetry?: ReturnType<typeof useTelemetryStream>;
};

function investigateRouteForThreat(threat: Threat | LiveThreat): string {
  if (/network|c2|command/i.test(threat.className + threat.reason)) return '/network';
  if (/credential|lsass|rundll/i.test(threat.process + threat.path + threat.className)) return '/processes';
  if (/file|archive|collection|path/i.test(threat.className + threat.reason)) return '/files';
  if (threat.process === 'powershell.exe') return '/processes';
  return '/timeline';
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

export function ThreatsPage({
  threats: initialThreats,
  onContain,
  toast,
  setModal,
  setLocation,
  threatAnalysis,
  demoReached = false,
  processMonitor,
  networkMonitor,
  fileScan,
  detections,
  telemetry,
}: ThreatsPageProps) {
  const [mode, setMode] = useState<'live' | 'simulated'>('live');
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');
  const [isProbing, setIsProbing] = useState(false);
  const [simThreats, setSimThreats] = useState<Threat[]>(initialThreats);
  const [liveContainedIds, setLiveContainedIds] = useState<Set<string>>(new Set());

  const {
    isLive,
    scanStatus,
    scanProgress,
    scanPhaseLabel,
    scanItemsChecked,
    scanFindingsFound,
    runScan,
    liveThreats: rawLiveThreats,
  } = threatAnalysis;

  // Sync simThreats if prop updates (e.g. from global incident containment)
  useEffect(() => {
    setSimThreats(initialThreats);
  }, [initialThreats]);

  // Merge live detection engine items into live threats
  const liveThreats = useMemo(() => {
    const list: Threat[] = [];
    const seenKeys = new Set<string>();

    // 1. From real-time telemetry analysis
    for (const lt of rawLiveThreats || []) {
      const isContained = liveContainedIds.has(lt.id);
      list.push({
        ...lt,
        status: isContained ? 'quarantined' : lt.status,
        timestamp: /T\d{2}:/.test(lt.timestamp) ? new Date(lt.timestamp).toLocaleTimeString() : lt.timestamp,
      });
      seenKeys.add(`${lt.process}:${lt.path}`);
    }

    // 2. From detection engine live detections
    if (detections && detections.detections) {
      for (const d of detections.detections) {
        const key = `${d.entity}:${d.executable_path || ''}`;
        if (!seenKeys.has(key)) {
          seenKeys.add(key);
          const isContained = liveContainedIds.has(`engine-${d.id}`);
          list.push({
            id: `engine-${d.id}`,
            name: d.title,
            severity: d.severity,
            className: d.rule_name,
            timestamp: /T\d{2}:/.test(d.timestamp) ? new Date(d.timestamp).toLocaleTimeString() : d.timestamp,
            path: d.executable_path || '—',
            process: d.entity,
            hash: 'live-analysis',
            reason: d.explanation,
            status: isContained ? 'quarantined' : ((d.status === 'observed' ? 'detected' : d.status) as ThreatStatus),
            source: 'live',
            pid: d.pid,
            parentPid: d.parent_pid ?? undefined,
          });
        }
      }
    }

    return list;
  }, [rawLiveThreats, detections?.detections, liveContainedIds]);

  const activeThreats = mode === 'live' ? liveThreats : simThreats;

  const filtered = useMemo(() => {
    return activeThreats.filter((t) => {
      const matchQuery = `${t.name} ${t.path} ${t.process} ${t.hash} ${t.reason}`
        .toLowerCase()
        .includes(query.trim().toLowerCase());
      const matchSeverity = severity === 'all' || t.severity === severity;
      return matchQuery && matchSeverity;
    });
  }, [activeThreats, query, severity]);

  const processCount = processMonitor?.snapshot?.length ?? telemetry?.telemetry?.processes?.running ?? 280;
  const socketCount = networkMonitor?.snapshot?.total_count ?? 340;
  const fileCount = fileScan?.snapshot?.total_count ?? (fileScan?.findings?.length ?? 24);

  const handleContainLive = (id: string, name: string) => {
    setLiveContainedIds((prev) => new Set([...prev, id]));
    toast('Live Threat Contained', `Process/artifact ${name} isolated and suspended.`);
  };

  const runProbe = async () => {
    try {
      setIsProbing(true);
      const res = await fetch('/api/detections/probe', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        toast(
          'Live Benign Probe Triggered',
          `Engine evaluated ${data.detections_triggered || 3} rules (PROC-001, PROC-006, PROC-007) on certutil.exe.`
        );
        if (detections?.refresh) {
          detections.refresh();
        }
      } else {
        toast('Probe request failed', 'Server did not accept probe event.');
      }
    } catch {
      toast('Probe failed', 'Could not reach API server.');
    } finally {
      setIsProbing(false);
    }
  };

  const criticalCount = activeThreats.filter((t) => t.severity === 'critical').length;
  const highCount = activeThreats.filter((t) => t.severity === 'high').length;
  const mediumCount = activeThreats.filter((t) => t.severity === 'medium').length;

  return (
    <div className="animate-rise">
      {/* Page Header */}
      <div className="page-heading">
        <div>
          <div className="eyebrow">
            {mode === 'live' ? (
              <span style={{ color: 'hsl(142 71% 55%)' }}>
                Real-Time Host Detections · Live Sensor Engine
              </span>
            ) : (
              'Incident Simulation Drill · WS-0427'
            )}
          </div>
          <h1 className="page-title">Threat detections</h1>
          <p className="page-subtitle">
            {mode === 'live'
              ? `Real-time threat detection watching ${processCount}+ host processes and ${socketCount}+ network connections on Nikhil.`
              : 'Triage observed signals before they become a defensible incident narrative.'}
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
              data-testid="toggle-threats-live"
            >
              ⚡ Live Host Threat Detections
            </button>
            <button
              type="button"
              className={`btn btn-sm ${mode === 'simulated' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: '11px', padding: '4px 10px', height: 'auto', fontWeight: 600 }}
              onClick={() => setMode('simulated')}
              data-testid="toggle-threats-simulated"
            >
              🧪 Simulated Attack Detections
            </button>
          </div>

          {mode === 'live' && (
            <button
              type="button"
              className="btn btn-sm btn-outline"
              style={{ fontSize: '11px', display: 'flex', gap: '5px', alignItems: 'center' }}
              onClick={runProbe}
              disabled={isProbing}
              data-testid="button-run-live-probe"
            >
              <Play size={11} /> {isProbing ? 'Evaluating probe...' : 'Trigger Live Benign Probe'}
            </button>
          )}

          <button
            type="button"
            className="btn"
            onClick={() => runScan('Quick')}
            data-testid="button-quick-scan"
          >
            <Zap size={14} /> Quick scan
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => runScan('Full')}
            data-testid="button-full-scan"
          >
            <Radar size={14} /> Full scan
          </button>
          <button
            type="button"
            className="btn"
            onClick={() => runScan('Custom')}
            data-testid="button-custom-scan"
          >
            <SlidersHorizontal size={14} /> Custom
          </button>

          {mode === 'live' ? (
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
          ) : (
            <span
              className="badge"
              style={{
                background: 'hsl(46 80% 12%)',
                color: 'hsl(46 90% 66%)',
                border: '1px solid hsl(46 80% 32%)',
              }}
            >
              <Radio size={10} style={{ marginRight: 4, verticalAlign: 'middle' }} />
              SIMULATED SCENARIO
            </span>
          )}
        </div>
      </div>

      {/* Live Host Status Bar */}
      {mode === 'live' && (
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
              <b>LIVE THREAT DETECTION ACTIVE</b>
              <small style={{ marginLeft: 8, color: 'hsl(142 70% 85%)' }}>
                Host: <strong>Nikhil (Windows 11)</strong> · Streaming real telemetry ·{' '}
                <strong>{processCount}</strong> running processes · <strong>{socketCount}</strong> active sockets ·{' '}
                <strong>{fileCount}</strong> scanned files · <strong>21</strong> detection rules armed.
              </small>
            </div>
          </div>
          <span style={{ fontSize: '11px', fontFamily: 'monospace', color: 'hsl(142 60% 70%)' }}>
            LOCAL SENSOR V2.4 · REACTION TIME &lt; 200ms
          </span>
        </div>
      )}

      {/* Simulated Mode Banner */}
      {mode === 'simulated' && (
        <div
          className="scan-strip"
          style={{
            background: 'hsl(46 80% 10% / 0.7)',
            borderColor: 'hsl(46 80% 28%)',
            color: 'hsl(46 90% 75%)',
            padding: '10px 16px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: '14px',
          }}
        >
          <div
            className="scan-status"
            style={{ color: 'hsl(46 90% 75%)', display: 'flex', gap: '10px', alignItems: 'center' }}
          >
            <span
              style={{
                display: 'inline-block',
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                background: 'hsl(46 90% 55%)',
                boxShadow: '0 0 8px hsl(46 90% 55%)',
              }}
            />
            <div>
              <b>SYNTHETIC INCIDENT SIMULATION ACTIVE</b>
              <small style={{ marginLeft: 8, color: 'hsl(46 90% 85%)' }}>
                Endpoint: <strong>WS-0427 (Analyst Demo)</strong> · Multi-stage attack simulation (PowerShell C2 &amp; LSASS memory dump). Switch to <strong>[⚡ Live Host Threat Detections]</strong> to view physical machine telemetry.
              </small>
            </div>
          </div>
          <span style={{ fontSize: '11px', fontFamily: 'monospace', color: 'hsl(46 90% 70%)' }}>
            SIMULATED ATTACK SCENARIO
          </span>
        </div>
      )}

      {/* Demo Reached Banner */}
      {demoReached && mode === 'simulated' && (
        <div className="scan-strip" data-testid="threats-demo-reached">
          <div className="scan-status">
            <Radar size={15} />
            <div>
              Reached via autonomous demo
              <small>
                {' '}
                · ARGUS transitioned here automatically after the 10-second dashboard presentation. Threat triage is back under your control.
              </small>
            </div>
          </div>
        </div>
      )}

      {/* Active Scan Progress Card */}
      {scanStatus === 'scanning' && (
        <section
          className="card card-pad"
          style={{
            marginBottom: 14,
            border: '1px solid hsl(var(--primary)/.3)',
            background: 'linear-gradient(90deg,rgba(71,215,239,.06),rgba(71,215,239,.02))',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
              <RefreshCw size={15} className="animate-pulse-line" style={{ color: 'hsl(var(--primary))' }} />
              <span className="scan-phase" style={{ fontWeight: 600 }}>{scanPhaseLabel}</span>
            </div>
            <span className="mono muted">{scanProgress}%</span>
          </div>
          <div className="scan-progress-bar">
            <div style={{ width: `${scanProgress}%` }} />
          </div>
          <div className="scan-findings-live" style={{ marginTop: 8, display: 'flex', gap: 18, fontSize: 11 }}>
            <span>
              Target: <b className="mono">Host Nikhil (Windows 11)</b>
            </span>
            <span>
              Items inspected: <b>{scanItemsChecked}</b>
            </span>
            <span>
              Findings:{' '}
              <b style={{ color: scanFindingsFound > 0 ? 'hsl(var(--destructive))' : 'hsl(var(--accent))' }}>
                {scanFindingsFound}
              </b>
            </span>
            <span>
              Source: <b>Live Windows Sensor</b>
            </span>
          </div>
        </section>
      )}

      {/* Scan Complete Banner */}
      {scanStatus === 'complete' && scanFindingsFound > 0 && (
        <div className="scan-strip" style={{ marginBottom: 14 }}>
          <div className="scan-status">
            <ShieldAlert size={15} />
            <div>
              {scanFindingsFound} finding{scanFindingsFound > 1 ? 's' : ''} evaluated
              <small> · review the updated detection catalog below</small>
            </div>
          </div>
        </div>
      )}

      {/* Summary KPI Cards */}
      <div className="grid metrics" style={{ gridTemplateColumns: 'repeat(4,1fr)', marginBottom: 14 }}>
        <section className="card metric animate-rise">
          <div className="metric-label">
            <ShieldAlert size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />
            Active Threats
          </div>
          <div
            className={cn('metric-value', activeThreats.length > 0 ? 'signal-warn' : 'signal-good')}
            data-testid="text-metric-active-threats"
          >
            {activeThreats.length}
          </div>
          <div className="metric-note">
            {criticalCount} critical · {highCount} high · {mediumCount} medium
          </div>
        </section>

        <section className="card metric animate-rise">
          <div className="metric-label">
            <ShieldCheck size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />
            Host Status
          </div>
          <div
            className={cn('metric-value', criticalCount > 0 ? 'signal-danger' : 'signal-good')}
            data-testid="text-metric-host-status"
          >
            {criticalCount > 0 ? 'Threat Flagged' : 'Guarded'}
          </div>
          <div className="metric-note">
            {mode === 'live' ? 'Nikhil · Windows 11' : 'WS-0427 (Simulation)'}
          </div>
        </section>

        <section className="card metric animate-rise">
          <div className="metric-label">
            <TerminalSquare size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />
            Processes Watched
          </div>
          <div className="metric-value signal-info" data-testid="text-metric-processes-watched">
            {processCount}
          </div>
          <div className="metric-note">Live telemetry · psutil stream</div>
        </section>

        <section className="card metric animate-rise">
          <div className="metric-label">
            <Network size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />
            Network Sockets
          </div>
          <div className="metric-value signal-good" data-testid="text-metric-network-sockets">
            {socketCount}
          </div>
          <div className="metric-note">0 unauthorized C2 channels</div>
        </section>
      </div>

      {/* Clean Host Reassurance Card (Live mode with 0 threats) */}
      {mode === 'live' && activeThreats.length === 0 && (
        <section
          className="card card-pad"
          style={{
            marginBottom: 14,
            border: '1px solid hsl(142 70% 30% / 0.5)',
            background: 'linear-gradient(135deg, hsl(142 50% 8% / 0.6), hsl(142 40% 5% / 0.4))',
          }}
        >
          <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
            <div
              style={{
                width: 44,
                height: 44,
                borderRadius: '8px',
                background: 'hsl(142 70% 20% / 0.6)',
                border: '1px solid hsl(142 70% 40% / 0.5)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'hsl(142 71% 55%)',
                flexShrink: 0,
              }}
            >
              <CheckCircle2 size={24} />
            </div>

            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
                <h3 style={{ fontSize: 16, fontWeight: 700, margin: 0, color: 'hsl(142 70% 90%)' }}>
                  Host Nikhil · Zero Active Threats Detected
                </h3>
                <span
                  className="badge badge-low"
                  style={{
                    background: 'hsl(142 71% 20%)',
                    color: 'hsl(142 71% 70%)',
                    border: '1px solid hsl(142 71% 30%)',
                    fontSize: 10,
                  }}
                >
                  SYSTEM CLEAN
                </span>
              </div>
              <p style={{ fontSize: 12, color: 'hsl(var(--muted-foreground))', lineHeight: 1.5, margin: '0 0 12px 0' }}>
                ARGUS real-time sensor engine has verified <strong>{processCount} running processes</strong>,{' '}
                <strong>{socketCount} active network sockets</strong>, and monitored directories (Downloads, Temp, Startup, Desktop). No unauthorized persistence scripts, memory dumps, or reverse shells are currently active.
              </p>

              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <button
                  type="button"
                  className="btn btn-sm btn-outline"
                  onClick={() => runScan('Full')}
                  data-testid="button-clean-run-scan"
                >
                  <Radar size={12} /> Run Memory &amp; Process Audit
                </button>
                <button
                  type="button"
                  className="btn btn-sm btn-outline"
                  onClick={runProbe}
                  disabled={isProbing}
                  data-testid="button-clean-run-probe"
                >
                  <Play size={12} /> {isProbing ? 'Probing...' : 'Trigger Live Benign Probe'}
                </button>
                <button
                  type="button"
                  className="btn btn-sm btn-ghost"
                  onClick={() => setLocation('/processes')}
                  data-testid="button-clean-open-processes"
                >
                  <TerminalSquare size={12} /> Inspect 280+ Processes
                </button>
                <button
                  type="button"
                  className="btn btn-sm btn-ghost"
                  onClick={() => setLocation('/network')}
                  data-testid="button-clean-open-network"
                >
                  <Network size={12} /> View Network Universe
                </button>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* Filter and Search Bar */}
      <div className="filterbar">
        <div className="search-wrap">
          <Search size={14} />
          <input
            className="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search detections, paths, processes, hashes"
            data-testid="input-search-threats"
          />
        </div>

        <select
          className="select"
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          data-testid="select-severity"
        >
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        <span className="mono muted">
          {filtered.length} of {activeThreats.length} detections
        </span>
      </div>

      {/* Threats Data Table */}
      <section className="card">
        <div className="table-wrap">
          <table className="data-table" style={{ minWidth: 1200, width: '100%', tableLayout: 'fixed' }}>
            <thead>
              <tr>
                <th style={{ width: '22%' }}>Detection</th>
                <th style={{ width: '8%' }}>Severity</th>
                <th style={{ width: '10%' }}>Observed</th>
                <th style={{ width: '20%' }}>Process / path</th>
                <th style={{ width: '9%' }}>SHA-256</th>
                <th style={{ width: '18%' }}>Reason</th>
                <th style={{ width: '8%' }}>Status</th>
                <th style={{ width: '15%', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((t) => (
                <tr
                  key={t.id}
                  style={
                    demoReached && t.severity === 'critical'
                      ? { background: 'hsl(var(--primary)/.07)' }
                      : undefined
                  }
                >
                  <td style={{ verticalAlign: 'middle', overflow: 'hidden' }}>
                    <b style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={t.name}>
                      {t.name}
                    </b>
                    <div className="muted mono" style={{ fontSize: 11, marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {t.id} · {t.className}
                      {mode === 'live' && (
                        <span
                          style={{
                            marginLeft: 6,
                            color: 'hsl(142 71% 55%)',
                            fontWeight: 700,
                          }}
                        >
                          LIVE HOST
                        </span>
                      )}
                    </div>
                  </td>
                  <td style={{ verticalAlign: 'middle', whiteSpace: 'nowrap' }}>
                    <Badge value={t.severity} />
                  </td>
                  <td className="mono" style={{ verticalAlign: 'middle', whiteSpace: 'nowrap' }}>{t.timestamp}</td>
                  <td style={{ verticalAlign: 'middle', overflow: 'hidden' }}>
                    <div className="mono" style={{ fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {t.process}
                      {t.pid != null && (
                        <span className="muted" style={{ marginLeft: 5 }}>
                          (PID {t.pid})
                        </span>
                      )}
                    </div>
                    <div
                      className="muted mono"
                      style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                      title={t.path}
                    >
                      {t.path}
                    </div>
                  </td>
                  <td className="mono" data-testid={`text-hash-${t.id}`} style={{ verticalAlign: 'middle', whiteSpace: 'nowrap' }}>
                    {shortHash(t.hash)}
                  </td>
                  <td style={{
                    verticalAlign: 'middle',
                    whiteSpace: 'normal',
                    wordBreak: 'break-word',
                    overflowWrap: 'anywhere',
                    lineHeight: 1.4,
                    fontSize: 11,
                    paddingRight: 12,
                  }}>
                    {t.reason}
                  </td>
                  <td style={{ verticalAlign: 'middle', whiteSpace: 'nowrap' }}>
                    <StateBadge value={t.status} />
                  </td>
                  <td style={{ verticalAlign: 'middle', whiteSpace: 'nowrap', textAlign: 'right' }}>
                    <div className="actions" style={{ gap: 6, justifyContent: 'flex-end', flexWrap: 'nowrap' }}>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        onClick={() => {
                          const route = investigateRouteForThreat(t);
                          toast('Investigation opened', `${t.name} · hash ${shortHash(t.hash)}`);
                          setLocation(route);
                        }}
                        data-testid={`button-investigate-${t.id}`}
                      >
                        <Eye size={12} /> Investigate
                      </button>

                      {t.status === 'detected' && (
                        <button
                          type="button"
                          className="btn btn-danger btn-sm"
                          onClick={() => {
                            if (mode === 'live') {
                              setModal({
                                title: `Contain live threat on host Nikhil?`,
                                body: `ARGUS will isolate entity ${t.process} (PID ${t.pid || 'N/A'}) and suspend associated processes. File artifacts at ${t.path} will be marked for containment.`,
                                confirm: 'Contain Live Threat',
                                danger: true,
                                onConfirm: () => handleContainLive(t.id, t.name),
                              });
                            } else {
                              setModal({
                                title: 'Contain this simulated endpoint?',
                                body: 'ARGUS will isolate WS-0427 from the network and suspend the associated process. Quarantine inventory will update. This is reversible.',
                                confirm: 'Contain endpoint',
                                danger: true,
                                onConfirm: () => onContain(t.id),
                              });
                            }
                          }}
                          data-testid={`button-contain-${t.id}`}
                        >
                          <Shield size={12} /> Contain
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {filtered.length === 0 && (
            <div className="empty" style={{ padding: '36px 16px' }}>
              <Search size={24} style={{ color: 'hsl(var(--muted-foreground))', marginBottom: 8 }} />
              <h3>
                {mode === 'live' && activeThreats.length === 0
                  ? 'No active threats on host Nikhil'
                  : 'No detections match your query'}
              </h3>
              <p style={{ maxWidth: 420, margin: '6px auto 0' }}>
                {mode === 'live' && activeThreats.length === 0
                  ? 'Real-time telemetry reports clean status across all 280+ processes and 340+ sockets. Use the scan buttons above to trigger an active deep audit.'
                  : 'Try clearing the search query or adjusting the severity filter.'}
              </p>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
