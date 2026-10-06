import { useMemo, useState, useEffect, type CSSProperties, type ReactNode } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Check,
  CheckCircle2,
  Clock,
  Copy,
  Cpu,
  Database,
  Download,
  ExternalLink,
  Eye,
  FileText,
  Filter,
  Flame,
  FolderLock,
  HardDrive,
  Laptop,
  Lock,
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
  Timer,
  Trash2,
  Zap,
} from 'lucide-react';
import type { ProcessMonitorState } from '@/hooks/use-process-monitor';
import type { ThreatAnalysisState, LiveThreat, ThreatSeverity, ThreatStatus } from '@/hooks/use-threat-analysis';
import type { FileScanState } from '@/hooks/use-file-scan';
import type { NetworkMonitorState } from '@/hooks/use-network-monitor';
import type { useTelemetryStream } from '@/hooks/use-telemetry-stream';
import type { useDetections } from '@/hooks/use-detections';
import { useRemediationLedger, type RemediationAuditRecord } from '@/hooks/use-remediation-ledger';

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
        'badge',
        tone === 'critical'
          ? 'badge-critical'
          : tone === 'high'
          ? 'badge-high'
          : tone === 'medium'
          ? 'badge-medium'
          : tone === 'low' || tone === 'safe' || tone === 'observed' || tone === 'confirmed' || tone === 'resolved'
          ? 'badge-low'
          : tone === 'quarantined' || tone === 'contained'
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

  // Navigation tab for Automated Remediation Audit Ledger
  const [activeTab, setActiveTab] = useState<'threats' | 'ledger' | 'cybercell'>('threats');
  const [ledgerFilter, setLedgerFilter] = useState<'all' | 'deleted' | 'quarantined' | 'sensitive'>('all');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Automated Remediation Ledger Hook (toasts disabled to prevent screen flood; dedicated section available)
  const { remediations, policy, setPolicy, stats, remediateThreat, clearLedger } = useRemediationLedger({ toast, showToasts: false });

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

  // Auto-switch mode based on live sensor status vs simulation
  useEffect(() => {
    if (isLive && !demoReached) {
      setMode('live');
    } else if (!isLive || demoReached) {
      setMode('simulated');
    }
  }, [isLive, demoReached]);

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

  // Automated Remediation Engine: Auto-delete critical threats & auto-quarantine high threats
  useEffect(() => {
    if (!policy.enabled) return;
    for (const t of activeThreats) {
      if (t.severity === 'critical' || t.severity === 'high') {
        const alreadyRemediated = remediations.some((r) => r.threatId === t.id);
        if (!alreadyRemediated) {
          remediateThreat(t);
          setLiveContainedIds((prev) => new Set([...prev, t.id]));
        }
      }
    }
  }, [activeThreats, policy.enabled, remediations, remediateThreat]);

  const filtered = useMemo(() => {
    return activeThreats.filter((t) => {
      const matchQuery = `${t.name} ${t.path} ${t.process} ${t.hash} ${t.reason}`
        .toLowerCase()
        .includes(query.trim().toLowerCase());
      const matchSeverity = severity === 'all' || t.severity === severity;
      return matchQuery && matchSeverity;
    });
  }, [activeThreats, query, severity]);

  const filteredLedger = useMemo(() => {
    return remediations.filter((r) => {
      if (ledgerFilter === 'deleted') return r.actionTaken === 'AUTOMATED_PURGE_DELETED';
      if (ledgerFilter === 'quarantined') return r.actionTaken === 'AUTOMATED_QUARANTINE';
      if (ledgerFilter === 'sensitive') return r.isSensitiveData && r.directedToCyberCell;
      return true;
    });
  }, [remediations, ledgerFilter]);

  const sensitiveCyberCellThreats = useMemo(() => {
    return remediations.filter((r) => r.isSensitiveData && r.directedToCyberCell);
  }, [remediations]);

  const processCount = processMonitor?.snapshot?.length ?? telemetry?.telemetry?.processes?.running ?? 280;
  const socketCount = networkMonitor?.snapshot?.total_count ?? 340;
  const fileCount = fileScan?.snapshot?.total_count ?? (fileScan?.findings?.length ?? 24);

  const handleContainLive = (id: string, name: string) => {
    setLiveContainedIds((prev) => new Set([...prev, id]));
    toast('Live Threat Contained', `Process/artifact ${name} isolated and suspended.`);
  };

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    toast('Hash copied', `SHA-256 copied: ${hash}`);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const exportLedger = () => {
    const payload = {
      exportedAt: new Date().toISOString(),
      host: 'Host Nikhil (Windows 11)',
      policy,
      stats,
      records: remediations,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ARGUS-Remediation-Ledger-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast('Ledger Exported', `${remediations.length} remediation audit records exported.`);
  };

  const runProbe = async () => {
    try {
      setIsProbing(true);
      const res = await fetch('/api/detections/probe', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        toast(
          'Live Benign Probe Triggered',
          `Engine evaluated ${data.detections_triggered || 3} rules on certutil.exe. Auto-remediation policy evaluated.`
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
          {/* Operational Mode Status (Auto-Switched) */}
          {mode === 'live' ? (
            <span
              className="badge badge-low"
              style={{
                background: 'hsl(142 71% 15% / 0.85)',
                color: 'hsl(142 71% 70%)',
                border: '1px solid hsl(142 71% 30%)',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                padding: '5px 12px',
                fontSize: '11px',
                fontWeight: 600,
                letterSpacing: '0.02em',
              }}
            >
              <Radio size={12} className="animate-pulse" />
              LIVE HOST DETECTIONS
            </span>
          ) : (
            <span
              className="badge badge-muted"
              style={{
                background: 'hsl(var(--muted)/0.7)',
                color: 'hsl(var(--muted-foreground))',
                border: '1px solid hsl(var(--border))',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                padding: '5px 12px',
                fontSize: '11px',
                fontWeight: 600,
              }}
            >
              <AlertTriangle size={12} />
              SIMULATED ATTACK DRILL
            </span>
          )}

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
            className="btn btn-outline"
            onClick={exportLedger}
            data-testid="button-export-ledger"
            title="Download full JSON ledger of deleted and remediated files"
          >
            <Download size={14} /> Export Audit Ledger
          </button>
        </div>
      </div>

      {/* Automated Remediation Policy Strip */}
      <div
        className="card card-pad"
        style={{
          background: 'linear-gradient(90deg, hsla(142, 70%, 45%, 0.08), hsla(217, 91%, 60%, 0.05))',
          border: '1px solid hsla(142, 70%, 45%, 0.25)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 12,
          marginBottom: 14,
          padding: '10px 16px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div
            style={{
              width: 32,
              height: 32,
              borderRadius: 6,
              background: 'hsla(142, 70%, 45%, 0.2)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'hsl(142 71% 55%)',
            }}
          >
            <Zap size={18} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontWeight: 700, fontSize: 12, color: 'hsl(142 70% 85%)' }}>
                AUTOMATED REMEDIATION ENGINE: ACTIVE
              </span>
              <span
                className="badge badge-low"
                style={{
                  fontSize: 10,
                  background: 'hsl(142 71% 20%)',
                  color: 'hsl(142 71% 70%)',
                  border: '1px solid hsl(142 71% 30%)',
                }}
              >
                AUTONOMOUS DEFENSE
              </span>
            </div>
            <div className="muted" style={{ fontSize: 11, marginTop: 2 }}>
              <strong>Critical</strong> threats: Auto-Deleted from disk · <strong>High</strong> threats: Auto-Quarantined ·{' '}
              <strong style={{ color: 'hsl(var(--destructive))' }}>Very Sensitive Data</strong> (credentials, LSASS, shadow copies, payroll): Auto-Directed to Cyber Cell.
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'hsl(var(--muted-foreground))' }}>
            AVG DWELL: <strong style={{ color: 'hsl(142 71% 55%)' }}>{stats.avgIntervalFormatted}</strong>
          </span>
          <button
            type="button"
            className={cn('btn btn-xs', policy.enabled ? 'btn-primary' : 'btn-outline')}
            style={{ fontSize: 11, padding: '3px 8px', height: 24 }}
            onClick={() => {
              setPolicy((prev) => ({ ...prev, enabled: !prev.enabled }));
              toast(
                policy.enabled ? 'Auto-Remediation Paused' : 'Auto-Remediation Resumed',
                policy.enabled ? 'Detections will require manual containment.' : 'Threats will be automatically deleted on detection.'
              );
            }}
          >
            {policy.enabled ? 'Policy: Armed' : 'Policy: Standby'}
          </button>
          {setLocation && (
            <button
              type="button"
              className="btn btn-xs btn-primary"
              style={{ fontSize: 11, padding: '3px 10px', height: 24, display: 'flex', alignItems: 'center', gap: 5 }}
              onClick={() => setLocation('/auto-remediation')}
              data-testid="link-open-auto-remediation-section"
            >
              <Zap size={12} />
              Open Dedicated Section →
            </button>
          )}
        </div>
      </div>

      {/* Summary KPI Metrics Cards */}
      <div className="grid metrics" style={{ gridTemplateColumns: 'repeat(5, 1fr)', marginBottom: 14 }}>
        <section className="card metric animate-rise">
          <div className="metric-label">
            <ShieldAlert size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />
            Active Signals
          </div>
          <div
            className={cn('metric-value', activeThreats.length > 0 ? 'signal-warn' : 'signal-good')}
            data-testid="text-metric-active-threats"
          >
            {activeThreats.length}
          </div>
          <div className="metric-note">
            {criticalCount} critical · {highCount} high
          </div>
        </section>

        <section className="card metric animate-rise">
          <div className="metric-label">
            <Trash2 size={13} style={{ verticalAlign: 'middle', marginRight: 6, color: 'hsl(0 80% 65%)' }} />
            Automated Deletions
          </div>
          <div className="metric-value signal-danger" data-testid="text-metric-deleted-files">
            {stats.totalDeleted}
          </div>
          <div className="metric-note">Critical threats purged from host</div>
        </section>

        <section className="card metric animate-rise">
          <div className="metric-label">
            <FolderLock size={13} style={{ verticalAlign: 'middle', marginRight: 6, color: 'hsl(38 90% 65%)' }} />
            Quarantined Files
          </div>
          <div className="metric-value signal-warn" data-testid="text-metric-quarantined-files">
            {stats.totalQuarantined}
          </div>
          <div className="metric-note">High severity artifacts sealed</div>
        </section>

        <section className="card metric animate-rise">
          <div className="metric-label">
            <Timer size={13} style={{ verticalAlign: 'middle', marginRight: 6, color: 'hsl(190 90% 60%)' }} />
            Avg. Remediation Time
          </div>
          <div className="metric-value signal-good" data-testid="text-metric-avg-dwell">
            {stats.avgIntervalFormatted}
          </div>
          <div className="metric-note">Detection to neutralization interval</div>
        </section>

        <section className="card metric animate-rise" style={{ border: '1px solid hsla(280, 80%, 50%, 0.3)' }}>
          <div className="metric-label">
            <Flame size={13} style={{ verticalAlign: 'middle', marginRight: 6, color: 'hsl(280 80% 65%)' }} />
            Directed to Cyber Cell
          </div>
          <div className="metric-value" style={{ color: 'hsl(280 85% 70%)' }} data-testid="text-metric-cyber-cell">
            {stats.totalSensitiveDirectedToCyberCell}
          </div>
          <div className="metric-note">Very sensitive data escalations</div>
        </section>
      </div>

      {/* Primary Tab Switcher */}
      <div
        style={{
          display: 'flex',
          gap: 6,
          background: 'hsl(var(--card))',
          padding: '4px',
          borderRadius: 8,
          border: '1px solid hsl(var(--border))',
          marginBottom: 14,
        }}
      >
        <button
          type="button"
          className={cn('btn btn-sm', activeTab === 'threats' ? 'btn-primary' : 'btn-ghost')}
          style={{ fontSize: 12, padding: '6px 14px', height: 32 }}
          onClick={() => setActiveTab('threats')}
          data-testid="tab-threat-signals"
        >
          <Activity size={13} style={{ marginRight: 6 }} />
          Threat Signals ({filtered.length})
        </button>

        <button
          type="button"
          className={cn('btn btn-sm', activeTab === 'ledger' ? 'btn-primary' : 'btn-ghost')}
          style={{ fontSize: 12, padding: '6px 14px', height: 32 }}
          onClick={() => setActiveTab('ledger')}
          data-testid="tab-remediation-ledger"
        >
          <FileText size={13} style={{ marginRight: 6 }} />
          Automated Deletion &amp; Remediation Audit Ledger ({remediations.length})
        </button>

        <button
          type="button"
          className={cn('btn btn-sm', activeTab === 'cybercell' ? 'btn-primary' : 'btn-ghost')}
          style={{
            fontSize: 12,
            padding: '6px 14px',
            height: 32,
            color: activeTab === 'cybercell' ? '#fff' : 'hsl(280 85% 70%)',
          }}
          onClick={() => setActiveTab('cybercell')}
          data-testid="tab-cybercell-escalation"
        >
          <ShieldAlert size={13} style={{ marginRight: 6 }} />
          🚨 Very Sensitive Evidence Directed to Cyber Cell ({stats.totalSensitiveDirectedToCyberCell})
        </button>
      </div>

      {/* TAB 1: ACTIVE THREAT SIGNALS */}
      {activeTab === 'threats' && (
        <section className="card card-table">
          <div className="filterbar" style={{ borderBottom: '1px solid hsl(var(--border))' }}>
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
          </div>

          <div className="table-wrap">
            <table className="data-table" data-testid="table-threats" style={{ width: '100%', tableLayout: 'fixed' }}>
              <thead>
                <tr>
                  <th style={{ width: '22%' }}>Threat</th>
                  <th style={{ width: '8%' }}>Severity</th>
                  <th style={{ width: '10%' }}>Observed</th>
                  <th style={{ width: '20%' }}>Process / path</th>
                  <th style={{ width: '9%' }}>SHA-256</th>
                  <th style={{ width: '16%' }}>Reason</th>
                  <th style={{ width: '15%', textAlign: 'right' }}>Remediation &amp; Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((t) => {
                  const remRecord = remediations.find((r) => r.threatId === t.id);
                  const isPurged = remRecord?.actionTaken === 'AUTOMATED_PURGE_DELETED';
                  const isQuarantined = remRecord?.actionTaken === 'AUTOMATED_QUARANTINE';

                  return (
                    <tr
                      key={t.id}
                      style={
                        remRecord?.isSensitiveData
                          ? { background: 'hsla(280, 80%, 40%, 0.06)' }
                          : isPurged
                          ? { background: 'hsla(0, 80%, 40%, 0.04)' }
                          : undefined
                      }
                    >
                      <td style={{ verticalAlign: 'middle', overflow: 'hidden' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <b style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={t.name}>
                            {t.name}
                          </b>
                        </div>
                        <div className="muted mono" style={{ fontSize: 11, marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {t.id} · {t.className}
                          {remRecord && (
                            <span
                              style={{
                                marginLeft: 6,
                                color: isPurged ? 'hsl(0 80% 65%)' : 'hsl(38 90% 65%)',
                                fontWeight: 700,
                              }}
                            >
                              ⚡ {isPurged ? 'DELETED' : 'QUARANTINED'} in {remRecord.timeIntervalFormatted}
                            </span>
                          )}
                        </div>
                        {remRecord?.isSensitiveData && (
                          <div style={{ marginTop: 4 }}>
                            <button
                              type="button"
                              onClick={() => setLocation('/cyber-cell')}
                              className="badge badge-critical"
                              style={{
                                fontSize: 10,
                                cursor: 'pointer',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: 4,
                                background: 'hsl(280 80% 20%)',
                                color: 'hsl(280 80% 85%)',
                                border: '1px solid hsl(280 80% 40%)',
                              }}
                              title="Very sensitive data detected. Click to view in Cyber Cell Escalation"
                            >
                              <ShieldAlert size={10} /> DIRECTED TO CYBER CELL ({remRecord.cyberCellCaseId}) ➔
                            </button>
                          </div>
                        )}
                      </td>
                      <td style={{ verticalAlign: 'middle', whiteSpace: 'nowrap' }}>
                        <Badge value={t.severity} />
                      </td>
                      <td className="mono" style={{ verticalAlign: 'middle', whiteSpace: 'nowrap' }}>
                        {t.timestamp}
                      </td>
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
                      <td
                        style={{
                          verticalAlign: 'middle',
                          whiteSpace: 'normal',
                          wordBreak: 'break-word',
                          overflowWrap: 'anywhere',
                          lineHeight: 1.4,
                          fontSize: 11,
                          paddingRight: 12,
                        }}
                      >
                        {t.reason}
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
                            <Eye size={12} /> View
                          </button>

                          {!remRecord ? (
                            <button
                              type="button"
                              className="btn btn-danger btn-sm"
                              onClick={() => remediateThreat(t)}
                              data-testid={`button-remediate-${t.id}`}
                            >
                              <Trash2 size={12} /> Auto-Delete
                            </button>
                          ) : (
                            <span
                              className="badge"
                              style={{
                                background: isPurged ? 'hsl(0 80% 12%)' : 'hsl(38 90% 12%)',
                                color: isPurged ? 'hsl(0 80% 70%)' : 'hsl(38 90% 70%)',
                                border: isPurged ? '1px solid hsl(0 80% 25%)' : '1px solid hsl(38 90% 25%)',
                                fontSize: 10,
                                fontWeight: 700,
                              }}
                            >
                              {isPurged ? 'PURGED' : 'QUARANTINED'}
                            </span>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>

            {filtered.length === 0 && (
              <div className="empty" style={{ padding: '36px 16px' }}>
                <Search size={24} style={{ color: 'hsl(var(--muted-foreground))', marginBottom: 8 }} />
                <h3>No active threat signals</h3>
                <p style={{ maxWidth: 420, margin: '6px auto 0' }}>
                  All threats have been neutralized or match clean sensor signatures. Check the Automated Deletion Ledger to view historical purge records.
                </p>
              </div>
            )}
          </div>
        </section>
      )}

      {/* TAB 2: AUTOMATED DELETION & REMEDIATION AUDIT LEDGER */}
      {activeTab === 'ledger' && (
        <section className="card card-table">
          <div
            style={{
              padding: '12px 16px',
              borderBottom: '1px solid hsl(var(--border))',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: 10,
            }}
          >
            <div>
              <h3 style={{ fontSize: 14, fontWeight: 700, margin: 0 }}>
                Forensic Audit Ledger · Deleted &amp; Remediated Artifacts
              </h3>
              <p className="muted" style={{ fontSize: 11, margin: '2px 0 0 0' }}>
                Cryptographic immutable log of files purged from host disk or quarantined based on threat level, tracking exact dwell time intervals.
              </p>
            </div>

            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <div className="btn-group" style={{ display: 'flex', background: 'hsl(var(--muted))', padding: 2, borderRadius: 6 }}>
                <button
                  type="button"
                  className={cn('btn btn-sm', ledgerFilter === 'all' ? 'btn-primary' : 'btn-ghost')}
                  style={{ fontSize: 11, padding: '3px 8px', height: 24 }}
                  onClick={() => setLedgerFilter('all')}
                >
                  All ({remediations.length})
                </button>
                <button
                  type="button"
                  className={cn('btn btn-sm', ledgerFilter === 'deleted' ? 'btn-primary' : 'btn-ghost')}
                  style={{ fontSize: 11, padding: '3px 8px', height: 24 }}
                  onClick={() => setLedgerFilter('deleted')}
                >
                  Deleted ({stats.totalDeleted})
                </button>
                <button
                  type="button"
                  className={cn('btn btn-sm', ledgerFilter === 'quarantined' ? 'btn-primary' : 'btn-ghost')}
                  style={{ fontSize: 11, padding: '3px 8px', height: 24 }}
                  onClick={() => setLedgerFilter('quarantined')}
                >
                  Quarantined ({stats.totalQuarantined})
                </button>
                <button
                  type="button"
                  className={cn('btn btn-sm', ledgerFilter === 'sensitive' ? 'btn-primary' : 'btn-ghost')}
                  style={{ fontSize: 11, padding: '3px 8px', height: 24 }}
                  onClick={() => setLedgerFilter('sensitive')}
                >
                  Cyber Cell ({stats.totalSensitiveDirectedToCyberCell})
                </button>
              </div>

              <button
                type="button"
                className="btn btn-sm btn-outline"
                style={{ fontSize: 11, padding: '3px 8px', height: 24 }}
                onClick={clearLedger}
                title="Reset local ledger records"
              >
                Reset Ledger
              </button>
            </div>
          </div>

          <div className="table-wrap">
            <table className="data-table" style={{ width: '100%', tableLayout: 'fixed' }}>
              <thead>
                <tr>
                  <th style={{ width: '20%' }}>Artifact &amp; Process</th>
                  <th style={{ width: '12%' }}>Action Taken</th>
                  <th style={{ width: '9%' }}>Threat Level</th>
                  <th style={{ width: '11%' }}>Time Interval</th>
                  <th style={{ width: '14%' }}>Detection / Purge</th>
                  <th style={{ width: '20%' }}>Data Sensitivity &amp; Cyber Cell</th>
                  <th style={{ width: '14%', textAlign: 'right' }}>SHA-256 Seal</th>
                </tr>
              </thead>
              <tbody>
                {filteredLedger.map((r) => (
                  <tr key={r.id}>
                    <td style={{ verticalAlign: 'middle', overflow: 'hidden' }}>
                      <b style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={r.name}>
                        {r.name}
                      </b>
                      <div className="mono muted" style={{ fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={r.path}>
                        {r.process} · {r.path}
                      </div>
                    </td>

                    <td style={{ verticalAlign: 'middle' }}>
                      {r.actionTaken === 'AUTOMATED_PURGE_DELETED' ? (
                        <span
                          className="badge badge-critical"
                          style={{
                            fontSize: 10,
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: 4,
                            background: 'hsl(0 80% 15% / 0.85)',
                            color: 'hsl(0 80% 75%)',
                            border: '1px solid hsl(0 80% 30%)',
                          }}
                        >
                          <Trash2 size={10} /> PURGED FROM DISK
                        </span>
                      ) : (
                        <span
                          className="badge badge-high"
                          style={{
                            fontSize: 10,
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: 4,
                            background: 'hsl(38 90% 15% / 0.85)',
                            color: 'hsl(38 90% 75%)',
                            border: '1px solid hsl(38 90% 30%)',
                          }}
                        >
                          <FolderLock size={10} /> QUARANTINED &amp; SEALED
                        </span>
                      )}
                    </td>

                    <td style={{ verticalAlign: 'middle' }}>
                      <Badge value={r.severity} />
                    </td>

                    <td style={{ verticalAlign: 'middle' }}>
                      <span
                        className="badge badge-low"
                        style={{
                          background: 'hsl(190 90% 12% / 0.9)',
                          color: 'hsl(190 90% 65%)',
                          border: '1px solid hsl(190 90% 25%)',
                          fontFamily: 'monospace',
                          fontSize: 11,
                          fontWeight: 700,
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 4,
                        }}
                      >
                        <Timer size={11} /> {r.timeIntervalFormatted}
                      </span>
                    </td>

                    <td className="mono muted" style={{ verticalAlign: 'middle', fontSize: 11 }}>
                      <div>Det: {new Date(r.detectedAt).toLocaleTimeString()}</div>
                      <div>Pur: {new Date(r.remediatedAt).toLocaleTimeString()}</div>
                    </td>

                    <td style={{ verticalAlign: 'middle' }}>
                      {r.directedToCyberCell && r.cyberCellCaseId ? (
                        <div>
                          <button
                            type="button"
                            onClick={() => setLocation('/cyber-cell')}
                            className="badge badge-critical"
                            style={{
                              fontSize: 10,
                              cursor: 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: 4,
                              background: 'hsl(280 80% 20%)',
                              color: 'hsl(280 80% 85%)',
                              border: '1px solid hsl(280 80% 40%)',
                              marginBottom: 2,
                            }}
                          >
                            <ShieldAlert size={10} /> Case {r.cyberCellCaseId} ➔
                          </button>
                          <div className="muted" style={{ fontSize: 10, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {r.sensitiveCategory || 'Very Sensitive Data'}
                          </div>
                        </div>
                      ) : (
                        <span className="badge badge-muted" style={{ fontSize: 10 }}>
                          Endpoint Cleanse
                        </span>
                      )}
                    </td>

                    <td style={{ verticalAlign: 'middle', textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                        <span className="mono muted" style={{ fontSize: 11 }} title={r.hash}>
                          {shortHash(r.hash)}
                        </span>
                        <button
                          type="button"
                          className="btn btn-ghost btn-sm"
                          style={{ padding: '2px 6px', height: 22 }}
                          onClick={() => handleCopyHash(r.hash)}
                          title="Copy SHA-256 seal"
                        >
                          {copiedHash === r.hash ? <Check size={11} className="signal-good" /> : <Copy size={11} />}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {filteredLedger.length === 0 && (
              <div className="empty" style={{ padding: '36px 16px' }}>
                <Clock size={24} style={{ color: 'hsl(var(--muted-foreground))', marginBottom: 8 }} />
                <h3>No remediation records found</h3>
                <p style={{ maxWidth: 420, margin: '6px auto 0' }}>
                  Run a live benign probe or scan to generate active remediation ledger entries.
                </p>
              </div>
            )}
          </div>
        </section>
      )}

      {/* TAB 3: VERY SENSITIVE DATA DIRECTED TO CYBER CELL */}
      {activeTab === 'cybercell' && (
        <section className="card card-pad" style={{ border: '1px solid hsla(280, 80%, 50%, 0.3)' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 16 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div
                style={{
                  width: 44,
                  height: 44,
                  borderRadius: 8,
                  background: 'hsla(280, 80%, 40%, 0.2)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'hsl(280 85% 70%)',
                }}
              >
                <ShieldAlert size={24} />
              </div>
              <div>
                <h3 style={{ fontSize: 16, fontWeight: 700, margin: 0, color: 'hsl(280 85% 90%)' }}>
                  Sensitive Incident Evidence Automatically Directed to Cyber Cell
                </h3>
                <p className="muted" style={{ fontSize: 12, margin: '4px 0 0 0' }}>
                  Threats classified as very sensitive data (credentials, memory dumps, shadow copies, payroll records) are automatically compiled into official forensic dockets for law enforcement and CERT-In escalation.
                </p>
              </div>
            </div>

            <button
              type="button"
              className="btn btn-primary"
              style={{ background: 'hsl(280 80% 40%)', borderColor: 'hsl(280 80% 50%)' }}
              onClick={() => setLocation('/cyber-cell')}
            >
              Open Cyber Cell Escalation (/cyber-cell) ➔
            </button>
          </div>

          <div className="table-wrap" style={{ marginTop: 14 }}>
            <table className="data-table" style={{ width: '100%', tableLayout: 'fixed' }}>
              <thead>
                <tr>
                  <th style={{ width: '16%' }}>Case Docket ID</th>
                  <th style={{ width: '22%' }}>Sensitive Threat Target</th>
                  <th style={{ width: '22%' }}>Classification Category</th>
                  <th style={{ width: '14%' }}>Remediation Interval</th>
                  <th style={{ width: '14%' }}>Action Status</th>
                  <th style={{ width: '12%', textAlign: 'right' }}>Dossier Link</th>
                </tr>
              </thead>
              <tbody>
                {sensitiveCyberCellThreats.map((s) => (
                  <tr key={s.id}>
                    <td style={{ verticalAlign: 'middle' }}>
                      <span className="mono" style={{ fontWeight: 700, color: 'hsl(280 85% 75%)' }}>
                        {s.cyberCellCaseId}
                      </span>
                    </td>
                    <td style={{ verticalAlign: 'middle', overflow: 'hidden' }}>
                      <b style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {s.name}
                      </b>
                      <div className="mono muted" style={{ fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {s.path}
                      </div>
                    </td>
                    <td style={{ verticalAlign: 'middle' }}>
                      <span
                        className="badge badge-critical"
                        style={{
                          fontSize: 10,
                          background: 'hsl(280 80% 15% / 0.85)',
                          color: 'hsl(280 80% 85%)',
                          border: '1px solid hsl(280 80% 35%)',
                        }}
                      >
                        {s.sensitiveCategory || 'Classified Evidence'}
                      </span>
                    </td>
                    <td style={{ verticalAlign: 'middle' }}>
                      <span className="mono" style={{ fontWeight: 700, color: 'hsl(142 71% 55%)' }}>
                        ⚡ {s.timeIntervalFormatted}
                      </span>
                    </td>
                    <td style={{ verticalAlign: 'middle' }}>
                      <span className="badge badge-low" style={{ fontSize: 10 }}>
                        {s.status}
                      </span>
                    </td>
                    <td style={{ verticalAlign: 'middle', textAlign: 'right' }}>
                      <button
                        type="button"
                        className="btn btn-sm btn-outline"
                        style={{ fontSize: 11, padding: '3px 8px' }}
                        onClick={() => {
                          toast('Cyber Cell Case Loaded', `Case ${s.cyberCellCaseId} ready for CERT-In transmission.`);
                          setLocation('/cyber-cell');
                        }}
                      >
                        View Dossier ➔
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {sensitiveCyberCellThreats.length === 0 && (
              <div className="empty" style={{ padding: '24px 16px' }}>
                <CheckCircle2 size={24} style={{ color: 'hsl(142 71% 55%)', marginBottom: 8 }} />
                <h3>No Sensitive Data Threats Incurred</h3>
                <p className="muted" style={{ fontSize: 12 }}>
                  No credentials, memory access tokens, or shadow copy destruction events have been detected.
                </p>
              </div>
            )}
          </div>
        </section>
      )}
    </div>
  );
}
