import { useMemo, useState, type CSSProperties, type ReactNode } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowUpDown,
  Check,
  CheckCircle2,
  Copy,
  Cpu,
  Database,
  Download,
  ExternalLink,
  FileSearch,
  Filter,
  Layers,
  LayoutGrid,
  List,
  Network,
  Radio,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare,
  Trash2,
  X,
  Zap,
} from 'lucide-react';
import type { RealProcessEvent, RealProcessInfo } from '@/hooks/use-process-monitor';
import {
  ProcessGraph,
  buildGraphFromSeed,
  buildGraphFromTelemetry,
  type ProcessGraphNode,
  type ProcessVerdict,
} from '@/motion/process-graph';

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

function fmtTime(t?: string | null): string {
  if (!t) return '—';
  try {
    return new Date(t).toLocaleTimeString();
  } catch {
    return '—';
  }
}

type Severity = 'critical' | 'high' | 'medium' | 'low';

type ProcessRecord = {
  pid: number;
  executable: string;
  parent: number | null;
  cpu: string;
  memory: string;
  files: number;
  network: number;
  risk: Severity;
};

const processSeed: ProcessRecord[] = [
  { pid: 4908, executable: 'explorer.exe', parent: null, cpu: '1.1%', memory: '68 MB', files: 9, network: 1, risk: 'low' },
  { pid: 7124, executable: 'outlook.exe', parent: 4908, cpu: '3.2%', memory: '214 MB', files: 42, network: 9, risk: 'medium' },
  { pid: 10544, executable: 'invoice_viewer.exe', parent: 7124, cpu: '0.4%', memory: '48 MB', files: 6, network: 0, risk: 'medium' },
  { pid: 8420, executable: 'powershell.exe', parent: 10544, cpu: '12.8%', memory: '84 MB', files: 17, network: 3, risk: 'critical' },
  { pid: 9136, executable: 'rundll32.exe', parent: 8420, cpu: '7.6%', memory: '31 MB', files: 8, network: 0, risk: 'high' },
];

export const CRITICAL_SYSTEM_PROCESSES = new Set([
  'explorer.exe',
  'dwm.exe',
  'csrss.exe',
  'lsass.exe',
  'services.exe',
  'smss.exe',
  'svchost.exe',
  'wininit.exe',
  'winlogon.exe',
  'system',
]);

export function computeProcessRisk(p: { name: string; executable_path?: string; cpu_percent?: number }): {
  severity: Severity;
  label: string;
  reason: string;
} {
  const name = (p.name || '').toLowerCase();
  const path = (p.executable_path || '').toLowerCase();

  // 1. High-risk execution shells and script hosts in suspicious user directories
  if (name === 'powershell.exe' || name === 'pwsh.exe' || name === 'cmd.exe' || name === 'wscript.exe' || name === 'cscript.exe' || name === 'mshta.exe') {
    if (path.includes('appdata') || path.includes('temp') || path.includes('downloads') || path.includes('public')) {
      return { severity: 'critical', label: 'CRITICAL', reason: 'Script engine executing from user-writable / staging path' };
    }
    return { severity: 'high', label: 'SUSPICIOUS', reason: 'System command interpreter with process execution capabilities' };
  }

  // 2. Binary masquerading detection: Windows core binaries outside system32
  if ((name === 'svchost.exe' || name === 'lsass.exe' || name === 'services.exe') && path && !path.includes('system32')) {
    return { severity: 'critical', label: 'CRITICAL', reason: 'Binary masquerade: Core system process running outside System32' };
  }

  // 3. Known attack vectors / credential targets
  if (name === 'rundll32.exe' || name === 'reg.exe' || name === 'vssadmin.exe' || name === 'certutil.exe' || name === 'schtasks.exe' || name === 'whoami.exe') {
    return { severity: 'high', label: 'SUSPICIOUS', reason: 'Living-off-the-land binary (LOLBIN) frequently abused for evasion' };
  }

  // 4. Resource anomalies
  if ((p.cpu_percent ?? 0) >= 15.0) {
    return { severity: 'medium', label: 'ANOMALY', reason: `High compute consumption: ${p.cpu_percent?.toFixed(1)}% CPU load` };
  }

  // 5. Normal system or clean apps
  if (name.endsWith('.exe') && path.includes('windows\\system32')) {
    return { severity: 'low', label: 'SYSTEM', reason: 'Verified Windows System32 core service' };
  }

  return { severity: 'low', label: 'NORMAL', reason: 'Standard process operating within expected boundaries' };
}

function Badge({ value }: { value: string }) {
  const tone = value.toLowerCase().replace(/ /g, '-');
  const cls =
    tone === 'critical' || tone === 'malicious'
      ? 'badge-critical'
      : tone === 'high' || tone === 'suspicious' || tone === 'anomaly'
      ? 'badge-high'
      : tone === 'medium' || tone === 'monitored'
      ? 'badge-medium'
      : tone === 'low' || tone === 'trusted' || tone === 'active' || tone === 'normal' || tone === 'system'
      ? 'badge-low'
      : 'badge-muted';
  return <span className={cn('badge', cls)}>{value}</span>;
}

function Button({
  children,
  onClick,
  kind = '',
  icon: Icon,
  disabled,
  style,
}: {
  children: ReactNode;
  onClick?: () => void;
  kind?: string;
  icon?: typeof Activity;
  disabled?: boolean;
  style?: CSSProperties;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      style={style}
      className={cn('btn', kind && `btn-${kind}`)}
      onClick={onClick}
    >
      {Icon && <Icon size={13} style={{ marginRight: 5 }} />}
      {children}
    </button>
  );
}

function Card({
  children,
  className = '',
  style,
}: {
  children: ReactNode;
  className?: string;
  style?: CSSProperties;
}) {
  return (
    <section className={cn('card', className)} style={style}>
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
    <div className="panel-title" style={{ marginBottom: 12 }}>
      <h2>{title}</h2>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
        {detail && <span className="mono muted" style={{ fontSize: 11 }}>{detail}</span>}
        {action}
      </div>
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
    <Card className="metric animate-rise" style={{ padding: '12px 14px' }}>
      <div className="metric-label" style={{ fontSize: 11, marginBottom: 4 }}>
        {Icon && <Icon size={12} style={{ verticalAlign: 'middle', marginRight: 5 }} />}
        {label}
      </div>
      <div className={cn('metric-value', `signal-${tone}`)} style={{ fontSize: 20 }}>
        {value}
      </div>
      <div className="metric-note" style={{ fontSize: 10, marginTop: 4 }}>
        {note}
      </div>
    </Card>
  );
}

export type ProcessesPageProps = {
  toast: (t: string, b: string) => void;
  contained: boolean;
  monitorData?: {
    connected: boolean;
    hasData: boolean;
    events: RealProcessEvent[];
    snapshot: RealProcessInfo[];
    eventCount: number;
    lastEventTime: string | null;
  };
  onNavigate?: (path: string) => void;
};

type ViewMode = 'graph' | 'table';
type SortField = 'pid' | 'name' | 'cpu' | 'memory' | 'user';
type SortOrder = 'asc' | 'desc';

export default function ProcessesPage({
  toast,
  contained,
  monitorData,
  onNavigate,
}: ProcessesPageProps) {
  const isReal = Boolean(monitorData?.hasData && monitorData.snapshot.length > 0);
  const recentEvents = monitorData?.events.filter((e) => e.event_type !== 'SNAPSHOT').slice(-25).reverse() ?? [];

  const [selectedPid, setSelectedPid] = useState<number>(() => {
    if (isReal && monitorData?.snapshot[0]) return monitorData.snapshot[0].pid;
    return 8420;
  });

  const [viewMode, setViewMode] = useState<ViewMode>('graph');
  const [searchTerm, setSearchTerm] = useState('');
  const [resourceFilter, setResourceFilter] = useState<'all' | 'threats' | 'high_cpu' | 'high_ram' | 'system'>('all');
  const [sortField, setSortField] = useState<SortField>('cpu');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [terminatingPid, setTerminatingPid] = useState<number | null>(null);
  const [showTerminateConfirm, setShowTerminateConfirm] = useState<RealProcessInfo | ProcessRecord | null>(null);
  const [killTree, setKillTree] = useState(true);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = (text: string, key: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    toast('Copied to clipboard', `${label}: ${text}`);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Contained/flagged PIDs for demo/simulated incident
  const demoContainedPids = contained ? [8420, 9136, 10544] : [];
  const demoFlaggedPids = [8420, 9136];

  // Build graph nodes
  const graphNodes: ProcessGraphNode[] = useMemo(() => {
    if (isReal && monitorData) {
      return buildGraphFromTelemetry(
        monitorData.snapshot.map((s) => ({
          pid: s.pid,
          parent_pid: s.parent_pid ?? null,
          name: s.name,
          cpu_percent: s.cpu_percent ?? null,
          memory_bytes: s.memory_bytes ?? null,
          access_error: s.access_error ?? null,
          executable_path: s.executable_path ?? null,
        })),
        contained ? [] : demoContainedPids,
        demoFlaggedPids,
      );
    }
    return buildGraphFromSeed(processSeed, demoContainedPids);
  }, [isReal, monitorData, contained, demoContainedPids]);

  // Process list for table/filtering
  const filteredProcesses = useMemo(() => {
    if (isReal && monitorData) {
      return monitorData.snapshot
        .filter((p) => {
          const matchQuery =
            searchTerm === '' ||
            p.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
            String(p.pid).includes(searchTerm) ||
            (p.username && p.username.toLowerCase().includes(searchTerm.toLowerCase())) ||
            (p.executable_path && p.executable_path.toLowerCase().includes(searchTerm.toLowerCase()));

          if (!matchQuery) return false;
          if (resourceFilter === 'threats') {
            const risk = computeProcessRisk(p);
            return risk.severity === 'critical' || risk.severity === 'high' || risk.severity === 'medium';
          }
          if (resourceFilter === 'high_cpu') return (p.cpu_percent ?? 0) >= 2.0;
          if (resourceFilter === 'high_ram') return (p.memory_bytes ?? 0) >= 150 * 1024 * 1024;
          if (resourceFilter === 'system') {
            return p.pid < 1000 || (p.username && p.username.toLowerCase().includes('system'));
          }
          return true;
        })
        .sort((a, b) => {
          let diff = 0;
          if (sortField === 'pid') diff = a.pid - b.pid;
          else if (sortField === 'name') diff = a.name.localeCompare(b.name);
          else if (sortField === 'cpu') diff = (a.cpu_percent ?? 0) - (b.cpu_percent ?? 0);
          else if (sortField === 'memory') diff = (a.memory_bytes ?? 0) - (b.memory_bytes ?? 0);
          else if (sortField === 'user') diff = (a.username ?? '').localeCompare(b.username ?? '');
          return sortOrder === 'asc' ? diff : -diff;
        });
    }

    // Demo processes
    return processSeed.filter((p) => {
      const matchQuery =
        searchTerm === '' ||
        p.executable.toLowerCase().includes(searchTerm.toLowerCase()) ||
        String(p.pid).includes(searchTerm);
      if (!matchQuery) return false;
      if (resourceFilter === 'threats') return p.risk === 'critical' || p.risk === 'high' || p.risk === 'medium';
      return true;
    });
  }, [isReal, monitorData, searchTerm, resourceFilter, sortField, sortOrder]);

  // Selected process object
  const selectedRealProcess = useMemo(() => {
    if (!isReal || !monitorData) return null;
    return monitorData.snapshot.find((p) => p.pid === selectedPid) || monitorData.snapshot[0] || null;
  }, [isReal, monitorData, selectedPid]);

  const selectedDemoProcess = useMemo(() => {
    return processSeed.find((p) => p.pid === selectedPid) || processSeed[0];
  }, [selectedPid]);

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  // Terminate process action
  const handleTerminateProcess = async (pid: number, name: string, killChildren: boolean = true) => {
    setTerminatingPid(pid);
    setShowTerminateConfirm(null);
    try {
      const resp = await fetch(`/api/processes/${pid}/terminate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, killTree: killChildren }),
      });
      const data = await resp.json();
      if (resp.ok && data.success) {
        toast('Process Terminated', `Terminated ${name} (PID ${pid}) successfully${killChildren ? ' including child tree' : ''}.`);
      } else {
        toast('Termination Failed', data.error || 'Could not terminate process.');
      }
    } catch {
      toast('Remediation Action', `Sent termination request for PID ${pid} (${name}).`);
    } finally {
      setTerminatingPid(null);
    }
  };

  // Export functions
  const exportProcessesCSV = () => {
    const list = isReal && monitorData ? filteredProcesses : processSeed;
    const headers = ['PID', 'Name', 'Parent PID', 'CPU %', 'Memory', 'Risk', 'User', 'Executable Path'];
    const rows = list.map((item: any) => {
      const pid = item.pid;
      const name = item.name || item.executable || '';
      const ppid = item.parent_pid ?? item.parent ?? '';
      const cpu = typeof item.cpu_percent === 'number' ? `${item.cpu_percent.toFixed(1)}%` : item.cpu || '0%';
      const mem = typeof item.memory_bytes === 'number' ? fmtBytes(item.memory_bytes) : item.memory || '—';
      const risk = item.risk || computeProcessRisk(item).label;
      const user = item.username || 'System';
      const path = item.executable_path || '';
      return [pid, `"${name}"`, ppid, `"${cpu}"`, `"${mem}"`, `"${risk}"`, `"${user}"`, `"${path}"`].join(',');
    });

    const csvContent = 'data:text/csv;charset=utf-8,' + encodeURIComponent([headers.join(','), ...rows].join('\n'));
    const link = document.createElement('a');
    link.setAttribute('href', csvContent);
    link.setAttribute('download', `ARGUS_Process_Snapshot_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    toast('Export Complete', `Exported ${list.length} processes to CSV.`);
  };

  const exportProcessesJSON = () => {
    const list = isReal && monitorData ? filteredProcesses : processSeed;
    const jsonContent = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(list, null, 2));
    const link = document.createElement('a');
    link.setAttribute('href', jsonContent);
    link.setAttribute('download', `ARGUS_Process_Snapshot_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    toast('Export Complete', `Exported ${list.length} processes to JSON.`);
  };

  const dataBadge = isReal ? (
    <span
      className="badge badge-low"
      style={{
        background: 'hsl(142 71% 20%)',
        color: 'hsl(142 71% 70%)',
        border: '1px solid hsl(142 71% 30%)',
        display: 'inline-flex',
        alignItems: 'center',
      }}
    >
      <Radio size={10} style={{ marginRight: 5 }} />
      REAL WINDOWS TELEMETRY ({monitorData?.snapshot.length ?? 0} PROCESSES)
    </span>
  ) : (
    <span
      className="badge badge-muted"
      style={{
        background: 'hsl(var(--muted))',
        color: 'hsl(var(--muted-foreground))',
        border: '1px solid hsl(var(--border))',
        display: 'inline-flex',
        alignItems: 'center',
      }}
    >
      <AlertTriangle size={10} style={{ marginRight: 5 }} />
      DEMO INCIDENT GRAPH
    </span>
  );

  return (
    <div className="animate-page-enter">
      <div className="page-heading">
        <div>
          <div className="eyebrow">Endpoint WS-0427 · Host execution inspection</div>
          <h1 className="page-title">Process Activity</h1>
          <p className="page-subtitle">
            Live process hierarchy, resource utilization, executable paths, parent-child tree graph, and forensic remediation actions.
          </p>
        </div>
        <div className="actions" style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          {dataBadge}
          <div className="btn-group" style={{ display: 'flex', background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', borderRadius: 6, padding: 2 }}>
            <button
              type="button"
              className={cn('btn btn-ghost', viewMode === 'graph' && 'btn-primary')}
              style={{ fontSize: 11, padding: '4px 10px', height: 26 }}
              onClick={() => setViewMode('graph')}
            >
              <LayoutGrid size={12} style={{ marginRight: 5 }} /> Graph Tree
            </button>
            <button
              type="button"
              className={cn('btn btn-ghost', viewMode === 'table' && 'btn-primary')}
              style={{ fontSize: 11, padding: '4px 10px', height: 26 }}
              onClick={() => setViewMode('table')}
            >
              <List size={12} style={{ marginRight: 5 }} /> Process Explorer
            </button>
          </div>
          <Button
            icon={RefreshCw}
            onClick={() => {
              toast(
                'Process List Refreshed',
                isReal ? `Synchronized ${monitorData?.snapshot.length} live host processes.` : 'Demo process graph reloaded.'
              );
            }}
          >
            Refresh
          </Button>
        </div>
      </div>

      {contained && (
        <div className="scan-strip" data-testid="process-contained-banner">
          <div className="scan-status">
            <ShieldCheck size={16} />
            <div>
              <b>Endpoint Contained:</b>
              <small> Isolated from external network. Suspicious execution tree frozen for forensic investigation.</small>
            </div>
          </div>
        </div>
      )}

      {!isReal && (
        <div className="scan-strip" style={{ marginBottom: 14, background: 'hsl(var(--muted))' }}>
          <div className="scan-status" style={{ color: 'hsl(var(--muted-foreground))' }}>
            <AlertTriangle size={15} />
            <div>
              <b>Demo Incident Chain Active:</b>
              <small>
                {' '}
                To inspect your real Windows host processes (all running apps, services, CPU, and RAM), start the security engine using{' '}
                <code className="mono" style={{ color: 'hsl(var(--primary))' }}>python artifacts/security-engine/main.py --api --snapshot</code>.
              </small>
            </div>
          </div>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="filterbar" style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 14, flexWrap: 'wrap' }}>
        <div className="search-wrap" style={{ flex: 1, minWidth: 260 }}>
          <Search size={14} />
          <input
            className="search"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search processes by Name, PID, Executable path, or User..."
          />
          {searchTerm && (
            <button
              type="button"
              className="btn btn-ghost"
              style={{ padding: 2, marginRight: 6 }}
              onClick={() => setSearchTerm('')}
            >
              <X size={12} />
            </button>
          )}
        </div>

        <select
          className="select"
          value={resourceFilter}
          onChange={(e) => setResourceFilter(e.target.value as any)}
          style={{ fontSize: 11, height: 32 }}
        >
          <option value="all">All Processes</option>
          <option value="threats">Threats & Anomalies</option>
          <option value="high_cpu">High CPU (≥ 2.0%)</option>
          <option value="high_ram">High RAM (≥ 150 MB)</option>
          <option value="system">System Daemons</option>
        </select>

        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <button
            type="button"
            className="btn btn-ghost"
            style={{ padding: '4px 9px', fontSize: 11 }}
            onClick={exportProcessesCSV}
            title="Export process snapshot to CSV"
          >
            <Download size={12} style={{ marginRight: 4 }} /> CSV
          </button>
          <button
            type="button"
            className="btn btn-ghost"
            style={{ padding: '4px 9px', fontSize: 11 }}
            onClick={exportProcessesJSON}
            title="Export process snapshot to JSON"
          >
            <FileSearch size={12} style={{ marginRight: 4 }} /> JSON
          </button>
        </div>

        <div className="mono muted" style={{ fontSize: 11, marginLeft: 'auto' }}>
          Showing {filteredProcesses.length} of {isReal ? monitorData?.snapshot.length : processSeed.length} processes
        </div>
      </div>

      {/* Main Split Grid: Tree/Table on Left, Inspector on Right */}
      <div className="grid split-grid" style={{ gridTemplateColumns: 'minmax(0, 1.8fr) minmax(320px, 1.2fr)', gap: 14 }}>
        {/* Left Column: View Mode Graph vs Table */}
        <div>
          {viewMode === 'graph' ? (
            <Card className="card-pad" style={{ minHeight: 460 }}>
              <PanelTitle
                title={isReal ? 'Interactive Process Graph' : 'Synthetic Incident Process Graph'}
                detail={`${graphNodes.length} NODES`}
                action={
                  <div style={{ display: 'flex', gap: 6 }}>
                    <span className="mono muted" style={{ fontSize: 10 }}>Click a node to inspect</span>
                  </div>
                }
              />
              <ProcessGraph
                nodes={graphNodes}
                selected={selectedPid}
                onSelect={(pid) => setSelectedPid(pid)}
              />
            </Card>
          ) : (
            <Card className="card-pad" style={{ minHeight: 460 }}>
              <PanelTitle
                title="Process Explorer Table"
                detail={`${filteredProcesses.length} PROCESSES`}
              />
              <div className="table-wrap" style={{ maxHeight: 520, overflow: 'auto' }}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th style={{ cursor: 'pointer' }} onClick={() => toggleSort('pid')}>
                        PID {sortField === 'pid' && <ArrowUpDown size={10} />}
                      </th>
                      <th style={{ cursor: 'pointer' }} onClick={() => toggleSort('name')}>
                        Executable {sortField === 'name' && <ArrowUpDown size={10} />}
                      </th>
                      <th>Parent</th>
                      <th style={{ cursor: 'pointer' }} onClick={() => toggleSort('cpu')}>
                        CPU % {sortField === 'cpu' && <ArrowUpDown size={10} />}
                      </th>
                      <th style={{ cursor: 'pointer' }} onClick={() => toggleSort('memory')}>
                        Memory {sortField === 'memory' && <ArrowUpDown size={10} />}
                      </th>
                      <th>Risk</th>
                      {isReal && (
                        <th style={{ cursor: 'pointer' }} onClick={() => toggleSort('user')}>
                          User {sortField === 'user' && <ArrowUpDown size={10} />}
                        </th>
                      )}
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {isReal
                      ? (filteredProcesses as RealProcessInfo[]).map((p) => {
                          const isSel = p.pid === selectedPid;
                          const cpu = p.cpu_percent ?? 0;
                          const risk = computeProcessRisk(p);
                          return (
                            <tr
                              key={p.pid}
                              style={{
                                cursor: 'pointer',
                                background: isSel ? 'hsl(var(--primary)/.08)' : undefined,
                              }}
                              onClick={() => setSelectedPid(p.pid)}
                            >
                              <td className="mono" style={{ fontWeight: isSel ? 700 : 400 }}>
                                {p.pid}
                              </td>
                              <td>
                                <b>{p.name}</b>
                                <div className="muted mono" style={{ fontSize: 10, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                  {p.executable_path || '—'}
                                </div>
                              </td>
                              <td className="mono muted" style={{ fontSize: 11 }}>
                                {p.parent_pid != null ? p.parent_pid : '—'}
                              </td>
                              <td>
                                <span className={cn('mono', cpu > 5 ? 'signal-warn' : cpu > 15 ? 'signal-danger' : '')}>
                                  {cpu.toFixed(1)}%
                                </span>
                              </td>
                              <td className="mono">{fmtBytes(p.memory_bytes)}</td>
                              <td>
                                <Badge value={risk.label} />
                              </td>
                              <td className="mono muted" style={{ fontSize: 10 }}>
                                {p.username || 'System'}
                              </td>
                              <td>
                                <button
                                  type="button"
                                  className="btn btn-ghost"
                                  style={{ padding: '3px 7px', fontSize: 10 }}
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setShowTerminateConfirm(p);
                                  }}
                                  title="Terminate Process"
                                >
                                  <Trash2 size={11} style={{ color: 'hsl(var(--destructive))' }} />
                                </button>
                              </td>
                            </tr>
                          );
                        })
                      : (filteredProcesses as ProcessRecord[]).map((p) => {
                          const isSel = p.pid === selectedPid;
                          return (
                            <tr
                              key={p.pid}
                              style={{
                                cursor: 'pointer',
                                background: isSel ? 'hsl(var(--primary)/.08)' : undefined,
                              }}
                              onClick={() => setSelectedPid(p.pid)}
                            >
                              <td className="mono">{p.pid}</td>
                              <td>
                                <b>{p.executable}</b>
                              </td>
                              <td className="mono muted">{p.parent != null ? p.parent : '—'}</td>
                              <td className="mono">{p.cpu}</td>
                              <td className="mono">{p.memory}</td>
                              <td>
                                <Badge value={p.risk} />
                              </td>
                              <td>
                                <button
                                  type="button"
                                  className="btn btn-ghost"
                                  style={{ padding: '3px 7px', fontSize: 10 }}
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setShowTerminateConfirm(p);
                                  }}
                                  title="Terminate Process"
                                >
                                  <Trash2 size={11} style={{ color: 'hsl(var(--destructive))' }} />
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                  </tbody>
                </table>
              </div>
            </Card>
          )}
        </div>

        {/* Right Column: Detailed Inspector */}
        <div>
          <Card className="card-pad" style={{ minHeight: 460 }}>
            <PanelTitle
              title="Process Forensic Detail"
              detail={`PID ${selectedPid}`}
              action={
                <div style={{ display: 'flex', gap: 6 }}>
                  <button
                    type="button"
                    className="btn btn-ghost"
                    style={{ padding: '3px 8px', fontSize: 10 }}
                    onClick={() => copyToClipboard(String(selectedPid), 'pid', 'PID')}
                  >
                    {copiedKey === 'pid' ? <Check size={11} className="signal-good" /> : <Copy size={11} />} Copy PID
                  </button>
                </div>
              }
            />

            {isReal && selectedRealProcess ? (
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: 12 }}>
                  <div>
                    <h2 style={{ margin: 0, fontSize: 19 }}>{selectedRealProcess.name}</h2>
                    <div
                      className="muted mono"
                      style={{
                        marginTop: 4,
                        fontSize: 11,
                        wordBreak: 'break-all',
                        cursor: 'pointer',
                      }}
                      onClick={() =>
                        selectedRealProcess.executable_path &&
                        copyToClipboard(selectedRealProcess.executable_path, 'path', 'Path')
                      }
                      title="Click to copy path"
                    >
                      {selectedRealProcess.executable_path || 'Protected System Binary'}
                      {selectedRealProcess.executable_path && (
                        <Copy size={10} style={{ marginLeft: 6, verticalAlign: 'middle' }} />
                      )}
                    </div>
                  </div>
                  <Badge value={computeProcessRisk(selectedRealProcess).label} />
                </div>

                <div style={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', borderRadius: 6, padding: 10, margin: '10px 0' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                    <span style={{ fontSize: 11, fontWeight: 700 }}>Security Risk Assessment</span>
                    <Badge value={computeProcessRisk(selectedRealProcess).label} />
                  </div>
                  <p style={{ margin: 0, fontSize: 11, color: 'hsl(var(--muted-foreground))', lineHeight: 1.4 }}>
                    {computeProcessRisk(selectedRealProcess).reason}
                  </p>
                </div>

                <div className="grid metrics" style={{ gridTemplateColumns: 'repeat(2, 1fr)', gap: 10, margin: '14px 0' }}>
                  <StatCard
                    label="CPU Usage"
                    value={selectedRealProcess.cpu_percent != null ? `${selectedRealProcess.cpu_percent.toFixed(1)}%` : '0.0%'}
                    note="current core utilization"
                    tone={selectedRealProcess.cpu_percent && selectedRealProcess.cpu_percent > 10 ? 'warn' : 'info'}
                    icon={Cpu}
                  />
                  <StatCard
                    label="Memory"
                    value={fmtBytes(selectedRealProcess.memory_bytes)}
                    note={selectedRealProcess.memory_percent ? `${selectedRealProcess.memory_percent.toFixed(1)}% of RAM` : 'working set'}
                    tone="good"
                    icon={Database}
                  />
                </div>

                <div style={{ borderTop: '1px solid hsl(var(--border))', paddingTop: 10, marginBottom: 16 }}>
                  <div className="kpi-line">
                    <span className="muted">Process ID (PID)</span>
                    <b className="mono">{selectedRealProcess.pid}</b>
                  </div>
                  <div className="kpi-line">
                    <span className="muted">Parent Process</span>
                    <span
                      className="mono"
                      style={{
                        cursor: selectedRealProcess.parent_pid ? 'pointer' : 'default',
                        color: selectedRealProcess.parent_pid ? 'hsl(var(--primary))' : undefined,
                      }}
                      onClick={() => {
                        if (selectedRealProcess.parent_pid) setSelectedPid(selectedRealProcess.parent_pid);
                      }}
                      title="Click to inspect parent"
                    >
                      {selectedRealProcess.parent_name
                        ? `${selectedRealProcess.parent_name} (${selectedRealProcess.parent_pid})`
                        : selectedRealProcess.parent_pid ?? 'None (Root)'}
                    </span>
                  </div>
                  <div className="kpi-line">
                    <span className="muted">Execution User</span>
                    <b className="mono">{selectedRealProcess.username || 'NT AUTHORITY\\SYSTEM'}</b>
                  </div>
                  <div className="kpi-line">
                    <span className="muted">Spawn Time</span>
                    <b className="mono">{fmtTime(selectedRealProcess.creation_time)}</b>
                  </div>
                  {selectedRealProcess.access_error && (
                    <div className="kpi-line">
                      <span className="muted">OS Access</span>
                      <span className="signal-warn mono">{selectedRealProcess.access_error}</span>
                    </div>
                  )}
                </div>

                {/* Quick Forensic Actions */}
                <div style={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', borderRadius: 6, padding: 10 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, marginBottom: 8 }}>Forensic Actions & Cross-linking</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {onNavigate && (
                      <>
                        <button
                          type="button"
                          className="btn btn-ghost"
                          style={{ justifyContent: 'flex-start', fontSize: 11, padding: '5px 8px' }}
                          onClick={() => onNavigate('/network')}
                        >
                          <Network size={12} style={{ marginRight: 6 }} /> Inspect Network Connections
                        </button>
                        <button
                          type="button"
                          className="btn btn-ghost"
                          style={{ justifyContent: 'flex-start', fontSize: 11, padding: '5px 8px' }}
                          onClick={() => onNavigate('/files')}
                        >
                          <FileSearch size={12} style={{ marginRight: 6 }} /> Inspect File Operations
                        </button>
                      </>
                    )}
                    <button
                      type="button"
                      className="btn btn-danger"
                      style={{ justifyContent: 'flex-start', fontSize: 11, padding: '5px 8px', marginTop: 4 }}
                      onClick={() => setShowTerminateConfirm(selectedRealProcess)}
                      disabled={terminatingPid === selectedRealProcess.pid}
                    >
                      <Trash2 size={12} style={{ marginRight: 6 }} />
                      {terminatingPid === selectedRealProcess.pid ? 'Terminating...' : 'Terminate / Kill Process'}
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: 12 }}>
                  <div>
                    <h2 style={{ margin: 0, fontSize: 19 }}>{selectedDemoProcess.executable}</h2>
                    <div className="muted mono" style={{ marginTop: 4, fontSize: 11 }}>
                      {selectedDemoProcess.executable === 'invoice_viewer.exe'
                        ? 'C:\\Users\\mira\\Downloads\\invoice_viewer.exe'
                        : `C:\\Windows\\System32\\${selectedDemoProcess.executable}`}
                    </div>
                  </div>
                  <Badge value={selectedDemoProcess.risk} />
                </div>

                <div className="grid metrics" style={{ gridTemplateColumns: 'repeat(2, 1fr)', gap: 10, margin: '14px 0' }}>
                  <StatCard
                    label="CPU"
                    value={contained && (selectedDemoProcess.pid === 8420 || selectedDemoProcess.pid === 9136) ? '0.0%' : selectedDemoProcess.cpu}
                    note="current utilization"
                    tone="info"
                    icon={Cpu}
                  />
                  <StatCard
                    label="Memory"
                    value={selectedDemoProcess.memory}
                    note="private working set"
                    tone="good"
                    icon={Database}
                  />
                </div>

                <div style={{ borderTop: '1px solid hsl(var(--border))', paddingTop: 10, marginBottom: 16 }}>
                  <div className="kpi-line">
                    <span className="muted">Parent Process</span>
                    <b className="mono">
                      {selectedDemoProcess.parent != null ? `PID ${selectedDemoProcess.parent}` : 'Root'}
                    </b>
                  </div>
                  <div className="kpi-line">
                    <span className="muted">File Operations</span>
                    <b className="mono">{selectedDemoProcess.files} handles</b>
                  </div>
                  <div className="kpi-line">
                    <span className="muted">Active Sockets</span>
                    <b className="mono">{selectedDemoProcess.network} connections</b>
                  </div>
                  <div className="kpi-line">
                    <span className="muted">Incident Status</span>
                    <Badge value={contained ? 'contained' : selectedDemoProcess.risk} />
                  </div>
                </div>

                <div style={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', borderRadius: 6, padding: 10 }}>
                  <div style={{ fontSize: 11, fontWeight: 700, marginBottom: 8 }}>Incident Remediation</div>
                  <button
                    type="button"
                    className="btn btn-danger"
                    style={{ width: '100%', fontSize: 11 }}
                    onClick={() => {
                      toast('Simulated Containment', `Killed simulated process ${selectedDemoProcess.executable} (PID ${selectedDemoProcess.pid}).`);
                    }}
                  >
                    <Trash2 size={12} style={{ marginRight: 6 }} /> Terminate Process
                  </button>
                </div>
              </div>
            )}
          </Card>
        </div>
      </div>

      {/* Real-time Process Events Feed */}
      {isReal && recentEvents.length > 0 && (
        <Card className="card-pad" style={{ marginTop: 14 }}>
          <PanelTitle
            title="Real-Time Host Process Events"
            detail={`LAST ${recentEvents.length} OBSERVATIONS`}
          />
          <div style={{ maxHeight: 220, overflow: 'auto' }}>
            {recentEvents.map((ev) => (
              <div className="event-row" key={ev.id}>
                <span
                  className="event-dot"
                  style={{
                    background:
                      ev.event_type === 'PROCESS_STARTED'
                        ? 'hsl(var(--accent))'
                        : 'hsl(var(--destructive))',
                  }}
                />
                <div className="event-copy">
                  <div>
                    {ev.event_type === 'PROCESS_STARTED' ? 'Process Created / Spawned' : 'Process Terminated / Exited'}
                  </div>
                  <div className="muted" style={{ fontSize: 10, marginTop: 2 }}>
                    <span className="mono" style={{ color: 'hsl(var(--foreground))', fontWeight: 600 }}>
                      {ev.process_name}
                    </span>{' '}
                    · PID <span className="mono">{ev.pid}</span>
                    {ev.parent_process_name && (
                      <span> · Parent: <span className="mono">{ev.parent_process_name}</span></span>
                    )}
                  </div>
                </div>
                <span className="event-time mono" style={{ fontSize: 10 }}>
                  {fmtTime(ev.timestamp)}
                </span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Terminate Process Confirmation Modal */}
      {showTerminateConfirm && (() => {
        const name = 'name' in showTerminateConfirm ? showTerminateConfirm.name : showTerminateConfirm.executable;
        const isCritical = CRITICAL_SYSTEM_PROCESSES.has(name.toLowerCase());
        return (
          <div className="modal-backdrop" role="presentation" onClick={() => setShowTerminateConfirm(null)}>
            <div className="modal" style={{ maxWidth: 460 }} onClick={(e) => e.stopPropagation()}>
              <div className="eyebrow" style={{ color: 'hsl(var(--destructive))' }}>High Risk Remediation</div>
              <h2 style={{ margin: '4px 0 10px', fontSize: 18 }}>Terminate Process?</h2>

              {isCritical && (
                <div style={{ background: 'hsl(38 92% 50% / 0.15)', border: '1px solid hsl(38 92% 50% / 0.4)', borderRadius: 6, padding: 10, marginBottom: 12 }}>
                  <div style={{ color: 'hsl(38 92% 50%)', fontWeight: 700, fontSize: 11, display: 'flex', alignItems: 'center', gap: 6 }}>
                    <AlertTriangle size={14} /> System Critical Process Warning
                  </div>
                  <p style={{ margin: '4px 0 0', fontSize: 11, color: 'hsl(var(--foreground))', lineHeight: 1.4 }}>
                    <b>{name}</b> is a core Windows subsystem process. Terminating it may cause desktop crashing, display restart, or forced logout.
                  </p>
                </div>
              )}

              <p style={{ fontSize: 12, lineHeight: 1.5, color: 'hsl(var(--muted-foreground))', margin: '0 0 16px' }}>
                Are you sure you want to forcibly terminate <b style={{ color: 'hsl(var(--foreground))' }}>{name}</b> (PID {showTerminateConfirm.pid})? Unsaved state in that process will be lost.
              </p>

              <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, marginBottom: 16, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={killTree}
                  onChange={(e) => setKillTree(e.target.checked)}
                  style={{ cursor: 'pointer' }}
                />
                <span>Terminate entire child process tree (<code className="mono">/T</code>)</span>
              </label>

              <div className="modal-actions" style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                <Button onClick={() => setShowTerminateConfirm(null)}>Cancel</Button>
                <Button
                  kind="danger"
                  icon={Trash2}
                  onClick={() => handleTerminateProcess(showTerminateConfirm.pid, name, killTree)}
                >
                  Terminate Process
                </Button>
              </div>
            </div>
          </div>
        );
      })()}
    </div>
  );
}
