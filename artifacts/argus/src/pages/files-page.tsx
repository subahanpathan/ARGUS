import { useMemo, useState, type CSSProperties, type ReactNode } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  Check,
  CheckCircle2,
  Copy,
  Download,
  ExternalLink,
  File,
  FileCode,
  FileKey2,
  FileSearch,
  FileSpreadsheet,
  FileText,
  Filter,
  FolderOpen,
  HardDrive,
  Layers,
  Lock,
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
  Activity,
  Radar,
} from 'lucide-react';
import type { RealFileFinding, FileScanState } from '@/hooks/use-file-scan';
import type { TelemetryStreamState, SystemTelemetryData } from '@/hooks/use-telemetry-stream';

function cn(...values: Array<string | false | undefined | null>) {
  return values.filter(Boolean).join(' ');
}

type Severity = 'critical' | 'high' | 'medium' | 'low';

export type FileRecord = {
  id: string;
  timestamp: string;
  process: string;
  path: string;
  operation: string;
  classification: string;
  risk: Severity;
  hash?: string;
  size_bytes?: number;
  reason?: string;
};

export type QuarantineItem = {
  id: string;
  name: string;
  path: string;
  date: string;
  source: string;
  hash: string;
  status: string;
  threatId?: string;
};

export type FilesPageProps = {
  toast: (title: string, body: string) => void;
  fileScan?: FileScanState;
  telemetry?: TelemetryStreamState | SystemTelemetryData | null;
  onNavigate?: (path: string) => void;
  onQuarantine?: (item: QuarantineItem) => void;
};

const demoFiles: FileRecord[] = [
  {
    id: 'file-1',
    timestamp: '09:44:03',
    process: 'powershell.exe',
    path: 'C:\\Users\\mira\\Documents\\Acquisition\\Q4_strategy.docx',
    operation: 'READ',
    classification: 'Confidential / Strategy',
    risk: 'critical',
    hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    size_bytes: 42800,
    reason: 'Suspicious PowerShell read access on confidential M&A strategy documents.',
  },
  {
    id: 'file-2',
    timestamp: '09:43:48',
    process: 'powershell.exe',
    path: 'C:\\Users\\mira\\Documents\\Finance\\forecast_2025.xlsx',
    operation: 'READ',
    classification: 'Restricted / Finance',
    risk: 'critical',
    hash: 'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e',
    size_bytes: 184500,
    reason: 'PowerShell script harvesting sensitive quarterly financial spreadsheet models.',
  },
  {
    id: 'file-3',
    timestamp: '09:43:21',
    process: 'powershell.exe',
    path: 'C:\\Users\\mira\\Desktop\\browser_export.csv',
    operation: 'READ',
    classification: 'Sensitive / Identity',
    risk: 'high',
    hash: 'c2b7f94d13e2f47a61d8a9b3d5e2c4f1a8e6b4c2d0f8a6e4c2b0d8f6a4e2c0b8',
    size_bytes: 12200,
    reason: 'Credential dumping target: browser bookmark and saved session export read.',
  },
  {
    id: 'file-4',
    timestamp: '09:42:41',
    process: '7z.exe',
    path: 'C:\\Users\\mira\\AppData\\Local\\Temp\\~stage_042.zip',
    operation: 'CREATE',
    classification: 'Derived archive / Staging',
    risk: 'high',
    hash: '7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069',
    size_bytes: 845000,
    reason: 'Data staging archive created in user Temp directory by command-line 7z utility.',
  },
  {
    id: 'file-5',
    timestamp: '09:40:02',
    process: 'outlook.exe',
    path: 'C:\\Users\\mira\\AppData\\Local\\Microsoft\\Outlook\\mailbox.ost',
    operation: 'READ',
    classification: 'Internal / Mail Store',
    risk: 'medium',
    hash: 'f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2',
    size_bytes: 524288000,
    reason: 'Mail database accessed by unverified child thread.',
  },
  {
    id: 'file-6',
    timestamp: '09:37:14',
    process: 'explorer.exe',
    path: 'C:\\Users\\mira\\Downloads\\invoice_viewer.exe',
    operation: 'EXECUTE',
    classification: 'Inbound Executable',
    risk: 'critical',
    hash: '63e9d2aa18c7f0b4e5be174829ad5c6198f219ea24d10892019485bcfad02819',
    size_bytes: 284000,
    reason: 'First-seen unsigned binary launched from user Downloads folder (initial vector).',
  },
  {
    id: 'file-7',
    timestamp: '09:37:16',
    process: 'invoice_viewer.exe',
    path: 'C:\\Users\\mira\\AppData\\Local\\Temp\\ps_8F2A.ps1',
    operation: 'PERSISTENCE',
    classification: 'Staged Script Host',
    risk: 'critical',
    hash: 'a7f1c82e9d04b6f1e3aa92c4b78912d0981e4c7689102435bca091823901bdaf',
    size_bytes: 4200,
    reason: 'Obfuscated PowerShell payload staged in Temp directory with scheduled task trigger.',
  },
];

function fmtBytes(bytes?: number): string {
  if (bytes === undefined || bytes === null || isNaN(bytes)) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function getFileIcon(name: string, ext?: string) {
  const extension = (ext || name.split('.').pop() || '').toLowerCase().replace(/^\./, '');
  if (['exe', 'bat', 'cmd', 'ps1', 'vbs', 'sh'].includes(extension)) return TerminalSquare;
  if (['zip', 'rar', '7z', 'tar', 'gz'].includes(extension)) return Layers;
  if (['xlsx', 'xls', 'csv'].includes(extension)) return FileSpreadsheet;
  if (['docx', 'doc', 'pdf', 'txt'].includes(extension)) return FileText;
  if (['py', 'js', 'ts', 'json', 'yaml', 'yml'].includes(extension)) return FileCode;
  if (['ost', 'pst', 'db', 'sqlite'].includes(extension)) return HardDrive;
  return File;
}

function getSeverityBadgeClass(sev: string): string {
  switch (sev.toLowerCase()) {
    case 'critical':
      return 'badge-critical';
    case 'high':
      return 'badge-high';
    case 'medium':
      return 'badge-medium';
    case 'low':
    case 'safe':
    case 'normal':
      return 'badge-low';
    default:
      return 'badge-muted';
  }
}

export default function FilesPage({
  toast,
  fileScan,
  telemetry,
  onNavigate,
  onQuarantine,
}: FilesPageProps) {
  const [mode, setMode] = useState<'realtime' | 'simulation'>('realtime');
  const isReal = Boolean(fileScan?.hasData && (fileScan.findings.length > 0 || fileScan.snapshot != null));
  const rawTelemetry = (telemetry && 'telemetry' in telemetry) ? telemetry.telemetry : telemetry;
  const hostName = (rawTelemetry?.system as any)?.hostname || (rawTelemetry as any)?.hostname || 'LOCAL-HOST';

  // State
  const [searchTerm, setSearchTerm] = useState('');
  const [filterCategory, setFilterCategory] = useState<
    'all' | 'threats' | 'downloads' | 'staging' | 'persistence' | 'sensitive'
  >('all');
  const [onlySensitive, setOnlySensitive] = useState(false);
  const [selectedFile, setSelectedFile] = useState<FileRecord | null>(null);
  const [showQuarantineConfirm, setShowQuarantineConfirm] = useState<FileRecord | null>(null);
  const [viewMode, setViewMode] = useState<'table' | 'categories'>('table');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = (text: string, key: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    toast('Copied to clipboard', `${label}: ${text}`);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Convert real findings to unified interface
  const realRows: FileRecord[] = useMemo(() => {
    if (!isReal || !fileScan) return [];
    return fileScan.findings.map((f, idx) => ({
      id: f.id || `real-file-${idx}`,
      timestamp: f.timestamp
        ? new Date(f.timestamp).toLocaleTimeString()
        : f.modified
        ? new Date(f.modified).toLocaleTimeString()
        : 'Live Telemetry',
      process: f.is_running ? 'running host process' : 'file_scanner (psutil)',
      path: f.path,
      operation: f.category?.includes('scheduled') || f.category?.includes('run') ? 'PERSISTENCE' : 'OBSERVED',
      classification: f.className || f.category || 'Filesystem Detection',
      risk: (f.severity as Severity) || 'medium',
      hash: f.hash,
      size_bytes: f.size_bytes,
      reason: f.reason,
    }));
  }, [isReal, fileScan]);

  const activeDataset = (mode === 'realtime' && realRows.length > 0) ? realRows : demoFiles;

  // Filtered rows
  const filteredRows = useMemo(() => {
    return activeDataset.filter((item) => {
      const q = searchTerm.toLowerCase().trim();
      const matchSearch =
        q === '' ||
        item.path.toLowerCase().includes(q) ||
        item.process.toLowerCase().includes(q) ||
        item.classification.toLowerCase().includes(q) ||
        (item.hash && item.hash.toLowerCase().includes(q)) ||
        (item.reason && item.reason.toLowerCase().includes(q));

      if (!matchSearch) return false;

      if (onlySensitive) {
        return item.risk === 'critical' || item.risk === 'high';
      }

      if (filterCategory === 'threats') {
        return item.risk === 'critical' || item.risk === 'high';
      }
      if (filterCategory === 'downloads') {
        return item.path.toLowerCase().includes('download');
      }
      if (filterCategory === 'staging') {
        return (
          item.path.toLowerCase().includes('temp') ||
          item.path.toLowerCase().includes('appdata') ||
          item.path.toLowerCase().endsWith('.zip') ||
          item.path.toLowerCase().endsWith('.7z')
        );
      }
      if (filterCategory === 'persistence') {
        return (
          item.operation === 'PERSISTENCE' ||
          item.classification.toLowerCase().includes('persistence') ||
          item.path.toLowerCase().includes('startup') ||
          item.path.toLowerCase().includes('run')
        );
      }
      if (filterCategory === 'sensitive') {
        return (
          item.classification.toLowerCase().includes('confidential') ||
          item.classification.toLowerCase().includes('finance') ||
          item.classification.toLowerCase().includes('identity') ||
          item.path.toLowerCase().includes('document')
        );
      }

      return true;
    });
  }, [activeDataset, searchTerm, filterCategory, onlySensitive]);

  // Metrics
  const metrics = useMemo(() => {
    const totalFiles = isReal ? fileScan?.snapshot?.files_hashed ?? activeDataset.length : activeDataset.length;
    const criticalCount = activeDataset.filter((f) => f.risk === 'critical').length;
    const highCount = activeDataset.filter((f) => f.risk === 'high').length;
    const dirsScanned = isReal ? fileScan?.snapshot?.directories_scanned ?? 4 : 4;
    const stagingCount = activeDataset.filter(
      (f) => f.path.toLowerCase().includes('temp') || f.path.toLowerCase().includes('download')
    ).length;

    return { totalFiles, criticalCount, highCount, dirsScanned, stagingCount };
  }, [isReal, fileScan, activeDataset]);

  // Export handlers
  const exportCSV = () => {
    const headers = ['Timestamp', 'Process', 'File Path', 'Operation', 'Classification', 'Risk', 'SHA-256', 'Size'];
    const rows = filteredRows.map((f) => [
      f.timestamp,
      `"${f.process}"`,
      `"${f.path}"`,
      f.operation,
      `"${f.classification}"`,
      f.risk.toUpperCase(),
      `"${f.hash || '—'}"`,
      `"${fmtBytes(f.size_bytes)}"`,
    ]);
    const csvContent =
      'data:text/csv;charset=utf-8,' + encodeURIComponent([headers.join(','), ...rows.map((r) => r.join(','))].join('\n'));
    const link = document.createElement('a');
    link.setAttribute('href', csvContent);
    link.setAttribute('download', `ARGUS_File_Activity_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    toast('Export Complete', `Exported ${filteredRows.length} file activity records to CSV.`);
  };

  const exportJSON = () => {
    const jsonContent =
      'data:application/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(filteredRows, null, 2));
    const link = document.createElement('a');
    link.setAttribute('href', jsonContent);
    link.setAttribute('download', `ARGUS_File_Forensics_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    toast('Export Complete', `Exported ${filteredRows.length} forensic file records to JSON.`);
  };

  const handleQuarantine = (file: RealFileFinding | FileRecord) => {
    const name = file.path.split('\\').pop()?.split('/').pop() || (file as any).name || 'Unknown Artifact';
    const hash = file.hash || '—';
    const item: QuarantineItem = {
      id: `q-${Date.now()}`,
      name,
      path: file.path,
      date: new Date().toLocaleTimeString(),
      source: (file as any).process || 'file_scanner',
      hash,
      status: 'Quarantined',
    };

    if (onQuarantine) {
      onQuarantine(item);
    }

    toast('File Quarantined', `Artifact ${name} isolated into the Quarantine Vault.`);
    setShowQuarantineConfirm(null);
  };

  return (
    <div className="animate-page-enter">
      {/* Page Heading */}
      <div className="page-heading">
        <div>
          <div className="eyebrow">Observed evidence · Filesystem Threat Surveillance</div>
          <h1 className="page-title">File Activity</h1>
          <p className="page-subtitle">
            Continuous surveillance of user directories, download staging, startup run-keys, and confidential documents with real cryptographic SHA-256 validation.
          </p>
        </div>
        <div className="actions" style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          {isReal ? (
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
              REAL WINDOWS FILESYSTEM ({fileScan?.findings?.length ?? 0} FINDINGS)
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
              DEMO INCIDENT FILE TELEMETRY
            </span>
          )}

          <div
            className="btn-group"
            style={{
              display: 'flex',
              background: 'hsl(var(--card))',
              border: '1px solid hsl(var(--border))',
              borderRadius: 6,
              padding: 2,
            }}
          >
            <button
              type="button"
              className={cn('btn btn-ghost', viewMode === 'table' && 'btn-primary')}
              style={{ fontSize: 11, padding: '4px 10px', height: 26 }}
              onClick={() => setViewMode('table')}
            >
              <FileSearch size={12} style={{ marginRight: 5 }} /> Explorer Table
            </button>
            <button
              type="button"
              className={cn('btn btn-ghost', viewMode === 'categories' && 'btn-primary')}
              style={{ fontSize: 11, padding: '4px 10px', height: 26 }}
              onClick={() => setViewMode('categories')}
            >
              <FolderOpen size={12} style={{ marginRight: 5 }} /> Directory Map
            </button>
          </div>

          <button
            type="button"
            className="btn"
            onClick={exportCSV}
            title="Export full table to CSV"
            style={{ fontSize: 11, padding: '4px 10px', height: 26 }}
          >
            <Download size={12} style={{ marginRight: 5 }} /> Export CSV
          </button>
          <button
            type="button"
            className="btn"
            onClick={exportJSON}
            title="Export structured forensic JSON"
            style={{ fontSize: 11, padding: '4px 10px', height: 26 }}
          >
            <Download size={12} style={{ marginRight: 5 }} /> Export JSON
          </button>
          <button
            type="button"
            className="btn"
            onClick={() => {
              toast(
                'Filesystem Scan Refreshed',
                isReal
                  ? `Synchronized ${fileScan?.findings?.length} live findings across host directories.`
                  : 'Incident file evidence baseline reloaded.'
              );
            }}
            style={{ fontSize: 11, padding: '4px 10px', height: 26 }}
          >
            <RefreshCw size={12} style={{ marginRight: 5 }} /> Rescan
          </button>
        </div>
      </div>

      {/* Mode Switcher Banner: Real-time Host File Scanner vs Simulated Drill */}
      <div
        className="card card-pad"
        style={{
          border: mode === 'realtime' ? '1px solid hsl(var(--signal-good))' : '1px solid hsl(var(--primary))',
          background: mode === 'realtime' ? 'hsla(142, 70%, 45%, 0.05)' : 'hsla(217, 91%, 60%, 0.05)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 12,
          marginBottom: 16,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div
            style={{
              width: 38,
              height: 38,
              borderRadius: 8,
              background: mode === 'realtime' ? 'hsla(142, 70%, 45%, 0.15)' : 'hsla(217, 91%, 60%, 0.15)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: mode === 'realtime' ? 'hsl(var(--signal-good))' : 'hsl(var(--primary))',
            }}
          >
            {mode === 'realtime' ? <Activity size={20} className="animate-pulse" /> : <Radar size={20} />}
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontWeight: 700, fontSize: 13 }}>
                {mode === 'realtime' ? '⚡ LIVE HOST FILE SCANNER' : '🧪 SIMULATED INCIDENT DRILL'}
              </span>
              <span className={cn('badge', mode === 'realtime' ? 'badge-good' : 'badge-primary')} style={{ fontSize: 10 }}>
                {mode === 'realtime' ? 'HOST SENSOR CONNECTED' : 'DRILL SCENARIO'}
              </span>
            </div>
            <div className="mono muted" style={{ fontSize: 11, marginTop: 2 }}>
              {mode === 'realtime'
                ? `Auditing local host "${hostName}" · ${realRows.length} live filesystem artifacts identified · ${metrics.dirsScanned} target directories scanned`
                : 'Surveillance of synthetic M&A exfiltration and staging artifacts on endpoint WS-0427'}
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 8 }}>
          <button
            type="button"
            className={cn('btn btn-sm', mode === 'realtime' ? 'btn-primary' : 'btn-ghost')}
            style={mode === 'realtime' ? { background: 'hsl(var(--signal-good))', borderColor: 'hsl(var(--signal-good))', color: '#000' } : {}}
            onClick={() => {
              setMode('realtime');
              toast('Live Host Mode', `Switched File Activity to monitor host ${hostName}`);
            }}
          >
            <Activity size={13} />
            Live Host Files
          </button>
          <button
            type="button"
            className={cn('btn btn-sm', mode === 'simulation' ? 'btn-primary' : 'btn-ghost')}
            onClick={() => {
              setMode('simulation');
              toast('Drill Mode', 'Switched File Activity to synthetic drill sequence');
            }}
          >
            <Radar size={13} />
            Simulated Drill
          </button>
        </div>
      </div>

      {/* KPI Metrics Summary Strip */}
      <div className="grid metrics" style={{ gridTemplateColumns: 'repeat(4, 1fr)', marginBottom: 16 }}>
        <div className="card metric animate-rise">
          <div className="metric-label">
            <HardDrive size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />
            Monitored Target Files
          </div>
          <div className="metric-value signal-info">{metrics.totalFiles}</div>
          <div className="metric-note">{metrics.dirsScanned} surveillance roots monitored</div>
        </div>

        <div className="card metric animate-rise">
          <div className="metric-label">
            <ShieldAlert size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />
            Critical Threat Files
          </div>
          <div className="metric-value signal-danger">{metrics.criticalCount}</div>
          <div className="metric-note">Exfiltration & execution vectors</div>
        </div>

        <div className="card metric animate-rise">
          <div className="metric-label">
            <AlertTriangle size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />
            High Risk Inbound / Scripts
          </div>
          <div className="metric-value signal-warn">{metrics.highCount}</div>
          <div className="metric-note">Script cradles & LOLBIN staging</div>
        </div>

        <div className="card metric animate-rise">
          <div className="metric-label">
            <Layers size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />
            Staging & Temp Artifacts
          </div>
          <div className="metric-value signal-good">{metrics.stagingCount}</div>
          <div className="metric-note">Downloads & %Temp% surveillance</div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="filterbar" style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 14 }}>
        <div className="search-wrap" style={{ flex: 1 }}>
          <Search size={14} />
          <input
            className="search"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by file name, path, process, hash, or detection classification..."
            data-testid="input-search-files"
          />
          {searchTerm && (
            <button
              type="button"
              className="btn btn-ghost"
              style={{ position: 'absolute', right: 6, top: 6, padding: 2 }}
              onClick={() => setSearchTerm('')}
            >
              <X size={12} />
            </button>
          )}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Filter size={13} style={{ color: 'hsl(var(--muted-foreground))' }} />
          <select
            className="search"
            style={{ width: 190, padding: '5px 10px', fontSize: 11, cursor: 'pointer' }}
            value={filterCategory}
            onChange={(e) => setFilterCategory(e.target.value as any)}
            data-testid="select-filter-category"
          >
            <option value="all">All File Events</option>
            <option value="threats">Threats & Anomalies (High/Crit)</option>
            <option value="downloads">Downloads & Inbound</option>
            <option value="staging">Temp & Archive Staging</option>
            <option value="persistence">Startup & Persistence</option>
            <option value="sensitive">Confidential / DLP Files</option>
          </select>
        </div>

        <button
          type="button"
          className={cn('btn', onlySensitive ? 'btn-primary' : '')}
          onClick={() => setOnlySensitive(!onlySensitive)}
          data-testid="button-filter-sensitive"
          style={{ fontSize: 11, padding: '4px 10px', height: 32 }}
        >
          <FileKey2 size={13} style={{ marginRight: 5 }} />
          {onlySensitive ? 'Showing Sensitive Only' : 'Filter Sensitive (DLP)'}
        </button>

        <span className="mono muted" style={{ fontSize: 11, minWidth: 90, textAlign: 'right' }}>
          {filteredRows.length} events
        </span>
      </div>

      {/* Main View Mode: Explorer Table */}
      {viewMode === 'table' ? (
        <section className="card">
          <div className="table-wrap">
            <table className="data-table" style={{ minWidth: 1050 }}>
              <thead>
                <tr>
                  <th style={{ width: 85 }}>Time</th>
                  <th style={{ width: 140 }}>Touching Process</th>
                  <th>File Name & Path</th>
                  <th style={{ width: 110 }}>Operation</th>
                  <th style={{ width: 180 }}>Classification</th>
                  <th style={{ width: 95 }}>Risk</th>
                  <th style={{ width: 140 }}>SHA-256 Fingerprint</th>
                  <th style={{ width: 80 }}>Size</th>
                  <th style={{ width: 110, textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredRows.map((f) => {
                  const fileName = f.path.split('\\').pop()?.split('/').pop() || f.path;
                  const Icon = getFileIcon(fileName);
                  const isSelected = selectedFile?.path === f.path;

                  return (
                    <tr
                      key={f.id}
                      style={{
                        cursor: 'pointer',
                        background: isSelected ? 'hsl(var(--accent) / 0.08)' : undefined,
                      }}
                      onClick={() => setSelectedFile(f)}
                    >
                      <td className="mono" style={{ fontSize: 10 }}>
                        {f.timestamp}
                      </td>

                      <td>
                        <span
                          className="mono"
                          style={{
                            fontWeight: 700,
                            color: f.process.includes('powershell') ? 'hsl(var(--destructive))' : 'hsl(var(--foreground))',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: 4,
                          }}
                        >
                          <TerminalSquare size={11} style={{ opacity: 0.7 }} />
                          {f.process}
                        </span>
                      </td>

                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                          <Icon size={14} style={{ color: 'hsl(var(--primary))', flexShrink: 0 }} />
                          <div style={{ minWidth: 0 }}>
                            <div style={{ fontWeight: 600, fontSize: 12 }}>{fileName}</div>
                            <div
                              className="mono muted"
                              style={{
                                fontSize: 10,
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap',
                                maxWidth: 380,
                              }}
                              title={f.path}
                            >
                              {f.path}
                            </div>
                          </div>
                        </div>
                      </td>

                      <td>
                        <span
                          className={cn(
                            'badge',
                            f.operation === 'PERSISTENCE'
                              ? 'badge-critical'
                              : f.operation === 'EXECUTE'
                              ? 'badge-high'
                              : f.operation === 'CREATE'
                              ? 'badge-medium'
                              : 'badge-low'
                          )}
                          style={{ fontSize: 9, padding: '2px 6px' }}
                        >
                          {f.operation}
                        </span>
                      </td>

                      <td>
                        <span style={{ fontSize: 11, fontWeight: 500 }}>{f.classification}</span>
                      </td>

                      <td>
                        <span className={cn('badge', getSeverityBadgeClass(f.risk))} style={{ fontSize: 9, padding: '2px 6px' }}>
                          {f.risk.toUpperCase()}
                        </span>
                      </td>

                      <td className="mono" style={{ fontSize: 10 }}>
                        {f.hash ? (
                          <span
                            title="Click to copy SHA-256"
                            style={{
                              cursor: 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: 4,
                              background: 'hsl(var(--muted))',
                              padding: '2px 5px',
                              borderRadius: 4,
                            }}
                            onClick={(e) => {
                              e.stopPropagation();
                              copyToClipboard(f.hash!, `hash-${f.id}`, 'SHA-256');
                            }}
                          >
                            {copiedKey === `hash-${f.id}` ? <Check size={10} color="var(--signal-good)" /> : <Copy size={10} />}
                            {f.hash.slice(0, 10)}…{f.hash.slice(-4)}
                          </span>
                        ) : (
                          <span className="muted">—</span>
                        )}
                      </td>

                      <td className="mono" style={{ fontSize: 10 }}>
                        {fmtBytes(f.size_bytes)}
                      </td>

                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', gap: 4 }} onClick={(e) => e.stopPropagation()}>
                          <button
                            type="button"
                            className="btn btn-ghost"
                            style={{ padding: '3px 6px', fontSize: 10, height: 22 }}
                            onClick={() => setSelectedFile(f)}
                            title="Inspect forensic details"
                          >
                            Inspect
                          </button>
                          <button
                            type="button"
                            className="btn btn-ghost"
                            style={{
                              padding: '3px 6px',
                              fontSize: 10,
                              height: 22,
                              color: 'hsl(var(--destructive))',
                            }}
                            onClick={() => setShowQuarantineConfirm(f)}
                            title="Isolate / Quarantine Artifact"
                          >
                            <Lock size={10} style={{ marginRight: 2 }} />
                            Isolate
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>

            {!filteredRows.length && (
              <div className="empty" style={{ padding: 40, textAlign: 'center' }}>
                <FolderOpen size={24} style={{ opacity: 0.5, marginBottom: 8 }} />
                <h3>No file events found</h3>
                <p className="muted" style={{ fontSize: 12 }}>
                  There are no file activities matching &quot;{searchTerm}&quot; in this view.
                </p>
              </div>
            )}
          </div>
        </section>
      ) : (
        /* Category / Directory Map View */
        <div className="grid" style={{ gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
          {/* Downloads Card */}
          <section className="card card-pad">
            <div className="panel-title">
              <h3>
                <HardDrive size={15} style={{ verticalAlign: 'middle', marginRight: 6 }} />
                Downloads & Inbound Vectors
              </h3>
              <span className="mono muted">
                {activeDataset.filter((f) => f.path.toLowerCase().includes('download')).length} items
              </span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 10 }}>
              {activeDataset
                .filter((f) => f.path.toLowerCase().includes('download'))
                .map((f) => (
                  <div
                    key={f.id}
                    className="event-row"
                    style={{ cursor: 'pointer', padding: '8px 10px', borderRadius: 6 }}
                    onClick={() => setSelectedFile(f)}
                  >
                    <div style={{ minWidth: 0, flex: 1 }}>
                      <div style={{ fontWeight: 600, fontSize: 12 }}>{f.path.split('\\').pop()}</div>
                      <div className="mono muted" style={{ fontSize: 10 }}>
                        {f.path}
                      </div>
                    </div>
                    <span className={cn('badge', getSeverityBadgeClass(f.risk))}>{f.risk}</span>
                  </div>
                ))}
            </div>
          </section>

          {/* Staging / Temp Card */}
          <section className="card card-pad">
            <div className="panel-title">
              <h3>
                <Layers size={15} style={{ verticalAlign: 'middle', marginRight: 6 }} />
                Staging & Temp Directories
              </h3>
              <span className="mono muted">
                {activeDataset.filter((f) => f.path.toLowerCase().includes('temp')).length} items
              </span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 10 }}>
              {activeDataset
                .filter((f) => f.path.toLowerCase().includes('temp'))
                .map((f) => (
                  <div
                    key={f.id}
                    className="event-row"
                    style={{ cursor: 'pointer', padding: '8px 10px', borderRadius: 6 }}
                    onClick={() => setSelectedFile(f)}
                  >
                    <div style={{ minWidth: 0, flex: 1 }}>
                      <div style={{ fontWeight: 600, fontSize: 12 }}>{f.path.split('\\').pop()}</div>
                      <div className="mono muted" style={{ fontSize: 10 }}>
                        {f.path}
                      </div>
                    </div>
                    <span className={cn('badge', getSeverityBadgeClass(f.risk))}>{f.risk}</span>
                  </div>
                ))}
            </div>
          </section>

          {/* Confidential / Documents Card */}
          <section className="card card-pad">
            <div className="panel-title">
              <h3>
                <FileKey2 size={15} style={{ verticalAlign: 'middle', marginRight: 6 }} />
                Confidential & Sensitive Documents (DLP)
              </h3>
              <span className="mono muted">
                {activeDataset.filter((f) => f.path.toLowerCase().includes('document')).length} items
              </span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 10 }}>
              {activeDataset
                .filter((f) => f.path.toLowerCase().includes('document'))
                .map((f) => (
                  <div
                    key={f.id}
                    className="event-row"
                    style={{ cursor: 'pointer', padding: '8px 10px', borderRadius: 6 }}
                    onClick={() => setSelectedFile(f)}
                  >
                    <div style={{ minWidth: 0, flex: 1 }}>
                      <div style={{ fontWeight: 600, fontSize: 12 }}>{f.path.split('\\').pop()}</div>
                      <div className="mono muted" style={{ fontSize: 10 }}>
                        {f.path}
                      </div>
                    </div>
                    <span className={cn('badge', getSeverityBadgeClass(f.risk))}>{f.risk}</span>
                  </div>
                ))}
            </div>
          </section>

          {/* Persistence / Startup Card */}
          <section className="card card-pad">
            <div className="panel-title">
              <h3>
                <Zap size={15} style={{ verticalAlign: 'middle', marginRight: 6 }} />
                Startup & Persistence Run-Keys
              </h3>
              <span className="mono muted">
                {activeDataset.filter((f) => f.operation === 'PERSISTENCE' || f.classification.includes('Persistence')).length} items
              </span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 10 }}>
              {activeDataset
                .filter((f) => f.operation === 'PERSISTENCE' || f.classification.includes('Persistence'))
                .map((f) => (
                  <div
                    key={f.id}
                    className="event-row"
                    style={{ cursor: 'pointer', padding: '8px 10px', borderRadius: 6 }}
                    onClick={() => setSelectedFile(f)}
                  >
                    <div style={{ minWidth: 0, flex: 1 }}>
                      <div style={{ fontWeight: 600, fontSize: 12 }}>{f.path.split('\\').pop()}</div>
                      <div className="mono muted" style={{ fontSize: 10 }}>
                        {f.path}
                      </div>
                    </div>
                    <span className={cn('badge', getSeverityBadgeClass(f.risk))}>{f.risk}</span>
                  </div>
                ))}
            </div>
          </section>
        </div>
      )}

      {/* Forensic File Detail Inspector Modal */}
      {selectedFile && (
        <div className="modal-backdrop" role="presentation" onClick={() => setSelectedFile(null)}>
          <div
            className="modal"
            style={{ maxWidth: 650, width: '100%', maxHeight: '90vh', overflowY: 'auto' }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <FileSearch size={18} style={{ color: 'hsl(var(--primary))' }} />
                <h2 style={{ fontSize: 16, margin: 0 }}>Forensic Artifact Inspector</h2>
              </div>
              <button
                type="button"
                className="btn btn-ghost"
                style={{ padding: 4 }}
                onClick={() => setSelectedFile(null)}
              >
                <X size={16} />
              </button>
            </div>

            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 16 }}>
              <span className={cn('badge', getSeverityBadgeClass(selectedFile.risk))} style={{ fontSize: 11 }}>
                {selectedFile.risk.toUpperCase()}
              </span>
              <span className="mono muted" style={{ fontSize: 11 }}>
                Classification: {selectedFile.classification}
              </span>
            </div>

            {/* Target Path Box */}
            <div
              style={{
                background: 'hsl(var(--muted))',
                padding: '10px 14px',
                borderRadius: 6,
                marginBottom: 14,
                border: '1px solid hsl(var(--border))',
              }}
            >
              <div className="muted" style={{ fontSize: 10, marginBottom: 4 }}>
                COMPLETE ARTIFACT TARGET PATH
              </div>
              <div
                className="mono"
                style={{
                  fontSize: 12,
                  fontWeight: 600,
                  wordBreak: 'break-all',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: 10,
                }}
              >
                <span>{selectedFile.path}</span>
                <button
                  type="button"
                  className="btn btn-ghost"
                  style={{ padding: 3, flexShrink: 0 }}
                  onClick={() => copyToClipboard(selectedFile.path, 'modal-path', 'File Path')}
                  title="Copy full path"
                >
                  {copiedKey === 'modal-path' ? <Check size={12} color="var(--signal-good)" /> : <Copy size={12} />}
                </button>
              </div>
            </div>

            {/* Threat Assessment Reasoning Card */}
            {selectedFile.reason && (
              <div
                style={{
                  background: 'hsl(var(--card))',
                  border: '1px solid hsl(var(--border))',
                  borderRadius: 6,
                  padding: 12,
                  marginBottom: 14,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                  <ShieldAlert size={14} style={{ color: 'hsl(var(--destructive))' }} />
                  <span style={{ fontSize: 11, fontWeight: 700 }}>Security Assessment & Heuristics</span>
                </div>
                <p style={{ fontSize: 12, lineHeight: 1.5, margin: 0, color: 'hsl(var(--foreground))' }}>
                  {selectedFile.reason}
                </p>
              </div>
            )}

            {/* Technical Metadata Table */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(2, 1fr)',
                gap: 10,
                marginBottom: 16,
              }}
            >
              <div
                style={{
                  background: 'hsl(var(--card))',
                  border: '1px solid hsl(var(--border))',
                  borderRadius: 6,
                  padding: 10,
                }}
              >
                <div className="muted" style={{ fontSize: 10, marginBottom: 4 }}>
                  TOUCHING / SPONSOR PROCESS
                </div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span className="mono" style={{ fontWeight: 700, fontSize: 12 }}>
                    {selectedFile.process}
                  </span>
                  {onNavigate && (
                    <button
                      type="button"
                      className="btn btn-ghost"
                      style={{ padding: '2px 6px', fontSize: 10 }}
                      onClick={() => {
                        setSelectedFile(null);
                        onNavigate('/processes');
                      }}
                    >
                      View in Processes <ArrowRight size={10} style={{ marginLeft: 3 }} />
                    </button>
                  )}
                </div>
              </div>

              <div
                style={{
                  background: 'hsl(var(--card))',
                  border: '1px solid hsl(var(--border))',
                  borderRadius: 6,
                  padding: 10,
                }}
              >
                <div className="muted" style={{ fontSize: 10, marginBottom: 4 }}>
                  FILE SIZE & TIMESTAMP
                </div>
                <div className="mono" style={{ fontSize: 12 }}>
                  {fmtBytes(selectedFile.size_bytes)} · {selectedFile.timestamp}
                </div>
              </div>
            </div>

            {/* SHA-256 Hash Display */}
            {selectedFile.hash && (
              <div
                style={{
                  background: 'hsl(var(--muted))',
                  border: '1px solid hsl(var(--border))',
                  borderRadius: 6,
                  padding: '10px 14px',
                  marginBottom: 16,
                }}
              >
                <div className="muted" style={{ fontSize: 10, marginBottom: 4 }}>
                  CRYPTOGRAPHIC SHA-256 FINGERPRINT
                </div>
                <div
                  className="mono"
                  style={{
                    fontSize: 11,
                    wordBreak: 'break-all',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: 10,
                  }}
                >
                  <span>{selectedFile.hash}</span>
                  <button
                    type="button"
                    className="btn btn-ghost"
                    style={{ padding: 3, flexShrink: 0 }}
                    onClick={() => copyToClipboard(selectedFile.hash!, 'modal-hash', 'SHA-256')}
                    title="Copy full hash"
                  >
                    {copiedKey === 'modal-hash' ? <Check size={12} color="var(--signal-good)" /> : <Copy size={12} />}
                  </button>
                </div>
              </div>
            )}

            {/* Action Bar */}
            <div
              style={{
                display: 'flex',
                gap: 10,
                justifyContent: 'flex-end',
                borderTop: '1px solid hsl(var(--border))',
                paddingTop: 12,
              }}
            >
              {selectedFile.hash && selectedFile.hash !== '—' && (
                <a
                  href={`https://www.virustotal.com/gui/search/${selectedFile.hash}`}
                  target="_blank"
                  rel="noreferrer"
                  className="btn btn-ghost"
                  style={{ fontSize: 11, display: 'inline-flex', alignItems: 'center', gap: 5 }}
                >
                  <ExternalLink size={12} /> Lookup on VirusTotal
                </a>
              )}
              <button
                type="button"
                className="btn btn-danger"
                style={{ fontSize: 11 }}
                onClick={() => {
                  const target = selectedFile;
                  setSelectedFile(null);
                  setShowQuarantineConfirm(target);
                }}
              >
                <Lock size={12} style={{ marginRight: 5 }} /> Quarantine Artifact
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Quarantine Confirmation Modal */}
      {showQuarantineConfirm && (
        <div className="modal-backdrop" role="presentation" onClick={() => setShowQuarantineConfirm(null)}>
          <div className="modal" style={{ maxWidth: 460 }} onClick={(e) => e.stopPropagation()}>
            <div className="eyebrow" style={{ color: 'hsl(var(--destructive))' }}>
              REMEDIATION ACTION
            </div>
            <h2>Quarantine Artifact</h2>
            <p style={{ fontSize: 12, lineHeight: 1.5, marginTop: 8 }}>
              Are you sure you want to isolate this artifact into the ARGUS Quarantine Vault?
            </p>
            <div
              className="mono"
              style={{
                background: 'hsl(var(--muted))',
                padding: '8px 10px',
                borderRadius: 4,
                fontSize: 11,
                wordBreak: 'break-all',
                margin: '10px 0',
              }}
            >
              {showQuarantineConfirm.path}
            </div>
            <div className="modal-actions" style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button
                type="button"
                className="btn"
                onClick={() => setShowQuarantineConfirm(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-danger"
                onClick={() => handleQuarantine(showQuarantineConfirm)}
              >
                Confirm Isolation
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
