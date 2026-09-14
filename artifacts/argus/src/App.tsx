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
  FileSearch, FileText, Fingerprint, FolderOpen, Globe2,
  History, Info, Laptop, LayoutDashboard, LockKeyhole, LogOut, Menu, Network,
  Pause, Play, Plus, RefreshCw, Radar, Search, Send, Settings2, Shield,
  ShieldAlert, ShieldCheck, SlidersHorizontal, Sparkles, TerminalSquare,
  Trash2, Wifi, X, Zap, Radio, ExternalLink
} from 'lucide-react';
import { useProcessMonitor, type RealProcessEvent, type RealProcessInfo } from '@/hooks/use-process-monitor';
import { useAutonomousDemo, DEMO_STEP, DEMO_DASHBOARD_DURATION_MS, type AutonomousDemoState, type DemoRunState } from '@/hooks/use-autonomous-demo';
import { useDetections, type DetectionStatus } from '@/hooks/use-detections';
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
import { ProcessGraph, buildGraphFromSeed, buildGraphFromTelemetry } from '@/motion/process-graph';
import { LiveChart } from '@/motion/live-chart';
import NotFound from '@/pages/not-found';

const queryClient = new QueryClient();

type Severity = 'critical' | 'high' | 'medium' | 'low';
type ThreatStatus = 'detected' | 'contained' | 'quarantined' | 'resolved';
type EvidenceStatus = 'observed' | 'potential' | 'confirmed';
type ModalState = { title: string; body: string; confirm: string; danger?: boolean; onConfirm: () => void } | null;

type Threat = {
  id: string; name: string; severity: Severity; className: string; timestamp: string;
  path: string; process: string; hash: string; reason: string; status: ThreatStatus;
};
type ProcessRecord = { pid: number; executable: string; parent: number | null; cpu: string; memory: string; files: number; network: number; risk: Severity };
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

/** Parent/child graph: explorer → outlook → invoice_viewer → powershell → rundll32 */
const processSeed: ProcessRecord[] = [
  { pid: 4908, executable: 'explorer.exe', parent: null, cpu: '1.1%', memory: '68 MB', files: 9, network: 1, risk: 'low' },
  { pid: 7124, executable: 'outlook.exe', parent: 4908, cpu: '3.2%', memory: '214 MB', files: 42, network: 9, risk: 'medium' },
  { pid: 10544, executable: 'invoice_viewer.exe', parent: 7124, cpu: '0.4%', memory: '48 MB', files: 6, network: 0, risk: 'medium' },
  { pid: 8420, executable: 'powershell.exe', parent: 10544, cpu: '12.8%', memory: '84 MB', files: 17, network: 3, risk: 'critical' },
  { pid: 9136, executable: 'rundll32.exe', parent: 8420, cpu: '7.6%', memory: '31 MB', files: 8, network: 0, risk: 'high' },
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
    ['/dashboard', 'Dashboard', LayoutDashboard], ['/threats', 'Threats', ShieldAlert], ['/detections', 'Detections', ShieldCheck], ['/monitoring', 'Monitoring', Activity],
    ['/processes', 'Processes', TerminalSquare], ['/files', 'Files', FileSearch],     ['/network', 'Network Universe', Network],
  ]},
  { label: 'Investigate', items: [
    ['/exposure', 'Exposure assessment', Eye], ['/exposure-window', 'Exposure window', Clock3], ['/timeline', 'Forensic timeline', History],
    ['/quarantine', 'Quarantine', Archive], ['/intelligence', 'Intelligence', BrainCircuit],
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
      {navGroups.map((group) => <div key={group.label}><div className="nav-section">{group.label}</div>{group.items.map(([href, label, Icon]) => <Link href={href} key={href} className={cn('nav-item', location === href ? 'active' : '')} onClick={onClose} data-testid={`link-nav-${label.toLowerCase().replace(/ /g, '-')}`}><IconLabel icon={Icon as typeof Activity}>{label}</IconLabel>{href === '/threats' && <span style={{ marginLeft: 'auto', font: '10px var(--app-font-mono)', color: 'hsl(var(--destructive))' }}>{String(threatCount).padStart(2, '0')}</span>}{href === '/detections' && <span style={{ marginLeft: 'auto', font: '10px var(--app-font-mono)', color: 'hsl(var(--primary))' }}>{String(detectionCount).padStart(2, '0')}</span>}</Link>)}</div>)}
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

function Dashboard({ phase, demoState, demo, startDemo, pauseDemo, resumeDemo, toast, telemetry, processMonitor, userName, threatAnalysis }: { phase: number; demoState: DemoRunState; demo: AutonomousDemoState; startDemo: () => void; pauseDemo: () => void; resumeDemo: () => void; toast: (title: string, body: string) => void; telemetry: ReturnType<typeof useTelemetryStream>; processMonitor: ReturnType<typeof useProcessMonitor>; userName: string; threatAnalysis: ReturnType<typeof useThreatAnalysis> }) {
  const refreshLabel = formatDashboardClock(new Date());
  const operator = userName.trim() || 'Investigator';
  const greeting = `${greetingForHour(new Date().getHours())}, ${operator}.`;
  const risk = phase >= 5 ? 86 : phase >= 3 ? 61 : 38;
  const incidentStatus = phase >= 8 ? 'Contained' : phase >= 7 ? 'Detected' : phase >= 5 ? 'Assessing' : 'Monitoring';
  const demoLabel = demoState === 'paused' ? 'Paused' : demoState === 'completed' ? 'Completed' : demoState === 'running' ? 'Running' : null;
  const autonomous = demo.demoMode;
  const autonomousDashboard = autonomous && demo.demoStep === DEMO_STEP.DASHBOARD;
  const hostOnline = telemetry.connected && telemetry.hasData && telemetry.telemetry != null;
  const t = telemetry.telemetry;
  const realEvents = processMonitor.events.filter((e) => e.event_type !== 'SNAPSHOT');
  const realStreamActive = processMonitor.connected && processMonitor.hasData;
  const heartbeatLabel = telemetry.lastUpdateTime ? `Last heartbeat ${fmtTime(telemetry.lastUpdateTime)}` : 'Last heartbeat 12 sec ago';
  return <div className="animate-page-enter">
    <PageHeading eyebrow={<LiveClock />} title={greeting} subtitle="The workspace is watching 24 endpoints across the Northstar environment." actions={<><Button icon={RefreshCw} onClick={() => toast('Workspace refreshed', `Sensor snapshots are current as of ${refreshLabel}.`)} testId="button-refresh-dashboard">Refresh</Button><Button icon={Play} kind="primary" onClick={startDemo} testId="button-start-demo">{autonomous ? 'Stop Demo' : phase >= 8 ? 'Reset Demo' : demoState === 'paused' ? 'Resume Demo' : 'Start Demo Mode'}</Button></>} />
    <div className="scan-strip" data-testid={autonomousDashboard ? 'dashboard-demo-strip' : undefined}><div className="scan-status"><span className={cn('event-dot', autonomousDashboard && 'animate-pulse-line')} style={{ margin: 0, background: autonomousDashboard ? 'hsl(var(--primary))' : phase >= 8 ? 'hsl(var(--accent))' : demoState === 'paused' ? 'hsl(var(--chart-3))' : 'hsl(var(--primary))' }} /><div>{autonomousDashboard ? <span key={demo.demoStatusLabel}>Autonomous demo · <span className="incident-card-enter" key={demo.demoStatusLabel}>{demo.demoStatusLabel}</span></span> : phase ? <span key={incidentStatus}>Synthetic incident · <span className="incident-card-enter" key={incidentStatus}>{incidentStatus}</span></span> : 'No active simulation'}<br /><small>{autonomousDashboard ? `Threat detection in ${demo.demoRemainingSeconds}s · endpoint WS-0427${demoLabel ? ` · ${demoLabel}` : ''}` : phase ? `Sequence ${Math.min(phase, 8)} of 8 · endpoint WS-0427${demoLabel ? ` · ${demoLabel}` : ''}` : 'Start Demo Mode to walk through an end-to-end exposure story.'}</small></div></div><div className="actions" style={{ position: 'relative', zIndex: 1 }}>{demoState === 'running' && <Button icon={Pause} onClick={pauseDemo} testId="button-pause-demo">Pause</Button>}{demoState === 'paused' && <Button icon={Play} kind="primary" onClick={resumeDemo} testId="button-resume-demo">Resume</Button>}{demoState === 'completed' && <span className="mono muted" data-testid="text-demo-completed">Completed</span>}<Link href="/exposure" className="btn" data-testid="link-view-assessment">View assessment <ArrowRight size={13} /></Link></div>{autonomousDashboard && <div className="demo-progress" data-testid="demo-dashboard-progress"><i style={{ width: `${Math.min(100, Math.max(0, (1 - demo.demoRemainingSeconds / (DEMO_DASHBOARD_DURATION_MS / 1000)) * 100))}%` }} /></div>}</div>
    <div className="grid metrics"><StatCard label="Protection score" value="94.8%" note="+2.6% from previous window" tone="good" icon={ShieldCheck} /><StatCard label="Active incidents" value={threatAnalysis.isLive ? String(threatAnalysis.threatCount) : phase >= 7 ? '01' : '02'} note={threatAnalysis.isLive ? `${threatAnalysis.criticalCount} critical · ${threatAnalysis.highCount} high › live detections` : phase >= 7 ? '1 awaiting containment' : '1 critical · 1 medium'} tone={threatAnalysis.isLive ? (threatAnalysis.criticalCount > 0 ? 'danger' : 'warn') : phase >= 7 ? 'danger' : 'warn'} icon={ShieldAlert} /><StatCard label="Endpoints online" value={hostOnline ? '1 / 1' : '24 / 24'} note={hostOnline ? `This host · ${heartbeatLabel.toLowerCase()}` : heartbeatLabel} tone="good" icon={Laptop} /><StatCard label="Exposure risk" value={`${risk}/100`} note={phase ? 'Synthetic incident in progress' : 'Within monitored baseline'} tone={risk > 70 ? 'danger' : 'warn'} icon={Activity} /></div>
    {hostOnline
      ? <Card className="card-pad" style={{ marginTop: 14 }} data-testid="dashboard-real-telemetry"><PanelTitle title="This host · real Windows telemetry" detail="PSUTIL · LIVE" action={<span className="badge badge-low" style={{ background: 'hsl(142 71% 20%)', color: 'hsl(142 71% 70%)', border: '1px solid hsl(142 71% 30%)' }}><Radio size={10} style={{ marginRight: 4, verticalAlign: 'middle' }} />REAL WINDOWS TELEMETRY</span>} /><div className="grid metrics" style={{ gridTemplateColumns: 'repeat(4,1fr)' }}>
        <StatCard label="CPU" value={t?.cpu?.percent != null ? `${t.cpu.percent.toFixed(1)}%` : '—'} note={t?.cpu?.count != null ? `${t.cpu.count} cores` : '—'} tone="info" icon={Cpu} />
        <StatCard label="Memory" value={t?.memory?.percent != null ? `${t.memory.percent.toFixed(1)}%` : '—'} note={fmtBytes(t?.memory?.used_bytes) + ' used'} tone="good" icon={Database} />
        <StatCard label="Processes" value={t?.processes?.running != null ? String(t.processes.running) : '—'} note="running" tone="good" icon={TerminalSquare} />
        <StatCard label="Uptime" value={fmtUptime(t?.system?.uptime_seconds)} note={`updated ${fmtTime(telemetry.lastUpdateTime ?? undefined)}`} tone="good" icon={Clock3} />
      </div></Card>
      : <div className="scan-strip" style={{ marginTop: 14, background: 'hsl(var(--muted))' }} data-testid="dashboard-telemetry-offline"><div className="scan-status" style={{ color: 'hsl(var(--muted-foreground))' }}><AlertTriangle size={15} /><div><b>MONITORING ENGINE OFFLINE</b><small> · Start the ARGUS security engine and API server to stream real Windows telemetry to the dashboard.</small></div></div></div>}
    <div className="grid dash-grid" style={{ marginTop: 14 }}>
      <Card className="card-pad"><PanelTitle title="Protection signal" detail="24H · ALL ENDPOINTS" /><div style={{ height: 190, position: 'relative' }}><LiveChart value={94.8 - (phase ? Math.min(phase * 2.4, 24) : 0)} label="signal integrity" max={100} format={(n) => `${n.toFixed(1)}%`} color="primary" height={160} /></div><div style={{ display: 'flex', gap: 22, marginTop: 17, fontSize: 10 }}><span><i className="event-dot" style={{ display: 'inline-block', margin: '0 6px 1px 0' }} />Signal integrity</span><span className="muted">Baseline confidence <b style={{ color: 'hsl(var(--foreground))' }}>98.2%</b></span></div></Card>
      <Card className="card-pad"><PanelTitle title="Live event stream" detail={realStreamActive ? 'REAL PROCESS EVENTS' : 'AUTO-REFRESH 12s'} action={<Link href="/monitoring" className="mono" style={{ color: 'hsl(var(--primary))', textDecoration: 'none' }} data-testid="link-live-stream">Open stream</Link>} />{(realStreamActive && realEvents.length > 0
        ? realEvents.slice(-4).reverse().map((event) => <div className="event-row" key={event.id}><span className="event-dot" style={event.event_type === 'PROCESS_STARTED' ? { background: 'hsl(var(--accent))' } : { background: 'hsl(var(--destructive))' }} /><div className="event-copy"><div>{event.event_type === 'PROCESS_STARTED' ? 'Process started' : 'Process terminated'}</div><div className="muted" style={{ fontSize: 10, marginTop: 2 }}><span className="mono">{event.process_name}</span> · PID {event.pid}{event.parent_process_name ? ` · ${event.parent_process_name}` : ''} · this host</div></div><span className="event-time">{new Date(event.timestamp).toLocaleTimeString()}</span></div>)
        : (phase ? timelineSeed.slice(Math.max(0, phase - 3), phase + 1).reverse() : timelineSeed.slice(0, 4)).map((event) => <div className="event-row" key={event.id}><span className="event-dot" style={event.status === 'potential' ? { background: 'hsl(var(--chart-3))', boxShadow: '0 0 0 3px hsl(var(--chart-3)/.1)' } : {}} /><div className="event-copy"><div>{event.title}</div><div className="muted" style={{ fontSize: 10, marginTop: 2 }}>{event.category} · WS-0427</div></div><span className="event-time">{event.time}</span></div>))}</Card>
      <Card className="wide"><div className="card-pad"><PanelTitle title="Recent incidents" detail={threatAnalysis.isLive ? 'REAL-TIME DETECTIONS' : 'LAST 7 DAYS'} action={<Link href="/threats" className="btn btn-ghost btn-sm" data-testid="link-all-incidents">View all <ArrowRight size={12} /></Link>} /><div className="table-wrap"><table className="data-table"><thead><tr><th>Incident</th><th>Severity</th><th>Endpoint</th><th>Observed</th><th>Risk</th><th>Status</th></tr></thead><tbody>{threatAnalysis.isLive && threatAnalysis.threatCount > 0 ? threatAnalysis.threats.slice(0, 3).map((t) => (
          <tr key={t.id}><td><b>{t.name}</b><div className="muted mono">{t.id} · {t.className}{t.source === 'live' ? ' · LIVE' : ''}</div></td><td><Badge value={t.severity} /></td><td className="mono">WS-0427 · This host</td><td className="mono">{t.timestamp.includes('T') ? new Date(t.timestamp).toLocaleTimeString() : t.timestamp}</td><td><div style={{ width: 88 }}><div className="risk-meter">{[1, 2, 3, 4, 5].map((n) => <i className={n <= Math.ceil((t.severity === 'critical' ? 100 : t.severity === 'high' ? 80 : t.severity === 'medium' ? 60 : 20) / 20) ? 'on' : ''} key={n} />)}</div></div></td><td><StateBadge value={t.status} /></td></tr>
        )) : (
          <><tr><td><b>Suspicious PowerShell execution</b><div className="muted mono">INC-2024-1042 · Command & Control</div></td><td><Badge value="critical" /></td><td className="mono">WS-0427 · Mira Alvarez</td><td className="mono">09:42:18</td><td><div style={{ width: 88 }}><div className="risk-meter">{[1, 2, 3, 4, 5].map((n) => <i className={n <= Math.ceil(risk / 20) ? 'on' : ''} key={n} />)}</div></div></td><td><Badge value={incidentStatus.toLowerCase()} /></td></tr><tr><td><b>Unsigned binary in user profile</b><div className="muted mono">INC-2024-1039 · Execution</div></td><td><Badge value="medium" /></td><td className="mono">WS-0198 · Theo Bennett</td><td className="mono">Yesterday 18:14</td><td><div style={{ width: 88 }}><div className="risk-meter">{[1, 2, 3, 4, 5].map((n) => <i className={n <= 3 ? 'on' : ''} key={n} />)}</div></div></td><td><Badge value="contained" /></td></tr></>
        )}</tbody></table></div></div></Card>
      <Card className="card-pad"><PanelTitle title="Threat intelligence" detail="CURATED SIGNALS" /><div className="event-row"><div className="avatar" style={{ borderRadius: 5 }}><Globe2 size={14} /></div><div className="event-copy"><b>cdn-sync-check[.]com</b><div className="muted">Newly registered · 3 feeds agree</div></div><Badge value="high" /></div><div className="event-row"><div className="avatar" style={{ borderRadius: 5 }}><Fingerprint size={14} /></div><div className="event-copy"><b>Hash a7f1…92c4</b><div className="muted">No prior internal sightings</div></div><Badge value="medium" /></div><Link href="/intelligence" className="btn btn-ghost btn-sm" style={{ marginTop: 12, paddingLeft: 0 }} data-testid="link-intelligence-dashboard">Open intelligence panel <ArrowRight size={12} /></Link></Card>
      <Card className="card-pad"><PanelTitle title="Sensor health" detail="LAST HEARTBEAT" />{hostOnline ? <><div style={{ display: 'flex', alignItems: 'center', gap: 15, marginBottom: 14 }}><div style={{ fontSize: 31, fontWeight: 800, letterSpacing: '-.06em' }}>100%</div><div className="signal-good" style={{ fontSize: 11 }}>This host streaming</div></div><div className="progress"><i style={{ width: '100%', background: 'hsl(var(--accent))' }} /></div><div className="kpi-line"><span className="muted">Toolchain</span><b className="mono">psutil · SSE</b></div><div className="kpi-line"><span className="muted">Process events</span><b className="mono">{processMonitor.eventCount}</b></div><div className="kpi-line"><span className="muted">Mean heartbeat</span><b className="mono">{heartbeatLabel.replace('Last heartbeat ', '')}</b></div></> : <><div style={{ display: 'flex', alignItems: 'center', gap: 15, marginBottom: 14 }}><div style={{ fontSize: 31, fontWeight: 800, letterSpacing: '-.06em' }}>100%</div><div className="signal-good" style={{ fontSize: 11 }}>All agents reporting</div></div><div className="progress"><i style={{ width: '100%', background: 'hsl(var(--accent))' }} /></div><div className="kpi-line"><span className="muted">Windows endpoints</span><b>18</b></div><div className="kpi-line"><span className="muted">macOS endpoints</span><b>6</b></div><div className="kpi-line"><span className="muted">Mean heartbeat</span><b className="mono">12 sec</b></div></>}</Card>
    </div>
  </div>;
}

function ThreatsPage({ threats, onContain, toast, setModal, setLocation, threatAnalysis, demoReached = false }: { threats: Threat[]; onContain: (id: string) => void; toast: (t: string, b: string) => void; setModal: (m: ModalState) => void; setLocation: (path: string) => void; threatAnalysis: ReturnType<typeof useThreatAnalysis>; demoReached?: boolean }) {
  const [query, setQuery] = useState(''); const [severity, setSeverity] = useState('all');
  const { isLive, scanStatus, scanProgress, scanPhaseLabel, scanItemsChecked, scanFindingsFound, runScan } = threatAnalysis;
  const liveThreats = threatAnalysis.threats;
  const allThreats = isLive && liveThreats.length > 0 ? liveThreats.map((t) => ({
    ...t,
    timestamp: /T\d{2}:/.test(t.timestamp) ? new Date(t.timestamp).toLocaleTimeString() : t.timestamp,
  })) as Threat[] : threats;
  const filtered = allThreats.filter((t) => `${t.name} ${t.path} ${t.process} ${t.hash}`.toLowerCase().includes(query.toLowerCase()) && (severity === 'all' || t.severity === severity));
  const detectionLabel = isLive ? 'Real-time detections · live engine' : 'Detection center · 02 requiring review';
  const subtitleLabel = isLive ? `${liveThreats.length} threats detected from live process and network analysis.` : 'Triage observed signals before they become a defensible incident narrative.';
  return <div className="animate-rise"><PageHeading eyebrow={detectionLabel} title="Threat detections" subtitle={subtitleLabel} actions={<>{isLive && <span className="badge badge-low" style={{ background: 'hsl(142 71% 20%)', color: 'hsl(142 71% 70%)', border: '1px solid hsl(142 71% 30%)' }}><Radio size={10} style={{ marginRight: 4, verticalAlign: 'middle' }} />REAL-TIME</span>}<Button onClick={() => runScan('Quick')} icon={Zap} testId="button-quick-scan">Quick scan</Button><Button onClick={() => runScan('Full')} icon={Radar} kind="primary" testId="button-full-scan">Full scan</Button><Button onClick={() => runScan('Custom')} icon={SlidersHorizontal} testId="button-custom-scan">Custom</Button></>} />
    {demoReached && <div className="scan-strip" data-testid="threats-demo-reached"><div className="scan-status"><Radar size={15} /><div>Reached via autonomous demo<small> · ARGUS transitioned here automatically after the 10-second dashboard presentation. Threat triage is back under your control.</small></div></div></div>}
    {!isLive && <div className="scan-strip" style={{ background: 'hsl(var(--muted))' }} data-testid="threats-offline-banner"><div className="scan-status" style={{ color: 'hsl(var(--muted-foreground))' }}><AlertTriangle size={15} /><div><b>DEMO DATA</b><small> · Start the ARGUS security engine to enable real-time threat detection from live process and network telemetry.</small></div></div></div>}
    {scanStatus === 'scanning' && <Card className="card-pad" style={{ marginBottom: 14, border: '1px solid hsl(var(--primary)/.3)', background: 'linear-gradient(90deg,rgba(71,215,239,.06),rgba(71,215,239,.02))' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
          <RefreshCw size={15} className="animate-pulse-line" style={{ color: 'hsl(var(--primary))' }} />
          <span className="scan-phase">{scanPhaseLabel}</span>
        </div>
        <span className="mono muted">{scanProgress}%</span>
      </div>
      <div className="scan-progress-bar"><div style={{ width: `${scanProgress}%` }} /></div>
      <div className="scan-findings-live" style={{ marginTop: 8 }}>
        <span>Items checked: <b>{scanItemsChecked}</b></span>
        <span>Findings: <b style={{ color: scanFindingsFound > 0 ? 'hsl(var(--destructive))' : 'hsl(var(--accent))' }}>{scanFindingsFound}</b></span>
        {isLive && <span>Source: <b>Live engine</b></span>}
      </div>
    </Card>}
    {scanStatus === 'complete' && scanFindingsFound > 0 && <div className="scan-strip" style={{ marginBottom: 14 }}><div className="scan-status"><ShieldAlert size={15} /><div>{scanFindingsFound} new finding{scanFindingsFound > 1 ? 's' : ''} discovered<small> · review the updated detection list below</small></div></div></div>}<div className="filterbar"><div className="search-wrap"><Search size={14} /><input className="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search detections, paths, processes, hashes" data-testid="input-search-threats" /></div><select className="select" value={severity} onChange={(e) => setSeverity(e.target.value)} data-testid="select-severity"><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select><span className="mono muted">{filtered.length} of {allThreats.length} detections</span></div><Card><div className="table-wrap"><table className="data-table" style={{ minWidth: 1180 }}><thead><tr><th>Detection</th><th>Severity</th><th>Observed</th><th>Process / path</th><th>SHA-256</th><th>Reason</th><th>Status</th><th /></tr></thead><tbody>{filtered.map((t) => <tr key={t.id} style={demoReached && t.severity === 'critical' ? { background: 'hsl(var(--primary)/.07)' } : undefined}><td><b>{t.name}</b><div className="muted mono">{t.id} · {t.className}</div></td><td><Badge value={t.severity} /></td><td className="mono">{t.timestamp}</td><td><div className="mono">{t.process}</div><div className="muted mono" style={{ maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis' }}>{t.path}</div></td><td className="mono" data-testid={`text-hash-${t.id}`}>{shortHash(t.hash)}</td><td style={{ maxWidth: 200, whiteSpace: 'normal', lineHeight: 1.4 }}>{t.reason}</td><td><StateBadge value={t.status} /></td><td><div className="actions"><Button kind="ghost" icon={Eye} onClick={() => { const route = investigateRouteForThreat(t); toast('Investigation opened', `${t.name} · hash ${shortHash(t.hash)}`); setLocation(route); }} testId={`button-investigate-${t.id}`}>Investigate</Button>{t.status === 'detected' && <Button kind="danger" icon={Shield} onClick={() => setModal({ title: 'Contain this endpoint?', body: 'ARGUS will isolate WS-0427 from the network and suspend the associated process. Quarantine inventory will update. This is reversible.', confirm: 'Contain endpoint', onConfirm: () => onContain(t.id) })} testId={`button-contain-${t.id}`}>Contain</Button>}</div></td></tr>)}</tbody></table>{!filtered.length && <div className="empty"><Search size={22} /><h3>No detections match</h3><p>Try clearing the filter or searching a process name.</p></div>}</div></Card></div>;
}

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

function MonitoringPage() {
  const telemetry = useTelemetryStream();
  const isOnline = telemetry.connected && telemetry.hasData && telemetry.telemetry != null;
  const latest = telemetry.telemetry;
  const cpu = latest?.cpu;
  const mem = latest?.memory;
  const disk = latest?.disk;
  const proc = latest?.processes;
  const sys = latest?.system;
  const net = latest?.network;

  const statusBadge = isOnline
    ? <span className="badge badge-low" style={{ background: 'hsl(142 71% 20%)', color: 'hsl(142 71% 70%)', border: '1px solid hsl(142 71% 30%)' }}><Radio size={10} style={{ marginRight: 4, verticalAlign: 'middle' }} />REAL WINDOWS TELEMETRY</span>
    : <span className="badge badge-muted" style={{ background: 'hsl(var(--muted))', color: 'hsl(var(--muted-foreground))', border: '1px solid hsl(var(--border))' }}><AlertTriangle size={10} style={{ marginRight: 4, verticalAlign: 'middle' }} />MONITORING ENGINE OFFLINE</span>;

  return <div className="animate-page-enter">
    <PageHeading eyebrow="Host telemetry · streaming" title="Live monitoring" subtitle="Real Windows system telemetry collected from this machine via psutil." actions={statusBadge} />
    {!isOnline && <div className="scan-strip" style={{ marginBottom: 14, background: 'hsl(var(--muted))' }} data-testid="telemetry-offline-banner"><div className="scan-status" style={{ color: 'hsl(var(--muted-foreground))' }}><AlertTriangle size={15} /><div><b>MONITORING ENGINE OFFLINE</b><small> · Start the ARGUS security engine and API server to stream real Windows telemetry. Values below are not displayed, as the stream is disconnected.</small></div></div></div>}
    <div className={isOnline ? "grid live-telemetry-grid" : "grid metrics"}>
      {isOnline ? (
        <div className="live-telemetry-row">
          <Card className="card-pad live-telemetry-cell"><LiveChart value={cpu?.percent ?? null} label="CPU utilization" max={100} format={(n) => `${n.toFixed(1)}%`} color="primary" height={140} /></Card>
          <Card className="card-pad live-telemetry-cell"><LiveChart value={mem?.percent ?? null} label="Memory pressure" max={100} format={(n) => `${n.toFixed(1)}%`} color="accent" height={140} /></Card>
          <Card className="card-pad live-telemetry-cell"><LiveChart value={disk?.percent ?? null} label="Disk utilization" max={100} format={(n) => `${n.toFixed(1)}%`} color="warn" height={140} /></Card>
        </div>
      ) : (
        <>
          <StatCard label="CPU" value={isOnline && cpu?.percent != null ? `${cpu.percent.toFixed(1)}%` : '—'} note={isOnline ? `${cpu?.count ?? '?'} logical · ${cpu?.physical_count ?? '?'} physical cores` : 'Stream disconnected'} tone="info" icon={Cpu} />
          <StatCard label="Memory" value={isOnline && mem?.percent != null ? `${mem.percent.toFixed(1)}%` : '—'} note={isOnline ? `${fmtBytes(mem?.used_bytes)} of ${fmtBytes(mem?.total_bytes)}` : 'Stream disconnected'} tone="good" icon={Database} />
          <StatCard label="Disk" value={isOnline && disk?.percent != null ? `${disk.percent.toFixed(1)}%` : '—'} note={isOnline ? `${fmtBytes(disk?.free_bytes)} free on ${disk?.mount ?? 'system'}` : 'Stream disconnected'} tone="good" icon={FolderOpen} />
          <StatCard label="Processes" value={isOnline && proc?.running != null ? String(proc.running) : '—'} note={isOnline ? 'running on this host' : 'Stream disconnected'} tone="good" icon={TerminalSquare} />
        </>
      )}
    </div>
    <div className="grid split-grid" style={{ marginTop: 14 }}>
      <Card className="card-pad">
        <PanelTitle title="System" detail="UPTIME & OS" />
        <div className="kpi-line"><span className="muted">Uptime</span><b className="mono">{isOnline ? fmtUptime(sys?.uptime_seconds) : '—'}</b></div>
        <div className="kpi-line"><span className="muted">Boot time</span><b className="mono">{isOnline && sys?.boot_time ? new Date(sys.boot_time * 1000).toLocaleString() : '—'}</b></div>
        <div className="kpi-line"><span className="muted">Source</span><b className="mono">{latest?.source ?? '—'}</b></div>
        <div className="kpi-line"><span className="muted">Observed</span><b className="mono">{latest?.observed ? 'true' : 'false'}</b></div>
        <div className="kpi-line"><span className="muted">Last update</span><b className="mono">{telemetry.hasData ? fmtTime(telemetry.lastUpdateTime ?? undefined) : '—'}</b></div>
      </Card>
      <Card className="card-pad">
        <PanelTitle title="Network interfaces" detail={`${isOnline ? `${net?.active_count ?? 0} ACTIVE / ${net?.total_count ?? 0} TOTAL` : '—'}`} />
        {(isOnline && net?.interfaces?.length) ? net.interfaces.slice(0, 6).map((iface) => (
          <div className="kpi-line" key={iface.name}>
            <span>{iface.name}<br /><span className="muted mono">{iface.addresses?.join(', ') || (iface.is_up ? 'up · no address' : 'down')}</span></span>
            <span style={{ textAlign: 'right' }}><span className={iface.is_up ? 'signal-good' : 'signal-warn'}>{iface.is_up ? 'UP' : 'DOWN'}</span><br /><span className="mono muted">{fmtBytes(iface.bytes_sent)} ↑ · {fmtBytes(iface.bytes_recv)} ↓</span></span>
          </div>
        )) : <div className="empty"><h3>No network telemetry</h3><p>{isOnline ? 'No interface data received.' : 'Connect the engine to see interface state.'}</p></div>}
      </Card>
    </div>
  </div>;
}

type ProcessesPageProps = {
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
};

function ProcessesPage({ toast, contained, monitorData }: ProcessesPageProps) {
  const [selected, setSelected] = useState(8420);
  const isReal = monitorData?.hasData && monitorData.snapshot.length > 0;
  const recentEvents = monitorData?.events.slice(-20).reverse() ?? [];

  const parentLabel = (parentPid: number | null) => {
    if (parentPid == null) return '—';
    const parent = processSeed.find((x) => x.pid === parentPid);
    return parent ? `${parent.executable} (${parent.pid})` : String(parentPid);
  };

  const dataBadge = isReal
    ? <span className="badge badge-low" style={{ background: 'hsl(142 71% 20%)', color: 'hsl(142 71% 70%)', border: '1px solid hsl(142 71% 30%)' }}><Radio size={10} style={{ marginRight: 4, verticalAlign: 'middle' }} />REAL WINDOWS TELEMETRY</span>
    : <span className="badge badge-muted" style={{ background: 'hsl(var(--muted))', color: 'hsl(var(--muted-foreground))', border: '1px solid hsl(var(--border))' }}><AlertTriangle size={10} style={{ marginRight: 4, verticalAlign: 'middle' }} />DEMO DATA</span>;

  const treeCount = isReal ? monitorData.snapshot.length : processSeed.length;
  const treeTitle = isReal ? "Interactive process graph" : "Interactive process graph (demo)";

  // Contained/flagged PIDs for the incident chain in both demo + live modes.
  const demoContainedPids = contained ? [8420, 9136, 10544] : [];
  const demoFlaggedPids = [8420, 9136];

  const graphNodes = isReal
    ? buildGraphFromTelemetry(
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
      )
    : buildGraphFromSeed(processSeed, demoContainedPids);

  const handleGraphSelect = (pid: number) => setSelected(pid);

  return <div className="animate-page-enter">
    <PageHeading eyebrow="Endpoint WS-0427 · live process graph" title="Process activity" subtitle="A parent-child view of execution, resource use, and connected evidence." actions={<>{dataBadge}<Button icon={RefreshCw} onClick={() => { toast('Process tree refreshed', isReal ? 'Merging latest Windows process snapshots.' : 'New process snapshots merged into the endpoint view.'); }} testId="button-refresh-processes">Refresh</Button></>} />
    {contained && <div className="scan-strip" data-testid="process-contained-banner"><div className="scan-status"><ShieldCheck size={15} /><div>Endpoint contained<small> · suspicious process tree remains visible for forensic review</small></div></div></div>}
    {monitorData?.connected === false && !isReal && <div className="scan-strip" style={{ marginBottom: 14, background: 'hsl(var(--muted))' }}><div className="scan-status" style={{ color: 'hsl(var(--muted-foreground))' }}><AlertTriangle size={15} /><div><b>Security engine offline</b><small> · Start the ARGUS security engine to enable real Windows process monitoring. Showing demo data.</small></div></div></div>}
    <div className="grid split-grid">
      <Card className="card-pad">
        <PanelTitle title={treeTitle} detail={`${treeCount} PROCESSES`} />
        <ProcessGraph nodes={graphNodes} selected={selected} onSelect={handleGraphSelect} />
      </Card>
      <Card className="card-pad">
        <PanelTitle title="Process detail" detail={`PID ${selected}`} />
        {isReal
          ? <RealProcessDetail snapshot={monitorData.snapshot} selected={selected} />
          : <DemoProcessDetail selected={selected} parentLabel={parentLabel} contained={contained} />}
      </Card>
    </div>
    {isReal && recentEvents.length > 0 && <Card className="card-pad" style={{ marginTop: 14 }}><PanelTitle title="Recent process events" detail={`LAST ${recentEvents.length} EVENTS`} /><div style={{ maxHeight: 240, overflow: 'auto' }}>{recentEvents.map((ev) => <div className="event-row" key={ev.id}><span className="event-dot" style={ev.event_type === 'PROCESS_STARTED' ? { background: 'hsl(var(--accent))' } : { background: 'hsl(var(--destructive))' }} /><div className="event-copy"><div>{ev.event_type === 'PROCESS_STARTED' ? 'Process started' : 'Process terminated'}</div><div className="muted" style={{ fontSize: 10, marginTop: 2 }}><span className="mono">{ev.process_name}</span> · PID {ev.pid}{ev.parent_process_name ? ` · parent: ${ev.parent_process_name}` : ''}</div></div><span className="event-time">{new Date(ev.timestamp).toLocaleTimeString()}</span></div>)}</div></Card>}
  </div>;
}

function RealProcessDetail({ snapshot, selected }: { snapshot: RealProcessInfo[]; selected: number }) {
  const p = snapshot.find((x) => x.pid === selected) || snapshot[0];
  if (!p) return <div className="empty"><h3>No process selected</h3></div>;
  const parent = snapshot.find((x) => x.pid === p.parent_pid);
  const memMB = p.memory_bytes ? `${(p.memory_bytes / 1048576).toFixed(0)} MB` : '—';
  const cpuStr = p.cpu_percent != null ? `${p.cpu_percent.toFixed(1)}%` : '—';
  return <>
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
      <div><h2 style={{ margin: 0, fontSize: 20 }}>{p.name}</h2><div className="muted mono" style={{ marginTop: 5 }}>{p.executable_path || '—'}</div></div>
      <Badge value={p.access_error ? 'restricted' : 'low'} />
    </div>
    <div className="grid metrics" style={{ gridTemplateColumns: 'repeat(2,1fr)', marginTop: 21 }}>
      <StatCard label="CPU" value={cpuStr} note="current utilization" tone="info" />
      <StatCard label="Memory" value={memMB} note="private working set" tone="good" />
    </div>
    <div className="kpi-line" style={{ marginTop: 13 }}><span className="muted">Parent</span><b className="mono">{parent ? `${parent.name} (${parent.pid})` : (p.parent_pid != null ? String(p.parent_pid) : '—')}</b></div>
    <div className="kpi-line"><span className="muted">Status</span><span className="signal-good mono"><Check size={12} style={{ verticalAlign: 'middle' }} /> {p.status || 'active'}</span></div>
    {p.username && <div className="kpi-line"><span className="muted">User</span><b className="mono">{p.username}</b></div>}
    {p.access_error && <div className="kpi-line"><span className="muted">Access</span><span className="signal-warn mono">{p.access_error}</span></div>}
    {p.creation_time && <div className="kpi-line"><span className="muted">Created</span><b className="mono">{new Date(p.creation_time).toLocaleTimeString()}</b></div>}
  </>;
}

function DemoProcessDetail({ selected, parentLabel, contained }: { selected: number; parentLabel: (pid: number | null) => string; contained: boolean }) {
  const p = processSeed.find((x) => x.pid === selected) || processSeed[0];
  const exePath = p.executable === 'invoice_viewer.exe' ? 'C:\\Users\\mira\\Downloads\\invoice_viewer.exe' : `C:\\Windows\\System32\\${p.executable}`;
  return <>
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
      <div><h2 style={{ margin: 0, fontSize: 20 }}>{p.executable}</h2><div className="muted mono" style={{ marginTop: 5 }}>{exePath}</div></div>
      <Badge value={p.risk} />
    </div>
    <div className="grid metrics" style={{ gridTemplateColumns: 'repeat(2,1fr)', marginTop: 21 }}>
      <StatCard label="CPU" value={contained && (p.pid === 8420 || p.pid === 9136 || p.pid === 10544) ? '0.0%' : p.cpu} note="current utilization" tone="info" />
      <StatCard label="Memory" value={p.memory} note="private working set" tone="good" />
    </div>
    <div className="kpi-line" style={{ marginTop: 13 }}><span className="muted">Parent</span><b className="mono">{parentLabel(p.parent)}</b></div>
    <div className="kpi-line"><span className="muted">File operations</span><b className="mono">{p.files}</b></div>
    <div className="kpi-line"><span className="muted">Network connections</span><b className="mono">{p.network}</b></div>
    <div className="kpi-line"><span className="muted">Status</span><span className="signal-good mono"><Check size={12} style={{ verticalAlign: 'middle' }} /> active</span></div>
    <div className="kpi-line"><span className="muted">Risk classification</span><Badge value={p.risk} /></div>
  </>;
}

function FilesPage({ toast }: { toast: (t: string, b: string) => void }) {
  const [query, setQuery] = useState(''); const [onlySensitive, setOnlySensitive] = useState(false); const rows = fileSeed.filter((f) => `${f.path} ${f.process} ${f.classification}`.toLowerCase().includes(query.toLowerCase()) && (!onlySensitive || f.risk === 'critical' || f.risk === 'high'));
  const exportFiles = () => {
    const csv = ['timestamp,process,path,operation,classification,risk,evidence', ...rows.map((f) => `${f.timestamp},${f.process},"${f.path}",${f.operation},"${f.classification}",${f.risk},observed`)].join('\n');
    downloadTextFile('INC-2024-1042-file-activity.csv', csv, 'text/csv');
    toast('Evidence export ready', 'File activity CSV downloaded locally.');
  };
  return <div className="animate-rise"><PageHeading eyebrow="Observed evidence · file telemetry" title="File activity" subtitle="Sensitive classifications are shown alongside the exact process that touched them." actions={<Button icon={Download} onClick={exportFiles} testId="button-export-files">Export CSV</Button>} /><div className="filterbar"><div className="search-wrap"><Search size={14} /><input className="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search file paths or processes" data-testid="input-search-files" /></div><Button kind={onlySensitive ? 'primary' : ''} icon={FileKey2} onClick={() => setOnlySensitive(!onlySensitive)} testId="button-filter-sensitive">{onlySensitive ? 'Showing sensitive' : 'Sensitive only'}</Button><span className="mono muted">{rows.length} events</span></div><Card><div className="table-wrap"><table className="data-table" style={{ minWidth: 900 }}><thead><tr><th>Time</th><th>Process</th><th>Path</th><th>Operation</th><th>Classification</th><th>Risk</th><th>Evidence</th></tr></thead><tbody>{rows.map((f) => <tr key={f.id}><td className="mono">{f.timestamp}</td><td><b>{f.process}</b></td><td className="mono">{f.path}</td><td><Badge value={f.operation.toLowerCase()} /></td><td>{f.classification}</td><td><Badge value={f.risk} /></td><td><span className="signal-good mono"><Check size={12} style={{ verticalAlign: 'middle' }} /> observed</span></td></tr>)}</tbody></table>{!rows.length && <div className="empty"><FolderOpen size={22} /><h3>No file events</h3><p>There are no file events matching this view.</p></div>}</div></Card></div>;
}

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

function DetectionsPage({ detections, toast, setLocation }: { detections: ReturnType<typeof useDetections>; toast: (t: string, b: string) => void; setLocation: (path: string) => void }) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [sevFilter, setSevFilter] = useState('all');
  const [domainFilter, setDomainFilter] = useState('all');
  const [ruleFilter, setRuleFilter] = useState('all');
  const live = detections.hasData;
  const selected = detections.selected && detections.selected.detection.id === selectedId ? detections.selected : null;
  const filtered = detections.detections.filter((d) =>
    (sevFilter === 'all' || d.severity === sevFilter) &&
    (domainFilter === 'all' || domainOf(d.rule_id) === domainFilter) &&
    (ruleFilter === 'all' || d.rule_id === ruleFilter) &&
    `${d.title} ${d.entity} ${d.rule_name} ${d.explanation} ${d.pid}`.toLowerCase().includes(query.trim().toLowerCase())
  );
  const updateStatus = async (id: string, status: DetectionStatus) => {
    const ok = await detections.updateStatus(id, status);
    toast(ok ? 'Status updated' : 'Update failed', `${id} marked ${status}.`);
  };
  const openDetail = (id: string) => { setSelectedId(id); detections.loadDetail(id); };

  if (selected) {
    const d = selected.detection;
    const change = (s: DetectionStatus) => { updateStatus(d.id, s); toast('Detection updated', `${d.id} transitioned to ${s}.`); };
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
      {!live && <div className="scan-strip" style={{ marginTop: 14, background: 'hsl(var(--muted))' }}><div className="scan-status" style={{ color: 'hsl(var(--muted-foreground))' }}><AlertTriangle size={15} /><div><b>ENGINE OFFLINE</b><small> · snapshot views may be incomplete while the security engine is not streaming.</small></div></div></div>}
    </div>;
  }

  return <div className="animate-rise">
    <PageHeading eyebrow={live ? `${detections.detections.length} buffered detections · live engine` : 'Deterministic rules · process/network/file telemetry'} title="Detection engine" subtitle="Rule-driven, explainable detections traced to real process, network and file telemetry. No demo seeding — every entry maps to an engine rule and its evidence." actions={<>{live && <span className="badge badge-low" style={{ background: 'hsl(142 71% 20%)', color: 'hsl(142 71% 70%)', border: '1px solid hsl(142 71% 30%)' }}><Radio size={10} style={{ marginRight: 4, verticalAlign: 'middle' }} />REAL-TIME</span>}<Link href="/detections/rules" className="btn btn-ghost" data-testid="link-detection-rules">Rule catalog</Link></>} />
    {!live && <div className="scan-strip" style={{ background: 'hsl(var(--muted))' }} data-testid="detections-offline-banner"><div className="scan-status" style={{ color: 'hsl(var(--muted-foreground))' }}><AlertTriangle size={15} /><div><b>DETECTION ENGINE STANDBY</b><small> · Start the ARGUS security engine and API server to evaluate live telemetry against the PROC / NET / FILE rule sets.</small></div></div></div>}
    <div className="filterbar"><div className="search-wrap"><Search size={14} /><input className="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search detections, rules, processes or PIDs" data-testid="input-search-detections" /></div><select className="select" value={domainFilter} onChange={(e) => setDomainFilter(e.target.value)} data-testid="select-detection-domain"><option value="all">All domains</option><option value="PROC">Process</option><option value="NET">Network</option><option value="FILE">File / persistence</option></select><select className="select" value={sevFilter} onChange={(e) => setSevFilter(e.target.value)} data-testid="select-detection-severity"><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select><select className="select" value={ruleFilter} onChange={(e) => setRuleFilter(e.target.value)} data-testid="select-detection-rule"><option value="all">All rules</option>{detections.rules.map((r) => <option key={r.rule_id} value={r.rule_id}>{r.rule_id}</option>)}</select><span className="mono muted">{filtered.length} of {detections.detections.length} detections</span></div>
    <Card><div className="table-wrap"><table className="data-table" style={{ minWidth: 1160 }}><thead><tr><th>Detection</th><th>Domain</th><th>Severity</th><th>Confidence</th><th>Process</th><th>Observed</th><th>Status</th><th /></tr></thead><tbody>{filtered.map((d) => <tr key={d.id}><td><b>{d.title}</b><div className="muted mono">{d.rule_id} · {d.rule_name}</div></td><td><Badge value={domainOf(d.rule_id)} /></td><td><Badge value={d.severity} /></td><td className="mono">{Math.round(d.confidence * 100)}%</td><td><div className="mono">{d.entity}</div><div className="muted mono" style={{ maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.executable_path ?? `PID ${d.pid}`}</div></td><td className="mono">{new Date(d.timestamp).toLocaleString()}</td><td><StateBadge value={d.status} /></td><td><div className="actions"><Button icon={Eye} kind="ghost" onClick={() => openDetail(d.id)} testId={`button-open-detection-${d.id}`}>View</Button></div></td></tr>)}</tbody></table>{filtered.length === 0 && <div className="empty"><Shield size={22} /><h3>{detections.detections.length === 0 ? 'No detections yet' : 'No matching detections'}</h3><p>{detections.detections.length === 0 ? 'The rule engine evaluates process, network and file telemetry as it streams in. Detections will appear here as rules fire.' : 'Adjust the filters or query to widen the view.'}</p></div>}</div></Card>
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

  const isLive = topology.connected && topology.hasData && topology.snapshot != null;
  const sim = useSimulatedNetwork(!isLive);
  const mode: NetworkMode = isLive ? 'live' : sim.data ? 'simulated' : 'offline';
  const dataActive = mode !== 'offline';

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
        ? `Observing this laptop, ${universeModel.stats.processes} processes, ${universeModel.stats.connections} connections, and ${universeModel.stats.interfaces} interfaces from the real Windows networking stack.`
        : mode === 'simulated'
          ? `Synthesized telemetry for ${universeModel.stats.processes} processes, ${universeModel.stats.connections} connections, and ${universeModel.stats.interfaces} interfaces. Real engine data replaces this automatically when the security engine connects.`
          : 'No network telemetry is streaming. Start the security engine to observe the real network universe.'}
      actions={<>
        <Button icon={Download} onClick={exportNetwork} testId="button-export-network">Export topology</Button>
        {isLive
          ? <span className="badge badge-low" style={{ background: 'hsl(142 71% 20%)', color: 'hsl(142 71% 70%)', border: '1px solid hsl(142 71% 30%)' }}><Radio size={10} style={{ marginRight: 4, verticalAlign: 'middle' }} />REAL NETWORK DATA</span>
          : mode === 'simulated'
            ? <span className="badge" style={{ background: 'hsl(46 80% 12%)', color: 'hsl(46 90% 66%)', border: '1px solid hsl(46 80% 32%)' }}><Radio size={10} style={{ marginRight: 4, verticalAlign: 'middle' }} />SIMULATED PREVIEW</span>
            : <span className="badge badge-high"><AlertTriangle size={10} style={{ marginRight: 4, verticalAlign: 'middle' }} />TELEMETRY OFFLINE</span>}
      </>} />

    {contained && <div className="scan-strip" data-testid="network-contained-banner"><div className="scan-status"><ShieldCheck size={15} /><div>Containment applied<small> · outbound sessions on this host were terminated; the observed connection history is retained for review.</small></div></div></div>}
    {!isLive && mode === 'simulated' && <div className="scan-strip" style={{ background: 'hsl(46 60% 7%)' }}><div className="scan-status" style={{ color: 'hsl(46 85% 66%)' }}><AlertTriangle size={15} /><div><b>SIMULATED PREVIEW ACTIVE</b><small> · No engine connection yet — the universe is generated locally in real time and switches to live telemetry the moment ARGUS connects (python main.py --api).</small></div></div></div>}
    {!isLive && mode === 'offline' && <div className="scan-strip" style={{ background: 'hsl(var(--muted))' }}><div className="scan-status" style={{ color: 'hsl(var(--muted-foreground))' }}><AlertTriangle size={15} /><div><b>NETWORK TELEMETRY OFFLINE</b><small> · Start ARGUS (python main.py --api) to stream the real network universe.</small></div></div></div>}

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

function ExposurePage({ phase, toast }: { phase: number; toast: (t: string, b: string) => void }) {
  const score = phase >= 5 ? 86 : phase >= 3 ? 61 : 38;
  const stages = [['Accessed', '5 files', 'Observed evidence', 'good'], ['Collected', '3 files', 'Observed evidence', 'good'], ['Staged', '1 archive', 'Observed evidence', 'good'], ['Potentially transmitted', '18.4 KB', 'Inferred from flow', 'warn'], ['Confirmed exfiltration', 'Not established', 'No direct payload evidence', 'muted']];
  const exportAssessment = () => {
    const text = [
      'ARGUS Exposure Assessment — INC-2024-1042',
      `Assessed risk: ${score}/100`,
      'Confirmed exfiltration: Not established',
      'Evidence model: observed vs potential/inferred kept separate.',
      'Synthetic demonstration export — local only.',
    ].join('\n');
    downloadTextFile('INC-2024-1042-exposure-assessment.txt', text);
    toast('Assessment exported', 'Exposure summary downloaded locally.');
  };
  return <div className="animate-rise"><PageHeading eyebrow="Decision support · incident INC-2024-1042" title="Exposure assessment" subtitle="A defensible separation between what the sensor observed and what the evidence only suggests." actions={<><Button icon={Download} onClick={exportAssessment} testId="button-export-exposure">Export assessment</Button><Link href="/reports" className="btn btn-primary" data-testid="link-generate-report-exposure">Generate report <ArrowRight size={13} /></Link></>} /><Card className="card-pad" style={{ marginBottom: 14, background: 'linear-gradient(105deg,hsl(var(--card)),hsl(190 45% 12%))' }}><div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 30, flexWrap: 'wrap' }}><div><div className="eyebrow">Current assessed risk</div><div style={{ fontSize: 49, fontWeight: 800, letterSpacing: '-.08em', marginTop: 4 }} className={score > 70 ? 'signal-danger' : 'signal-warn'}>{score}<span style={{ fontSize: 16, color: 'hsl(var(--muted-foreground))', letterSpacing: 0 }}>/100</span></div><div className="muted" style={{ fontSize: 11 }}>Risk reflects correlation confidence, data sensitivity, and destination novelty. It is not proof of data theft.</div></div><div style={{ width: 300, maxWidth: '100%' }}><div className="risk-meter" style={{ height: 12, gap: 4 }}>{[1, 2, 3, 4, 5].map((n) => <i className={n <= Math.ceil(score / 20) ? 'on' : ''} key={n} />)}</div><div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 7 }} className="mono muted"><span>Low</span><span>Critical</span></div></div></div></Card><div className="grid split-grid"><Card className="card-pad"><PanelTitle title="Exposure stages" detail="EVIDENCE CHAIN" />{stages.map(([title, value, note, tone], i) => <div className="kpi-line" key={title}><div style={{ display: 'flex', gap: 10, alignItems: 'center' }}><div style={{ width: 21, height: 21, borderRadius: '50%', display: 'grid', placeItems: 'center', background: i === 4 ? 'hsl(var(--muted))' : 'hsl(var(--accent)/.12)', color: i === 4 ? 'hsl(var(--muted-foreground))' : 'hsl(var(--accent))', font: '10px var(--app-font-mono)' }}>{i < 4 ? <Check size={12} /> : '5'}</div><span><b>{title}</b><br /><span className="muted" style={{ fontSize: 10 }}>{note}</span></span></div><span style={{ textAlign: 'right' }}><b className={tone === 'warn' ? 'signal-warn' : tone === 'muted' ? 'muted' : ''}>{value}</b><br /><span className="mono muted">{i < 4 ? 'supported' : 'not confirmed'}</span></span></div>)}</Card><Card className="card-pad"><PanelTitle title="Risk breakdown" detail="CONTRIBUTING SIGNALS" />{[['Data sensitivity', 'High', 82, 'danger'], ['Process novelty', 'High', 74, 'danger'], ['Destination reputation', 'Medium', 58, 'warn'], ['Payload visibility', 'Low confidence', 31, 'warn'], ['Correlation confidence', 'Strong', 91, 'good']].map(([label, value, width, tone]) => <div style={{ marginBottom: 17 }} key={label as string}><div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 7 }}><span>{label}</span><b className={`signal-${tone}`}>{value}</b></div><div className="progress"><i style={{ width: `${width}%`, background: tone === 'danger' ? 'hsl(var(--destructive))' : tone === 'warn' ? 'hsl(var(--chart-3))' : 'hsl(var(--accent))' }} /></div></div>)}</Card></div><Card className="card-pad" style={{ marginTop: 14 }}><PanelTitle title="Linked evidence" detail="CLICK TO TRACE" />{timelineSeed.slice(1, 6).map((e) => <div className="event-row" key={e.id}><div className="avatar" style={{ borderRadius: 5, color: e.status === 'potential' ? 'hsl(var(--chart-3))' : 'hsl(var(--primary))' }}>{e.category === 'network' ? <Network size={14} /> : e.category === 'collection' ? <FileKey2 size={14} /> : <Activity size={14} />}</div><div className="event-copy"><b>{e.title}</b><div className="muted">{e.detail}</div></div><Badge value={e.status} /><span className="event-time">{e.time}</span></div>)}</Card></div>;
}

function TimelinePage({ phase }: { phase: number }) {
  const [selected, setSelected] = useState('tl-6'); const visible = phase ? timelineSeed.slice(0, Math.min(phase + 1, timelineSeed.length)) : timelineSeed;
  const chosen = visible.find((e) => e.id === selected) || visible[0];
  return <div className="animate-rise"><PageHeading eyebrow="Incident reconstruction · INC-2024-1042" title="Forensic timeline" subtitle="Select an event to inspect the exact evidence and confidence attached to the sequence." actions={<Link href="/exposure-window" className="btn" data-testid="link-exposure-window">Open exposure window <ArrowRight size={13} /></Link>} /><div className="grid split-grid"><Card className="card-pad"><PanelTitle title="Sequence of activity" detail={`${visible.length} EVENTS`} /><div className="timeline">{visible.map((e) => <div className={cn('timeline-item', selected === e.id && 'selected')} key={e.id} onClick={() => setSelected(e.id)} data-testid={`timeline-event-${e.id}`}><time>{e.time} UTC · {e.category}</time><h3>{e.title} <Badge value={e.status} /></h3><p>{e.detail}</p></div>)}</div></Card><Card className="card-pad"><PanelTitle title="Event detail" detail={chosen?.id.toUpperCase()} />{chosen ? <><div className="eyebrow">{chosen.category} · {chosen.status} evidence</div><h2 style={{ margin: '9px 0 8px', fontSize: 19 }}>{chosen.title}</h2><p className="muted" style={{ fontSize: 12, lineHeight: 1.65 }}>{chosen.detail}</p><div className="kpi-line" style={{ marginTop: 21 }}><span className="muted">Timestamp</span><b className="mono">{chosen.time} UTC</b></div><div className="kpi-line"><span className="muted">Endpoint</span><b className="mono">WS-0427</b></div><div className="kpi-line"><span className="muted">Confidence</span><b className={chosen.status === 'potential' ? 'signal-warn' : 'signal-good'}>{chosen.status === 'potential' ? 'Inferred · 62%' : 'Observed · 99%'}</b></div><div style={{ marginTop: 18, padding: 12, background: chosen.status === 'potential' ? 'hsl(var(--chart-3)/.08)' : 'hsl(var(--accent)/.08)', borderRadius: 5, fontSize: 11, lineHeight: 1.5, color: chosen.status === 'potential' ? 'hsl(var(--chart-3))' : 'hsl(var(--accent))' }}>{chosen.status === 'potential' ? 'This event is modeled from network metadata. ARGUS did not observe the payload or prove data delivery.' : 'Sensor-level evidence is directly available for review and export.'}</div></> : <div className="empty"><History size={22} /><h3>Nothing selected</h3></div>}</Card></div></div>;
}

function QuarantinePage({ items, setItems, toast, setModal, setLocation }: { items: QuarantineItem[]; setItems: (items: QuarantineItem[]) => void; toast: (t: string, b: string) => void; setModal: (m: ModalState) => void; setLocation: (path: string) => void }) {
  const action = (id: string, kind: 'restore' | 'delete') => setModal({ title: `${kind === 'delete' ? 'Permanently delete' : 'Restore'} item?`, body: kind === 'delete' ? 'This removes the artifact from the quarantine vault. The action cannot be undone.' : 'Restoring makes this file available to the endpoint again. Only do this with confirmed intent.', confirm: kind === 'delete' ? 'Permanently delete' : 'Restore item', danger: kind === 'delete', onConfirm: () => { setItems(items.filter((i) => i.id !== id)); toast(kind === 'delete' ? 'Artifact deleted' : 'Artifact restored', 'Quarantine inventory updated successfully.'); } });
  const exportManifest = () => {
    const payload = { incidentId: 'INC-2024-1042', items, synthetic: true };
    downloadTextFile('INC-2024-1042-quarantine-manifest.json', JSON.stringify(payload, null, 2), 'application/json');
    toast('Vault inventory exported', 'Quarantine manifest downloaded locally.');
  };
  return <div className="animate-rise"><PageHeading eyebrow="Response controls · secured vault" title="Quarantine" subtitle="Manage isolated artifacts with a deliberate confirmation step for every destructive action." actions={<Button icon={Download} onClick={exportManifest} testId="button-export-quarantine">Export manifest</Button>} />{items.length ? <Card><div className="table-wrap"><table className="data-table" style={{ minWidth: 850 }}><thead><tr><th>Artifact</th><th>Source process</th><th>Quarantined</th><th>SHA-256</th><th>Status</th><th>Actions</th></tr></thead><tbody>{items.map((item) => <tr key={item.id} data-testid={`row-quarantine-${item.id}`}><td><b>{item.name}</b><div className="muted mono">{item.path}</div></td><td className="mono">{item.source}</td><td className="mono">{item.date}</td><td className="mono">{shortHash(item.hash)}</td><td><Badge value="safe" /></td><td><div className="actions"><Button icon={Eye} onClick={() => { toast('Artifact investigation opened', `${item.name} is isolated and safe to inspect.`); setLocation('/files'); }} testId={`button-investigate-${item.id}`}>Investigate</Button><Button icon={ArrowLeft} onClick={() => action(item.id, 'restore')} testId={`button-restore-${item.id}`}>Restore</Button><Button kind="danger" icon={Trash2} onClick={() => action(item.id, 'delete')} testId={`button-delete-${item.id}`}>Delete</Button></div></td></tr>)}</tbody></table></div></Card> : <div className="empty" data-testid="quarantine-empty"><Archive size={24} /><h3>Quarantine is clear</h3><p>Isolated artifacts will appear here after a containment action.</p></div>}</div>;
}

function IntelligencePage({ toast }: { toast: (t: string, b: string) => void }) {
  const [followed, setFollowed] = useState(false);
  return <div className="animate-rise"><PageHeading eyebrow="Context layer · curated synthetic feeds" title="Threat intelligence" subtitle="Reputation and context are supporting signals, not a substitute for endpoint evidence." actions={<Button icon={RefreshCw} onClick={() => toast('Feeds refreshed', 'Three synthetic intelligence sources returned current context.')} testId="button-refresh-intelligence">Refresh feeds</Button>} /><div className="grid metrics"><StatCard label="Indicators tracked" value="12,842" note="+184 this week" tone="info" icon={Radar} /><StatCard label="Newly observed" value="27" note="Across 6 sources" tone="warn" icon={Sparkles} /><StatCard label="Feed health" value="3 / 3" note="Last sync 4 min ago" tone="good" icon={Wifi} /><StatCard label="Correlated today" value="08" note="2 require review" tone="danger" icon={Fingerprint} /></div><div className="grid split-grid" style={{ marginTop: 14 }}><Card className="card-pad"><PanelTitle title="Indicator dossier" detail="DOMAIN · cdn-sync-check[.]com" /><div className="eyebrow">Domain reputation</div><div style={{ display: 'flex', gap: 15, alignItems: 'center', margin: '10px 0 18px' }}><div style={{ fontSize: 34, fontWeight: 800 }} className="signal-danger">12</div><div className="muted" style={{ fontSize: 11 }}>of 87 engines flag this indicator</div></div><div className="kpi-line"><span className="muted">First registered</span><b className="mono">2024-10-11</b></div><div className="kpi-line"><span className="muted">Registrar pattern</span><b>Disposable infrastructure</b></div><div className="kpi-line"><span className="muted">Internal sightings</span><b>1 · today</b></div><Button kind={followed ? 'primary' : ''} icon={followed ? Check : Plus} onClick={() => { setFollowed(!followed); toast(followed ? 'Indicator unfollowed' : 'Indicator followed', followed ? 'No further alerts will be generated.' : 'ARGUS will surface future sightings in this workspace.'); }} style={{ marginTop: 17 }} testId="button-follow-indicator">{followed ? 'Following indicator' : 'Follow indicator'}</Button></Card><Card className="card-pad"><PanelTitle title="Source coverage" detail="SYNTHETIC DATASETS" />{[['Northstar DNS telemetry', 'Live', '2 min ago'], ['ARGUS community exchange', 'Live', '4 min ago'], ['Sandbox reputation set', 'Live', '4 min ago'], ['Internal sightings', 'Live', '12 sec ago']].map(([a, b, c]) => <div className="kpi-line" key={a}><span><b>{a}</b><br /><span className="mono muted">{c}</span></span><span className="signal-good"><CheckCircle2 size={14} style={{ verticalAlign: 'middle', marginRight: 5 }} />{b}</span></div>)}<div style={{ marginTop: 20, padding: 13, border: '1px solid hsl(var(--border))', borderRadius: 5, fontSize: 10, lineHeight: 1.5 }}><Info size={13} style={{ verticalAlign: 'middle', marginRight: 6, color: 'hsl(var(--primary))' }} />Reputation is one input to the risk model. Review process and file evidence before escalating.</div></Card></div></div>;
}

function ReportsPage({ phase, incidentStatus, quarantineCount, toast }: { phase: number; incidentStatus: string; quarantineCount: number; toast: (t: string, b: string) => void }) {
  const [generated, setGenerated] = useState(false); const [format, setFormat] = useState<'TXT' | 'JSON'>('TXT');
  const risk = phase >= 5 ? 86 : phase >= 3 ? 61 : 38;
  const generate = () => { setGenerated(true); toast('Report generated', 'INC-2024-1042 report is ready to review and share.'); };
  const downloadReport = () => {
    if (format === 'JSON') {
      const payload = {
        incidentId: 'INC-2024-1042',
        endpoint: 'WS-0427',
        riskScore: risk,
        status: incidentStatus,
        quarantineArtifacts: quarantineCount,
        evidenceNote: 'Potential transmission is inferred from connection metadata; confirmed exfiltration is not established.',
        observed: { files: 5, connections: 4, timelineEvents: Math.min(phase || 8, 8) },
        synthetic: true,
      };
      downloadTextFile('INC-2024-1042-evidence.json', JSON.stringify(payload, null, 2), 'application/json');
    } else {
      const text = [
        'ARGUS Security Intelligence — Synthetic Incident Report',
        '=====================================================',
        'Incident: INC-2024-1042',
        'Endpoint: WS-0427',
        `Status: ${incidentStatus}`,
        `Assessed risk: ${risk}/100 (demonstration score — not proof of data theft)`,
        `Quarantine artifacts: ${quarantineCount}`,
        '',
        'Summary',
        '-------',
        'A critical PowerShell detection correlated with sensitive file access, local staging,',
        'and a novel network destination. Process tree: explorer → outlook → invoice_viewer → powershell → rundll32.',
        '',
        'Evidence boundaries',
        '-------------------',
        'Observed: process, file, and network metadata from synthetic sensors.',
        'Potential / inferred: transmission volume from connection timing/bytes.',
        'Confirmed exfiltration: Not established.',
        '',
        'This file is generated locally for demonstration. No data was sent externally.',
      ].join('\n');
      downloadTextFile('INC-2024-1042-report.txt', text, 'text/plain');
    }
    toast('Download started', `${format} synthetic report saved locally.`);
  };
  return <div className="animate-rise"><PageHeading eyebrow="Decision artifact · defensible narrative" title="Incident reports" subtitle="Turn correlated evidence into a reviewable record with clear limits on inference." actions={<Button icon={FileText} kind="primary" onClick={generate} testId="button-generate-report">Generate incident report</Button>} /><div className="grid split-grid"><Card className="card-pad"><PanelTitle title="Report builder" detail="INC-2024-1042" /><div className="field"><label>Report title</label><input defaultValue="Exposure assessment · WS-0427" data-testid="input-report-title" /></div><div className="field"><label>Audience</label><select className="select" style={{ width: '100%' }} defaultValue="Security leadership" data-testid="select-report-audience"><option>Security leadership</option><option>Legal & compliance</option><option>Incident response</option></select></div><div className="field"><label>Export format</label><div className="actions"><Button kind={format === 'TXT' ? 'primary' : ''} onClick={() => setFormat('TXT')} testId="button-format-txt">Report (TXT)</Button><Button kind={format === 'JSON' ? 'primary' : ''} onClick={() => setFormat('JSON')} testId="button-format-json">JSON evidence</Button></div></div><div style={{ padding: 13, background: 'hsl(var(--muted))', borderRadius: 5, fontSize: 11, lineHeight: 1.5, marginTop: 17 }}><CheckCircle2 size={14} className="signal-good" style={{ verticalAlign: 'middle', marginRight: 6 }} />Includes timeline, files, connections, quarantine count ({quarantineCount}), and exposure confidence notes. Downloads stay on this device.</div>{generated && <div style={{ marginTop: 14 }}><Button icon={Download} onClick={downloadReport} testId="button-download-report">Download Report</Button><Button icon={Send} onClick={() => toast('Share link copied', 'A local review link was copied to your clipboard.')} testId="button-share-report">Share</Button></div>}</Card><Card className="card-pad"><PanelTitle title="Preview" detail={generated ? 'READY TO REVIEW' : 'DRAFT'} /><div style={{ border: '1px solid hsl(var(--border))', borderRadius: 5, padding: 20, minHeight: 350, background: 'hsl(216 33% 9%)' }}><div className="eyebrow">ARGUS · CONFIDENTIAL</div><h2 style={{ margin: '14px 0 6px', fontSize: 22 }}>Exposure assessment</h2><div className="mono muted">INC-2024-1042 / WS-0427 / 14 OCT 2024</div><div style={{ height: 1, background: 'hsl(var(--border))', margin: '20px 0' }} /><p style={{ fontSize: 11, lineHeight: 1.7, color: 'hsl(var(--muted-foreground))' }}>A critical PowerShell detection correlated with sensitive file access, local staging, and a novel network destination. Potential transmission is inferred from connection metadata; confirmed exfiltration is not established by available sensor evidence.</p><div className="grid metrics" style={{ gridTemplateColumns: 'repeat(3,1fr)', marginTop: 20 }}><StatCard label="Risk" value={String(risk)} note="/ 100" tone="danger" /><StatCard label="Evidence" value="17" note="linked records" tone="info" /><StatCard label="Status" value={incidentStatus} note="shared incident state" tone="warn" /></div></div></Card></div></div>;
}

function HistoryPage({ toast }: { toast: (t: string, b: string) => void }) {
  return <div className="animate-rise"><PageHeading eyebrow="Decision archive · 14 reports" title="Report history" subtitle="A review trail for decisions made from ARGUS evidence." actions={<Button icon={Download} onClick={() => toast('History exported', 'Report index CSV downloaded.')} testId="button-export-history">Export index</Button>} /><Card><div className="table-wrap"><table className="data-table"><thead><tr><th>Report</th><th>Incident</th><th>Author</th><th>Created</th><th>Format</th><th>Status</th><th /></tr></thead><tbody>{[['Exposure assessment · WS-0427', 'INC-2024-1042', 'Mira Alvarez', 'Today, 09:49', 'PDF', 'Ready'], ['Unsigned binary review · WS-0198', 'INC-2024-1039', 'Mira Alvarez', 'Yesterday, 18:32', 'PDF', 'Shared'], ['Quarterly endpoint review', 'BATCH-2024-Q3', 'Jon Bell', 'Oct 01, 2024', 'JSON', 'Archived']].map((r, i) => <tr key={r[0]}><td><b>{r[0]}</b><div className="muted mono">RPT-00{i + 41}</div></td><td className="mono">{r[1]}</td><td>{r[2]}</td><td className="mono">{r[3]}</td><td><Badge value={r[4]} /></td><td><Badge value={r[5]} /></td><td><Button icon={Eye} onClick={() => toast('Report opened', `${r[0]} is available in review mode.`)} testId={`button-open-report-${i}`}>Open</Button></td></tr>)}</tbody></table></div></Card></div>;
}

function CyberCellPage({ toast, incidentStatus, phase, quarantineCount, submitted, onSubmitted, onResetSubmission }: { toast: (t: string, b: string) => void; incidentStatus: string; phase: number; quarantineCount: number; submitted: boolean; onSubmitted: () => void; onResetSubmission: () => void }) {
  const [consentShare, setConsentShare] = useState(false);
  const [consentSynthetic, setConsentSynthetic] = useState(false);
  const canSubmit = consentShare && consentSynthetic;
  const summary = `Critical PowerShell activity on WS-0427 correlated with sensitive file access, staging, and a novel destination. Shared incident status: ${incidentStatus}. Demo sequence ${Math.min(phase || 0, 8)}/8. Quarantine artifacts: ${quarantineCount}. Confirmed exfiltration not established.`;
  return <div className="animate-rise"><PageHeading eyebrow="Escalation channel · consent required" title="Cyber Cell" subtitle="Submit a concise incident brief to the response coordination team when internal action needs a second set of hands." />{submitted ? <Card className="card-pad" style={{ maxWidth: 720, margin: '20px auto', textAlign: 'center', padding: 50 }}><div className="brand-mark" style={{ margin: '0 auto 18px' }}><CheckCircle2 size={18} /></div><h2 style={{ fontSize: 21 }}>Submission recorded locally</h2><p className="muted" style={{ fontSize: 12, lineHeight: 1.6 }}>Case CC-2024-188 is queued in this synthetic demo only. Nothing was transmitted to an external Cyber Cell service. Incident status remains <b>{incidentStatus}</b>.</p><Button icon={ArrowLeft} onClick={() => { setConsentShare(false); setConsentSynthetic(false); onResetSubmission(); }} testId="button-new-submission">Create another submission</Button></Card> : <Card className="card-pad" style={{ maxWidth: 720, margin: '20px auto' }}><PanelTitle title="Incident submission" detail="LOCAL SYNTHETIC WORKSPACE" /><div className="field"><label>Incident summary</label><textarea rows={4} defaultValue={summary} key={summary} data-testid="input-cell-summary" /></div><div className="field"><label>Requested support</label><select className="select" style={{ width: '100%' }} defaultValue="Forensic review" data-testid="select-cell-support"><option>Forensic review</option><option>Threat hunting support</option><option>Legal / compliance guidance</option></select></div>
    <div style={{ display: 'flex', gap: 10, alignItems: 'start', padding: 14, background: 'hsl(var(--muted))', borderRadius: 5, margin: '18px 0 10px' }}><button type="button" onClick={() => setConsentShare(!consentShare)} style={{ background: 'transparent', border: 0, padding: 0, color: consentShare ? 'hsl(var(--accent))' : 'hsl(var(--muted-foreground))' }} data-testid="button-consent-share" aria-pressed={consentShare}><CheckCircle2 size={17} /></button><div style={{ fontSize: 11, lineHeight: 1.5 }}><b>Consent to share this incident brief</b><div className="muted">I understand this report may be visible to the Cyber Cell review queue in a real deployment.</div></div></div>
    <div style={{ display: 'flex', gap: 10, alignItems: 'start', padding: 14, background: 'hsl(var(--muted))', borderRadius: 5, margin: '0 0 18px' }}><button type="button" onClick={() => setConsentSynthetic(!consentSynthetic)} style={{ background: 'transparent', border: 0, padding: 0, color: consentSynthetic ? 'hsl(var(--accent))' : 'hsl(var(--muted-foreground))' }} data-testid="button-consent-synthetic" aria-pressed={consentSynthetic}><CheckCircle2 size={17} /></button><div style={{ fontSize: 11, lineHeight: 1.5 }}><b>Confirm synthetic / local-only submission</b><div className="muted">I confirm this is demonstration data and ARGUS will not send it to any external service.</div></div></div>
    <Button kind="primary" icon={Send} disabled={!canSubmit} onClick={() => { onSubmitted(); toast('Submission recorded', 'Local Cyber Cell intake acknowledged the synthetic report. No external transmission.'); }} testId="button-submit-cell">Submit to Cyber Cell</Button><span className="mono muted" style={{ marginLeft: 12 }}>{canSubmit ? 'Both consents recorded' : 'Both consents required'}</span></Card>}</div>;
}

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

function ExposureWindowPage({ phase, toast }: { phase: number; toast: (t: string, b: string) => void }) {
  const progress = phase ? Math.min(100, phase * 13) : 78;
  return <div className="animate-rise"><PageHeading eyebrow="Signature window · first suspicious activity → detection" title="Exposure window" subtitle="A bounded view of the period in which suspicious activity could have affected the endpoint." actions={<Button icon={Download} onClick={() => toast('Window exported', 'Exposure window CSV and visual summary downloaded.')} testId="button-export-window">Export window</Button>} /><Card className="card-pad" style={{ marginBottom: 14 }}><PanelTitle title="Incident window" detail="WS-0427 · 09:37 — 09:47 UTC" /><div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, fontSize: 10 }}><span className="mono">09:37:14<br /><span className="muted">first suspicious activity</span></span><span className="mono" style={{ textAlign: 'right' }}>09:47:11<br /><span className="muted">detection & containment</span></span></div><div style={{ height: 52, position: 'relative', margin: '16px 0 8px', background: 'linear-gradient(90deg,hsl(var(--chart-3)/.1),hsl(var(--destructive)/.14))', borderRadius: 4, border: '1px solid hsl(var(--border))' }}><div style={{ position: 'absolute', left: `${progress - 8}%`, top: 0, bottom: 0, width: 2, background: 'hsl(var(--primary))', transition: 'left .3s' }} /><div style={{ position: 'absolute', left: '2%', top: '19px', width: '96%', height: 1, background: 'hsl(var(--muted-foreground)/.45)' }} />{[['2%', 'appearance'], ['25%', 'collection'], ['49%', 'staging'], ['69%', 'potential'], ['97%', 'detection']].map(([left, label]) => <div key={label} style={{ position: 'absolute', left, top: 14, transform: 'translateX(-50%)', textAlign: 'center', fontSize: 9, color: 'hsl(var(--muted-foreground))' }}><i style={{ display: 'block', width: 9, height: 9, borderRadius: '50%', background: label === 'potential' ? 'hsl(var(--chart-3))' : 'hsl(var(--primary))', margin: '0 auto 7px', boxShadow: '0 0 0 3px hsl(var(--primary)/.1)' }} />{label}</div>)}</div><div className="mono muted" style={{ textAlign: 'center' }}>10 minutes · 9 seconds</div></Card><div className="grid split-grid"><Card className="card-pad"><PanelTitle title="Activities in window" detail="8 LINKED EVENTS" />{timelineSeed.map((e) => <div className="event-row" key={e.id}><span className="event-time">{e.time}</span><div className="event-copy"><b>{e.title}</b><div className="muted">{e.category} · {e.status === 'potential' ? 'potential / inferred' : 'observed evidence'}</div></div><Badge value={e.status} /></div>)}</Card><Card className="card-pad"><PanelTitle title="Window interpretation" detail="ANALYST NOTE" /><div style={{ padding: 15, background: 'hsl(var(--chart-3)/.08)', borderLeft: '2px solid hsl(var(--chart-3))', borderRadius: 4, fontSize: 11, lineHeight: 1.65, color: 'hsl(var(--foreground))' }}>The exposure window begins with the first observed child process and closes at endpoint containment. Network bytes were observed during this interval, but payload content and successful delivery remain unconfirmed.</div><div className="kpi-line" style={{ marginTop: 17 }}><span className="muted">Observed duration</span><b>10m 57s</b></div><div className="kpi-line"><span className="muted">High-sensitivity files</span><b className="signal-danger">3</b></div><div className="kpi-line"><span className="muted">Novel destinations</span><b className="signal-warn">2</b></div><div className="kpi-line"><span className="muted">Confirmed exfiltration</span><b className="signal-good">Not established</b></div></Card></div></div>;
}

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
  const [session, setSession] = useState(false);
  const [userName, setUserName] = useState('');
  const [authMode, setAuthMode] = useState<AuthMode>('login');
  const [mobileOpen, setMobileOpen] = useState(false);
  const [phase, setPhase] = useState(0);
  const [demoState, setDemoState] = useState<DemoRunState>('idle');
  const [threats, setThreats] = useState(threatsSeed);
  const [quarantine, setQuarantine] = useState<QuarantineItem[]>(quarantineSeed);
  const [cyberCellSubmitted, setCyberCellSubmitted] = useState(false);
  const [modal, setModal] = useState<ModalState>(null);
  const [toasts, setToasts] = useState<Array<{ id: number; title: string; body: string }>>([]);

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
        if (!next.some((q) => q.id === item.id)) next.unshift(item);
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
    setSession(false);
    setAuthMode('login');
    setMobileOpen(false);
    setModal(null);
    setLocation('/login');
    toast('Signed out', 'Session cleared. Incident demo state is preserved for the next sign-in.');
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
    if (!session && location !== '/login') setLocation('/login');
  }, [session, location, setLocation]);

  const incidentStatus = phase >= 8 ? 'Contained' : phase >= 7 ? 'Detected' : phase >= 5 ? 'Assessing' : phase > 0 ? 'Monitoring' : 'Open';
  const contained = phase >= 8 || threats.some((t) => t.status === 'quarantined' && (t.id === 'thr-1' || t.id === 'thr-2'));

  const page = useMemo(() => {
    if (location === '/dashboard') return <Dashboard phase={phase} demoState={demoState} demo={autoDemo.state} startDemo={startDemo} pauseDemo={pauseDemo} resumeDemo={resumeDemo} toast={toast} telemetry={telemetryStream} processMonitor={processMonitor} userName={userName} threatAnalysis={threatAnalysis} />;
    if (location === '/threats') return <ThreatsPage threats={threats} onContain={containThreat} toast={toast} setModal={setModal} setLocation={setLocation} threatAnalysis={threatAnalysis} demoReached={autoDemo.state.demoReached} />;
    if (location === '/detections') return <DetectionsPage detections={detections} toast={toast} setLocation={setLocation} />;
    if (location === '/detections/rules') return <RuleCatalogPage detections={detections} />;
    if (location === '/monitoring') return <MonitoringPage />;
    if (location === '/processes') return <ProcessesPage toast={toast} contained={contained} monitorData={processMonitor} />;
    if (location === '/files') return <FilesPage toast={toast} />;
    if (location === '/network') return <NetworkPage toast={toast} contained={contained} />;
    if (location === '/exposure') return <ExposurePage phase={phase} toast={toast} />;
    if (location === '/exposure-window') return <ExposureWindowPage phase={phase} toast={toast} />;
    if (location === '/timeline') return <TimelinePage phase={phase} />;
    if (location === '/quarantine') return <QuarantinePage items={quarantine} setItems={setQuarantine} toast={toast} setModal={setModal} setLocation={setLocation} />;
    if (location === '/intelligence') return <IntelligencePage toast={toast} />;
    if (location === '/reports') return <ReportsPage phase={phase} incidentStatus={incidentStatus} quarantineCount={quarantine.length} toast={toast} />;
    if (location === '/history') return <HistoryPage toast={toast} />;
    if (location === '/cyber-cell') return <CyberCellPage toast={toast} incidentStatus={incidentStatus} phase={phase} quarantineCount={quarantine.length} submitted={cyberCellSubmitted} onSubmitted={() => setCyberCellSubmitted(true)} onResetSubmission={() => setCyberCellSubmitted(false)} />;
    if (location === '/settings') return <SettingsPage toast={toast} />;
    if (location === '/about') return <AboutPage />;
    return <NotFound />;
  }, [location, phase, demoState, threats, quarantine, incidentStatus, contained, cyberCellSubmitted, processMonitor, telemetryStream, networkMonitor, threatAnalysis, detections, autoDemo.state]);

  const toastStack = <div className="toast-stack">{toasts.map((t) => <div className="toast" key={t.id} data-testid={`toast-${t.id}`}><strong>{t.title}</strong><p>{t.body}</p></div>)}</div>;

  if (!session || location === '/login') {
    return <>
      <AuthScreen
        onAuthed={(name) => {
          setUserName(name || 'Analyst');
          setSession(true);
          setAuthMode('login');
          setLocation('/dashboard');
          toast(authMode === 'register' ? `Welcome, ${name || 'Analyst'}` : `Welcome back, ${name || 'Investigator'}`, authMode === 'register' ? 'Account provisioned and secure workspace initialized with local synthetic telemetry.' : 'Demo workspace initialized with local synthetic telemetry.');
        }}
        onSwitch={setAuthMode}
        mode={authMode}
        initialName={userName ? userName.split(' ')[0] : ''}
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
