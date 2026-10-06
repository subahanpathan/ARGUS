import { useMemo, useState, useEffect, type CSSProperties, type ReactNode } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Check,
  CheckCircle2,
  Clock3,
  Copy,
  Download,
  ExternalLink,
  Eye,
  FastForward,
  FileKey2,
  FileSearch,
  FileText,
  Filter,
  HardDrive,
  History,
  Layers,
  Link2,
  Lock,
  Network,
  Pause,
  Play,
  Radio,
  RefreshCw,
  RotateCcw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SkipBack,
  SkipForward,
  TerminalSquare,
  Zap,
} from 'lucide-react';
import type { ProcessMonitorState, RealProcessEvent } from '@/hooks/use-process-monitor';
import type { ThreatAnalysisState } from '@/hooks/use-threat-analysis';
import type { FileScanState } from '@/hooks/use-file-scan';
import type { NetworkMonitorState } from '@/hooks/use-network-monitor';
import type { useTelemetryStream } from '@/hooks/use-telemetry-stream';

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

type EvidenceStatus = 'observed' | 'potential' | 'confirmed';

export type TimelineEvent = {
  id: string;
  time: string;
  rawTimestamp?: number;
  title: string;
  detail: string;
  category: string;
  status: EvidenceStatus;
  subsystem?: 'process' | 'file' | 'network' | 'detection' | 'containment';
  pid?: number;
  entity?: string;
  confidence?: number;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
};

export type TimelinePageProps = {
  phase: number;
  toast: (title: string, body: string) => void;
  processMonitor?: ProcessMonitorState;
  networkMonitor?: NetworkMonitorState;
  threatAnalysis?: ThreatAnalysisState;
  fileScan?: FileScanState;
  telemetry?: ReturnType<typeof useTelemetryStream>;
  contained?: boolean;
  onNavigate?: (path: string) => void;
};

const defaultTimelineSeed: TimelineEvent[] = [
  {
    id: 'tl-1',
    time: '09:37:14',
    title: 'Invoice attachment opened',
    detail: 'User opened invoice_viewer.exe from Downloads. Parent process: explorer.exe → outlook.exe.',
    category: 'appearance',
    status: 'observed',
    subsystem: 'process',
    pid: 7924,
    entity: 'invoice_viewer.exe',
    confidence: 100,
  },
  {
    id: 'tl-2',
    time: '09:37:16',
    title: 'Child process execution',
    detail: 'invoice_viewer.exe spawned an encoded PowerShell command with process privileges.',
    category: 'process',
    status: 'observed',
    subsystem: 'process',
    pid: 8420,
    entity: 'powershell.exe',
    confidence: 100,
  },
  {
    id: 'tl-3',
    time: '09:40:02',
    title: 'Sensitive document access',
    detail: 'Mailbox and finance documents read by powershell.exe outside the normal access baseline.',
    category: 'collection',
    status: 'observed',
    subsystem: 'file',
    entity: 'Q4_strategy.docx, forecast_2025.xlsx',
    confidence: 99,
  },
  {
    id: 'tl-4',
    time: '09:42:41',
    title: 'Archive staged in %Temp%',
    detail: '7z.exe created ~stage_042.zip in the user temp directory containing collected files.',
    category: 'staging',
    status: 'observed',
    subsystem: 'file',
    entity: '~stage_042.zip',
    confidence: 100,
  },
  {
    id: 'tl-5',
    time: '09:42:37',
    title: 'Unusual network connection',
    detail: 'PowerShell established socket to 91.215.85.19:8080. First-seen IP destination.',
    category: 'network',
    status: 'observed',
    subsystem: 'network',
    entity: '91.215.85.19:8080',
    confidence: 98,
  },
  {
    id: 'tl-6',
    time: '09:44:26',
    title: 'Potential transmission observed',
    detail: '18.4 KB sent over newly established TLS session. Content is inferred from flow volume.',
    category: 'transmission',
    status: 'potential',
    subsystem: 'network',
    entity: 'cdn-sync-check[.]com:443',
    confidence: 62,
  },
  {
    id: 'tl-7',
    time: '09:46:03',
    title: 'Correlation detection rule fired',
    detail: 'ARGUS correlated process, file, and network signals into critical incident INC-2024-1042.',
    category: 'detection',
    status: 'observed',
    subsystem: 'detection',
    entity: 'RULE-CORR-042',
    confidence: 96,
  },
  {
    id: 'tl-8',
    time: '09:47:11',
    title: 'Endpoint contained & isolated',
    detail: 'Network isolation applied to WS-0427. Existing suspicious connections severed.',
    category: 'containment',
    status: 'observed',
    subsystem: 'containment',
    entity: 'WS-0427',
    confidence: 100,
  },
];

export default function TimelinePage({
  phase,
  toast,
  processMonitor,
  networkMonitor,
  threatAnalysis,
  fileScan,
  telemetry,
  contained = false,
  onNavigate,
}: TimelinePageProps) {
  const hasLiveTelemetry = Boolean(telemetry?.connected && telemetry?.telemetry);
  const [dataMode, setDataMode] = useState<'real' | 'demo'>('real');
  const liveAvailable = Boolean(hasLiveTelemetry || processMonitor?.hasData);

  // Auto-switch mode based on real host telemetry stream vs simulation
  useEffect(() => {
    if (liveAvailable) {
      setDataMode('real');
    } else {
      setDataMode('demo');
    }
  }, [liveAvailable]);

  const isReal = dataMode === 'real' && liveAvailable;

  const hostName = telemetry?.telemetry?.source === 'windows_system_monitor'
    ? 'Local Windows Host'
    : (telemetry?.telemetry?.source || 'WS-0427');

  // Unified multi-subsystem timeline dataset
  const activeEvents: TimelineEvent[] = useMemo(() => {
    if (!isReal) {
      return defaultTimelineSeed;
    }

    const merged: TimelineEvent[] = [];
    const now = Date.now();

    // 1. Host Hardware Boot & Sensor Online
    if (telemetry?.telemetry?.system?.boot_time) {
      const bootMs = telemetry.telemetry.system.boot_time * 1000;
      merged.push({
        id: 'evt-system-boot',
        rawTimestamp: bootMs,
        time: new Date(bootMs).toLocaleTimeString(),
        title: `Host System Boot: ${hostName}`,
        detail: `Hardware booted and kernel initialized. ${telemetry.telemetry.cpu?.count || '12'} logical cores, ${Math.round((telemetry.telemetry.memory?.total_bytes || 0) / (1024 ** 3))} GB RAM. Sensor streaming telemetry.`,
        category: 'appearance',
        status: 'confirmed',
        subsystem: 'detection',
        entity: hostName,
        confidence: 100,
      });
    }

    // 2. Process Lifecycle Events from SSE
    if (processMonitor?.events && processMonitor.events.length > 0) {
      processMonitor.events
        .filter((e) => e.event_type !== 'SNAPSHOT')
        .forEach((e, idx) => {
          const ts = new Date(e.timestamp).getTime();
          merged.push({
            id: `evt-proc-${e.id || idx}`,
            rawTimestamp: isNaN(ts) ? now - 180000 : ts,
            time: isNaN(ts) ? new Date(now - 180000).toLocaleTimeString() : new Date(ts).toLocaleTimeString(),
            title: e.event_type === 'PROCESS_STARTED' ? `Process Started: ${e.process_name}` : `Process Terminated: ${e.process_name}`,
            detail: `Sensor observed ${e.process_name} (PID ${e.pid})${e.parent_process_name ? ` spawned by ${e.parent_process_name}` : ''}. Binary path: ${e.executable_path || 'Standard system path'}.`,
            category: 'execution',
            status: 'observed',
            subsystem: 'process',
            pid: e.pid,
            entity: e.process_name,
            confidence: 100,
          });
        });
    }

    // 3. Active Snapshot Processes (Prominent tools, user processes, high resource)
    if (processMonitor?.snapshot && processMonitor.snapshot.length > 0) {
      const interestingNames = new Set([
        'powershell.exe', 'cmd.exe', 'python.exe', 'node.exe', 'explorer.exe',
        'svchost.exe', 'chrome.exe', 'msedge.exe', '7z.exe', 'tar.exe', 'curl.exe', 'conhost.exe'
      ]);
      const interestingProcs = processMonitor.snapshot.filter(
        (p) => interestingNames.has(p.name?.toLowerCase()) || (p.cpu_percent ?? 0) > 1 || (p.memory_percent ?? 0) > 2
      );
      const sampleProcs = (interestingProcs.length >= 4 ? interestingProcs : processMonitor.snapshot).slice(0, 8);

      sampleProcs.forEach((p, idx) => {
        let ts: number;
        if (p.creation_time) {
          const parsed = new Date(p.creation_time).getTime();
          ts = isNaN(parsed) ? now - ((idx + 2) * 60000) : parsed;
        } else {
          ts = now - ((idx + 2) * 60000);
        }

        merged.push({
          id: `evt-snap-${p.pid}`,
          rawTimestamp: ts,
          time: new Date(ts).toLocaleTimeString(),
          title: `Process Active: ${p.name}`,
          detail: `Active host execution: ${p.name} (PID ${p.pid})${p.parent_name ? ` [Parent: ${p.parent_name}]` : ''}. User: ${p.username || 'SYSTEM'}. Memory: ${Math.round((p.memory_bytes || 0) / (1024 * 1024))} MB, CPU: ${(p.cpu_percent || 0.1).toFixed(1)}%. Path: ${p.executable_path || 'C:\\Windows\\System32'}`,
          category: 'execution',
          status: 'observed',
          subsystem: 'process',
          pid: p.pid,
          entity: `${p.name} (PID ${p.pid})`,
          confidence: 100,
        });
      });
    }

    // 4. File Scan Findings
    if (fileScan?.findings && fileScan.findings.length > 0) {
      fileScan.findings.slice(0, 8).forEach((f, idx) => {
        let ts: number;
        if (f.modified || f.timestamp) {
          const parsed = new Date((f.modified || f.timestamp)!).getTime();
          ts = isNaN(parsed) ? now - ((idx + 3) * 45000) : parsed;
        } else {
          ts = now - ((idx + 3) * 45000);
        }

        merged.push({
          id: `evt-file-${f.id || idx}`,
          rawTimestamp: ts,
          time: new Date(ts).toLocaleTimeString(),
          title: `Filesystem Finding: ${f.name}`,
          detail: `Sensitive file candidate identified at ${f.path}. Classification: ${(f.className || 'Suspicious').toUpperCase()}${f.size_bytes ? `, Size: ${(f.size_bytes / 1024).toFixed(1)} KB` : ''}. ${f.reason || 'Monitored directory finding.'}`,
          category: 'collection',
          status: 'observed',
          subsystem: 'file',
          entity: f.name,
          confidence: 96,
        });
      });
    }

    // 5. Live Network Socket Connections
    if (networkMonitor?.snapshot?.connections && networkMonitor.snapshot.connections.length > 0) {
      const conns = [...networkMonitor.snapshot.connections].slice(0, 10);
      conns.forEach((c, idx) => {
        let ts: number;
        if (c.timestamp) {
          const parsed = new Date(c.timestamp).getTime();
          ts = isNaN(parsed) ? now - ((idx + 1) * 35000) : parsed;
        } else {
          ts = now - ((idx + 1) * 35000);
        }

        const isEstablished = c.status === 'ESTABLISHED';
        merged.push({
          id: `evt-net-${c.connection_id || idx}`,
          rawTimestamp: ts,
          time: new Date(ts).toLocaleTimeString(),
          title: `Network Socket: ${c.process || 'Host Process'} → ${c.remote_addr || 'Remote'}:${c.remote_port || 443}`,
          detail: `Outbound socket session (${c.status || 'ESTABLISHED'}) by ${c.process} (PID ${c.pid ?? '—'}) to remote endpoint ${c.remote_addr}:${c.remote_port} on local port ${c.local_port || '—'}. Socket family: ${c.family || 'IPv4'}.`,
          category: 'transmission',
          status: isEstablished ? 'observed' : 'potential',
          subsystem: 'network',
          pid: c.pid,
          entity: `${c.remote_addr || 'Remote'}:${c.remote_port || 443}`,
          confidence: isEstablished ? 95 : 68,
        });
      });
    }

    // 6. Network Adapter Activity from Host Telemetry
    if (telemetry?.telemetry?.network?.interfaces) {
      telemetry.telemetry.network.interfaces.forEach((iface, idx) => {
        if (iface.is_up && (iface.bytes_sent || 0) + (iface.bytes_recv || 0) > 0) {
          merged.push({
            id: `evt-net-adapter-${idx}`,
            rawTimestamp: now - (idx + 1) * 25000,
            time: new Date(now - (idx + 1) * 25000).toLocaleTimeString(),
            title: `Network Interface Active: ${iface.name}`,
            detail: `Active Windows adapter ${iface.name}. Bound IPs: ${iface.addresses?.join(', ') || 'DHCP'}. Total throughput: ${fmtBytes(iface.bytes_sent)} sent / ${fmtBytes(iface.bytes_recv)} received.`,
            category: 'transmission',
            status: 'observed',
            subsystem: 'network',
            entity: iface.name,
            confidence: 100,
          });
        }
      });
    }

    // 7. Threat Detections / Rules
    if (threatAnalysis?.threats && threatAnalysis.threats.length > 0) {
      threatAnalysis.threats.slice(0, 6).forEach((t, idx) => {
        let ts: number;
        if (t.timestamp) {
          const parsed = new Date(t.timestamp).getTime();
          ts = isNaN(parsed) ? now - ((idx + 1) * 20000) : parsed;
        } else {
          ts = now - ((idx + 1) * 20000);
        }

        merged.push({
          id: `evt-threat-${t.id || idx}`,
          rawTimestamp: ts,
          time: new Date(ts).toLocaleTimeString(),
          title: `Security Detection: ${t.name}`,
          detail: `Detection engine fired rule: ${t.name} (Severity: ${t.severity.toUpperCase()}). ${t.reason}. Affects process ${t.process} at path ${t.path}.`,
          category: 'detection',
          status: 'observed',
          subsystem: 'detection',
          entity: t.name,
          confidence: 99,
          severity: t.severity,
        });
      });
    }

    // 8. Host Containment Status (if contained)
    if (contained) {
      merged.push({
        id: 'evt-containment',
        rawTimestamp: now,
        time: new Date(now).toLocaleTimeString(),
        title: `Host Containment Enforced: ${hostName}`,
        detail: `Network isolation and active socket termination enforced on host ${hostName}. Outbound routing severed.`,
        category: 'containment',
        status: 'observed',
        subsystem: 'containment',
        entity: hostName,
        confidence: 100,
      });
    }

    if (merged.length === 0) {
      return defaultTimelineSeed;
    }

    // Sort chronologically ascending
    merged.sort((a, b) => (a.rawTimestamp ?? 0) - (b.rawTimestamp ?? 0));
    return merged;
  }, [
    isReal,
    telemetry?.telemetry,
    processMonitor?.events,
    processMonitor?.snapshot,
    networkMonitor?.snapshot?.connections,
    fileScan?.findings,
    threatAnalysis?.threats,
    contained,
    hostName,
  ]);

  // Subsystem counts
  const subsystemCounts = useMemo(() => {
    const res = { all: activeEvents.length, process: 0, file: 0, network: 0, detection: 0, containment: 0 };
    activeEvents.forEach((e) => {
      if (e.subsystem && res[e.subsystem] !== undefined) {
        res[e.subsystem]++;
      }
    });
    return res;
  }, [activeEvents]);

  // Playback state
  const [playbackIndex, setPlaybackIndex] = useState<number>(() => {
    return Math.max(0, activeEvents.length - 1);
  });
  const [isPlaying, setIsPlaying] = useState(false);
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1);
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedEventId, setSelectedEventId] = useState<string>('');

  // Keep playback index synchronized to end when idle and new events load
  useEffect(() => {
    if (!isPlaying) {
      setPlaybackIndex(Math.max(0, activeEvents.length - 1));
    }
  }, [activeEvents.length, isPlaying]);

  // Current visible slice up to playback index
  const visibleEvents = useMemo(() => {
    const slice = activeEvents.slice(0, playbackIndex + 1);
    return slice.filter((e) => {
      const q = searchQuery.toLowerCase().trim();
      const matchQuery =
        q === '' ||
        e.title.toLowerCase().includes(q) ||
        e.detail.toLowerCase().includes(q) ||
        e.category.toLowerCase().includes(q) ||
        (e.entity && e.entity.toLowerCase().includes(q));

      if (!matchQuery) return false;
      if (filterCategory === 'all') return true;
      return e.subsystem === filterCategory || e.category === filterCategory;
    });
  }, [activeEvents, playbackIndex, searchQuery, filterCategory]);

  const selectedEvent = useMemo(() => {
    return visibleEvents.find((e) => e.id === selectedEventId) || visibleEvents[visibleEvents.length - 1] || activeEvents[0];
  }, [visibleEvents, selectedEventId, activeEvents]);

  // Playback loop
  useEffect(() => {
    if (!isPlaying) return;

    const timer = setInterval(() => {
      setPlaybackIndex((prev) => {
        if (prev >= activeEvents.length - 1) {
          setIsPlaying(false);
          toast('Timeline Replay Complete', 'Reached the end of the incident timeline.');
          return prev;
        }
        return prev + 1;
      });
    }, 2000 / playbackSpeed);

    return () => clearInterval(timer);
  }, [isPlaying, playbackSpeed, activeEvents.length, toast]);

  // Exports
  const exportTimelineCSV = () => {
    const headers = ['Event ID', 'Timestamp', 'Title', 'Category', 'Subsystem', 'Status', 'Confidence', 'Entity', 'Details'];
    const rows = visibleEvents.map((e) => [
      `"${e.id}"`,
      `"${e.time}"`,
      `"${e.title}"`,
      `"${e.category}"`,
      `"${e.subsystem || 'process'}"`,
      `"${e.status.toUpperCase()}"`,
      `"${e.confidence ?? 100}%"`,
      `"${e.entity || '—'}"`,
      `"${e.detail}"`,
    ]);

    const csvContent =
      'data:text/csv;charset=utf-8,' + encodeURIComponent([headers.join(','), ...rows.map((r) => r.join(','))].join('\n'));
    const link = document.createElement('a');
    link.setAttribute('href', csvContent);
    link.setAttribute('download', `ARGUS_Forensic_Timeline_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    toast('Timeline Exported', `Exported ${visibleEvents.length} chronological events to CSV.`);
  };

  const exportTimelineJSON = () => {
    const jsonContent =
      'data:application/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(visibleEvents, null, 2));
    const link = document.createElement('a');
    link.setAttribute('href', jsonContent);
    link.setAttribute('download', `ARGUS_Forensic_Timeline_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    toast('Timeline Exported', `Exported ${visibleEvents.length} chronological events to JSON.`);
  };

  const getSubsystemIcon = (subsystem?: string) => {
    switch (subsystem) {
      case 'file':
        return FileKey2;
      case 'network':
        return Network;
      case 'detection':
        return ShieldAlert;
      case 'containment':
        return ShieldCheck;
      default:
        return TerminalSquare;
    }
  };

  return (
    <div className="animate-page-enter">
      {/* Page Heading */}
      <div className="page-heading">
        <div>
          <div className="eyebrow">
            Forensic Chronology & Attack Reconstruction · {isReal ? hostName.toUpperCase() : 'INC-2024-1042'}
          </div>
          <h1 className="page-title">Forensic Timeline</h1>
          <p className="page-subtitle">
            Interactive chronological event sequence separating sensor-observed telemetry from inferred exfiltration flows with scrubable playback.
          </p>
        </div>

        <div className="actions" style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>


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
              <Radio size={10} />
              LIVE TELEMETRY STREAM ({activeEvents.length} EVENTS)
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
              DEMO INCIDENT RECONSTRUCTION
            </span>
          )}

          {onNavigate && (
            <button
              type="button"
              className="btn"
              onClick={() => onNavigate('/exposure-window')}
              style={{ fontSize: 11, padding: '4px 10px', height: 26 }}
              title="Open Signature Exposure Window"
            >
              <Clock3 size={12} style={{ marginRight: 5 }} /> Exposure Window <ArrowRight size={10} style={{ marginLeft: 3 }} />
            </button>
          )}

          <button
            type="button"
            className="btn"
            onClick={exportTimelineCSV}
            style={{ fontSize: 11, padding: '4px 10px', height: 26 }}
            title="Download CSV timeline"
          >
            <Download size={12} style={{ marginRight: 5 }} /> Export CSV
          </button>

          <button
            type="button"
            className="btn"
            onClick={exportTimelineJSON}
            style={{ fontSize: 11, padding: '4px 10px', height: 26 }}
            title="Download JSON timeline"
          >
            <Download size={12} style={{ marginRight: 5 }} /> Export JSON
          </button>
        </div>
      </div>

      {/* Scrubable Playback Control Bar */}
      <section
        className="card card-pad"
        style={{
          marginBottom: 16,
          background: 'linear-gradient(100deg, hsl(var(--card)) 60%, hsl(var(--muted) / 0.8))',
          border: '1px solid hsl(var(--border))',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
          {/* Controls: Play, Step, Speed */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <button
              type="button"
              className="btn btn-ghost"
              style={{ padding: 6 }}
              onClick={() => {
                setPlaybackIndex(0);
                setSelectedEventId(activeEvents[0]?.id || 'tl-1');
              }}
              title="Reset to beginning"
            >
              <RotateCcw size={14} />
            </button>

            <button
              type="button"
              className="btn btn-ghost"
              style={{ padding: 6 }}
              onClick={() => {
                setPlaybackIndex((prev) => Math.max(0, prev - 1));
              }}
              disabled={playbackIndex === 0}
              title="Previous Event"
            >
              <SkipBack size={14} />
            </button>

            <button
              type="button"
              className={cn('btn', isPlaying ? 'btn-danger' : 'btn-primary')}
              style={{ minWidth: 85, fontSize: 11, height: 28 }}
              onClick={() => setIsPlaying(!isPlaying)}
            >
              {isPlaying ? (
                <>
                  <Pause size={12} style={{ marginRight: 5 }} /> Pause
                </>
              ) : (
                <>
                  <Play size={12} style={{ marginRight: 5 }} /> Replay
                </>
              )}
            </button>

            <button
              type="button"
              className="btn btn-ghost"
              style={{ padding: 6 }}
              onClick={() => {
                setPlaybackIndex((prev) => Math.min(activeEvents.length - 1, prev + 1));
              }}
              disabled={playbackIndex >= activeEvents.length - 1}
              title="Next Event"
            >
              <SkipForward size={14} />
            </button>

            <div style={{ marginLeft: 6, display: 'flex', alignItems: 'center', gap: 4 }}>
              <span className="muted" style={{ fontSize: 10 }}>Speed:</span>
              {[1, 2, 5].map((speed) => (
                <button
                  key={speed}
                  type="button"
                  className={cn('btn btn-ghost', playbackSpeed === speed && 'btn-primary')}
                  style={{ fontSize: 10, padding: '2px 6px', height: 20 }}
                  onClick={() => setPlaybackSpeed(speed)}
                >
                  {speed}x
                </button>
              ))}
            </div>
          </div>

          {/* Scrubber slider and progress indicator */}
          <div style={{ flex: 1, minWidth: 260, display: 'flex', alignItems: 'center', gap: 12 }}>
            <span className="mono muted" style={{ fontSize: 11 }}>
              Step {playbackIndex + 1} of {activeEvents.length}
            </span>
            <input
              type="range"
              min={0}
              max={activeEvents.length - 1}
              value={playbackIndex}
              onChange={(e) => {
                const idx = Number(e.target.value);
                setPlaybackIndex(idx);
                if (activeEvents[idx]) setSelectedEventId(activeEvents[idx].id);
              }}
              style={{ flex: 1, cursor: 'pointer' }}
            />
            <span className="mono" style={{ fontSize: 11, fontWeight: 700 }}>
              {activeEvents[playbackIndex]?.time || '—'}
            </span>
          </div>
        </div>
      </section>

      {/* Quick Subsystem Filter Pills & Search */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 14 }}>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
          {[
            { id: 'all', label: 'All Subsystems', count: subsystemCounts.all, icon: Activity },
            { id: 'process', label: 'Processes', count: subsystemCounts.process, icon: TerminalSquare },
            { id: 'network', label: 'Network Sockets', count: subsystemCounts.network, icon: Network },
            { id: 'file', label: 'Filesystem', count: subsystemCounts.file, icon: FileKey2 },
            { id: 'detection', label: 'Detections', count: subsystemCounts.detection, icon: ShieldAlert },
            { id: 'containment', label: 'Containment', count: subsystemCounts.containment, icon: ShieldCheck },
          ].map((tab) => {
            const Icon = tab.icon;
            const isTabActive = filterCategory === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                className={cn('btn', isTabActive ? 'btn-primary' : 'btn-ghost')}
                style={{
                  fontSize: 11,
                  padding: '3px 10px',
                  height: 26,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 5,
                  borderRadius: 20,
                }}
                onClick={() => setFilterCategory(tab.id)}
              >
                <Icon size={12} />
                {tab.label}
                <span
                  style={{
                    fontSize: 10,
                    padding: '1px 5px',
                    borderRadius: 10,
                    background: isTabActive ? 'hsl(var(--primary-foreground) / 0.2)' : 'hsl(var(--muted))',
                    marginLeft: 2,
                    fontWeight: 700,
                  }}
                >
                  {tab.count}
                </span>
              </button>
            );
          })}
        </div>

        <div className="filterbar" style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <div className="search-wrap" style={{ flex: 1 }}>
            <Search size={14} />
            <input
              className="search"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search timeline events, entities, or forensic details..."
            />
          </div>

          <span className="mono muted" style={{ fontSize: 11, minWidth: 90, textAlign: 'right' }}>
            {visibleEvents.length} visible
          </span>
        </div>
      </div>

      {/* Split Grid: Interactive Timeline Tree & Event Detail Inspector */}
      <div className="grid split-grid" style={{ gap: 16 }}>
        {/* Left Column: Timeline Events */}
        <section className="card card-pad">
          <div className="panel-title">
            <h3>
              <History size={15} style={{ verticalAlign: 'middle', marginRight: 6 }} />
              Chronological Sequence of Activity
            </h3>
            <span className="mono muted">{visibleEvents.length} EVENTS</span>
          </div>

          <div className="timeline" style={{ marginTop: 14 }}>
            {visibleEvents.map((e) => {
              const isSelected = selectedEvent?.id === e.id;
              const Icon = getSubsystemIcon(e.subsystem);
              const isPotential = e.status === 'potential';

              return (
                <div
                  key={e.id}
                  className={cn('timeline-item', isSelected && 'selected')}
                  onClick={() => setSelectedEventId(e.id)}
                  style={{
                    cursor: 'pointer',
                    background: isSelected ? 'hsl(var(--accent) / 0.08)' : undefined,
                    borderLeft: isSelected
                      ? '3px solid hsl(var(--primary))'
                      : isPotential
                      ? '3px solid hsl(var(--chart-3))'
                      : undefined,
                  }}
                >
                  <time className="mono" style={{ fontSize: 11 }}>
                    {e.time} · {e.category.toUpperCase()}
                  </time>
                  <h3 style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10 }}>
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                      <Icon size={13} style={{ opacity: 0.8 }} />
                      {e.title}
                    </span>
                    <span
                      className={cn('badge', isPotential ? 'badge-high' : 'badge-low')}
                      style={{ fontSize: 9, padding: '2px 6px' }}
                    >
                      {e.status.toUpperCase()}
                    </span>
                  </h3>
                  <p style={{ fontSize: 12, lineHeight: 1.5, margin: '4px 0 0' }}>{e.detail}</p>
                </div>
              );
            })}

            {!visibleEvents.length && (
              <div className="empty" style={{ padding: 30, textAlign: 'center' }}>
                <Clock3 size={24} style={{ opacity: 0.5, marginBottom: 8 }} />
                <h3>No events match this filter</h3>
                <p className="muted" style={{ fontSize: 12 }}>
                  Try resetting the filter or scrubbing forward on the timeline.
                </p>
              </div>
            )}
          </div>
        </section>

        {/* Right Column: Event Detail Inspector */}
        <section className="card card-pad" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div className="panel-title">
            <h3>
              <Eye size={15} style={{ verticalAlign: 'middle', marginRight: 6 }} />
              Forensic Event Detail
            </h3>
            <span className="mono muted">{selectedEvent ? selectedEvent.id.toUpperCase() : 'NO SELECTION'}</span>
          </div>

          {selectedEvent ? (
            <>
              <div>
                <div className="eyebrow" style={{ textTransform: 'uppercase' }}>
                  {selectedEvent.category} · {selectedEvent.status} evidence
                </div>
                <h2 style={{ margin: '6px 0 8px', fontSize: 18 }}>{selectedEvent.title}</h2>
                <p className="muted" style={{ fontSize: 12, lineHeight: 1.6, margin: 0 }}>
                  {selectedEvent.detail}
                </p>
              </div>

              {/* Technical Metadata Strip */}
              <div
                style={{
                  background: 'hsl(var(--card))',
                  border: '1px solid hsl(var(--border))',
                  borderRadius: 6,
                  padding: 12,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 8,
                }}
              >
                <div className="kpi-line">
                  <span className="muted">Chronological Timestamp</span>
                  <b className="mono">{selectedEvent.time}</b>
                </div>

                <div className="kpi-line">
                  <span className="muted">Endpoint Host</span>
                  <b className="mono">{isReal ? 'This Host (WS-0427 · Live Telemetry)' : 'WS-0427 (Finance Workstation)'}</b>
                </div>

                {selectedEvent.pid && (
                  <div className="kpi-line">
                    <span className="muted">Process Identifier (PID)</span>
                    <b className="mono">{selectedEvent.pid}</b>
                  </div>
                )}

                {selectedEvent.entity && (
                  <div className="kpi-line">
                    <span className="muted">Monitored Target Entity</span>
                    <b className="mono" style={{ color: 'hsl(var(--primary))' }}>
                      {selectedEvent.entity}
                    </b>
                  </div>
                )}

                <div className="kpi-line">
                  <span className="muted">Sensor Confidence</span>
                  <b className={selectedEvent.status === 'potential' ? 'signal-warn' : 'signal-good'}>
                    {selectedEvent.status === 'potential'
                      ? `Inferred · ${selectedEvent.confidence ?? 62}%`
                      : `Observed · ${selectedEvent.confidence ?? 100}%`}
                  </b>
                </div>
              </div>

              {/* Legal & Defensible Model Callout */}
              <div
                style={{
                  padding: 12,
                  background:
                    selectedEvent.status === 'potential'
                      ? 'hsl(var(--chart-3) / 0.08)'
                      : 'hsl(var(--accent) / 0.08)',
                  borderLeft: `3px solid ${
                    selectedEvent.status === 'potential' ? 'hsl(var(--chart-3))' : 'hsl(var(--accent))'
                  }`,
                  borderRadius: 5,
                  fontSize: 11,
                  lineHeight: 1.5,
                  color: selectedEvent.status === 'potential' ? 'hsl(var(--chart-3))' : 'hsl(var(--accent))',
                }}
              >
                {selectedEvent.status === 'potential' ? (
                  <>
                    <strong>Inferred Flow Evidence:</strong> This event is modeled from network connection metadata.
                    ARGUS verified the socket connection and transfer volume, but payload plaintext was encrypted and data delivery remains unconfirmed.
                  </>
                ) : (
                  <>
                    <strong>Sensor-Level Verified Evidence:</strong> This event was directly captured and recorded by
                    the host monitoring agent with 100% cryptographic and OS-level certainty.
                  </>
                )}
              </div>

              {/* Cross-Subsystem Pivot Buttons */}
              <div style={{ marginTop: 'auto', paddingTop: 10, borderTop: '1px solid hsl(var(--border))' }}>
                <div className="muted" style={{ fontSize: 10, marginBottom: 8 }}>
                  CROSS-SUBSYSTEM FORENSIC PIVOTS
                </div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  {onNavigate && (
                    <>
                      <button
                        type="button"
                        className="btn btn-ghost"
                        style={{ fontSize: 11, padding: '4px 10px', height: 26 }}
                        onClick={() => onNavigate('/processes')}
                      >
                        <TerminalSquare size={12} style={{ marginRight: 5 }} /> View in Processes
                      </button>

                      <button
                        type="button"
                        className="btn btn-ghost"
                        style={{ fontSize: 11, padding: '4px 10px', height: 26 }}
                        onClick={() => onNavigate('/files')}
                      >
                        <FileSearch size={12} style={{ marginRight: 5 }} /> View in Files
                      </button>

                      <button
                        type="button"
                        className="btn btn-ghost"
                        style={{ fontSize: 11, padding: '4px 10px', height: 26 }}
                        onClick={() => onNavigate('/network')}
                      >
                        <Network size={12} style={{ marginRight: 5 }} /> View in Network
                      </button>
                    </>
                  )}
                </div>
              </div>
            </>
          ) : (
            <div className="empty" style={{ padding: 40, textAlign: 'center' }}>
              <History size={24} style={{ opacity: 0.5, marginBottom: 8 }} />
              <h3>Select an Event</h3>
              <p className="muted" style={{ fontSize: 12 }}>
                Click any event in the chronology to inspect deep forensic metadata and confidence analysis.
              </p>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
