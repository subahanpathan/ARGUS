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

function cn(...values: Array<string | false | undefined | null>) {
  return values.filter(Boolean).join(' ');
}

type EvidenceStatus = 'observed' | 'potential' | 'confirmed';

export type TimelineEvent = {
  id: string;
  time: string;
  title: string;
  detail: string;
  category: string;
  status: EvidenceStatus;
  subsystem?: 'process' | 'file' | 'network' | 'detection' | 'containment';
  pid?: number;
  entity?: string;
  confidence?: number;
};

export type TimelinePageProps = {
  phase: number;
  toast: (title: string, body: string) => void;
  processMonitor?: ProcessMonitorState;
  threatAnalysis?: ThreatAnalysisState;
  fileScan?: FileScanState;
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
  threatAnalysis,
  fileScan,
  onNavigate,
}: TimelinePageProps) {
  const isReal = Boolean(processMonitor?.connected && processMonitor.events.length > 0);

  // Playback state
  const [playbackIndex, setPlaybackIndex] = useState<number>(() => {
    return phase > 0 ? Math.min(phase - 1, defaultTimelineSeed.length - 1) : defaultTimelineSeed.length - 1;
  });
  const [isPlaying, setIsPlaying] = useState(false);
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1);
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedEventId, setSelectedEventId] = useState<string>('tl-6');

  // Unified timeline dataset
  const activeEvents: TimelineEvent[] = useMemo(() => {
    // If real process events are streaming locally, merge them
    if (isReal && processMonitor) {
      const realEvts: TimelineEvent[] = processMonitor.events
        .filter((e) => e.event_type !== 'SNAPSHOT')
        .slice(-20)
        .map((e, idx) => ({
          id: `real-evt-${idx}`,
          time: new Date(e.timestamp).toLocaleTimeString(),
          title: e.event_type === 'PROCESS_STARTED' ? `Process Started: ${e.process_name}` : `Process Terminated: ${e.process_name}`,
          detail: `Host execution by ${e.process_name} (PID ${e.pid})${e.parent_process_name ? ` spawned by ${e.parent_process_name}` : ''}. Executable: ${e.executable_path || 'System path'}.`,
          category: 'process',
          status: 'observed',
          subsystem: 'process',
          pid: e.pid,
          entity: e.process_name,
          confidence: 100,
        }));

      if (realEvts.length > 0) {
        return realEvts;
      }
    }

    return defaultTimelineSeed;
  }, [isReal, processMonitor]);

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
          <div className="eyebrow">Forensic Chronology & Attack Reconstruction · INC-2024-1042</div>
          <h1 className="page-title">Forensic Timeline</h1>
          <p className="page-subtitle">
            Interactive chronological event sequence separating sensor-observed telemetry from inferred exfiltration flows with scrubable playback.
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
              {activeEvents[playbackIndex]?.time || '09:47:11'} UTC
            </span>
          </div>
        </div>
      </section>

      {/* Filter and Search Bar */}
      <div className="filterbar" style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 14 }}>
        <div className="search-wrap" style={{ flex: 1 }}>
          <Search size={14} />
          <input
            className="search"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search timeline events, entities, or forensic details..."
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Filter size={13} style={{ color: 'hsl(var(--muted-foreground))' }} />
          <select
            className="search"
            style={{ width: 180, padding: '5px 10px', fontSize: 11, cursor: 'pointer' }}
            value={filterCategory}
            onChange={(e) => setFilterCategory(e.target.value)}
          >
            <option value="all">All Subsystems</option>
            <option value="process">Process Execution</option>
            <option value="file">File Access & Staging</option>
            <option value="network">Network & Egress</option>
            <option value="detection">Correlation & Rules</option>
            <option value="containment">Containment Actions</option>
          </select>
        </div>

        <span className="mono muted" style={{ fontSize: 11, minWidth: 90, textAlign: 'right' }}>
          {visibleEvents.length} visible
        </span>
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
                    {e.time} UTC · {e.category}
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
                  <b className="mono">{selectedEvent.time} UTC</b>
                </div>

                <div className="kpi-line">
                  <span className="muted">Endpoint Host</span>
                  <b className="mono">WS-0427 (Finance Workstation)</b>
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
