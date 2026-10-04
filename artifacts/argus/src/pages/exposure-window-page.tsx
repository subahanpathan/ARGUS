import { useMemo, useState, type CSSProperties } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Check,
  CheckCircle2,
  Clock3,
  Download,
  Eye,
  FileKey2,
  FileSearch,
  FileText,
  HardDrive,
  History,
  Layers,
  Lock,
  Network,
  Radio,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare,
  Zap,
} from 'lucide-react';

function cn(...values: Array<string | false | undefined | null>) {
  return values.filter(Boolean).join(' ');
}

export type ExposureWindowPageProps = {
  phase: number;
  toast: (title: string, body: string) => void;
  onNavigate?: (path: string) => void;
};

export default function ExposureWindowPage({
  phase,
  toast,
  onNavigate,
}: ExposureWindowPageProps) {
  const [selectedMilestone, setSelectedMilestone] = useState<string>('detection');

  const progress = phase ? Math.min(100, Math.max(25, phase * 13)) : 82;

  const milestones = [
    {
      id: 'appearance',
      pct: '5%',
      label: 'Initial Execution',
      time: '09:37:14 UTC',
      detail: 'invoice_viewer.exe opened from user Downloads folder.',
      subsystem: 'process',
      status: 'observed',
    },
    {
      id: 'collection',
      pct: '28%',
      label: 'Document Access',
      time: '09:40:02 UTC',
      detail: 'PowerShell script read 3 sensitive financial and corporate strategy documents.',
      subsystem: 'file',
      status: 'observed',
    },
    {
      id: 'staging',
      pct: '52%',
      label: 'Archive Staging',
      time: '09:42:41 UTC',
      detail: '7z.exe created ~stage_042.zip in the user Temp directory.',
      subsystem: 'file',
      status: 'observed',
    },
    {
      id: 'transmission',
      pct: '74%',
      label: 'Outbound Flow',
      time: '09:44:26 UTC',
      detail: '18.4 KB sent over TLS 1.3 to cdn-sync-check[.]com. Modeled flow, unverified plaintext.',
      subsystem: 'network',
      status: 'potential',
    },
    {
      id: 'detection',
      pct: '96%',
      label: 'Containment',
      time: '09:47:11 UTC',
      detail: 'Network isolation applied to WS-0427. Outbound sockets dropped.',
      subsystem: 'containment',
      status: 'observed',
    },
  ];

  const windowMetrics = [
    { label: 'Total Exposure Duration', value: '9m 57s', note: '09:37:14 — 09:47:11 UTC', tone: 'warn' },
    { label: 'Dwell Time (Pre-Detection)', value: '8m 49s', note: 'First execution to rule trigger', tone: 'danger' },
    { label: 'Mean Time to Contain (MTTC)', value: '1m 08s', note: 'Rule trigger to network isolation', tone: 'good' },
    { label: 'Data Exfiltration Verdict', value: 'Not Established', note: 'Protected by DLP boundary', tone: 'good' },
  ];

  const exportWindowCSV = () => {
    const headers = ['Milestone', 'Time', 'Timeline Position', 'Status', 'Details'];
    const rows = milestones.map((m) => [
      `"${m.label}"`,
      `"${m.time}"`,
      `"${m.pct}"`,
      `"${m.status.toUpperCase()}"`,
      `"${m.detail}"`,
    ]);

    const csvContent =
      'data:text/csv;charset=utf-8,' + encodeURIComponent([headers.join(','), ...rows.map((r) => r.join(','))].join('\n'));
    const link = document.createElement('a');
    link.setAttribute('href', csvContent);
    link.setAttribute('download', `ARGUS_Exposure_Window_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    toast('Window Exported', 'Exposure signature window CSV downloaded successfully.');
  };

  const exportWindowJSON = () => {
    const payload = {
      incidentId: 'INC-2024-1042',
      host: 'WS-0427',
      windowDuration: '9m 57s',
      startTime: '09:37:14 UTC',
      containmentTime: '09:47:11 UTC',
      metrics: windowMetrics,
      milestones,
      timestamp: new Date().toISOString(),
    };

    const jsonContent =
      'data:application/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(payload, null, 2));
    const link = document.createElement('a');
    link.setAttribute('href', jsonContent);
    link.setAttribute('download', `ARGUS_Exposure_Window_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    toast('Window Exported', 'Exposure signature window JSON downloaded.');
  };

  const activeMilestone = milestones.find((m) => m.id === selectedMilestone) || milestones[milestones.length - 1];

  return (
    <div className="animate-page-enter">
      {/* Page Heading */}
      <div className="page-heading">
        <div>
          <div className="eyebrow">Signature Window & Dwell Time Analysis · WS-0427</div>
          <h1 className="page-title">Exposure Window</h1>
          <p className="page-subtitle">
            A bounded mathematical analysis of the exact period in which suspicious activity operated before host isolation severed egress routing.
          </p>
        </div>

        <div className="actions" style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          {onNavigate && (
            <button
              type="button"
              className="btn"
              onClick={() => onNavigate('/timeline')}
              style={{ fontSize: 11, padding: '4px 10px', height: 26 }}
              title="Return to Forensic Timeline"
            >
              <History size={12} style={{ marginRight: 5 }} /> Forensic Timeline
            </button>
          )}

          <button
            type="button"
            className="btn"
            onClick={exportWindowCSV}
            style={{ fontSize: 11, padding: '4px 10px', height: 26 }}
            title="Download Exposure Window CSV"
          >
            <Download size={12} style={{ marginRight: 5 }} /> Export CSV
          </button>

          <button
            type="button"
            className="btn btn-primary"
            onClick={exportWindowJSON}
            style={{ fontSize: 11, padding: '4px 10px', height: 26 }}
            title="Download Structured Window JSON"
          >
            <Download size={12} style={{ marginRight: 5 }} /> Export JSON
          </button>
        </div>
      </div>

      {/* Hero Window Visualization Banner */}
      <section
        className="card card-pad"
        style={{
          marginBottom: 16,
          background: 'linear-gradient(100deg, hsl(var(--card)) 50%, hsl(210 50% 12%))',
          border: '1px solid hsl(var(--border))',
        }}
      >
        <div className="panel-title">
          <h3>
            <Clock3 size={15} style={{ verticalAlign: 'middle', marginRight: 6, color: 'hsl(var(--primary))' }} />
            Signature Exposure Interval: 09:37:14 — 09:47:11 UTC
          </h3>
          <span className="mono" style={{ color: 'hsl(var(--chart-3))', fontWeight: 700, fontSize: 13 }}>
            9 MIN 57 SEC ACTIVE WINDOW
          </span>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, fontSize: 11, marginTop: 14 }}>
          <span className="mono">
            <strong>09:37:14 UTC</strong>
            <br />
            <span className="muted">First execution staging</span>
          </span>
          <span className="mono" style={{ textAlign: 'center' }}>
            <span className="badge badge-high" style={{ fontSize: 9 }}>
              18.4 KB INFERRED FLOW
            </span>
          </span>
          <span className="mono" style={{ textAlign: 'right' }}>
            <strong>09:47:11 UTC</strong>
            <br />
            <span className="muted" style={{ color: 'hsl(var(--accent))' }}>
              Host containment applied
            </span>
          </span>
        </div>

        {/* Scrubable Interactive Progress Track */}
        <div
          style={{
            height: 64,
            position: 'relative',
            margin: '18px 0 12px',
            background: 'linear-gradient(90deg, hsl(var(--chart-3) / 0.12), hsl(var(--destructive) / 0.18))',
            borderRadius: 8,
            border: '1px solid hsl(var(--border))',
          }}
        >
          {/* Active Progress Needle */}
          <div
            style={{
              position: 'absolute',
              left: `${progress}%`,
              top: 0,
              bottom: 0,
              width: 3,
              background: 'hsl(var(--primary))',
              boxShadow: '0 0 12px hsl(var(--primary) / 0.8)',
              transition: 'left 0.4s ease',
              zIndex: 3,
            }}
          />

          {/* Center Timeline Track Line */}
          <div
            style={{
              position: 'absolute',
              left: '2%',
              top: '25px',
              width: '96%',
              height: 2,
              background: 'hsl(var(--muted-foreground) / 0.3)',
            }}
          />

          {/* Interactive Milestone Nodes */}
          {milestones.map((m) => {
            const isSelected = selectedMilestone === m.id;
            const isPotential = m.status === 'potential';

            return (
              <div
                key={m.id}
                onClick={() => setSelectedMilestone(m.id)}
                style={{
                  position: 'absolute',
                  left: m.pct,
                  top: 18,
                  transform: 'translateX(-50%)',
                  textAlign: 'center',
                  fontSize: 10,
                  cursor: 'pointer',
                  zIndex: 4,
                }}
              >
                <i
                  style={{
                    display: 'block',
                    width: isSelected ? 16 : 12,
                    height: isSelected ? 16 : 12,
                    borderRadius: '50%',
                    background: isPotential ? 'hsl(var(--chart-3))' : 'hsl(var(--primary))',
                    margin: '0 auto 6px',
                    boxShadow: isSelected
                      ? '0 0 0 4px hsl(var(--primary) / 0.3)'
                      : '0 0 0 2px hsl(var(--card))',
                    transition: 'all 0.2s ease',
                  }}
                />
                <span
                  style={{
                    fontWeight: isSelected ? 700 : 500,
                    color: isSelected ? 'hsl(var(--foreground))' : 'hsl(var(--muted-foreground))',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {m.label}
                </span>
              </div>
            );
          })}
        </div>
      </section>

      {/* 4-KPI Metric Strip */}
      <div className="grid metrics" style={{ gridTemplateColumns: 'repeat(4, 1fr)', marginBottom: 16 }}>
        {windowMetrics.map((kpi) => (
          <div key={kpi.label} className="card metric animate-rise">
            <div className="metric-label">{kpi.label}</div>
            <div className={`metric-value signal-${kpi.tone}`}>{kpi.value}</div>
            <div className="metric-note">{kpi.note}</div>
          </div>
        ))}
      </div>

      {/* Split Grid: Milestone Deep Dive & Dwell Time Interpretation */}
      <div className="grid split-grid" style={{ gap: 16 }}>
        {/* Left Column: Milestone Inspector */}
        <section className="card card-pad">
          <div className="panel-title">
            <h3>
              <Activity size={15} style={{ verticalAlign: 'middle', marginRight: 6 }} />
              Milestone Sequence Detail
            </h3>
            <span className="mono muted">{activeMilestone.time}</span>
          </div>

          <div
            style={{
              background: 'hsl(var(--muted))',
              padding: '12px 14px',
              borderRadius: 6,
              marginTop: 12,
              border: '1px solid hsl(var(--border))',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
              <div style={{ fontWeight: 700, fontSize: 13 }}>{activeMilestone.label}</div>
              <span
                className={cn('badge', activeMilestone.status === 'potential' ? 'badge-high' : 'badge-low')}
              >
                {activeMilestone.status.toUpperCase()}
              </span>
            </div>

            <p style={{ fontSize: 12, lineHeight: 1.6, margin: '6px 0 0', color: 'hsl(var(--foreground))' }}>
              {activeMilestone.detail}
            </p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 14 }}>
            <div className="kpi-line">
              <span className="muted">Subsystem Origin</span>
              <b className="mono" style={{ textTransform: 'uppercase' }}>
                {activeMilestone.subsystem}
              </b>
            </div>
            <div className="kpi-line">
              <span className="muted">Timeline Relative Position</span>
              <b className="mono">{activeMilestone.pct} into window</b>
            </div>
            <div className="kpi-line">
              <span className="muted">Confidence Metric</span>
              <b className={activeMilestone.status === 'potential' ? 'signal-warn' : 'signal-good'}>
                {activeMilestone.status === 'potential' ? 'Inferred Flow (62%)' : 'Observed Host Telemetry (100%)'}
              </b>
            </div>
          </div>
        </section>

        {/* Right Column: Legal / Compliance Analyst Note */}
        <section className="card card-pad">
          <div className="panel-title">
            <h3>
              <ShieldCheck size={15} style={{ verticalAlign: 'middle', marginRight: 6, color: 'hsl(var(--accent))' }} />
              Dwell Time & Compliance Interpretation
            </h3>
          </div>

          <div
            style={{
              padding: 14,
              background: 'hsl(var(--chart-3) / 0.08)',
              borderLeft: '3px solid hsl(var(--chart-3))',
              borderRadius: 5,
              fontSize: 12,
              lineHeight: 1.6,
              color: 'hsl(var(--foreground))',
              marginTop: 12,
            }}
          >
            <strong>Bounded Forensic Exposure:</strong> The exposure window began with the execution of <code>invoice_viewer.exe</code> at 09:37:14 UTC and closed with endpoint network containment at 09:47:11 UTC.
            <br /><br />
            Although egress socket traffic of 18.4 KB occurred during this window, no lateral authentication against adjacent domain controllers or remote plaintext delivery has been confirmed.
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 16 }}>
            <div className="kpi-line">
              <span className="muted">High-Sensitivity Files Touched</span>
              <b className="signal-danger">3 Files (M&A / Finance)</b>
            </div>
            <div className="kpi-line">
              <span className="muted">Novel External Dest-IPs</span>
              <b className="signal-warn">2 IPs (185.199.110.27, 91.215.85.19)</b>
            </div>
            <div className="kpi-line">
              <span className="muted">Lateral Subnet Infection</span>
              <b className="signal-good">0 Hosts (VLAN 10 isolated)</b>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}
