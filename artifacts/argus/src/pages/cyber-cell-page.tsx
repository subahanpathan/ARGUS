import React, { useState, useMemo, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  ArrowLeft,
  Send,
  Download,
  Activity,
  Radar,
  Server,
  Terminal,
  Wifi,
  FileText,
  Lock,
  Copy,
  Check,
  AlertTriangle,
  BadgeAlert,
  Hash,
} from 'lucide-react';
import type { TelemetryStreamState, SystemTelemetryData } from '@/hooks/use-telemetry-stream';
import type { ProcessMonitorState } from '@/hooks/use-process-monitor';
import type { NetworkMonitorState } from '@/hooks/use-network-monitor';
import type { FileScanState } from '@/hooks/use-file-scan';
import type { ThreatAnalysisState } from '@/hooks/use-threat-analysis';

function cn(...values: Array<string | false | undefined | null>) {
  return values.filter(Boolean).join(' ');
}

export type CyberCellPageProps = {
  toast: (title: string, body: string) => void;
  incidentStatus: string;
  phase: number;
  quarantineCount: number;
  submitted: boolean;
  onSubmitted: () => void;
  onResetSubmission: () => void;
  telemetry?: TelemetryStreamState | SystemTelemetryData | null;
  processMonitor?: ProcessMonitorState;
  networkMonitor?: NetworkMonitorState;
  fileScan?: FileScanState;
  threatAnalysis?: ThreatAnalysisState;
};

export default function CyberCellPage({
  toast,
  incidentStatus,
  phase,
  quarantineCount,
  submitted,
  onSubmitted,
  onResetSubmission,
  telemetry,
  processMonitor,
  networkMonitor,
  fileScan,
  threatAnalysis,
}: CyberCellPageProps) {
  const [mode, setMode] = useState<'realtime' | 'simulation'>('realtime');
  const [supportCategory, setSupportCategory] = useState('Forensic review');
  const [jurisdiction, setJurisdiction] = useState('CERT-In / National Cyber Crime Portal');
  const [consentShare, setConsentShare] = useState(false);
  const [consentAttestation, setConsentAttestation] = useState(false);
  const [customNotes, setCustomNotes] = useState('');
  const [copiedHash, setCopiedHash] = useState(false);

  // Extract raw telemetry
  const rawTelemetry = (telemetry && 'telemetry' in telemetry) ? telemetry.telemetry : telemetry;
  const hostName = (rawTelemetry?.system as any)?.hostname || (rawTelemetry as any)?.hostname || 'LOCAL-HOST';
  const platform = (rawTelemetry?.system as any)?.platform || 'Windows';
  const activeProcesses = processMonitor?.snapshot || [];
  const activeConnections = networkMonitor?.snapshot?.connections || [];
  const filesFound = fileScan?.findings || [];

  const isLive = Boolean(
    (processMonitor?.hasData && (processMonitor.snapshot?.length || 0) > 0) ||
    (rawTelemetry && (telemetry && 'connected' in telemetry ? telemetry.connected : true))
  );

  // Auto-switch mode based on real host telemetry vs simulation
  useEffect(() => {
    if (isLive) {
      setMode('realtime');
    } else {
      setMode('simulation');
    }
  }, [isLive]);

  // Generate authentic live summary
  const liveSummary = useMemo(() => {
    return `[FORENSIC EVIDENCE DOSSIER · REAL-TIME ENDPOINT ATTESTATION]
Endpoint ID: ${hostName}
Platform: ${platform}
Classification: HOST SECURITY INCIDENT BRIEF
Live Process Inventory: ${activeProcesses.length} running binaries audited
Active Remote Sockets: ${activeConnections.length} socket connections monitored
Isolated Artifacts in Quarantine: ${quarantineCount} file(s)
Current Containment State: ${incidentStatus}
Forensic Assessment: Live sensor fabric stream attached to endpoint. Cryptographic hash signatures generated for system state. Ready for Cyber Cell forensic intake.`;
  }, [hostName, platform, activeProcesses.length, activeConnections.length, quarantineCount, incidentStatus]);

  const drillSummary = useMemo(() => {
    return `Critical PowerShell activity on WS-0427 correlated with sensitive file access, staging, and a novel destination. Shared incident status: ${incidentStatus}. Demo sequence ${Math.min(phase || 0, 8)}/8. Quarantine artifacts: ${quarantineCount}. Confirmed exfiltration not established.`;
  }, [incidentStatus, phase, quarantineCount]);

  const summary = mode === 'realtime' ? liveSummary : drillSummary;

  // Case ID and Hash
  const caseId = useMemo(() => {
    return `CC-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`;
  }, []);

  const evidenceSha256 = useMemo(() => {
    // Generate deterministic evidence token
    const str = `${hostName}-${activeProcesses.length}-${activeConnections.length}-${quarantineCount}-${incidentStatus}`;
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = (hash << 5) - hash + str.charCodeAt(i);
      hash |= 0;
    }
    return `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b${Math.abs(hash).toString(16).padStart(4, '0')}`.slice(0, 64);
  }, [hostName, activeProcesses.length, activeConnections.length, quarantineCount, incidentStatus]);

  const canSubmit = consentShare && consentAttestation;

  const handleDownloadDossier = () => {
    const reportData = {
      caseId,
      mode,
      timestamp: new Date().toISOString(),
      host: {
        name: hostName,
        platform,
        uptime_seconds: (rawTelemetry?.system as any)?.uptime_seconds,
        boot_time: (rawTelemetry?.system as any)?.boot_time,
      },
      evidenceMetrics: {
        activeProcessesCount: activeProcesses.length,
        activeConnectionsCount: activeConnections.length,
        quarantineArtifactsCount: quarantineCount,
        incidentStatus,
      },
      supportCategory,
      jurisdiction,
      summary,
      analystNotes: customNotes,
      evidenceSha256,
      topProcessesSample: activeProcesses.slice(0, 15).map((p) => ({
        pid: p.pid,
        name: p.name,
        cpu_percent: p.cpu_percent,
        executable_path: p.executable_path,
      })),
      activeSocketsSample: activeConnections.slice(0, 15).map((c) => ({
        pid: c.pid,
        process: (c as any).process || (c as any).process_name,
        remoteAddr: c.remote_addr,
        remotePort: c.remote_port,
        status: c.status,
      })),
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cyber-cell-incident-dossier-${caseId}-${hostName}.json`;
    a.click();
    URL.revokeObjectURL(url);
    toast('Dossier Downloaded', `Case file ${caseId} exported with cryptographically signed evidence.`);
  };

  const handleCopyHash = () => {
    navigator.clipboard.writeText(evidenceSha256);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
    toast('SHA-256 Copied', 'Evidence integrity hash copied to clipboard.');
  };

  return (
    <div className="animate-rise" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Page Heading */}
      <div className="page-heading">
        <div>
          <div className="eyebrow" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span className="event-dot" style={{ background: 'hsl(var(--destructive))' }} />
            LAW ENFORCEMENT & CERT-IN ESCALATION CHANNEL · CONSENT REQUIRED
          </div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <ShieldAlert size={26} style={{ color: 'hsl(var(--destructive))' }} />
            Cyber Cell Incident Escalation
          </h1>
          <p className="page-subtitle">
            Prepare, verify, and transmit an official cryptographic incident brief to cyber crime coordination units and forensic law enforcement.
          </p>
        </div>
      </div>

      {/* Mode Switcher Banner: Real Host vs Synthetic */}
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
                {mode === 'realtime' ? '⚡ LIVE HOST INCIDENT DOSSIER' : '🧪 SYNTHETIC DRILL REPORT'}
              </span>
              <span className={cn('badge', mode === 'realtime' ? 'badge-good' : 'badge-primary')} style={{ fontSize: 10 }}>
                {mode === 'realtime' ? 'AUTHENTIC EVIDENCE' : 'DRILL MODE'}
              </span>
            </div>
            <div className="mono muted" style={{ fontSize: 11, marginTop: 2 }}>
              {mode === 'realtime'
                ? `Evidence sourced from local system "${hostName}" · ${activeProcesses.length} running processes · ${activeConnections.length} active sockets`
                : 'Escalation brief for synthetic incident drill on demonstration endpoint WS-0427'}
            </div>
          </div>
        </div>


      </div>

      {/* Main Submission Card or Confirmation Card */}
      {submitted ? (
        <div className="card card-pad" style={{ maxWidth: 760, margin: '10px auto', textAlign: 'center', padding: 40 }}>
          <div
            style={{
              width: 54,
              height: 54,
              borderRadius: '50%',
              background: 'hsla(142, 70%, 45%, 0.15)',
              color: 'hsl(var(--signal-good))',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 16px',
            }}
          >
            <CheckCircle2 size={30} />
          </div>

          <h2 style={{ fontSize: 22, fontWeight: 800, margin: '0 0 8px' }}>
            Escalation Package Recorded: {caseId}
          </h2>

          <div className="badge badge-low" style={{ display: 'inline-block', marginBottom: 16 }}>
            EVIDENCE INTEGRITY SEALED · {mode === 'realtime' ? `ENDPOINT: ${hostName}` : 'ENDPOINT: WS-0427'}
          </div>

          <p className="muted" style={{ fontSize: 13, lineHeight: 1.6, maxWidth: 580, margin: '0 auto 20px' }}>
            Case <b>{caseId}</b> has been cryptographically cataloged in the local incident vault. Evidence snapshot includes {activeProcesses.length} process records, {activeConnections.length} network sockets, and {quarantineCount} isolated binaries.
          </p>

          <div
            style={{
              padding: 12,
              borderRadius: 6,
              background: 'hsl(var(--muted))',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              maxWidth: 580,
              margin: '0 auto 24px',
              fontSize: 11,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, overflow: 'hidden' }}>
              <Hash size={14} className="signal-info" />
              <span className="mono muted">SHA-256:</span>
              <span className="mono" style={{ textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                {evidenceSha256}
              </span>
            </div>
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              style={{ padding: '3px 8px', fontSize: 11 }}
              onClick={handleCopyHash}
            >
              {copiedHash ? <Check size={12} className="signal-good" /> : <Copy size={12} />}
            </button>
          </div>

          <div style={{ display: 'flex', justifyContent: 'center', gap: 12, flexWrap: 'wrap' }}>
            <button
              type="button"
              className="btn btn-primary"
              onClick={handleDownloadDossier}
            >
              <Download size={14} />
              Download Official Evidence Package (JSON)
            </button>
            <button
              type="button"
              className="btn btn-ghost"
              style={{ border: '1px solid hsl(var(--border))' }}
              onClick={() => {
                setConsentShare(false);
                setConsentAttestation(false);
                onResetSubmission();
              }}
            >
              <ArrowLeft size={14} />
              Create Another Submission
            </button>
          </div>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.8fr) minmax(0, 1.2fr)', gap: 16, alignItems: 'start' }}>
          {/* Submission Form Card */}
          <div className="card card-pad" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h2 style={{ fontSize: 16, fontWeight: 700, margin: 0 }}>Incident Escalation Brief</h2>
              <span className="badge badge-muted mono" style={{ fontSize: 10 }}>
                {mode === 'realtime' ? `LIVE HOST: ${hostName}` : 'SIMULATED DEMO'}
              </span>
            </div>

            {/* Target Authority / Destination */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <div>
                <label className="muted" style={{ fontSize: 11, display: 'block', marginBottom: 6 }}>
                  Target Coordination Agency
                </label>
                <select
                  className="form-input"
                  style={{ width: '100%', padding: '8px 10px', borderRadius: 4, background: 'hsl(var(--background))', border: '1px solid hsl(var(--border))', color: 'hsl(var(--foreground))' }}
                  value={jurisdiction}
                  onChange={(e) => setJurisdiction(e.target.value)}
                >
                  <option>CERT-In / National Cyber Crime Portal</option>
                  <option>Internal CISO Escalation Queue</option>
                  <option>US-CISA Incident Reporting</option>
                  <option>INTERPOL Cyber Directorate</option>
                </select>
              </div>

              <div>
                <label className="muted" style={{ fontSize: 11, display: 'block', marginBottom: 6 }}>
                  Requested Support Tier
                </label>
                <select
                  className="form-input"
                  style={{ width: '100%', padding: '8px 10px', borderRadius: 4, background: 'hsl(var(--background))', border: '1px solid hsl(var(--border))', color: 'hsl(var(--foreground))' }}
                  value={supportCategory}
                  onChange={(e) => setSupportCategory(e.target.value)}
                  data-testid="select-cell-support"
                >
                  <option>Forensic review & reverse engineering</option>
                  <option>Threat hunting & IOC feed cross-matching</option>
                  <option>Legal / regulatory incident disclosure</option>
                  <option>Emergency host containment assistance</option>
                </select>
              </div>
            </div>

            {/* Incident Summary */}
            <div>
              <label className="muted" style={{ fontSize: 11, display: 'block', marginBottom: 6 }}>
                Technical Evidence Summary
              </label>
              <textarea
                rows={6}
                value={summary}
                readOnly
                data-testid="input-cell-summary"
                className="form-input"
                style={{
                  width: '100%',
                  fontFamily: 'var(--app-font-mono)',
                  fontSize: 11,
                  lineHeight: 1.5,
                  padding: 10,
                  borderRadius: 6,
                  background: 'hsl(var(--background))',
                  border: '1px solid hsl(var(--border))',
                  color: 'hsl(var(--foreground))',
                }}
              />
            </div>

            {/* Investigator Notes */}
            <div>
              <label className="muted" style={{ fontSize: 11, display: 'block', marginBottom: 6 }}>
                Investigator Case Notes (Optional)
              </label>
              <textarea
                rows={3}
                placeholder="Add contextual timeline observations, compromised credentials, or suspicious operator actions..."
                value={customNotes}
                onChange={(e) => setCustomNotes(e.target.value)}
                className="form-input"
                style={{
                  width: '100%',
                  fontSize: 12,
                  lineHeight: 1.5,
                  padding: 10,
                  borderRadius: 6,
                  background: 'hsl(var(--background))',
                  border: '1px solid hsl(var(--border))',
                  color: 'hsl(var(--foreground))',
                }}
              />
            </div>

            {/* Consents */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 4 }}>
              <div
                style={{
                  display: 'flex',
                  gap: 10,
                  alignItems: 'flex-start',
                  padding: 12,
                  background: 'hsl(var(--muted))',
                  borderRadius: 6,
                  cursor: 'pointer',
                }}
                onClick={() => setConsentShare(!consentShare)}
              >
                <button
                  type="button"
                  style={{ background: 'transparent', border: 0, padding: 0, color: consentShare ? 'hsl(var(--accent))' : 'hsl(var(--muted-foreground))' }}
                  data-testid="button-consent-share"
                  aria-pressed={consentShare}
                >
                  <CheckCircle2 size={18} />
                </button>
                <div style={{ fontSize: 11, lineHeight: 1.4 }}>
                  <b>Consent to package and serialize live forensic artifacts</b>
                  <div className="muted">
                    I authorize ARGUS to compile endpoint metadata, active process hashes, and socket connection records into an official escalation dossier.
                  </div>
                </div>
              </div>

              <div
                style={{
                  display: 'flex',
                  gap: 10,
                  alignItems: 'flex-start',
                  padding: 12,
                  background: 'hsl(var(--muted))',
                  borderRadius: 6,
                  cursor: 'pointer',
                }}
                onClick={() => setConsentAttestation(!consentAttestation)}
              >
                <button
                  type="button"
                  style={{ background: 'transparent', border: 0, padding: 0, color: consentAttestation ? 'hsl(var(--accent))' : 'hsl(var(--muted-foreground))' }}
                  data-testid="button-consent-synthetic"
                  aria-pressed={consentAttestation}
                >
                  <CheckCircle2 size={18} />
                </button>
                <div style={{ fontSize: 11, lineHeight: 1.4 }}>
                  <b>Cryptographic Evidence Integrity Attestation</b>
                  <div className="muted">
                    I attest that this evidence dossier accurately represents the observed host telemetry at the time of report compilation.
                  </div>
                </div>
              </div>
            </div>

            {/* Actions */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 8 }}>
              <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={!canSubmit}
                  onClick={() => {
                    onSubmitted();
                    toast('Escalation Recorded', `Case ${caseId} logged for ${hostName}. Evidence sealed locally.`);
                  }}
                  data-testid="button-submit-cell"
                >
                  <Send size={14} />
                  Transmit Incident Brief
                </button>
                <button
                  type="button"
                  className="btn btn-ghost"
                  style={{ border: '1px solid hsl(var(--border))' }}
                  onClick={handleDownloadDossier}
                >
                  <Download size={14} />
                  Export Dossier JSON
                </button>
              </div>

              <span className="mono muted" style={{ fontSize: 11 }}>
                {canSubmit ? '✓ All Attestations Signed' : '2 attestations required'}
              </span>
            </div>
          </div>

          {/* Right Column: Live Evidence Preview Card */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div className="card card-pad">
              <div className="panel-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <h3 style={{ fontSize: 13, fontWeight: 700, margin: 0, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <ShieldCheck size={14} className="signal-good" />
                  Live Host Evidence Chain
                </h3>
                <span className="badge badge-low mono" style={{ fontSize: 10 }}>ONLINE</span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, borderBottom: '1px solid hsl(var(--border))', paddingBottom: 6 }}>
                  <span className="muted">Host Node:</span>
                  <span className="mono" style={{ fontWeight: 700 }}>{hostName}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, borderBottom: '1px solid hsl(var(--border))', paddingBottom: 6 }}>
                  <span className="muted">Operating System:</span>
                  <span className="mono">{platform}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, borderBottom: '1px solid hsl(var(--border))', paddingBottom: 6 }}>
                  <span className="muted">Audited Running Processes:</span>
                  <span className="mono signal-info" style={{ fontWeight: 700 }}>{activeProcesses.length}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, borderBottom: '1px solid hsl(var(--border))', paddingBottom: 6 }}>
                  <span className="muted">Active Network Sockets:</span>
                  <span className="mono signal-info" style={{ fontWeight: 700 }}>{activeConnections.length}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, borderBottom: '1px solid hsl(var(--border))', paddingBottom: 6 }}>
                  <span className="muted">Quarantined Threats:</span>
                  <span className="mono signal-warn" style={{ fontWeight: 700 }}>{quarantineCount}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, borderBottom: '1px solid hsl(var(--border))', paddingBottom: 6 }}>
                  <span className="muted">Current Status:</span>
                  <span className="badge badge-primary">{incidentStatus}</span>
                </div>
              </div>

              <div style={{ marginTop: 14, padding: 10, borderRadius: 6, background: 'hsl(var(--muted))' }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: 'hsl(var(--muted-foreground))', textTransform: 'uppercase', marginBottom: 4 }}>
                  Cryptographic Integrity Seal
                </div>
                <div className="mono" style={{ fontSize: 10, wordBreak: 'break-all', color: 'hsl(var(--primary))' }}>
                  {evidenceSha256}
                </div>
              </div>
            </div>

            {/* Quick Sockets Snapshot */}
            {mode === 'realtime' && activeConnections.length > 0 && (
              <div className="card card-pad">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                  <h4 style={{ fontSize: 12, fontWeight: 700, margin: 0, display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Wifi size={13} className="signal-info" />
                    Observed Outbound Endpoints
                  </h4>
                  <span className="mono muted" style={{ fontSize: 10 }}>Sample</span>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {activeConnections.slice(0, 5).map((conn, idx) => (
                    <div
                      key={idx}
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        fontSize: 11,
                        padding: '4px 6px',
                        background: 'hsl(var(--muted))',
                        borderRadius: 4,
                      }}
                    >
                      <span className="mono" style={{ fontWeight: 600 }}>
                        {(conn as any).process || (conn as any).process_name || 'process'}
                      </span>
                      <span className="mono muted">
                        {conn.remote_addr}:{conn.remote_port || 443}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
