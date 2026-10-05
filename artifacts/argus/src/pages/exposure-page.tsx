import { useMemo, useState, type CSSProperties, type ReactNode } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Check,
  CheckCircle2,
  Clock3,
  Copy,
  Download,
  ExternalLink,
  Eye,
  FileKey2,
  FileSearch,
  FileText,
  Fingerprint,
  HardDrive,
  History,
  Layers,
  Link2,
  Lock,
  Network,
  Radio,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare,
  UserCheck,
  Users,
  Zap,
} from 'lucide-react';
import type { ThreatAnalysisState } from '@/hooks/use-threat-analysis';
import type { FileScanState } from '@/hooks/use-file-scan';
import type { ProcessMonitorState } from '@/hooks/use-process-monitor';
import type { NetworkMonitorState } from '@/hooks/use-network-monitor';

function cn(...values: Array<string | false | undefined | null>) {
  return values.filter(Boolean).join(' ');
}

type Severity = 'critical' | 'high' | 'medium' | 'low';

export type ExposurePageProps = {
  phase: number;
  toast: (title: string, body: string) => void;
  threatAnalysis?: ThreatAnalysisState;
  fileScan?: FileScanState;
  processMonitor?: ProcessMonitorState;
  networkMonitor?: NetworkMonitorState;
  onNavigate?: (path: string) => void;
  contained?: boolean;
  onContain?: () => void;
};

type ExposureTab = 'killchain' | 'blastradius' | 'riskfactors' | 'playbook';

export default function ExposurePage({
  phase,
  toast,
  threatAnalysis,
  fileScan,
  processMonitor,
  networkMonitor,
  onNavigate,
  contained = false,
  onContain,
}: ExposurePageProps) {
  const [activeTab, setActiveTab] = useState<ExposureTab>('killchain');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Compute live vs demo risk score
  const isReal = Boolean(
    (processMonitor?.hasData && processMonitor.snapshot.length > 0) ||
    (networkMonitor?.snapshot && networkMonitor.snapshot.connections.length > 0) ||
    (fileScan?.findings && fileScan.findings.length > 0) ||
    (threatAnalysis?.isLive && threatAnalysis.threatCount > 0)
  );

  const riskScore = useMemo(() => {
    if (isReal) {
      if (threatAnalysis && threatAnalysis.threatCount > 0) {
        const crit = threatAnalysis.criticalCount * 28;
        const high = threatAnalysis.highCount * 16;
        const med = threatAnalysis.mediumCount * 8;
        return Math.min(96, Math.max(30, 20 + crit + high + med));
      }
      return 26; // Monitored baseline risk when sensors are active with no uncontained critical threats
    }
    // Demo progression score based on phase
    return phase >= 7 ? 88 : phase >= 5 ? 86 : phase >= 3 ? 61 : 38;
  }, [isReal, threatAnalysis, phase]);

  const riskTone = riskScore > 75 ? 'danger' : riskScore > 50 ? 'warn' : 'good';

  const copyToClipboard = (text: string, key: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    toast('Copied to clipboard', `${label}: ${text}`);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Top process and network artifacts for live presentation
  const topProc = useMemo(() => {
    if (!processMonitor?.snapshot || processMonitor.snapshot.length === 0) return null;
    return (
      processMonitor.snapshot.find((p) => p.name === 'powershell.exe' || (p.cpu_percent ?? 0) > 5) ||
      processMonitor.snapshot[0]
    );
  }, [processMonitor?.snapshot]);

  const topConn = useMemo(() => {
    if (!networkMonitor?.snapshot?.connections || networkMonitor.snapshot.connections.length === 0) return null;
    return (
      networkMonitor.snapshot.connections.find((c) => c.status === 'ESTABLISHED' && c.remote_addr !== '127.0.0.1') ||
      networkMonitor.snapshot.connections[0]
    );
  }, [networkMonitor?.snapshot?.connections]);

  const connCount = networkMonitor?.snapshot?.connections?.length ?? 0;
  const establishedCount = networkMonitor?.snapshot?.established_count ?? 0;
  const findingCount = fileScan?.findings?.length ?? 0;

  // Exposure Kill-Chain Stages
  const exposureStages = useMemo(() => {
    if (isReal) {
      return [
        {
          stage: 'Initial Vector & Execution',
          target: topProc ? `${topProc.name} (PID ${topProc.pid})` : 'Host Process Execution',
          evidenceType: 'Observed Telemetry',
          status: 'confirmed',
          details: topProc
            ? `Active execution observed on endpoint WS-0427. User: ${topProc.username || 'Current User'}, Memory: ${Math.round((topProc.memory_bytes || 0) / (1024 * 1024))} MB, CPU: ${(topProc.cpu_percent || 0.1).toFixed(1)}%. Path: ${topProc.executable_path || 'C:\\Windows\\System32'}.`
            : 'Host process execution observed via sensor network.',
          observed: true,
          route: '/processes',
          metric: topProc ? `PID ${topProc.pid} · User: ${topProc.username || 'Analyst'}` : 'Live Telemetry',
        },
        {
          stage: 'Sensitive Data Collection',
          target: findingCount > 0
            ? fileScan!.findings.slice(0, 3).map((f) => f.file_name).join(', ')
            : 'Candidate Filesystem Inspection',
          evidenceType: 'Observed Telemetry',
          status: 'confirmed',
          details: findingCount > 0
            ? `${findingCount} candidate files identified across monitored directories. High entropy and classification flags observed.`
            : 'Automated filesystem inspection of user documents and temporary directories. Clean monitored baseline.',
          observed: true,
          route: '/files',
          metric: `${findingCount} Files Scanned · ${(fileScan?.findings ? fileScan.findings.reduce((acc, f) => acc + (f.size_bytes || 0), 0) / 1024 : 0).toFixed(1)} KB`,
        },
        {
          stage: 'Archive Staging',
          target: 'NTFS Write Buffers & Local Staging Paths',
          evidenceType: 'Observed Telemetry',
          status: 'confirmed',
          details: 'Continuous surveillance of temporary directories (%TEMP%, AppData, Downloads) for payload unpack, archive compression, or script staging signatures.',
          observed: true,
          route: '/files',
          metric: '4 Monitored Root Directories',
        },
        {
          stage: 'Potential Exfiltration',
          target: topConn ? `${topConn.remote_addr}:${topConn.remote_port} (${topConn.process})` : 'Active Network Sockets Egress',
          evidenceType: 'Potential / Inferred',
          status: 'potential',
          details: `${connCount} active socket connections observed on network interfaces (${establishedCount} established). Egress telemetry monitored.`,
          observed: false,
          route: '/network',
          metric: `${connCount} Active Sockets (Flow Inferred)`,
        },
        {
          stage: 'Confirmed Exfiltration',
          target: 'Plaintext Exfiltrated Payload',
          evidenceType: 'Defensible Boundary',
          status: 'unconfirmed',
          details: 'No decrypted exfiltration payload or proof of remote receipt established. Sensor separates metadata from proof of theft.',
          observed: false,
          route: '/reports',
          metric: 'Not established (Protected by DLP)',
        },
      ];
    }

    // Demo Progression Stages
    return [
      {
        stage: 'Initial Vector & Execution',
        target: 'invoice_viewer.exe → powershell.exe',
        evidenceType: 'Observed Telemetry',
        status: 'confirmed',
        details: 'Executable attachment spawned encoded PowerShell child process with process privilege elevation.',
        observed: true,
        route: '/processes',
        metric: 'PID 8420 · 09:37:16 UTC',
      },
      {
        stage: 'Sensitive Data Collection',
        target: 'Q4_strategy.docx, forecast_2025.xlsx, browser_export.csv',
        evidenceType: 'Observed Telemetry',
        status: 'confirmed',
        details: '3 classified documents (M&A Strategy, Corporate Finance, Saved Passwords) opened by external script host.',
        observed: true,
        route: '/files',
        metric: '3 Files · 239.5 KB total',
      },
      {
        stage: 'Archive Staging',
        target: '~stage_042.zip (C:\\Users\\mira\\AppData\\Local\\Temp)',
        evidenceType: 'Observed Telemetry',
        status: 'confirmed',
        details: '7-Zip CLI created encrypted archive in user Temp staging folder containing collected documents.',
        observed: true,
        route: '/files',
        metric: '845 KB compressed archive',
      },
      {
        stage: 'Potential Exfiltration',
        target: 'cdn-sync-check[.]com (185.199.110.27:443)',
        evidenceType: 'Potential / Inferred',
        status: 'potential',
        details: 'Outbound TLS 1.3 flow observed over novelty external IP. Flow metadata shows 18.4 KB sent.',
        observed: false,
        route: '/network',
        metric: '18.4 KB transmitted (Flow inferred)',
      },
      {
        stage: 'Confirmed Exfiltration',
        target: 'Plaintext Exfiltrated Payload',
        evidenceType: 'Defensible Boundary',
        status: 'unconfirmed',
        details: 'No decrypted exfiltration payload or proof of remote receipt established. Sensor separates metadata from proof of theft.',
        observed: false,
        route: '/reports',
        metric: 'Not established (Protected by DLP)',
      },
    ];
  }, [isReal, topProc, topConn, connCount, establishedCount, findingCount, fileScan?.findings]);

  // Contributing Risk Factors
  const riskFactors = useMemo(() => {
    if (isReal) {
      const threatCount = threatAnalysis?.threatCount ?? 0;
      return [
        {
          label: 'Data Sensitivity & Classification',
          value: findingCount > 0 ? 'Elevated' : 'Baseline',
          score: findingCount > 0 ? 74 : 22,
          tone: findingCount > 0 ? 'warn' : 'good',
          note: `${findingCount} candidate files evaluated across roots`,
        },
        {
          label: 'Process Execution Novelty',
          value: topProc ? (topProc.name.includes('powershell') ? 'Elevated' : 'Observed') : 'Low',
          score: topProc?.name.includes('powershell') ? 78 : 34,
          tone: topProc?.name.includes('powershell') ? 'danger' : 'good',
          note: `${processMonitor?.snapshot?.length ?? 299} active Windows processes`,
        },
        {
          label: 'Network Egress & Socket Exposure',
          value: connCount > 10 ? 'High Activity' : 'Normal',
          score: Math.min(88, Math.max(30, Math.round(connCount * 0.1))),
          tone: connCount > 50 ? 'warn' : 'good',
          note: `${connCount} active sockets (${establishedCount} established)`,
        },
        {
          label: 'Payload Exfiltration Visibility',
          value: 'Defensible Boundary',
          score: 28,
          tone: 'good',
          note: 'Metadata logged, encrypted payload boundary unconfirmed',
        },
        {
          label: 'Multi-Sensor Correlation',
          value: 'Operational (100%)',
          score: 98,
          tone: 'good',
          note: 'Process, File, and Network feeds actively streaming',
        },
      ];
    }

    return [
      { label: 'Data Sensitivity & Classification', value: 'High', score: 84, tone: 'danger', note: 'M&A and Finance documents accessed' },
      { label: 'Process Execution Novelty', value: 'High', score: 78, tone: 'danger', note: 'PowerShell executing from staging directory' },
      { label: 'Destination Reputation (C2)', value: 'Suspicious', score: 65, tone: 'warn', note: 'Newly registered domain (12/87 flags)' },
      { label: 'Payload Exfiltration Visibility', value: 'Low Confidence', score: 32, tone: 'warn', note: 'Flow volume measured, payload encrypted' },
      { label: 'Multi-Sensor Correlation', value: 'Strong (99%)', score: 94, tone: 'good', note: 'Process, File, and Network signals match' },
    ];
  }, [isReal, findingCount, topProc, connCount, establishedCount, processMonitor?.snapshot, threatAnalysis?.threatCount]);

  // Blast Radius Assets
  const blastRadiusAssets = useMemo(() => {
    if (isReal) {
      const threatCount = threatAnalysis?.threatCount ?? 0;
      return [
        {
          type: 'Endpoint Host',
          name: 'WS-0427 (Live Windows Telemetry)',
          owner: 'Primary Workstation',
          ip: '127.0.0.1 / Local Adapter',
          status: contained ? 'Network Isolated' : 'Real-Time Sensor Active',
          severity: (contained ? 'low' : threatCount > 0 ? 'critical' : 'low') as Severity,
          icon: TerminalSquare,
        },
        {
          type: 'Identity & Credentials',
          name: topProc?.username || 'Current User Context',
          owner: 'Active Windows User Session',
          ip: 'Interactive Security Token',
          status: threatCount > 0 ? 'Credential Review Recommended' : 'Baseline Security Token Valid',
          severity: (threatCount > 0 ? 'high' : 'low') as Severity,
          icon: UserCheck,
        },
        {
          type: 'Data Repositories',
          name: 'Local Drives & Monitored Paths',
          owner: 'NTFS Filesystem Storage',
          ip: 'Local NTFS Drive C:',
          status: `${findingCount} Candidate Files Under Inspection`,
          severity: (findingCount > 0 ? 'high' : 'low') as Severity,
          icon: FileKey2,
        },
        {
          type: 'Network Perimeter',
          name: `${connCount} Active TCP/UDP Sockets`,
          owner: 'TCP/IP Transport Stack',
          ip: `${establishedCount} Established Sockets`,
          status: contained ? 'Outbound Sockets Severed' : 'Continuous Egress Surveillance',
          severity: (contained ? 'low' : 'medium') as Severity,
          icon: Network,
        },
      ];
    }

    return [
      {
        type: 'Endpoint Host',
        name: 'WS-0427 (Finance Workstation)',
        owner: 'Mira Alvarez (Sr. Financial Analyst)',
        ip: '10.14.8.27 (VLAN 10 - Finance)',
        status: contained ? 'Network Isolated' : 'Under Investigation',
        severity: 'critical' as Severity,
        icon: TerminalSquare,
      },
      {
        type: 'Identity & Credentials',
        name: 'CORP\\mira.alvarez',
        owner: 'Active Directory Domain User',
        ip: 'Kerberos TGT Issued',
        status: 'Credential Rotation Required',
        severity: 'high' as Severity,
        icon: UserCheck,
      },
      {
        type: 'Data Repositories',
        name: 'Documents\\Acquisition & Finance',
        owner: 'Restricted Share Access',
        ip: 'Local NTFS Drive C:',
        status: '3 Files Staged in Temp',
        severity: 'high' as Severity,
        icon: FileKey2,
      },
      {
        type: 'Lateral Peers (Adjacent)',
        name: 'WS-0198, WS-0341, DC-01',
        owner: 'Same VLAN Subnet (10.14.8.0/24)',
        ip: '3 Host Peers Scanned',
        status: 'No Lateral Movement Observed',
        severity: 'low' as Severity,
        icon: Users,
      },
    ];
  }, [isReal, topProc, findingCount, connCount, establishedCount, contained, threatAnalysis?.threatCount]);

  // Export handlers
  const exportAssessmentCSV = () => {
    const headers = ['Stage', 'Target / Entity', 'Evidence Model', 'Status', 'Metric', 'Forensic Details'];
    const rows = exposureStages.map((s) => [
      `"${s.stage}"`,
      `"${s.target}"`,
      `"${s.evidenceType}"`,
      `"${s.status.toUpperCase()}"`,
      `"${s.metric}"`,
      `"${s.details}"`,
    ]);

    const csvContent =
      'data:text/csv;charset=utf-8,' + encodeURIComponent([headers.join(','), ...rows.map((r) => r.join(','))].join('\n'));
    const link = document.createElement('a');
    link.setAttribute('href', csvContent);
    link.setAttribute('download', `ARGUS_Exposure_Assessment_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    toast('Assessment Exported', 'Exposure Assessment CSV downloaded successfully.');
  };

  const exportAssessmentJSON = () => {
    const payload = {
      incidentId: 'INC-2024-1042',
      endpoint: 'WS-0427',
      user: 'mira.alvarez',
      assessedRiskScore: riskScore,
      exposureStages,
      blastRadiusAssets,
      riskFactors,
      defensibleVerdict: 'Confirmed exfiltration is not established. Flow inferred from connection metadata.',
      timestamp: new Date().toISOString(),
    };

    const jsonContent =
      'data:application/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(payload, null, 2));
    const link = document.createElement('a');
    link.setAttribute('href', jsonContent);
    link.setAttribute('download', `ARGUS_Exposure_Dossier_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    toast('Dossier Exported', 'Forensic Exposure Dossier JSON downloaded.');
  };

  const exportExecutiveMemo = () => {
    const text = [
      '================================================================================',
      'ARGUS SECURITY INTELLIGENCE — DEFENSIVE EXPOSURE ASSESSMENT MEMORANDUM',
      '================================================================================',
      `INCIDENT ID       : INC-2024-1042`,
      `TARGET HOST       : WS-0427 (Finance Workstation)`,
      `OPERATOR ACCOUNT  : CORP\\mira.alvarez`,
      `ASSESSED RISK     : ${riskScore} / 100 (${riskScore > 75 ? 'CRITICAL EXPOSURE' : 'ELEVATED RISK'})`,
      `CONTAINMENT STATE : ${contained ? 'CONTAINED / ISOLATED' : 'ACTIVE SURVEILLANCE'}`,
      `DATE / TIMESTAMP  : ${new Date().toUTCString()}`,
      '--------------------------------------------------------------------------------',
      '1. EXECUTIVE SUMMARY & EVIDENCE SEPARATION PRINCIPLE:',
      '   ARGUS enforces a defensible boundary separating direct sensor observation',
      '   from modeled/inferred risk. While suspicious process staging and document read',
      '   operations were observed on WS-0427, CONFIRMED DATA THEFT IS NOT ESTABLISHED.',
      '',
      '2. KILL-CHAIN PROGRESSION & OBSERVED ARTIFACTS:',
      ...exposureStages.map((s, idx) => `   [${idx + 1}] ${s.stage.toUpperCase()}: ${s.target}\n       • Evidence: ${s.evidenceType} (${s.status.toUpperCase()})\n       • Details : ${s.details}`),
      '',
      '3. ASSET BLAST RADIUS:',
      ...blastRadiusAssets.map((a) => `   • [${a.type}] ${a.name} — Status: ${a.status}`),
      '',
      '4. RECOMMENDED REMEDIATION ACTIONS:',
      '   [x] Apply immediate host network isolation to WS-0427.',
      '   [x] Terminate unauthorized script interpreters and child trees (PID 8420).',
      '   [x] Force password reset and Kerberos ticket revocation for CORP\\mira.alvarez.',
      '   [x] Block egress destinations (185.199.110.27, cdn-sync-check[.]com) on edge firewall.',
      '================================================================================',
    ].join('\n');

    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ARGUS_Exposure_Memo_INC-2024-1042.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast('Executive Memo Ready', 'Defensive assessment briefing memo downloaded.');
  };

  return (
    <div className="animate-page-enter">
      {/* Page Heading */}
      <div className="page-heading">
        <div>
          <div className="eyebrow">
            Decision Support & Blast Radius Analysis · {isReal ? 'LIVE HOST WS-0427' : 'INC-2024-1042'}
          </div>
          <h1 className="page-title">Exposure Assessment</h1>
          <p className="page-subtitle">
            A rigorous, defensible separation between what host telemetry observed, potential transmission inferences, and blast radius impact across the enterprise.
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
                gap: 5,
              }}
            >
              <Radio size={10} />
              LIVE TELEMETRY EXPOSURE (RISK {riskScore}/100)
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
              DEMO INCIDENT EXPOSURE (PHASE {phase}/8)
            </span>
          )}

          <button
            type="button"
            className="btn"
            onClick={exportAssessmentCSV}
            style={{ fontSize: 11, padding: '4px 10px', height: 26 }}
            title="Download exposure stage matrix CSV"
          >
            <Download size={12} style={{ marginRight: 5 }} /> Export CSV
          </button>

          <button
            type="button"
            className="btn"
            onClick={exportAssessmentJSON}
            style={{ fontSize: 11, padding: '4px 10px', height: 26 }}
            title="Download structured JSON incident dossier"
          >
            <Download size={12} style={{ marginRight: 5 }} /> Export JSON
          </button>

          <button
            type="button"
            className="btn btn-primary"
            onClick={exportExecutiveMemo}
            style={{ fontSize: 11, padding: '4px 10px', height: 26 }}
            title="Generate executive briefing memo"
          >
            <FileText size={12} style={{ marginRight: 5 }} /> Executive Memo
          </button>
        </div>
      </div>

      {/* Hero Assessed Risk Score & Blast Radius Summary Banner */}
      <section
        className="card card-pad"
        style={{
          marginBottom: 16,
          background: 'linear-gradient(105deg, hsl(var(--card)) 40%, hsl(205 60% 12%))',
          border: '1px solid hsl(var(--border))',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 30, flexWrap: 'wrap' }}>
          <div>
            <div className="eyebrow" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <ShieldAlert size={13} style={{ color: riskTone === 'danger' ? 'hsl(var(--destructive))' : 'hsl(var(--chart-3))' }} />
              ASSESSED RISK SCORE & SEVERITY
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginTop: 4 }}>
              <div
                style={{ fontSize: 52, fontWeight: 900, letterSpacing: '-0.07em', lineHeight: 1 }}
                className={riskTone === 'danger' ? 'signal-danger' : 'signal-warn'}
              >
                {riskScore}
                <span style={{ fontSize: 18, color: 'hsl(var(--muted-foreground))', letterSpacing: 0 }}>/100</span>
              </div>
              <span
                className={cn('badge', riskTone === 'danger' ? 'badge-critical' : 'badge-high')}
                style={{ fontSize: 11, padding: '3px 8px' }}
              >
                {riskScore > 75 ? 'CRITICAL EXPOSURE' : 'ELEVATED RISK'}
              </span>
            </div>
            <p className="muted" style={{ fontSize: 12, margin: '8px 0 0', maxWidth: 540, lineHeight: 1.5 }}>
              Score synthesizes sensitive file access, executable process novelty, and outbound network flow metrics.
              <strong style={{ color: 'hsl(var(--foreground))' }}> Confirmed data theft is not established</strong> (distinction enforced by ARGUS Evidence Model).
            </p>
          </div>

          <div style={{ width: 340, maxWidth: '100%' }}>
            <div className="risk-meter" style={{ height: 14, gap: 5 }}>
              {[1, 2, 3, 4, 5].map((n) => (
                <i
                  className={n <= Math.ceil(riskScore / 20) ? 'on' : ''}
                  key={n}
                  style={{
                    background:
                      n <= Math.ceil(riskScore / 20)
                        ? riskScore > 75
                          ? 'hsl(var(--destructive))'
                          : 'hsl(var(--chart-3))'
                        : undefined,
                  }}
                />
              ))}
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8, fontSize: 10 }} className="mono muted">
              <span>0 (Baseline)</span>
              <span>25 (Monitored)</span>
              <span>50 (Elevated)</span>
              <span>75 (High)</span>
              <span>100 (Critical)</span>
            </div>

            <div
              style={{
                marginTop: 14,
                padding: '8px 12px',
                background: 'hsl(var(--muted))',
                borderRadius: 6,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                fontSize: 11,
              }}
            >
              <span className="muted">Host Containment State:</span>
              <span
                className="mono"
                style={{
                  fontWeight: 700,
                  color: contained ? 'hsl(var(--accent))' : 'hsl(var(--destructive))',
                }}
              >
                {contained ? 'ENDPOINT ISOLATED' : 'EGRESS ACTIVE'}
              </span>
            </div>
          </div>
        </div>
      </section>

      {/* 4-KPI Metric Strip */}
      <div className="grid metrics" style={{ gridTemplateColumns: 'repeat(4, 1fr)', marginBottom: 16 }}>
        <div className="card metric animate-rise">
          <div className="metric-label">
            <TerminalSquare size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />
            Primary Affected Host
          </div>
          <div className="metric-value signal-danger">WS-0427</div>
          <div className="metric-note">Mira Alvarez (Corp Finance)</div>
        </div>

        <div className="card metric animate-rise">
          <div className="metric-label">
            <FileKey2 size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />
            Sensitive Documents Touched
          </div>
          <div className="metric-value signal-warn">5 Files</div>
          <div className="metric-note">M&A Strategy & Finance models</div>
        </div>

        <div className="card metric animate-rise">
          <div className="metric-label">
            <Network size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />
            Staged / Inferred Flow
          </div>
          <div className="metric-value signal-info">18.4 KB</div>
          <div className="metric-note">Outbound TLS 1.3 flow (Inferred)</div>
        </div>

        <div className="card metric animate-rise">
          <div className="metric-label">
            <ShieldCheck size={13} style={{ verticalAlign: 'middle', marginRight: 6 }} />
            Confirmed Exfiltration
          </div>
          <div className="metric-value signal-good">None</div>
          <div className="metric-note">Protected by DLP proof boundary</div>
        </div>
      </div>

      {/* Navigation Tab Bar */}
      <div
        style={{
          display: 'flex',
          gap: 4,
          background: 'hsl(var(--card))',
          border: '1px solid hsl(var(--border))',
          borderRadius: 8,
          padding: 3,
          marginBottom: 16,
          width: 'fit-content',
        }}
      >
        <button
          type="button"
          className={cn('btn btn-ghost', activeTab === 'killchain' && 'btn-primary')}
          style={{ fontSize: 11, padding: '5px 14px', height: 28 }}
          onClick={() => setActiveTab('killchain')}
        >
          <Layers size={13} style={{ marginRight: 6 }} /> Kill-Chain Evidence Chain
        </button>

        <button
          type="button"
          className={cn('btn btn-ghost', activeTab === 'blastradius' && 'btn-primary')}
          style={{ fontSize: 11, padding: '5px 14px', height: 28 }}
          onClick={() => setActiveTab('blastradius')}
        >
          <Server size={13} style={{ marginRight: 6 }} /> Blast Radius & Asset Impact
        </button>

        <button
          type="button"
          className={cn('btn btn-ghost', activeTab === 'riskfactors' && 'btn-primary')}
          style={{ fontSize: 11, padding: '5px 14px', height: 28 }}
          onClick={() => setActiveTab('riskfactors')}
        >
          <Activity size={13} style={{ marginRight: 6 }} /> Contributing Risk Factors
        </button>

        <button
          type="button"
          className={cn('btn btn-ghost', activeTab === 'playbook' && 'btn-primary')}
          style={{ fontSize: 11, padding: '5px 14px', height: 28 }}
          onClick={() => setActiveTab('playbook')}
        >
          <Lock size={13} style={{ marginRight: 6 }} /> Incident Response Playbook
        </button>
      </div>

      {/* Tab 1: Kill-Chain Evidence Progression */}
      {activeTab === 'killchain' && (
        <div className="grid split-grid" style={{ gap: 16 }}>
          <section className="card card-pad">
            <div className="panel-title">
              <h3>
                <Layers size={15} style={{ verticalAlign: 'middle', marginRight: 6 }} />
                Kill-Chain Sequence & Evidence Verification
              </h3>
              <span className="mono muted">5 STAGES EVALUATED</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 14, marginTop: 14 }}>
              {exposureStages.map((item, idx) => {
                const isConfirmed = item.status === 'confirmed';
                const isPotential = item.status === 'potential';
                const isUnconfirmed = item.status === 'unconfirmed';

                return (
                  <div
                    key={item.stage}
                    style={{
                      background: 'hsl(var(--card))',
                      border: '1px solid hsl(var(--border))',
                      borderRadius: 6,
                      padding: '12px 14px',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: 8,
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <div
                          style={{
                            width: 22,
                            height: 22,
                            borderRadius: '50%',
                            display: 'grid',
                            placeItems: 'center',
                            background: isConfirmed
                              ? 'hsl(var(--accent) / 0.15)'
                              : isPotential
                              ? 'hsl(var(--chart-3) / 0.15)'
                              : 'hsl(var(--muted))',
                            color: isConfirmed
                              ? 'hsl(var(--accent))'
                              : isPotential
                              ? 'hsl(var(--chart-3))'
                              : 'hsl(var(--muted-foreground))',
                            fontSize: 11,
                            fontWeight: 700,
                          }}
                        >
                          {idx + 1}
                        </div>
                        <span style={{ fontWeight: 700, fontSize: 13 }}>{item.stage}</span>
                      </div>

                      <span
                        className={cn(
                          'badge',
                          isConfirmed ? 'badge-low' : isPotential ? 'badge-high' : 'badge-muted'
                        )}
                        style={{ fontSize: 9, padding: '2px 7px' }}
                      >
                        {item.evidenceType.toUpperCase()}
                      </span>
                    </div>

                    <div className="mono" style={{ fontSize: 11, color: 'hsl(var(--foreground))', fontWeight: 600 }}>
                      Target: {item.target}
                    </div>

                    <p className="muted" style={{ fontSize: 11, margin: 0, lineHeight: 1.5 }}>
                      {item.details}
                    </p>

                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        paddingTop: 6,
                        borderTop: '1px solid hsl(var(--border))',
                        fontSize: 10,
                      }}
                    >
                      <span className="mono muted">{item.metric}</span>
                      {onNavigate && (
                        <button
                          type="button"
                          className="btn btn-ghost"
                          style={{ padding: '2px 8px', fontSize: 10, height: 22 }}
                          onClick={() => onNavigate(item.route)}
                        >
                          Investigate in {item.route.replace('/', '')} <ArrowRight size={10} style={{ marginLeft: 3 }} />
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </section>

          {/* Defensible Separation Explainer & Evidence Model Card */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <section
              className="card card-pad"
              style={{
                background: 'hsl(var(--card))',
                borderLeft: '3px solid hsl(var(--accent))',
              }}
            >
              <div className="panel-title">
                <h3>
                  <ShieldCheck size={15} style={{ verticalAlign: 'middle', marginRight: 6, color: 'hsl(var(--accent))' }} />
                  ARGUS Defensible Evidence Model
                </h3>
              </div>
              <p style={{ fontSize: 12, lineHeight: 1.6, color: 'hsl(var(--foreground))', marginTop: 10 }}>
                In forensic incident response, establishing whether sensitive corporate assets left the boundary requires
                <strong> distinguishing verifiable host observations from external traffic inferences</strong>:
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 12 }}>
                <div
                  style={{
                    background: 'hsl(var(--accent) / 0.08)',
                    border: '1px solid hsl(var(--accent) / 0.25)',
                    padding: 10,
                    borderRadius: 6,
                  }}
                >
                  <div style={{ fontWeight: 700, fontSize: 11, color: 'hsl(var(--accent))' }}>
                    1. Observed Host Evidence (100% Proven)
                  </div>
                  <div className="muted" style={{ fontSize: 11, marginTop: 3 }}>
                    The host sensor proved that <code>powershell.exe</code> touched 3 confidential files and that <code>7z.exe</code> created <code>~stage_042.zip</code>.
                  </div>
                </div>

                <div
                  style={{
                    background: 'hsl(var(--chart-3) / 0.08)',
                    border: '1px solid hsl(var(--chart-3) / 0.25)',
                    padding: 10,
                    borderRadius: 6,
                  }}
                >
                  <div style={{ fontWeight: 700, fontSize: 11, color: 'hsl(var(--chart-3))' }}>
                    2. Inferred Transmission (Metadata Model)
                  </div>
                  <div className="muted" style={{ fontSize: 11, marginTop: 3 }}>
                    A network socket transferred 18.4 KB over TLS to <code>185.199.110.27</code>. Because TLS payload encryption was maintained, data contents are inferred from timing correlation, not verified plaintext.
                  </div>
                </div>

                <div
                  style={{
                    background: 'hsl(var(--muted))',
                    border: '1px solid hsl(var(--border))',
                    padding: 10,
                    borderRadius: 6,
                  }}
                >
                  <div style={{ fontWeight: 700, fontSize: 11, color: 'hsl(var(--muted-foreground))' }}>
                    3. Confirmed Exfiltration (Protected by Law)
                  </div>
                  <div className="muted" style={{ fontSize: 11, marginTop: 3 }}>
                    Unless the egress payload is recovered or the remote C2 server responds with receipt, regulatory filings should document &quot;potential exposure&quot; rather than &quot;confirmed data theft&quot;.
                  </div>
                </div>
              </div>
            </section>

            <section className="card card-pad">
              <div className="panel-title">
                <h3>
                  <Clock3 size={15} style={{ verticalAlign: 'middle', marginRight: 6 }} />
                  Exposure Timing Window
                </h3>
              </div>
              <div className="kpi-line" style={{ marginTop: 10 }}>
                <span className="muted">First Execution Staging</span>
                <b className="mono">09:37:14 UTC</b>
              </div>
              <div className="kpi-line">
                <span className="muted">Confidential Access Spike</span>
                <b className="mono">09:43:21 UTC</b>
              </div>
              <div className="kpi-line">
                <span className="muted">Egress Network Attempt</span>
                <b className="mono">09:44:26 UTC</b>
              </div>
              <div className="kpi-line">
                <span className="muted">Host Isolation / Containment</span>
                <b className="mono signal-good">09:47:11 UTC</b>
              </div>
              <div className="kpi-line">
                <span className="muted">Total Vulnerability Window</span>
                <b className="mono signal-warn">9 min 57 sec</b>
              </div>
            </section>
          </div>
        </div>
      )}

      {/* Tab 2: Blast Radius & Asset Impact */}
      {activeTab === 'blastradius' && (
        <div className="grid" style={{ gridTemplateColumns: 'repeat(2, 1fr)', gap: 16 }}>
          {blastRadiusAssets.map((asset) => {
            const Icon = asset.icon;
            return (
              <section key={asset.name} className="card card-pad" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <div
                      style={{
                        padding: 7,
                        borderRadius: 6,
                        background: 'hsl(var(--muted))',
                        color: 'hsl(var(--primary))',
                      }}
                    >
                      <Icon size={16} />
                    </div>
                    <div>
                      <div className="muted" style={{ fontSize: 10, textTransform: 'uppercase' }}>
                        {asset.type}
                      </div>
                      <div style={{ fontWeight: 700, fontSize: 13 }}>{asset.name}</div>
                    </div>
                  </div>

                  <span
                    className={cn(
                      'badge',
                      asset.severity === 'critical'
                        ? 'badge-critical'
                        : asset.severity === 'high'
                        ? 'badge-high'
                        : 'badge-low'
                    )}
                  >
                    {asset.severity.toUpperCase()}
                  </span>
                </div>

                <div
                  style={{
                    background: 'hsl(var(--muted))',
                    padding: '8px 12px',
                    borderRadius: 6,
                    fontSize: 11,
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 4,
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="muted">Entity / Owner:</span>
                    <span className="mono">{asset.owner}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="muted">Network / Scope:</span>
                    <span className="mono">{asset.ip}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="muted">Remediation Status:</span>
                    <span className="mono" style={{ color: 'hsl(var(--foreground))', fontWeight: 600 }}>
                      {asset.status}
                    </span>
                  </div>
                </div>
              </section>
            );
          })}
        </div>
      )}

      {/* Tab 3: Contributing Risk Factors */}
      {activeTab === 'riskfactors' && (
        <section className="card card-pad">
          <div className="panel-title">
            <h3>
              <Activity size={15} style={{ verticalAlign: 'middle', marginRight: 6 }} />
              Risk Score Decomposition & Weightings
            </h3>
            <span className="mono muted">COMPOSITE MULTI-SIGNAL MODEL</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 16, marginTop: 16 }}>
            {riskFactors.map((factor) => (
              <div key={factor.label}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 6 }}>
                  <span>
                    <strong>{factor.label}</strong>
                    <span className="muted" style={{ marginLeft: 8, fontSize: 11 }}>
                      ({factor.note})
                    </span>
                  </span>
                  <span className={`signal-${factor.tone}`} style={{ fontWeight: 700 }}>
                    {factor.value} ({factor.score}%)
                  </span>
                </div>
                <div className="progress" style={{ height: 8 }}>
                  <i
                    style={{
                      width: `${factor.score}%`,
                      background:
                        factor.tone === 'danger'
                          ? 'hsl(var(--destructive))'
                          : factor.tone === 'warn'
                          ? 'hsl(var(--chart-3))'
                          : 'hsl(var(--accent))',
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Tab 4: Incident Response Playbook */}
      {activeTab === 'playbook' && (
        <div className="grid" style={{ gridTemplateColumns: 'repeat(2, 1fr)', gap: 16 }}>
          <section className="card card-pad">
            <div className="panel-title">
              <h3>
                <Lock size={15} style={{ verticalAlign: 'middle', marginRight: 6 }} />
                Immediate Containment Controls
              </h3>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 12 }}>
              <div
                style={{
                  background: 'hsl(var(--muted))',
                  padding: 10,
                  borderRadius: 6,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                }}
              >
                <div>
                  <div style={{ fontWeight: 600, fontSize: 12 }}>Host Network Isolation</div>
                  <div className="muted" style={{ fontSize: 10 }}>Cut all outbound IP routing for WS-0427</div>
                </div>
                <button
                  type="button"
                  className={cn('btn', contained ? 'btn-primary' : 'btn-danger')}
                  style={{ fontSize: 10, padding: '3px 8px', height: 24 }}
                  onClick={() => {
                    if (onContain) onContain();
                    toast('Endpoint Isolated', 'Network containment applied to host WS-0427.');
                  }}
                >
                  {contained ? 'Isolated' : 'Isolate Now'}
                </button>
              </div>

              <div
                style={{
                  background: 'hsl(var(--muted))',
                  padding: 10,
                  borderRadius: 6,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                }}
              >
                <div>
                  <div style={{ fontWeight: 600, fontSize: 12 }}>Process Tree Termination</div>
                  <div className="muted" style={{ fontSize: 10 }}>Kill powershell.exe (PID 8420) & child trees</div>
                </div>
                {onNavigate && (
                  <button
                    type="button"
                    className="btn btn-ghost"
                    style={{ fontSize: 10, padding: '3px 8px', height: 24 }}
                    onClick={() => onNavigate('/processes')}
                  >
                    Go to Processes <ArrowRight size={10} style={{ marginLeft: 3 }} />
                  </button>
                )}
              </div>

              <div
                style={{
                  background: 'hsl(var(--muted))',
                  padding: 10,
                  borderRadius: 6,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                }}
              >
                <div>
                  <div style={{ fontWeight: 600, fontSize: 12 }}>Quarantine Staged Artifacts</div>
                  <div className="muted" style={{ fontSize: 10 }}>Isolate ~stage_042.zip and ps_8F2A.ps1</div>
                </div>
                {onNavigate && (
                  <button
                    type="button"
                    className="btn btn-ghost"
                    style={{ fontSize: 10, padding: '3px 8px', height: 24 }}
                    onClick={() => onNavigate('/quarantine')}
                  >
                    Vault Inventory <ArrowRight size={10} style={{ marginLeft: 3 }} />
                  </button>
                )}
              </div>
            </div>
          </section>

          <section className="card card-pad">
            <div className="panel-title">
              <h3>
                <UserCheck size={15} style={{ verticalAlign: 'middle', marginRight: 6 }} />
                Identity & Lateral Safeguards
              </h3>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 12 }}>
              <div
                style={{
                  background: 'hsl(var(--muted))',
                  padding: 10,
                  borderRadius: 6,
                }}
              >
                <div style={{ fontWeight: 600, fontSize: 12 }}>Active Directory Ticket Invalidation</div>
                <p className="muted" style={{ fontSize: 11, margin: '4px 0 0' }}>
                  Force immediate Kerberos TGT invalidation and reset CORP\mira.alvarez password to prevent lateral authentication.
                </p>
              </div>

              <div
                style={{
                  background: 'hsl(var(--muted))',
                  padding: 10,
                  borderRadius: 6,
                }}
              >
                <div style={{ fontWeight: 600, fontSize: 12 }}>Perimeter Egress Blocklist</div>
                <p className="muted" style={{ fontSize: 11, margin: '4px 0 0' }}>
                  Publish firewall drop rules for C2 endpoints: <code>185.199.110.27</code> and <code>cdn-sync-check[.]com</code> across all egress gateways.
                </p>
              </div>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
