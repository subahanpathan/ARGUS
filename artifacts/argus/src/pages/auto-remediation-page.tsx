import React, { useState, useMemo } from 'react';
import {
  Zap,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  Archive,
  Clock3,
  Send,
  Download,
  Copy,
  Check,
  Filter,
  Search,
  RefreshCw,
  AlertTriangle,
  Play,
  SlidersHorizontal,
  CheckCircle2,
  FileText,
  Lock,
  ExternalLink,
  ChevronRight,
  Flame,
  Radio,
  Eye
} from 'lucide-react';
import { useRemediationLedger, type RemediationAuditRecord } from '@/hooks/use-remediation-ledger';
import type { Threat } from '@/pages/threats-page';

interface AutoRemediationPageProps {
  threats?: Threat[];
  toast?: (title: string, body: string) => void;
  onNavigate?: (path: string) => void;
  telemetry?: any;
  processMonitor?: any;
  networkMonitor?: any;
  fileScan?: any;
}

export default function AutoRemediationPage({
  threats = [],
  toast,
  onNavigate,
  telemetry,
  processMonitor,
  networkMonitor,
  fileScan,
}: AutoRemediationPageProps) {
  // We explicitly disable floating toast popups here so the section is dedicated and quiet!
  const {
    remediations,
    policy,
    setPolicy,
    stats,
    remediateThreat,
    clearLedger,
  } = useRemediationLedger({ toast, showToasts: false });

  const [activeTab, setActiveTab] = useState<'stream' | 'ledger' | 'cybercell'>('stream');
  const [searchQuery, setSearchQuery] = useState('');
  const [filterAction, setFilterAction] = useState<'all' | 'purged' | 'quarantined' | 'sensitive'>('all');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [isSimulating, setIsSimulating] = useState(false);

  // Copy hash to clipboard
  const handleCopyHash = (hash: string) => {
    navigator.clipboard?.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  // Filtered records
  const filteredRecords = useMemo(() => {
    return remediations.filter((rec) => {
      const q = searchQuery.toLowerCase();
      const matchSearch =
        rec.name.toLowerCase().includes(q) ||
        rec.path.toLowerCase().includes(q) ||
        rec.process.toLowerCase().includes(q) ||
        (rec.ruleName || '').toLowerCase().includes(q) ||
        (rec.cyberCellCaseId && rec.cyberCellCaseId.toLowerCase().includes(q));

      if (!matchSearch) return false;

      if (filterAction === 'purged') return rec.actionTaken === 'AUTOMATED_PURGE_DELETED';
      if (filterAction === 'quarantined') return rec.actionTaken === 'AUTOMATED_QUARANTINE';
      if (filterAction === 'sensitive') return rec.isSensitiveData;
      return true;
    });
  }, [remediations, searchQuery, filterAction]);

  // Export JSON
  const handleExportJSON = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(remediations, null, 2));
    const a = document.createElement('a');
    a.setAttribute('href', dataStr);
    a.setAttribute('download', `ARGUS-AutoRemediation-Ledger-${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  // Export CSV
  const handleExportCSV = () => {
    const headers = [
      'Record ID',
      'Threat Name',
      'Process',
      'Target Path',
      'Action Taken',
      'Severity',
      'Detection Time',
      'Remediation Time',
      'Dwell Interval (ms)',
      'SHA-256',
      'Sensitive Data',
      'Cyber Cell Case ID',
      'Status',
    ];
    const rows = remediations.map((r) => [
      r.id,
      `"${r.name.replace(/"/g, '""')}"`,
      `"${r.process.replace(/"/g, '""')}"`,
      `"${r.path.replace(/"/g, '""')}"`,
      r.actionTaken,
      r.severity,
      r.detectedAt,
      r.remediatedAt,
      r.timeIntervalMs,
      r.hash,
      r.isSensitiveData ? 'YES' : 'NO',
      r.cyberCellCaseId || 'N/A',
      `"${r.status.replace(/"/g, '""')}"`,
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((e) => e.join(','))].join('\n');
    const a = document.createElement('a');
    a.setAttribute('href', encodeURI(csvContent));
    a.setAttribute('download', `ARGUS-AutoRemediation-Ledger-${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  // Trigger test attack & neutralization
  const handleSimulateAttack = () => {
    setIsSimulating(true);
    setTimeout(() => {
      const isCritical = Math.random() > 0.4;
      const isSensitive = Math.random() > 0.5;
      const mockThreat: Threat = {
        id: `sim-threat-${Date.now()}`,
        name: isSensitive ? 'lsass_dump_memory.dmp' : (isCritical ? 'trojan.dropper.win64.exe' : 'cobalt_beacon.dll'),
        title: isSensitive ? 'LSASS Memory Dumping Credential Access' : (isCritical ? 'Unsigned Dropper Payload Executable' : 'C2 Memory Injection Module'),
        severity: isCritical ? 'critical' : 'high',
        process: isSensitive ? 'procdump.exe' : (isCritical ? 'powershell.exe' : 'rundll32.exe'),
        path: isSensitive ? 'C:\\Windows\\Temp\\lsass_dump_memory.dmp' : 'C:\\Users\\Public\\Downloads\\trojan.dropper.win64.exe',
        timestamp: new Date(Date.now() - Math.floor(45 + Math.random() * 95)).toISOString(),
        hash: Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
        reason: isSensitive ? 'Automated detection: Unauthorized credential extraction from security subsystem memory' : 'Malicious binary signature match against heuristic database',
        rule_name: isSensitive ? 'MITRE T1003.001 - OS Credential Dumping' : 'MITRE T1059 - Command and Scripting Interpreter',
        rule_id: isSensitive ? 'CRED-001' : 'EXEC-009',
        className: isSensitive ? 'Credential Access' : 'Command & Control',
        status: 'detected',
      };

      remediateThreat(mockThreat);
      setIsSimulating(false);
    }, 450);
  };

  return (
    <div className="page-container animate-fade-in" style={{ padding: '24px 32px', maxWidth: 1400, margin: '0 auto' }}>
      {/* Top Breadcrumb & Heading */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20, flexWrap: 'wrap', gap: 16 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
            <span className="badge badge-low" style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 10, padding: '3px 8px' }}>
              <Zap size={11} className="signal-accent" />
              AUTONOMOUS CONTAINMENT ENGINE
            </span>
            <span className="mono muted" style={{ fontSize: 11 }}>
              {policy.enabled ? 'ACTIVE ENFORCEMENT' : 'STANDBY MODE'}
            </span>
          </div>
          <h1 style={{ fontSize: 24, fontWeight: 800, margin: '0 0 6px 0', letterSpacing: '-0.02em', display: 'flex', alignItems: 'center', gap: 10 }}>
            Automated Threat Remediation & Audit Ledger
          </h1>
          <p className="muted" style={{ margin: 0, fontSize: 13, maxWidth: 840 }}>
            Dedicated operations feed and cryptographic audit trail for threats automatically deleted or quarantined based on threat level, including dwell time interval telemetry and referral of sensitive records to the Cyber Cell.
          </p>
        </div>

        {/* Global Action Buttons */}
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={handleSimulateAttack}
            disabled={isSimulating}
            style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, padding: '8px 14px' }}
          >
            <Play size={13} className={isSimulating ? 'animate-spin' : ''} />
            {isSimulating ? 'Neutralizing...' : 'Simulate Threat & Auto-Remediate'}
          </button>

          <button
            type="button"
            className="btn btn-ghost"
            style={{ border: '1px solid hsl(var(--border))', fontSize: 12, padding: '8px 14px' }}
            onClick={handleExportCSV}
            title="Download CSV report"
          >
            <Download size={13} />
            Export CSV
          </button>

          <button
            type="button"
            className="btn btn-ghost"
            style={{ border: '1px solid hsl(var(--border))', fontSize: 12, padding: '8px 14px' }}
            onClick={handleExportJSON}
            title="Download JSON ledger"
          >
            <FileText size={13} />
            Export JSON
          </button>
        </div>
      </div>

      {/* Policy Control Banner */}
      <div
        className="card card-pad"
        style={{
          background: 'linear-gradient(135deg, hsl(var(--card)) 0%, hsl(var(--card)/0.9) 100%)',
          border: '1px solid hsl(var(--border))',
          borderRadius: 8,
          marginBottom: 20,
          boxShadow: '0 4px 20px rgba(0,0,0,0.15)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 14, marginBottom: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div
              style={{
                width: 32,
                height: 32,
                borderRadius: '50%',
                background: policy.enabled ? 'hsl(142 70% 15%)' : 'hsl(0 70% 15%)',
                color: policy.enabled ? 'hsl(142 70% 50%)' : 'hsl(0 70% 50%)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Zap size={16} />
            </div>
            <div>
              <div style={{ fontSize: 14, fontWeight: 700 }}>Autonomous Policy Directives</div>
              <div className="muted" style={{ fontSize: 11 }}>
                Policy engine executes zero-latency containment immediately upon detection signal ingestion
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span className="mono muted" style={{ fontSize: 11 }}>Master Switch:</span>
            <button
              type="button"
              className={policy.enabled ? 'btn btn-primary' : 'btn btn-ghost'}
              style={{ fontSize: 11, padding: '4px 12px' }}
              onClick={() => setPolicy((p) => ({ ...p, enabled: !p.enabled }))}
            >
              {policy.enabled ? 'AUTONOMOUS ENGINE ENGAGED' : 'ENGINE PAUSED'}
            </button>
          </div>
        </div>

        {/* Policy Checkboxes */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: 12,
            paddingTop: 12,
            borderTop: '1px solid hsl(var(--border))',
          }}
        >
          <label style={{ display: 'flex', alignItems: 'flex-start', gap: 8, cursor: 'pointer', fontSize: 12 }}>
            <input
              type="checkbox"
              checked={policy.autoDeleteCritical}
              onChange={(e) => setPolicy((p) => ({ ...p, autoDeleteCritical: e.target.checked }))}
              style={{ marginTop: 2 }}
            />
            <div>
              <div style={{ fontWeight: 600, color: 'hsl(var(--destructive))' }}>
                Auto-Purge & Delete Critical Threats
              </div>
              <div className="muted" style={{ fontSize: 11 }}>
                Immediately unlinks and permanently deletes files and kills processes with critical score.
              </div>
            </div>
          </label>

          <label style={{ display: 'flex', alignItems: 'flex-start', gap: 8, cursor: 'pointer', fontSize: 12 }}>
            <input
              type="checkbox"
              checked={policy.autoQuarantineHigh}
              onChange={(e) => setPolicy((p) => ({ ...p, autoQuarantineHigh: e.target.checked }))}
              style={{ marginTop: 2 }}
            />
            <div>
              <div style={{ fontWeight: 600, color: 'hsl(38 92% 50%)' }}>
                Auto-Quarantine High Severity Threats
              </div>
              <div className="muted" style={{ fontSize: 11 }}>
                Isolates files into the AES-256 encrypted quarantine vault with execution permission revoked.
              </div>
            </div>
          </label>

          <label style={{ display: 'flex', alignItems: 'flex-start', gap: 8, cursor: 'pointer', fontSize: 12 }}>
            <input
              type="checkbox"
              checked={policy.autoDirectSensitiveToCyberCell}
              onChange={(e) => setPolicy((p) => ({ ...p, autoDirectSensitiveToCyberCell: e.target.checked }))}
              style={{ marginTop: 2 }}
            />
            <div>
              <div style={{ fontWeight: 600, color: 'hsl(280 85% 70%)' }}>
                Escalate Sensitive Data to Cyber Cell
              </div>
              <div className="muted" style={{ fontSize: 11 }}>
                Generates certified referral dossier for LSASS, credentials, and ransomware tampering.
              </div>
            </div>
          </label>
        </div>
      </div>

      {/* KPI Metrics Strip */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: 14,
          marginBottom: 24,
        }}
      >
        <div className="card card-pad" style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{ width: 40, height: 40, borderRadius: 8, background: 'hsl(var(--muted))', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <ShieldAlert size={20} className="signal-accent" />
          </div>
          <div>
            <div className="muted" style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Total Remediations</div>
            <div style={{ fontSize: 22, fontWeight: 800, fontFamily: 'var(--app-font-mono)' }}>{stats.total}</div>
            <div className="muted" style={{ fontSize: 10 }}>Autonomous interventions</div>
          </div>
        </div>

        <div className="card card-pad" style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{ width: 40, height: 40, borderRadius: 8, background: 'hsl(0 80% 15%)', color: 'hsl(0 80% 65%)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Trash2 size={20} />
          </div>
          <div>
            <div className="muted" style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Purged & Deleted</div>
            <div style={{ fontSize: 22, fontWeight: 800, fontFamily: 'var(--app-font-mono)', color: 'hsl(var(--destructive))' }}>{stats.purged}</div>
            <div className="muted" style={{ fontSize: 10 }}>Critical files unlinked</div>
          </div>
        </div>

        <div className="card card-pad" style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{ width: 40, height: 40, borderRadius: 8, background: 'hsl(38 90% 15%)', color: 'hsl(38 90% 65%)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Archive size={20} />
          </div>
          <div>
            <div className="muted" style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Quarantined Files</div>
            <div style={{ fontSize: 22, fontWeight: 800, fontFamily: 'var(--app-font-mono)', color: 'hsl(38 92% 50%)' }}>{stats.quarantined}</div>
            <div className="muted" style={{ fontSize: 10 }}>Vault encrypted isolation</div>
          </div>
        </div>

        <div className="card card-pad" style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{ width: 40, height: 40, borderRadius: 8, background: 'hsl(210 80% 15%)', color: 'hsl(210 80% 65%)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Clock3 size={20} />
          </div>
          <div>
            <div className="muted" style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Avg. Dwell Interval</div>
            <div style={{ fontSize: 22, fontWeight: 800, fontFamily: 'var(--app-font-mono)', color: 'hsl(210 90% 65%)' }}>{stats.avgIntervalFormatted}</div>
            <div className="muted" style={{ fontSize: 10 }}>Detection to neutralization</div>
          </div>
        </div>

        <div className="card card-pad" style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{ width: 40, height: 40, borderRadius: 8, background: 'hsl(280 80% 15%)', color: 'hsl(280 85% 75%)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Send size={20} />
          </div>
          <div>
            <div className="muted" style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Directed to Cyber Cell</div>
            <div style={{ fontSize: 22, fontWeight: 800, fontFamily: 'var(--app-font-mono)', color: 'hsl(280 85% 75%)' }}>{stats.sensitive}</div>
            <div className="muted" style={{ fontSize: 10 }}>Escalated cases</div>
          </div>
        </div>
      </div>

      {/* Main Tabs Navigation */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid hsl(var(--border))', marginBottom: 20, flexWrap: 'wrap', gap: 12 }}>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            type="button"
            className={activeTab === 'stream' ? 'btn btn-primary' : 'btn btn-ghost'}
            style={{ borderRadius: '6px 6px 0 0', display: 'flex', alignItems: 'center', gap: 8, padding: '10px 18px', fontSize: 13 }}
            onClick={() => setActiveTab('stream')}
          >
            <Zap size={14} />
            Live Remediation Stream
            <span className="badge badge-low mono" style={{ fontSize: 10 }}>{filteredRecords.length}</span>
          </button>

          <button
            type="button"
            className={activeTab === 'ledger' ? 'btn btn-primary' : 'btn btn-ghost'}
            style={{ borderRadius: '6px 6px 0 0', display: 'flex', alignItems: 'center', gap: 8, padding: '10px 18px', fontSize: 13 }}
            onClick={() => setActiveTab('ledger')}
          >
            <FileText size={14} />
            Cryptographic Audit Ledger
            <span className="badge badge-muted mono" style={{ fontSize: 10 }}>{remediations.length}</span>
          </button>

          <button
            type="button"
            className={activeTab === 'cybercell' ? 'btn btn-primary' : 'btn btn-ghost'}
            style={{ borderRadius: '6px 6px 0 0', display: 'flex', alignItems: 'center', gap: 8, padding: '10px 18px', fontSize: 13 }}
            onClick={() => setActiveTab('cybercell')}
          >
            <Send size={14} />
            Cyber Cell Escalations
            <span className="badge" style={{ background: 'hsl(280 80% 20%)', color: 'hsl(280 85% 75%)', fontSize: 10 }}>{stats.sensitive}</span>
          </button>
        </div>

        {/* Quick Search & Filters */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, paddingBottom: 6 }}>
          <div style={{ position: 'relative', width: 240 }}>
            <Search size={13} style={{ position: 'absolute', left: 10, top: 10, color: 'hsl(var(--muted-foreground))' }} />
            <input
              type="text"
              className="form-input"
              style={{ width: '100%', paddingLeft: 30, fontSize: 12, padding: '6px 10px 6px 30px', borderRadius: 4, background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', color: 'hsl(var(--foreground))' }}
              placeholder="Search remediations..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <select
            className="form-input"
            style={{ fontSize: 12, padding: '6px 10px', borderRadius: 4, background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', color: 'hsl(var(--foreground))' }}
            value={filterAction}
            onChange={(e) => setFilterAction(e.target.value as any)}
          >
            <option value="all">All Actions</option>
            <option value="purged">Purged / Deleted</option>
            <option value="quarantined">Quarantined</option>
            <option value="sensitive">Sensitive / Cyber Cell</option>
          </select>
        </div>
      </div>

      {/* TAB 1: LIVE REMEDIATION STREAM (Dedicated separate section for the event cards) */}
      {activeTab === 'stream' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {filteredRecords.length === 0 ? (
            <div className="card card-pad" style={{ textAlign: 'center', padding: 48 }}>
              <ShieldCheck size={48} className="signal-good" style={{ margin: '0 auto 16px auto' }} />
              <h3 style={{ fontSize: 16, fontWeight: 700, margin: '0 0 6px 0' }}>No Remediation Events Match Filter</h3>
              <p className="muted" style={{ fontSize: 13, margin: '0 0 16px 0' }}>
                All observed host threats have been addressed or no active records meet the current search query.
              </p>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={handleSimulateAttack}
              >
                <Play size={13} />
                Simulate Threat & Auto-Remediate
              </button>
            </div>
          ) : (
            filteredRecords.map((item) => (
              <div
                key={item.id}
                className="card card-pad"
                style={{
                  borderLeft: item.actionTaken === 'AUTOMATED_PURGE_DELETED'
                    ? '4px solid hsl(var(--destructive))'
                    : '4px solid hsl(38 92% 50%)',
                  background: 'hsl(var(--card))',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 12,
                  transition: 'all 0.2s ease',
                }}
              >
                {/* Event Card Header */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 10 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                    <span
                      style={{
                        padding: '3px 8px',
                        borderRadius: 4,
                        fontSize: 10,
                        fontWeight: 700,
                        fontFamily: 'var(--app-font-mono)',
                        background: item.actionTaken === 'AUTOMATED_PURGE_DELETED' ? 'hsl(0 80% 15%)' : 'hsl(38 90% 15%)',
                        color: item.actionTaken === 'AUTOMATED_PURGE_DELETED' ? 'hsl(0 80% 75%)' : 'hsl(38 90% 75%)',
                        border: item.actionTaken === 'AUTOMATED_PURGE_DELETED' ? '1px solid hsl(0 80% 30%)' : '1px solid hsl(38 90% 30%)',
                      }}
                    >
                      {item.actionTaken === 'AUTOMATED_PURGE_DELETED' ? '⚡ AUTOMATED PURGE DELETED' : '🔒 AUTOMATED QUARANTINE'}
                    </span>

                    <span
                      className="badge mono"
                      style={{
                        fontSize: 11,
                        background: 'hsl(var(--muted))',
                        color: 'hsl(var(--accent))',
                        fontWeight: 700,
                      }}
                    >
                      ⚡ {item.timeIntervalFormatted} dwell interval
                    </span>

                    <span
                      className="badge mono"
                      style={{
                        fontSize: 10,
                        background: item.severity === 'critical' ? 'hsl(0 80% 15%)' : 'hsl(38 90% 15%)',
                        color: item.severity === 'critical' ? 'hsl(0 80% 75%)' : 'hsl(38 90% 75%)',
                      }}
                    >
                      {item.severity.toUpperCase()} SEVERITY
                    </span>

                    {item.isSensitiveData && (
                      <span
                        className="badge"
                        style={{
                          fontSize: 10,
                          background: 'hsl(280 80% 15%)',
                          color: 'hsl(280 85% 75%)',
                          border: '1px solid hsl(280 80% 35%)',
                          display: 'flex',
                          alignItems: 'center',
                          gap: 4,
                        }}
                      >
                        <Send size={10} />
                        DIRECTED TO CYBER CELL ({item.cyberCellCaseId})
                      </span>
                    )}
                  </div>

                  <div className="mono muted" style={{ fontSize: 11 }}>
                    {new Date(item.remediatedAt).toLocaleTimeString()} · {new Date(item.remediatedAt).toLocaleDateString()}
                  </div>
                </div>

                {/* Event Card Body */}
                <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 2fr) minmax(0, 1fr)', gap: 16 }}>
                  <div>
                    <div style={{ fontSize: 15, fontWeight: 700, marginBottom: 4 }}>{item.name}</div>
                    <div className="mono muted" style={{ fontSize: 11, wordBreak: 'break-all', marginBottom: 8 }}>
                      Target: {item.path}
                    </div>
                    <div style={{ fontSize: 12, color: 'hsl(var(--foreground)/0.85)', lineHeight: 1.4 }}>
                      {item.details}
                    </div>
                  </div>

                  <div style={{ background: 'hsl(var(--background))', padding: '10px 14px', borderRadius: 6, border: '1px solid hsl(var(--border))', fontSize: 11 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                      <span className="muted">Process:</span>
                      <span className="mono" style={{ fontWeight: 600 }}>{item.process}</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                      <span className="muted">Rule:</span>
                      <span className="mono" style={{ fontWeight: 600 }}>{item.ruleId}</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                      <span className="muted">Detected:</span>
                      <span className="mono">{new Date(item.detectedAt).toLocaleTimeString()}</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span className="muted">Remediated:</span>
                      <span className="mono">{new Date(item.remediatedAt).toLocaleTimeString()}</span>
                    </div>
                  </div>
                </div>

                {/* Event Card Footer: Hash & Cyber Cell Link */}
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    paddingTop: 10,
                    borderTop: '1px solid hsl(var(--border))',
                    flexWrap: 'wrap',
                    gap: 10,
                    fontSize: 11,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span className="muted">SHA-256 Seal:</span>
                    <span className="mono muted" style={{ fontSize: 10 }}>
                      {item.hash.slice(0, 16)}…{item.hash.slice(-16)}
                    </span>
                    <button
                      type="button"
                      className="btn btn-ghost"
                      style={{ padding: '2px 6px', fontSize: 10 }}
                      onClick={() => handleCopyHash(item.hash)}
                    >
                      {copiedHash === item.hash ? <Check size={11} className="signal-good" /> : <Copy size={11} />}
                      {copiedHash === item.hash ? 'Copied' : 'Copy'}
                    </button>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    {item.isSensitiveData && onNavigate && (
                      <button
                        type="button"
                        className="btn btn-primary"
                        style={{
                          fontSize: 11,
                          padding: '4px 10px',
                          background: 'hsl(280 80% 40%)',
                          borderColor: 'hsl(280 80% 50%)',
                        }}
                        onClick={() => onNavigate('/cyber-cell')}
                      >
                        <Send size={11} />
                        View Cyber Cell Case {item.cyberCellCaseId}
                      </button>
                    )}

                    <span className="badge badge-low" style={{ fontSize: 9 }}>
                      ✓ {item.status}
                    </span>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* TAB 2: CRYPTOGRAPHIC AUDIT LEDGER TABLE */}
      {activeTab === 'ledger' && (
        <div className="card" style={{ overflow: 'hidden' }}>
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ background: 'hsl(var(--muted))', textAlign: 'left', borderBottom: '1px solid hsl(var(--border))' }}>
                  <th style={{ padding: '10px 14px' }}>Record ID</th>
                  <th style={{ padding: '10px 14px' }}>Target Artifact</th>
                  <th style={{ padding: '10px 14px' }}>Action Taken</th>
                  <th style={{ padding: '10px 14px' }}>Severity</th>
                  <th style={{ padding: '10px 14px' }}>Dwell Interval</th>
                  <th style={{ padding: '10px 14px' }}>Detection / Remediation</th>
                  <th style={{ padding: '10px 14px' }}>SHA-256 Verification</th>
                  <th style={{ padding: '10px 14px' }}>Cyber Cell Case</th>
                </tr>
              </thead>
              <tbody>
                {filteredRecords.map((row) => (
                  <tr key={row.id} style={{ borderBottom: '1px solid hsl(var(--border))' }}>
                    <td style={{ padding: '10px 14px' }}>
                      <span className="mono" style={{ fontSize: 11, fontWeight: 600 }}>{row.id}</span>
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      <div style={{ fontWeight: 600 }}>{row.name}</div>
                      <div className="mono muted" style={{ fontSize: 10, maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {row.path}
                      </div>
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      <span
                        style={{
                          fontSize: 10,
                          fontWeight: 700,
                          fontFamily: 'var(--app-font-mono)',
                          padding: '3px 8px',
                          borderRadius: 4,
                          background: row.actionTaken === 'AUTOMATED_PURGE_DELETED' ? 'hsl(0 80% 15%)' : 'hsl(38 90% 15%)',
                          color: row.actionTaken === 'AUTOMATED_PURGE_DELETED' ? 'hsl(0 80% 75%)' : 'hsl(38 90% 75%)',
                        }}
                      >
                        {row.actionTaken === 'AUTOMATED_PURGE_DELETED' ? 'PURGED' : 'QUARANTINE'}
                      </span>
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      <span className={row.severity === 'critical' ? 'badge badge-high' : 'badge badge-mid'} style={{ fontSize: 10 }}>
                        {row.severity.toUpperCase()}
                      </span>
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      <span className="badge badge-low mono" style={{ fontSize: 10, fontWeight: 700 }}>
                        ⚡ {row.timeIntervalFormatted}
                      </span>
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      <div className="mono" style={{ fontSize: 10 }}>Det: {new Date(row.detectedAt).toLocaleTimeString()}</div>
                      <div className="mono muted" style={{ fontSize: 10 }}>Rem: {new Date(row.remediatedAt).toLocaleTimeString()}</div>
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span className="mono muted" style={{ fontSize: 10 }}>
                          {row.hash.slice(0, 8)}…{row.hash.slice(-6)}
                        </span>
                        <button
                          type="button"
                          className="btn btn-ghost"
                          style={{ padding: 2 }}
                          onClick={() => handleCopyHash(row.hash)}
                          title="Copy SHA-256 Hash"
                        >
                          {copiedHash === row.hash ? <Check size={11} className="signal-good" /> : <Copy size={11} />}
                        </button>
                      </div>
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      {row.isSensitiveData && row.cyberCellCaseId ? (
                        <span
                          className="badge"
                          style={{
                            fontSize: 10,
                            background: 'hsl(280 80% 20%)',
                            color: 'hsl(280 85% 75%)',
                            fontFamily: 'var(--app-font-mono)',
                          }}
                        >
                          {row.cyberCellCaseId}
                        </span>
                      ) : (
                        <span className="mono muted" style={{ fontSize: 10 }}>—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 3: SENSITIVE INCIDENTS DIRECTED TO CYBER CELL */}
      {activeTab === 'cybercell' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div
            className="card card-pad"
            style={{
              background: 'linear-gradient(135deg, hsl(280 40% 12%) 0%, hsl(var(--card)) 100%)',
              border: '1px solid hsl(280 60% 30%)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: 14,
            }}
          >
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <Send size={16} style={{ color: 'hsl(280 85% 75%)' }} />
                <h3 style={{ fontSize: 15, fontWeight: 700, margin: 0, color: 'hsl(280 85% 85%)' }}>
                  Law Enforcement & CERT-In Referral Registry
                </h3>
              </div>
              <p className="muted" style={{ margin: 0, fontSize: 12 }}>
                Threats involving confidential credential extraction (LSASS), shadow copy purging (ransomware preparation), or sensitive corporate documents are sequestered and packaged into signed dossiers.
              </p>
            </div>

            {onNavigate && (
              <button
                type="button"
                className="btn btn-primary"
                style={{
                  background: 'hsl(280 80% 40%)',
                  borderColor: 'hsl(280 80% 50%)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  fontSize: 12,
                }}
                onClick={() => onNavigate('/cyber-cell')}
              >
                <Send size={13} />
                Open Cyber Cell Escalation Portal
              </button>
            )}
          </div>

          {remediations.filter((r) => r.isSensitiveData).length === 0 ? (
            <div className="card card-pad" style={{ textAlign: 'center', padding: 40 }}>
              <CheckCircle2 size={40} className="signal-good" style={{ margin: '0 auto 12px auto' }} />
              <div style={{ fontSize: 14, fontWeight: 700 }}>No Sensitive Breaches Detected</div>
              <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                No active threats have touched credential vaults or sensitive system directories.
              </div>
            </div>
          ) : (
            remediations
              .filter((r) => r.isSensitiveData)
              .map((rec) => (
                <div
                  key={rec.id}
                  className="card card-pad"
                  style={{
                    border: '1px solid hsl(280 50% 25%)',
                    background: 'hsl(var(--card))',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 12,
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span className="mono" style={{ fontWeight: 800, color: 'hsl(280 85% 75%)', fontSize: 14 }}>
                        {rec.cyberCellCaseId}
                      </span>
                      <span className="badge badge-high" style={{ fontSize: 10 }}>
                        {rec.severity.toUpperCase()} SEVERITY
                      </span>
                      <span className="badge badge-low mono" style={{ fontSize: 10 }}>
                        ⚡ {rec.timeIntervalFormatted} dwell
                      </span>
                    </div>

                    <div className="mono muted" style={{ fontSize: 11 }}>
                      Remediated: {new Date(rec.remediatedAt).toLocaleString()}
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.6fr) minmax(0, 1.4fr)', gap: 16 }}>
                    <div>
                      <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 4 }}>{rec.name}</div>
                      <div className="mono muted" style={{ fontSize: 11, marginBottom: 6 }}>{rec.path}</div>
                      <div style={{ fontSize: 12, color: 'hsl(var(--foreground)/0.85)' }}>{rec.details}</div>
                    </div>

                    <div style={{ background: 'hsl(var(--background))', padding: '10px 14px', borderRadius: 6, border: '1px solid hsl(var(--border))', fontSize: 11 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                        <span className="muted">Category:</span>
                        <span style={{ fontWeight: 600, color: 'hsl(280 85% 75%)' }}>{rec.sensitiveCategory}</span>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                        <span className="muted">Remediation Status:</span>
                        <span className="mono" style={{ color: 'hsl(var(--destructive))', fontWeight: 600 }}>{rec.status}</span>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                        <span className="muted">Cryptographic Seal:</span>
                        <span className="mono muted">{rec.hash.slice(0, 10)}…{rec.hash.slice(-8)}</span>
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: 8, borderTop: '1px solid hsl(var(--border))' }}>
                    <span className="muted" style={{ fontSize: 11 }}>
                      Forensic artifacts archived and sealed in the evidence vault.
                    </span>

                    {onNavigate && (
                      <button
                        type="button"
                        className="btn btn-primary"
                        style={{
                          fontSize: 11,
                          padding: '4px 12px',
                          background: 'hsl(280 80% 40%)',
                          borderColor: 'hsl(280 80% 50%)',
                        }}
                        onClick={() => onNavigate('/cyber-cell')}
                      >
                        <Send size={11} />
                        Transmit Brief to Cyber Cell
                      </button>
                    )}
                  </div>
                </div>
              ))
          )}
        </div>
      )}
    </div>
  );
}
