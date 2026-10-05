import React, { useState, useMemo } from 'react';
import {
  History,
  FileText,
  Download,
  Trash2,
  Eye,
  Plus,
  Search,
  Filter,
  Shield,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  Clock,
  User,
  Radio,
  X,
  FileCode,
  Copy,
  Printer,
  Archive,
  ExternalLink,
  Layers,
  Database
} from 'lucide-react';
import type { ReportRecord } from '@/hooks/use-reports';

interface HistoryPageProps {
  reports: ReportRecord[];
  onDeleteReport: (id: string) => Promise<boolean>;
  toast: (title: string, body: string) => void;
  onNavigate: (path: string) => void;
  vaultPath?: string | null;
}

function shortHash(hash: string): string {
  if (!hash || hash === '—') return '—';
  if (hash.length <= 16) return hash;
  return `${hash.slice(0, 8)}...${hash.slice(-8)}`;
}

function downloadTextFile(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export default function HistoryPage({
  reports,
  onDeleteReport,
  toast,
  onNavigate,
  vaultPath,
}: HistoryPageProps) {
  // Search & Filter
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'Ready' | 'Shared' | 'Archived'>('all');
  const [formatFilter, setFormatFilter] = useState<'all' | 'PDF' | 'JSON' | 'TXT'>('all');

  // Modal inspection
  const [inspectReport, setInspectReport] = useState<ReportRecord | null>(null);

  // Delete modal state
  const [deleteTarget, setDeleteTarget] = useState<ReportRecord | null>(null);

  // Filtered reports
  const filteredReports = useMemo(() => {
    return (reports || []).filter((r) => {
      const q = (query || '').toLowerCase().trim();
      const matchQuery =
        !q ||
        (r.title || '').toLowerCase().includes(q) ||
        (r.incidentId || '').toLowerCase().includes(q) ||
        (r.author || '').toLowerCase().includes(q) ||
        (r.id || '').toLowerCase().includes(q);

      const matchStatus = statusFilter === 'all' || r.status === statusFilter;
      const matchFormat = formatFilter === 'all' || r.format === formatFilter;

      return matchQuery && matchStatus && matchFormat;
    });
  }, [reports, query, statusFilter, formatFilter]);

  // KPI Calculations
  const stats = useMemo(() => {
    const total = (reports || []).length;
    const critical = (reports || []).filter((r) => r.riskScore >= 70).length;
    const pdfCount = (reports || []).filter((r) => r.format === 'PDF').length;
    const jsonCount = (reports || []).filter((r) => r.format === 'JSON').length;
    return { total, critical, pdfCount, jsonCount };
  }, [reports]);

  // Export full history CSV
  const exportHistoryCSV = () => {
    const headers = ['Report ID', 'Incident ID', 'Title', 'Author', 'Created At', 'Status', 'Format', 'Risk Score', 'Audience'];
    const rows = filteredReports.map((r) => [
      `"${r.id}"`,
      `"${r.incidentId}"`,
      `"${r.title.replace(/"/g, '""')}"`,
      `"${r.author}"`,
      `"${r.createdAt}"`,
      `"${r.status}"`,
      `"${r.format}"`,
      `"${r.riskScore}"`,
      `"${r.audience}"`,
    ]);
    const csv = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    downloadTextFile('ARGUS_Report_Archive_Index.csv', csv, 'text/csv');
    toast('Archive Exported', 'Downloaded ARGUS_Report_Archive_Index.csv');
  };

  // Re-download a specific report
  const handleDownloadReport = (r: ReportRecord) => {
    const filename = `${r.id}_${r.incidentId}.${r.format.toLowerCase()}`;
    const content = r.content || JSON.stringify(r, null, 2);
    const mime = r.format === 'JSON' ? 'application/json' : 'text/plain';
    downloadTextFile(filename, content, mime);
    toast('Download Started', `Downloaded ${filename}`);
  };

  // Delete handler
  const confirmDelete = async () => {
    if (!deleteTarget) return;
    const targetId = deleteTarget.id;
    try {
      await onDeleteReport(targetId);
      if (inspectReport?.id === targetId) setInspectReport(null);
      setDeleteTarget(null);
      toast('Report Purged', `Successfully removed ${targetId} from archive.`);
    } catch {
      toast('Delete Failed', `Could not delete ${targetId}.`);
    }
  };

  return (
    <div className="animate-rise" style={{ paddingBottom: 50 }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20, flexWrap: 'wrap', gap: 14 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'hsl(var(--primary))' }}>
              DECISION ARCHIVE · FORENSIC AUDIT TRAIL
            </span>
            <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 10, background: 'hsl(var(--primary)/0.15)', color: 'hsl(var(--primary))', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
              <Radio size={9} /> Persistent Vault
            </span>
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, letterSpacing: '-0.03em', margin: 0, color: 'hsl(var(--foreground))' }}>
            Report History & Archive
          </h1>
          <p style={{ fontSize: 13, color: 'hsl(var(--muted-foreground))', margin: '4px 0 0', maxWidth: 660, lineHeight: 1.5 }}>
            Immutable evidentiary record of past investigations, exposure assessments, and formal incident dossiers archived with tamper-evident audit seals.
          </p>
          <div style={{ marginTop: 8, display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11 }} className="mono">
            <span className="badge badge-low" style={{ background: 'hsl(142 71% 18%)', color: 'hsl(142 71% 75%)', border: '1px solid hsl(142 71% 28%)', fontSize: 10 }}>
              <Database size={9} style={{ marginRight: 4 }} />
              REPORTS DISK VAULT
            </span>
            <span className="muted" style={{ fontSize: 10 }}>
              {vaultPath || 'artifacts/reports_vault'}
            </span>
          </div>
        </div>

        {/* Top Action Buttons */}
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <button
            onClick={() => onNavigate('/reports')}
            data-testid="button-create-new-report"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              background: 'hsl(var(--primary))',
              color: 'hsl(var(--primary-foreground))',
              border: 'none',
              borderRadius: 6,
              padding: '8px 14px',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            <Plus size={14} /> Generate New Report
          </button>

          <button
            onClick={exportHistoryCSV}
            data-testid="button-export-history-csv"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
              background: 'hsl(var(--secondary))',
              color: 'hsl(var(--secondary-foreground))',
              border: '1px solid hsl(var(--border))',
              borderRadius: 6,
              padding: '8px 14px',
              fontSize: 12,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            <Download size={13} /> Export Archive Index (CSV)
          </button>
        </div>
      </div>

      {/* KPI Cards Strip */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))',
          gap: 12,
          marginBottom: 20,
        }}
      >
        <div style={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', borderRadius: 8, padding: 14 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: 'hsl(var(--muted-foreground))', textTransform: 'uppercase' }}>
              Archived Reports
            </span>
            <History size={15} style={{ color: 'hsl(var(--primary))' }} />
          </div>
          <div style={{ fontSize: 24, fontWeight: 800, color: 'hsl(var(--foreground))' }}>{stats.total}</div>
          <div style={{ fontSize: 11, color: 'hsl(var(--muted-foreground))', marginTop: 3 }}>
            Stored in local reports vault
          </div>
        </div>

        <div style={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', borderRadius: 8, padding: 14 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: 'hsl(var(--muted-foreground))', textTransform: 'uppercase' }}>
              High-Risk Incidents
            </span>
            <ShieldAlert size={15} style={{ color: 'hsl(0 84% 60%)' }} />
          </div>
          <div style={{ fontSize: 24, fontWeight: 800, color: 'hsl(0 84% 60%)' }}>{stats.critical}</div>
          <div style={{ fontSize: 11, color: 'hsl(var(--muted-foreground))', marginTop: 3 }}>
            Risk Score ≥ 70 / 100
          </div>
        </div>

        <div style={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', borderRadius: 8, padding: 14 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: 'hsl(var(--muted-foreground))', textTransform: 'uppercase' }}>
              PDF Executive Memos
            </span>
            <FileText size={15} style={{ color: 'hsl(var(--primary))' }} />
          </div>
          <div style={{ fontSize: 24, fontWeight: 800, color: 'hsl(var(--foreground))' }}>{stats.pdfCount}</div>
          <div style={{ fontSize: 11, color: 'hsl(var(--muted-foreground))', marginTop: 3 }}>
            Official printable dossiers
          </div>
        </div>

        <div style={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', borderRadius: 8, padding: 14 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: 'hsl(var(--muted-foreground))', textTransform: 'uppercase' }}>
              JSON Evidence Bundles
            </span>
            <FileCode size={15} style={{ color: 'hsl(var(--info, 217 91% 60%))' }} />
          </div>
          <div style={{ fontSize: 24, fontWeight: 800, color: 'hsl(var(--foreground))' }}>{stats.jsonCount}</div>
          <div style={{ fontSize: 11, color: 'hsl(var(--muted-foreground))', marginTop: 3 }}>
            Technical machine packages
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div
        style={{
          display: 'flex',
          gap: 10,
          alignItems: 'center',
          marginBottom: 16,
          flexWrap: 'wrap',
          background: 'hsl(var(--card))',
          border: '1px solid hsl(var(--border))',
          borderRadius: 8,
          padding: 10,
        }}
      >
        <div style={{ position: 'relative', flex: '1 1 240px' }}>
          <Search size={14} style={{ position: 'absolute', left: 10, top: 9, color: 'hsl(var(--muted-foreground))' }} />
          <input
            type="text"
            placeholder="Search by report title, incident ID, or investigator..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={{
              width: '100%',
              background: 'hsl(var(--muted)/0.5)',
              border: '1px solid hsl(var(--border))',
              borderRadius: 6,
              padding: '6px 10px 6px 32px',
              fontSize: 12,
              color: 'hsl(var(--foreground))',
            }}
          />
        </div>

        {/* Status Filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <span style={{ fontSize: 11, color: 'hsl(var(--muted-foreground))', marginRight: 4 }}>Status:</span>
          {(['all', 'Ready', 'Shared', 'Archived'] as const).map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              style={{
                fontSize: 11,
                padding: '4px 8px',
                borderRadius: 4,
                border: '1px solid hsl(var(--border))',
                background: statusFilter === st ? 'hsl(var(--primary))' : 'hsl(var(--muted)/0.4)',
                color: statusFilter === st ? 'hsl(var(--primary-foreground))' : 'hsl(var(--muted-foreground))',
                cursor: 'pointer',
                fontWeight: 600,
              }}
            >
              {st === 'all' ? 'All' : st}
            </button>
          ))}
        </div>

        {/* Format Filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <span style={{ fontSize: 11, color: 'hsl(var(--muted-foreground))', marginRight: 4 }}>Format:</span>
          {(['all', 'PDF', 'JSON', 'TXT'] as const).map((fmt) => (
            <button
              key={fmt}
              onClick={() => setFormatFilter(fmt)}
              style={{
                fontSize: 11,
                padding: '4px 8px',
                borderRadius: 4,
                border: '1px solid hsl(var(--border))',
                background: formatFilter === fmt ? 'hsl(var(--primary))' : 'hsl(var(--muted)/0.4)',
                color: formatFilter === fmt ? 'hsl(var(--primary-foreground))' : 'hsl(var(--muted-foreground))',
                cursor: 'pointer',
                fontWeight: 600,
              }}
            >
              {fmt === 'all' ? 'All' : fmt}
            </button>
          ))}
        </div>
      </div>

      {/* Reports Table */}
      <div style={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', borderRadius: 8, overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse', textAlign: 'left' }}>
            <thead>
              <tr style={{ background: 'hsl(var(--muted)/0.4)', borderBottom: '1px solid hsl(var(--border))', color: 'hsl(var(--muted-foreground))', fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                <th style={{ padding: '10px 14px' }}>Report Dossier</th>
                <th style={{ padding: '10px 14px' }}>Incident ID</th>
                <th style={{ padding: '10px 14px' }}>Lead Author</th>
                <th style={{ padding: '10px 14px' }}>Created</th>
                <th style={{ padding: '10px 14px' }}>Format</th>
                <th style={{ padding: '10px 14px' }}>Risk</th>
                <th style={{ padding: '10px 14px' }}>Status</th>
                <th style={{ padding: '10px 14px', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredReports.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ padding: 36, textAlign: 'center', color: 'hsl(var(--muted-foreground))' }}>
                    <History size={28} style={{ margin: '0 auto 8px', opacity: 0.5 }} />
                    <div style={{ fontWeight: 600, fontSize: 13 }}>No archived reports found</div>
                    <div style={{ fontSize: 11, marginTop: 4 }}>Try clearing your search query or generate a new incident report.</div>
                  </td>
                </tr>
              ) : (
                filteredReports.map((r) => (
                  <tr key={r.id} style={{ borderBottom: '1px solid hsl(var(--border)/0.5)', transition: 'background 0.15s ease' }}>
                    <td style={{ padding: '10px 14px' }}>
                      <div style={{ fontWeight: 700, color: 'hsl(var(--foreground))' }}>{r.title}</div>
                      <div className="mono muted" style={{ fontSize: 10 }}>{r.id}</div>
                    </td>
                    <td style={{ padding: '10px 14px' }} className="mono">
                      <span style={{ color: 'hsl(var(--primary))', fontWeight: 600 }}>{r.incidentId}</span>
                    </td>
                    <td style={{ padding: '10px 14px', color: 'hsl(var(--muted-foreground))' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                        <User size={12} />
                        <span>{r.author}</span>
                      </div>
                    </td>
                    <td style={{ padding: '10px 14px', color: 'hsl(var(--muted-foreground))' }} className="mono">
                      {r.createdAt}
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      <span className="badge badge-muted" style={{ fontSize: 10, padding: '2px 6px' }}>
                        {r.format}
                      </span>
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      <span
                        className={r.riskScore >= 70 ? 'badge badge-critical' : r.riskScore >= 50 ? 'badge badge-high' : 'badge badge-low'}
                        style={{ fontSize: 10, padding: '2px 7px' }}
                      >
                        {r.riskScore} / 100
                      </span>
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      <span
                        style={{
                          fontSize: 10,
                          padding: '2px 7px',
                          borderRadius: 4,
                          fontWeight: 700,
                          background: r.status === 'Ready' ? 'hsl(142 71% 18%)' : r.status === 'Shared' ? 'hsl(217 91% 20%)' : 'hsl(var(--muted))',
                          color: r.status === 'Ready' ? 'hsl(142 71% 75%)' : r.status === 'Shared' ? 'hsl(217 91% 75%)' : 'hsl(var(--muted-foreground))',
                        }}
                      >
                        {r.status}
                      </span>
                    </td>
                    <td style={{ padding: '10px 14px', textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', gap: 6 }}>
                        <button
                          onClick={() => setInspectReport(r)}
                          title="Inspect Dossier"
                          style={{
                            background: 'hsl(var(--muted)/0.5)',
                            border: '1px solid hsl(var(--border))',
                            borderRadius: 4,
                            padding: '5px 8px',
                            cursor: 'pointer',
                            color: 'hsl(var(--foreground))',
                            fontSize: 11,
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: 4,
                          }}
                        >
                          <Eye size={12} /> Inspect
                        </button>

                        <button
                          onClick={() => handleDownloadReport(r)}
                          title="Download"
                          style={{
                            background: 'hsl(var(--muted)/0.5)',
                            border: '1px solid hsl(var(--border))',
                            borderRadius: 4,
                            padding: '5px 8px',
                            cursor: 'pointer',
                            color: 'hsl(var(--primary))',
                            fontSize: 11,
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: 4,
                          }}
                        >
                          <Download size={12} />
                        </button>

                        <button
                          onClick={() => setDeleteTarget(r)}
                          title="Purge"
                          style={{
                            background: 'hsl(var(--muted)/0.5)',
                            border: '1px solid hsl(var(--border))',
                            borderRadius: 4,
                            padding: '5px 8px',
                            cursor: 'pointer',
                            color: 'hsl(0 84% 60%)',
                            fontSize: 11,
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: 4,
                          }}
                        >
                          <Trash2 size={12} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Inspect Report Modal */}
      {inspectReport && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.7)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 9999,
            padding: 20,
          }}
          onClick={() => setInspectReport(null)}
        >
          <div
            style={{
              background: 'hsl(var(--card))',
              border: '1px solid hsl(var(--border))',
              borderRadius: 8,
              width: '100%',
              maxWidth: 760,
              maxHeight: '90vh',
              overflowY: 'auto',
              padding: 24,
              boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
              position: 'relative',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid hsl(var(--border))', paddingBottom: 14, marginBottom: 16 }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
                  <span className="mono" style={{ fontSize: 11, color: 'hsl(var(--primary))', fontWeight: 700 }}>
                    {inspectReport.id} · {inspectReport.incidentId}
                  </span>
                  <span className="badge badge-critical" style={{ fontSize: 10 }}>
                    Risk: {inspectReport.riskScore}/100
                  </span>
                </div>
                <h2 style={{ fontSize: 18, fontWeight: 800, margin: 0 }}>{inspectReport.title}</h2>
                <div style={{ fontSize: 11, color: 'hsl(var(--muted-foreground))', marginTop: 2 }}>
                  Author: <b>{inspectReport.author}</b> · Created: {inspectReport.createdAt}
                </div>
              </div>

              <button
                onClick={() => setInspectReport(null)}
                style={{ background: 'none', border: 'none', color: 'hsl(var(--muted-foreground))', cursor: 'pointer', padding: 4 }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Evidence Badges */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8, marginBottom: 18 }}>
              <div style={{ background: 'hsl(var(--muted)/0.3)', padding: 10, borderRadius: 6, border: '1px solid hsl(var(--border))' }}>
                <div style={{ fontSize: 10, color: 'hsl(var(--muted-foreground))' }}>Monitored PIDs</div>
                <div style={{ fontSize: 16, fontWeight: 800 }}>{inspectReport.evidenceCounts?.processes || 0}</div>
              </div>
              <div style={{ background: 'hsl(var(--muted)/0.3)', padding: 10, borderRadius: 6, border: '1px solid hsl(var(--border))' }}>
                <div style={{ fontSize: 10, color: 'hsl(var(--muted-foreground))' }}>Quarantined Files</div>
                <div style={{ fontSize: 16, fontWeight: 800, color: 'hsl(var(--primary))' }}>{inspectReport.evidenceCounts?.quarantined || 0}</div>
              </div>
              <div style={{ background: 'hsl(var(--muted)/0.3)', padding: 10, borderRadius: 6, border: '1px solid hsl(var(--border))' }}>
                <div style={{ fontSize: 10, color: 'hsl(var(--muted-foreground))' }}>Network Sockets</div>
                <div style={{ fontSize: 16, fontWeight: 800 }}>{inspectReport.evidenceCounts?.connections || 0}</div>
              </div>
              <div style={{ background: 'hsl(var(--muted)/0.3)', padding: 10, borderRadius: 6, border: '1px solid hsl(var(--border))' }}>
                <div style={{ fontSize: 10, color: 'hsl(var(--muted-foreground))' }}>Target Endpoint</div>
                <div style={{ fontSize: 13, fontWeight: 700, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{inspectReport.endpoint}</div>
              </div>
            </div>

            {/* Summary */}
            <div style={{ marginBottom: 18 }}>
              <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'hsl(var(--primary))', marginBottom: 6 }}>
                Executive Findings Summary
              </div>
              <p style={{ fontSize: 12, lineHeight: 1.6, background: 'hsl(var(--muted)/0.2)', padding: 12, borderRadius: 6, border: '1px solid hsl(var(--border))', margin: 0 }}>
                {inspectReport.summary}
              </p>
            </div>

            {/* Quarantined Artifacts if present */}
            {inspectReport.quarantinedArtifacts && inspectReport.quarantinedArtifacts.length > 0 && (
              <div style={{ marginBottom: 18 }}>
                <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'hsl(var(--primary))', marginBottom: 6 }}>
                  Quarantined Evidence Files ({inspectReport.quarantinedArtifacts.length})
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 11 }}>
                  {inspectReport.quarantinedArtifacts.map((q, i) => (
                    <div key={i} style={{ display: 'flex', justifyContent: 'space-between', background: 'hsl(var(--muted)/0.3)', padding: '6px 10px', borderRadius: 4 }}>
                      <span style={{ fontWeight: 600, color: 'hsl(var(--primary))' }}>{q.name} ({q.size})</span>
                      <span className="mono" style={{ color: 'hsl(var(--muted-foreground))' }}>{shortHash(q.hash)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Raw content preview if present */}
            {inspectReport.content && (
              <div style={{ marginBottom: 18 }}>
                <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', color: 'hsl(var(--primary))', marginBottom: 6 }}>
                  Dossier Document Source ({inspectReport.format})
                </div>
                <pre
                  style={{
                    background: 'hsl(216 33% 6%)',
                    border: '1px solid hsl(var(--border))',
                    borderRadius: 6,
                    padding: 12,
                    fontSize: 10,
                    maxHeight: 200,
                    overflowY: 'auto',
                    fontFamily: 'monospace',
                    color: 'hsl(var(--muted-foreground))',
                    whiteSpace: 'pre-wrap',
                  }}
                >
                  {inspectReport.content}
                </pre>
              </div>
            )}

            {/* Modal Actions */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, borderTop: '1px solid hsl(var(--border))', paddingTop: 14 }}>
              <button
                onClick={() => handleDownloadReport(inspectReport)}
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 6,
                  background: 'hsl(var(--primary))',
                  color: 'hsl(var(--primary-foreground))',
                  border: 'none',
                  borderRadius: 6,
                  padding: '8px 14px',
                  fontSize: 12,
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                <Download size={13} /> Download File ({inspectReport.format})
              </button>

              <button
                onClick={() => setInspectReport(null)}
                style={{
                  background: 'hsl(var(--secondary))',
                  color: 'hsl(var(--secondary-foreground))',
                  border: '1px solid hsl(var(--border))',
                  borderRadius: 6,
                  padding: '8px 14px',
                  fontSize: 12,
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteTarget && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.7)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 9999,
            padding: 20,
          }}
          onClick={() => setDeleteTarget(null)}
        >
          <div
            style={{
              background: 'hsl(var(--card))',
              border: '1px solid hsl(0 84% 60%/0.3)',
              borderRadius: 8,
              width: '100%',
              maxWidth: 440,
              padding: 22,
              boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
              <Trash2 size={20} style={{ color: 'hsl(0 84% 60%)' }} />
              <h3 style={{ fontSize: 16, fontWeight: 700, margin: 0 }}>Permanently Purge Report?</h3>
            </div>
            <p style={{ fontSize: 12, color: 'hsl(var(--muted-foreground))', lineHeight: 1.5, margin: '0 0 18px' }}>
              Are you sure you want to delete <b>{deleteTarget.id}</b> ({deleteTarget.title})? This will permanently wipe the archived dossier from the reports vault.
            </p>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
              <button
                onClick={() => setDeleteTarget(null)}
                style={{
                  background: 'hsl(var(--secondary))',
                  color: 'hsl(var(--secondary-foreground))',
                  border: '1px solid hsl(var(--border))',
                  borderRadius: 6,
                  padding: '7px 12px',
                  fontSize: 12,
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                Cancel
              </button>
              <button
                onClick={confirmDelete}
                style={{
                  background: 'hsl(0 84% 60%)',
                  color: '#fff',
                  border: 'none',
                  borderRadius: 6,
                  padding: '7px 14px',
                  fontSize: 12,
                  fontWeight: 700,
                  cursor: 'pointer',
                }}
              >
                Purge Report
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
