import { useState, useEffect, useCallback } from 'react';

export type ReportEvidenceCounts = {
  processes: number;
  connections: number;
  quarantined: number;
  detections: number;
  timelineEvents: number;
};

export type ReportRecord = {
  id: string;
  incidentId: string;
  title: string;
  author: string;
  createdAt: string;
  status: 'Ready' | 'Shared' | 'Archived';
  format: 'PDF' | 'JSON' | 'TXT';
  audience: string;
  riskScore: number;
  endpoint: string;
  summary: string;
  evidenceCounts: ReportEvidenceCounts;
  metrics?: {
    cpu?: string;
    ram?: string;
    uptime?: string;
  };
  quarantinedArtifacts?: Array<{
    id: string;
    name: string;
    hash: string;
    size: string;
    status: string;
  }>;
  suspiciousProcesses?: Array<{
    pid: number;
    name: string;
    cmdline?: string;
  }>;
  externalConnections?: Array<{
    destination: string;
    port: number;
    process: string;
  }>;
  content?: string;
  filePath?: string;
};

export type UseReportsState = {
  reports: ReportRecord[];
  loading: boolean;
  error: string | null;
  vaultPath: string | null;
  createReport: (data: Partial<ReportRecord>) => Promise<ReportRecord | null>;
  deleteReport: (id: string) => Promise<boolean>;
  refetch: () => Promise<void>;
};

export const initialReportSeed: ReportRecord[] = [
  {
    id: 'RPT-2026-0041',
    incidentId: 'INC-2026-1042',
    title: 'Executive Exposure Assessment · Host WS-0427',
    author: 'Lead Forensic Investigator',
    createdAt: 'Today, 09:49',
    status: 'Ready',
    format: 'PDF',
    audience: 'Security Leadership & CISO',
    riskScore: 78,
    endpoint: 'WS-0427 (Windows Host)',
    summary: 'Suspicious PowerShell execution correlated with sensitive document staging and outbound C2 connection attempt. Endpoint isolated in quarantine vault with zero data loss.',
    evidenceCounts: {
      processes: 274,
      connections: 752,
      quarantined: 3,
      detections: 4,
      timelineEvents: 18,
    },
    metrics: {
      cpu: '8.4%',
      ram: '58.2%',
      uptime: '2d 4h',
    },
  },
  {
    id: 'RPT-2026-0040',
    incidentId: 'INC-2026-1039',
    title: 'Unsigned Binary Review & Memory Handle Triage',
    author: 'SecOps Tier-3 Analyst',
    createdAt: 'Yesterday, 18:32',
    status: 'Shared',
    format: 'PDF',
    audience: 'Incident Response Team',
    riskScore: 65,
    endpoint: 'WS-0198 (Finance Terminal)',
    summary: 'First-seen executable invoice_viewer.exe sequestered to evidence vault. Tamper seal verified with 100% cryptographic integrity.',
    evidenceCounts: {
      processes: 185,
      connections: 240,
      quarantined: 2,
      detections: 2,
      timelineEvents: 12,
    },
  },
  {
    id: 'RPT-2026-0039',
    incidentId: 'BATCH-2026-Q3',
    title: 'Quarterly Host Integrity & Regulatory Audit',
    author: 'Cyber Risk & Compliance',
    createdAt: 'Oct 01, 2026',
    status: 'Archived',
    format: 'JSON',
    audience: 'Legal & Compliance',
    riskScore: 32,
    endpoint: 'Enterprise Monitored Fleet',
    summary: 'Periodic integrity audit across active endpoint sensors. Zero active backdoors detected.',
    evidenceCounts: {
      processes: 290,
      connections: 810,
      quarantined: 0,
      detections: 0,
      timelineEvents: 85,
    },
  },
];

export function useReports(): UseReportsState {
  const [reports, setReports] = useState<ReportRecord[]>(initialReportSeed);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [vaultPath, setVaultPath] = useState<string | null>(null);

  const fetchReports = useCallback(async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/reports');
      if (!res.ok) throw new Error(`HTTP error ${res.status}`);
      const data = await res.json();
      if (data && Array.isArray(data.reports) && data.reports.length > 0) {
        setReports(data.reports);
        setVaultPath(data.vaultPath || null);
      }
      setError(null);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchReports();
  }, [fetchReports]);

  const createReport = useCallback(async (data: Partial<ReportRecord>) => {
    try {
      const res = await fetch('/api/reports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      if (!res.ok) throw new Error(`Failed to archive report (${res.status})`);
      const resData = await res.json();
      if (resData.report) {
        setReports((prev) => [resData.report, ...prev]);
        return resData.report;
      }
    } catch (err) {
      console.error('Failed to create report on backend:', err);
    }
    // Optimistic fallback
    const id = `RPT-${new Date().getFullYear()}-${String(Date.now()).slice(-4)}`;
    const optimistic: ReportRecord = {
      id,
      incidentId: data.incidentId || `INC-LOCAL-${Math.floor(1000 + Math.random() * 9000)}`,
      title: data.title || 'Incident Report',
      author: data.author || 'Investigator',
      createdAt: 'Just now',
      status: 'Ready',
      format: data.format || 'PDF',
      audience: data.audience || 'Security Leadership',
      riskScore: data.riskScore || 75,
      endpoint: data.endpoint || 'WS-0427',
      summary: data.summary || '',
      evidenceCounts: data.evidenceCounts || {
        processes: 0,
        connections: 0,
        quarantined: 0,
        detections: 0,
        timelineEvents: 0,
      },
      metrics: data.metrics,
      content: data.content,
    };
    setReports((prev) => [optimistic, ...prev]);
    return optimistic;
  }, []);

  const deleteReport = useCallback(async (id: string) => {
    try {
      const res = await fetch(`/api/reports/${id}`, { method: 'DELETE' });
      if (!res.ok) throw new Error(`Failed to delete report ${id}`);
      setReports((prev) => prev.filter((r) => r.id !== id));
      return true;
    } catch (err) {
      console.error('Failed to delete report on backend:', err);
      setReports((prev) => prev.filter((r) => r.id !== id));
      return true;
    }
  }, []);

  return {
    reports,
    loading,
    error,
    vaultPath,
    createReport,
    deleteReport,
    refetch: fetchReports,
  };
}
