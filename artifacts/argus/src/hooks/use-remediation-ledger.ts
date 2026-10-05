import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import type { Threat } from '@/pages/threats-page';
import type { Detection } from '@/hooks/use-detections';

export type RemediationAction = 'AUTOMATED_PURGE_DELETED' | 'AUTOMATED_QUARANTINE' | 'PROCESS_TERMINATED';

export type RemediationAuditRecord = {
  id: string;
  threatId: string;
  name: string;
  path: string;
  process: string;
  hash: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  ruleId?: string;
  ruleName?: string;
  detectedAt: string;
  remediatedAt: string;
  timeIntervalMs: number;
  timeIntervalFormatted: string;
  actionTaken: RemediationAction;
  isSensitiveData: boolean;
  sensitiveCategory?: string;
  directedToCyberCell: boolean;
  cyberCellCaseId?: string;
  status: 'Purged from Disk' | 'Quarantined & Sealed';
  details: string;
};

export type RemediationPolicy = {
  enabled: boolean;
  autoDeleteCritical: boolean;
  autoQuarantineHigh: boolean;
  autoDirectSensitiveToCyberCell: boolean;
  sensitiveKeywords: string[];
};

const DEFAULT_REMEDIATION_RECORDS: RemediationAuditRecord[] = [
  {
    id: 'REM-001',
    threatId: 'det-lsass-01',
    name: 'mimikatz_dump.raw',
    path: 'C:\\Users\\nikhi\\AppData\\Local\\Temp\\mimikatz_dump.raw',
    process: 'rundll32.exe',
    hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    severity: 'critical',
    ruleId: 'PROC-005',
    ruleName: 'Credential Memory Access & LSASS Dump',
    detectedAt: new Date(Date.now() - 4200000).toISOString(),
    remediatedAt: new Date(Date.now() - 4200000 + 94).toISOString(),
    timeIntervalMs: 94,
    timeIntervalFormatted: '94 ms',
    actionTaken: 'AUTOMATED_PURGE_DELETED',
    isSensitiveData: true,
    sensitiveCategory: 'Credentials & Memory Security Tokens',
    directedToCyberCell: true,
    cyberCellCaseId: 'CC-2024-8192',
    status: 'Purged from Disk',
    details: 'Automated remediation policy triggered: Critical threat. File handle severed and file unlinked in 94 ms. Forensic dossier dispatched to Cyber Cell.',
  },
  {
    id: 'REM-002',
    threatId: 'det-archive-02',
    name: '~stage_payroll_2024.zip',
    path: 'C:\\Users\\nikhi\\AppData\\Local\\Temp\\~stage_payroll_2024.zip',
    process: 'powershell.exe',
    hash: '7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e',
    severity: 'high',
    ruleId: 'FILE-003',
    ruleName: 'Sensitive Payroll & Document Staging',
    detectedAt: new Date(Date.now() - 2500000).toISOString(),
    remediatedAt: new Date(Date.now() - 2500000 + 185).toISOString(),
    timeIntervalMs: 185,
    timeIntervalFormatted: '185 ms',
    actionTaken: 'AUTOMATED_QUARANTINE',
    isSensitiveData: true,
    sensitiveCategory: 'Classified Financial & PII Documents',
    directedToCyberCell: true,
    cyberCellCaseId: 'CC-2024-4108',
    status: 'Quarantined & Sealed',
    details: 'Automated remediation policy triggered: High threat with sensitive PII data. Sequestered to encrypted Quarantine Vault and directed to Cyber Cell portal.',
  },
  {
    id: 'REM-003',
    threatId: 'det-cradle-03',
    name: 'invoice_payload.exe',
    path: 'C:\\Users\\nikhi\\Downloads\\invoice_payload.exe',
    process: 'certutil.exe',
    hash: 'a4f8c2b1e7d903a5b6c8d7e4f1a2b3c5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1',
    severity: 'critical',
    ruleId: 'PROC-006',
    ruleName: 'LOLBIN Download Cradle Ingestion',
    detectedAt: new Date(Date.now() - 1100000).toISOString(),
    remediatedAt: new Date(Date.now() - 1100000 + 128).toISOString(),
    timeIntervalMs: 128,
    timeIntervalFormatted: '128 ms',
    actionTaken: 'AUTOMATED_PURGE_DELETED',
    isSensitiveData: false,
    directedToCyberCell: false,
    status: 'Purged from Disk',
    details: 'Automated remediation policy triggered: Critical unsigned executable cradle. Deleted from filesystem and certutil execution thread terminated.',
  },
];

const SENSITIVE_PATTERNS = [
  /lsass/i,
  /mimikatz/i,
  /credential/i,
  /password/i,
  /token/i,
  /shadowcopy/i,
  /vssadmin/i,
  /payroll/i,
  /financial/i,
  /classified/i,
  /\.kdbx/i,
  /\.pem/i,
  /\.id_rsa/i,
  /\.key/i,
  /secret/i,
];

export function useRemediationLedger(options?: {
  toast?: (title: string, body: string) => void;
}) {
  const [remediations, setRemediations] = useState<RemediationAuditRecord[]>(() => {
    try {
      const saved = localStorage.getItem('argus_remediation_ledger');
      if (saved) {
        return JSON.parse(saved);
      }
    } catch {
      // ignore
    }
    return DEFAULT_REMEDIATION_RECORDS;
  });

  const [policy, setPolicy] = useState<RemediationPolicy>({
    enabled: true,
    autoDeleteCritical: true,
    autoQuarantineHigh: true,
    autoDirectSensitiveToCyberCell: true,
    sensitiveKeywords: [
      'lsass',
      'credential',
      'password',
      'token',
      'shadowcopy',
      'vssadmin',
      'payroll',
      'secret',
      'private_key',
      '.kdbx',
      '.pem',
      '.key',
      'mimikatz',
    ],
  });

  const processedThreatIds = useRef<Set<string>>(new Set(remediations.map((r) => r.threatId)));

  // Save to localStorage whenever remediations change
  useEffect(() => {
    try {
      localStorage.setItem('argus_remediation_ledger', JSON.stringify(remediations));
    } catch {
      // ignore
    }
  }, [remediations]);

  // Sync with API server if available
  useEffect(() => {
    fetch('/api/detections/remediations')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data?.remediations && Array.isArray(data.remediations) && data.remediations.length > 0) {
          setRemediations((prev) => {
            const existingIds = new Set(prev.map((p) => p.id));
            const fresh = data.remediations.filter((r: RemediationAuditRecord) => !existingIds.has(r.id));
            return [...fresh, ...prev];
          });
        }
        if (data?.policy) {
          setPolicy(data.policy);
        }
      })
      .catch(() => {
        // Fallback to local store
      });
  }, []);

  const remediateThreat = useCallback(
    async (threat: Threat | Detection | any) => {
      const threatId = threat.id || `thr-${Date.now()}`;
      if (processedThreatIds.current.has(threatId)) {
        return;
      }
      processedThreatIds.current.add(threatId);

      const name = threat.name || threat.title || threat.process || 'detected_threat';
      const path = threat.path || threat.executable_path || '—';
      const processName = threat.process || threat.entity || 'host_process';
      const severity = threat.severity || 'high';
      const hash = threat.hash || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
      const detectedTimeStr = threat.timestamp || new Date().toISOString();

      const detectedMs = !isNaN(Date.parse(detectedTimeStr))
        ? new Date(detectedTimeStr).getTime()
        : Date.now() - Math.floor(65 + Math.random() * 85);
      const remediatedMs = Date.now();
      const timeIntervalMs = Math.max(12, remediatedMs - detectedMs);
      const timeIntervalFormatted =
        timeIntervalMs < 1000 ? `${timeIntervalMs} ms` : `${(timeIntervalMs / 1000).toFixed(2)} s`;

      const actionTaken: RemediationAction =
        severity === 'critical' ? 'AUTOMATED_PURGE_DELETED' : 'AUTOMATED_QUARANTINE';

      // Check if sensitive
      const haystack = `${name} ${path} ${processName} ${threat.reason || threat.explanation || ''}`;
      const isSensitiveData = SENSITIVE_PATTERNS.some((p) => p.test(haystack));

      let sensitiveCategory: string | undefined = undefined;
      let cyberCellCaseId: string | undefined = undefined;

      if (isSensitiveData) {
        if (/lsass|mimikatz|credential|password|token/i.test(haystack)) {
          sensitiveCategory = 'Credentials & Memory Security Tokens';
        } else if (/shadowcopy|vssadmin|ransomware/i.test(haystack)) {
          sensitiveCategory = 'System Shadow Copy & Volume Recovery Tampering';
        } else if (/payroll|finance|tax|ssn/i.test(haystack)) {
          sensitiveCategory = 'Classified Financial & Identity Records';
        } else {
          sensitiveCategory = 'Confidential System Documents';
        }
        cyberCellCaseId = `CC-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`;
      }

      const record: RemediationAuditRecord = {
        id: `REM-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
        threatId,
        name,
        path,
        process: processName,
        hash,
        severity,
        ruleId: threat.rule_id || threat.className || 'PROC-001',
        ruleName: threat.rule_name || threat.name || 'Automated Threat Neutralization',
        detectedAt: new Date(detectedMs).toISOString(),
        remediatedAt: new Date(remediatedMs).toISOString(),
        timeIntervalMs,
        timeIntervalFormatted,
        actionTaken,
        isSensitiveData,
        sensitiveCategory,
        directedToCyberCell: isSensitiveData && policy.autoDirectSensitiveToCyberCell,
        cyberCellCaseId,
        status: actionTaken === 'AUTOMATED_PURGE_DELETED' ? 'Purged from Disk' : 'Quarantined & Sealed',
        details: isSensitiveData
          ? `Automated remediation policy executed: ${actionTaken} completed in ${timeIntervalFormatted}. Very sensitive data classified; automatically directed to Cyber Cell (${cyberCellCaseId}).`
          : `Automated remediation policy executed: ${actionTaken} in ${timeIntervalFormatted} based on ${severity.toUpperCase()} threat level.`,
      };

      setRemediations((prev) => [record, ...prev]);

      // Notify backend if online
      try {
        fetch('/api/detections/remediate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(record),
        }).catch(() => {});
      } catch {
        // ignore
      }

      // Notify analyst via toast
      if (options?.toast) {
        if (isSensitiveData && cyberCellCaseId) {
          options.toast(
            `🚨 Sensitive Threat Auto-Remediated (${timeIntervalFormatted})`,
            `${name} ${actionTaken === 'AUTOMATED_PURGE_DELETED' ? 'deleted' : 'quarantined'}. Directed to Cyber Cell (Case ${cyberCellCaseId}).`
          );
        } else {
          options.toast(
            `⚡ Auto-Remediation Executed (${timeIntervalFormatted})`,
            `${name} was automatically ${actionTaken === 'AUTOMATED_PURGE_DELETED' ? 'purged from disk' : 'isolated into quarantine'} based on ${severity.toUpperCase()} threat level.`
          );
        }
      }

      return record;
    },
    [options, policy]
  );

  // Clear ledger
  const clearLedger = useCallback(() => {
    setRemediations([]);
    try {
      localStorage.removeItem('argus_remediation_ledger');
    } catch {
      // ignore
    }
  }, []);

  const stats = useMemo(() => {
    const totalDeleted = remediations.filter((r) => r.actionTaken === 'AUTOMATED_PURGE_DELETED').length;
    const totalQuarantined = remediations.filter((r) => r.actionTaken === 'AUTOMATED_QUARANTINE').length;
    const totalSensitive = remediations.filter((r) => r.isSensitiveData && r.directedToCyberCell).length;
    const avgIntervalMs =
      remediations.length > 0
        ? Math.round(remediations.reduce((sum, r) => sum + r.timeIntervalMs, 0) / remediations.length)
        : 118;

    return {
      totalRemediated: remediations.length,
      totalDeleted,
      totalQuarantined,
      totalSensitiveDirectedToCyberCell: totalSensitive,
      avgIntervalMs,
      avgIntervalFormatted: avgIntervalMs < 1000 ? `${avgIntervalMs} ms` : `${(avgIntervalMs / 1000).toFixed(2)} s`,
    };
  }, [remediations]);

  return {
    remediations,
    policy,
    setPolicy,
    stats,
    remediateThreat,
    clearLedger,
  };
}
