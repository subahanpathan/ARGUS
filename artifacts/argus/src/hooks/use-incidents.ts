/**
 * useIncidents — React hook for ARGUS Automated Incident Response Orchestration & Recovery.
 *
 * Interfaces with /api/incidents endpoints to manage the strict 12-state incident lifecycle machine,
 * automated response levels (0-4), human override approvals, empirical containment verification,
 * VSS/staging data recovery with SHA-256 integrity checks, and immutable audit logs.
 */

import { useCallback, useEffect, useState } from "react";

export type IncidentLifecycleState =
  | "DETECTED"
  | "TRACING"
  | "INVESTIGATING"
  | "IMPACT_ASSESSED"
  | "CONTAINMENT_PENDING"
  | "CONTAINED"
  | "RECOVERY_PENDING"
  | "RECOVERING"
  | "VERIFYING"
  | "RECOVERED"
  | "CLOSED"
  | "FAILED"
  | "REQUIRES_USER_ACTION";

export type ResponseLevel = 0 | 1 | 2 | 3 | 4;

export type ResponseLevelLabel =
  | "LOG_AND_MONITOR"
  | "ISOLATE_PROCESS"
  | "CONTAIN_PROCESS_AND_FILE"
  | "FULL_SYSTEM_CONTAINMENT"
  | "EMERGENCY_RECOVERY_ISOLATION";

export type ContainmentActionRecord = {
  pid?: number;
  processName?: string;
  actionType: "TERMINATE_PROCESS" | "QUARANTINE_FILE" | "REVOKE_NETWORK" | "SNAPSHOT_EVIDENCE";
  status: "SUCCESS" | "FAILED" | "SKIPPED";
  timestamp: string;
  verificationMethod?: string;
  verificationResult?: "VERIFIED" | "FAILED" | "UNVERIFIED";
  details?: string;
};

export type HashMatchStatus = "VERIFIED" | "MISMATCH" | "NOT_AVAILABLE" | "FAILED";

export type RecoverySourceType =
  | "VSS_SHADOW_COPY"
  | "BACKUP_ROOT"
  | "BASELINE"
  | "STAGING_VAULT"
  | "NONE";

export type RecoveryResultRecord = {
  filePath: string;
  originalHash?: string | null;
  recoveredHash?: string | null;
  hashMatchStatus: HashMatchStatus;
  sourceUsed: RecoverySourceType;
  recoveryStatus: "SUCCESS" | "FAILED" | "PARTIAL";
  restoredToPath?: string;
  timestamp: string;
  details?: string;
};

export type IncidentAuditEntry = {
  auditId: string;
  incidentId: string;
  timestamp: string;
  stateBefore: string;
  stateAfter: string;
  action: string;
  triggeredBy: "AUTOMATED_ORCHESTRATOR" | "HUMAN_OPERATOR" | "DETECTION_ENGINE";
  evidenceSummary: string;
  status: "SUCCESS" | "FAILED" | "PENDING_APPROVAL";
};

export type IncidentRecord = {
  incidentId: string;
  title: string;
  state: IncidentLifecycleState;
  severity: "critical" | "high" | "medium" | "low";
  confidence: number;
  primaryPid?: number;
  primaryProcessName?: string;
  responseLevel: ResponseLevel;
  responseLevelLabel: ResponseLevelLabel;
  containmentAutomated: boolean;
  containmentApprovedByHuman: boolean;
  recoveryAutomated: boolean;
  recoveryApprovedByHuman: boolean;
  containmentActions: ContainmentActionRecord[];
  recoveryResults: RecoveryResultRecord[];
  auditLog: IncidentAuditEntry[];
  detectionTime: string;
  lastStateTransitionTime: string;
  closedTime?: string;
  closureReason?: string;
  evidenceSummaryReport?: string;
  evidenceSnapshot?: {
    incidentId: string;
    ruleId: string;
    ruleName: string;
    ruleTitle: string;
    severity: string;
    confidence: number;
    detectionTimestamp: string;
    firstSeenTimestamp: string;
    evidenceCapturedTimestamp: string;
    pid: number;
    ppid: number | null;
    processName: string;
    executablePath: string | null;
    commandLine: string | null;
    username: string | null;
    processAncestry: Array<{ pid: number; name: string }>;
    executableHash: string | null;
    localEndpoint?: string;
    remoteEndpoint?: string;
    protocol?: string;
    socketState?: string;
    primaryProcess?: {
      name?: string;
      pid?: number;
      parentPid?: number | null;
      executablePath?: string | null;
      commandLine?: string | null;
      username?: string | null;
      executableHash?: string | null;
    };
    network?: {
      localEndpoint?: string;
      remoteEndpoint?: string;
      protocol?: string;
      socketState?: string;
    };
    mitreTechniques: string[];
    relevantFileEvents: Array<any>;
    monitoredFileHashes: Array<{ filePath: string; hash: string }>;
  };
  t_first_seen?: string;
  t_detected?: string;
  t_evidence_captured?: string;
  t_containment_started?: string;
  t_contained?: string;
  exposureDurationMs?: number;
  exposureDurationSeconds?: number;
  containmentStatus?: string;
  correlatedTrace?: any;
};

export function useIncidents() {
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchIncidents = useCallback(async () => {
    setLoading(true);
    try {
      const resp = await fetch("/api/incidents");
      if (resp.ok) {
        const data = await resp.json();
        if (Array.isArray(data.incidents)) {
          setIncidents(data.incidents);
          setError(null);
        }
      } else {
        setError(`HTTP error ${resp.status}`);
      }
    } catch (err: any) {
      setError(err?.message || "Failed to fetch incidents");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchIncidents();
    const interval = setInterval(fetchIncidents, 2000);
    return () => clearInterval(interval);
  }, [fetchIncidents]);

  const getIncidentById = useCallback(async (incidentId: string): Promise<IncidentRecord | null> => {
    try {
      const resp = await fetch(`/api/incidents/${incidentId}`);
      if (resp.ok) {
        const data = await resp.json();
        return data.incident || null;
      }
    } catch {
      // ignore error
    }
    return null;
  }, []);

  const triggerContainment = useCallback(
    async (incidentId: string, options?: { forceUserApproval?: boolean }) => {
      try {
        const resp = await fetch(`/api/incidents/${incidentId}/contain`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(options || {}),
        });
        const data = await resp.json();
        await fetchIncidents();
        return data;
      } catch (err: any) {
        return { success: false, message: err?.message || "Containment request failed" };
      }
    },
    [fetchIncidents]
  );

  const triggerRecovery = useCallback(
    async (
      incidentId: string,
      options?: { preferredSource?: string; userApprovalGranted?: boolean }
    ) => {
      try {
        const resp = await fetch(`/api/incidents/${incidentId}/recovery`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(options || {}),
        });
        const data = await resp.json();
        await fetchIncidents();
        return data;
      } catch (err: any) {
        return { success: false, message: err?.message || "Recovery request failed" };
      }
    },
    [fetchIncidents]
  );

  const closeIncident = useCallback(
    async (incidentId: string, reason?: string) => {
      try {
        const resp = await fetch(`/api/incidents/${incidentId}/close`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ reason: reason || "Resolved by operator" }),
        });
        const data = await resp.json();
        await fetchIncidents();
        return data;
      } catch (err: any) {
        return { success: false, message: err?.message || "Incident closure failed" };
      }
    },
    [fetchIncidents]
  );

  const fetchAuditLog = useCallback(async (incidentId: string): Promise<IncidentAuditEntry[]> => {
    try {
      const resp = await fetch(`/api/incidents/${incidentId}/audit`);
      if (resp.ok) {
        const data = await resp.json();
        return data.auditLog || [];
      }
    } catch {
      // ignore
    }
    return [];
  }, []);

  useEffect(() => {
    fetchIncidents();
    const interval = setInterval(fetchIncidents, 6000);
    return () => clearInterval(interval);
  }, [fetchIncidents]);

  return {
    incidents,
    loading,
    error,
    fetchIncidents,
    getIncidentById,
    triggerContainment,
    triggerRecovery,
    closeIncident,
    fetchAuditLog,
  };
}
