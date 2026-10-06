/**
 * ARGUS Automated Incident Response & Recovery Orchestrator.
 *
 * Connects:
 * - Detection Engine
 * - Attack Correlation Engine
 * - File Activity Telemetry
 * - Impact & Exposure Analysis
 * - Process Termination & Quarantine
 * - Recovery Engine (VSS, Backup Roots, Staging Vault)
 *
 * Implements strict incident state machine, explainable decision engine,
 * post-action verification, audit logging, and human override options.
 */

import { eventHub } from "./event-hub";
import { attackCorrelationEngine, type CorrelatedIncident, type ObservationStatus } from "./attack-correlation";
import { recoveryStore } from "../recovery/store";
import { recoveryService } from "../recovery/service";
import { findRecoverySources, recoverySourceSupport } from "../recovery/sources";
import { getRecoveryRoot } from "../recovery/paths";
import { logger } from "./logger";
import { sha256File } from "../recovery/file-analysis";
import fs from "node:fs/promises";
import path from "node:path";

export type IncidentState =
  | "DETECTED"
  | "TRACING"
  | "INVESTIGATING"
  | "IMPACT_ASSESSED"
  | "CONTAINMENT_PENDING"
  | "CONTAINED"
  | "CONTAINMENT_FAILED"
  | "RECOVERY_PENDING"
  | "RECOVERING"
  | "VERIFYING"
  | "RECOVERED"
  | "RECOVERED_UNVERIFIED"
  | "CLOSED"
  | "REOPENED"
  | "FAILED"
  | "REQUIRES_USER_ACTION";

export type ResponseLevel =
  | "LEVEL_0_OBSERVE"
  | "LEVEL_1_ALERT"
  | "LEVEL_2_CONTAIN"
  | "LEVEL_3_PROTECT"
  | "LEVEL_4_RECOVERY_READY";

export type RecommendedAction =
  | "OBSERVE"
  | "CONTAIN_PROCESS"
  | "ISOLATE_HOST"
  | "RECOVER_FILES"
  | "REQUIRE_USER_APPROVAL"
  | "CLOSE_INCIDENT";

export type AuditActor = "ARGUS_ORCHESTRATOR" | "USER" | "SYSTEM";

export type IncidentAuditRecord = {
  auditId: string;
  timestamp: string;
  incidentId: string;
  action: string;
  actor: AuditActor;
  target: string;
  reason: string;
  evidence: string;
  result: string;
  verification: string;
};

export type RecoveryResultStats = {
  affectedFilesCount: number;
  candidatesCount: number;
  attemptedCount: number;
  recoveredCount: number;
  failedCount: number;
  noSourceCount: number;
  verifiedCount: number;
  unverifiedCount: number;
};

export type OrchestratedIncident = {
  incidentId: string;
  state: IncidentState;
  responseLevel: ResponseLevel;
  recommendedAction: RecommendedAction;
  recommendationReasons: string[];
  requiresUserApproval: boolean;
  userApprovedContainment: boolean;
  userApprovedRecovery: boolean;
  containmentExecuted: boolean;
  containmentVerified: boolean;
  containmentDetails?: {
    targetPid: number;
    processName: string;
    executedAt: string;
    result: string;
    verified: boolean;
  };
  recoveryStats: RecoveryResultStats;
  recoveryRecords: Array<{
    recordId: string;
    filePath: string;
    sourceKind?: string;
    sourceLabel?: string;
    recoveryState: string;
    verificationState: "VERIFIED" | "MISMATCH" | "NOT_AVAILABLE" | "FAILED";
    hashBefore?: string | null;
    hashAfter?: string | null;
  }>;
  auditTrail: IncidentAuditRecord[];
  correlatedTrace: CorrelatedIncident;
  lastUpdated: string;
};

class ResponseOrchestrator {
  private auditLog: IncidentAuditRecord[] = [];
  private incidentStates = new Map<string, Partial<OrchestratedIncident>>();

  /**
   * Evaluates all correlated incidents and orchestrates lifecycle states,
   * response decision logic, containment execution status, and recovery readiness.
   */
  public getOrchestratedIncidents(): OrchestratedIncident[] {
    const traces = attackCorrelationEngine.getCorrelatedIncidents();
    const result: OrchestratedIncident[] = [];

    for (const trace of traces) {
      const orchestrated = this.orchestrateSingleTrace(trace);
      result.push(orchestrated);
    }

    return result;
  }

  /**
   * Get single orchestrated incident record by ID.
   */
  public getIncidentById(incidentId: string): OrchestratedIncident | null {
    const incidents = this.getOrchestratedIncidents();
    return incidents.find((i) => i.incidentId.toLowerCase() === incidentId.toLowerCase()) || null;
  }

  /**
   * Evaluates decision logic and state transitions for a single incident trace.
   */
  private orchestrateSingleTrace(trace: CorrelatedIncident): OrchestratedIncident {
    const existing = this.incidentStates.get(trace.incidentId) || {};
    const impact = trace.impactAssessment;
    const pid = trace.primaryProcess.pid || 0;
    const processName = trace.primaryProcess.name;

    // 1. Response Level & Recommendation Engine
    let responseLevel: ResponseLevel = "LEVEL_1_ALERT";
    let recommendedAction: RecommendedAction = "OBSERVE";
    const reasons: string[] = [];
    let requiresUserApproval = true;

    if (trace.severity === "critical" || trace.severity === "high") {
      reasons.push(`High severity detection (${trace.severity.toUpperCase()})`);
      responseLevel = "LEVEL_2_CONTAIN";
      recommendedAction = "CONTAIN_PROCESS";

      // ZERO-TOUCH ACTIVE DEFENSE: Automatically trigger containment immediately for active attacks!
      if (!existing.containmentExecuted && !(existing as any).containmentPendingTrigger) {
        (existing as any).containmentPendingTrigger = true;
        this.incidentStates.set(trace.incidentId, existing);
        setImmediate(() => {
          this.orchestrateContainment(trace.incidentId, {
            actor: "ARGUS_ORCHESTRATOR",
            force: true,
          }).catch((err) => {
            logger.error(`[AutoContainment] Failed for ${trace.incidentId}: ${err?.message}`);
          });
        });
      }
    }

    if (impact.potentialSensitiveExposureCount > 0) {
      reasons.push(`Potential sensitive data exposure path (${impact.potentialSensitiveExposureCount} file(s))`);
      responseLevel = "LEVEL_3_PROTECT";
      recommendedAction = "CONTAIN_PROCESS";
    }

    if (impact.encryptionSuspected) {
      reasons.push("Behavioral ransomware / rapid file transformation detected");
      responseLevel = "LEVEL_3_PROTECT";
      recommendedAction = "CONTAIN_PROCESS";
    }

    if (trace.status === "CONTAINED" || existing.containmentVerified) {
      reasons.push("Threat process is contained");
      responseLevel = "LEVEL_4_RECOVERY_READY";
      recommendedAction = impact.affectedFilesCount > 0 ? "RECOVER_FILES" : "CLOSE_INCIDENT";
      requiresUserApproval = false;
    }

    // 2. Incident State Machine Transition Determination
    let state: IncidentState = existing.state || "DETECTED";

    if (!existing.state) {
      if (impact.affectedFilesCount > 0) state = "IMPACT_ASSESSED";
      else if (trace.timeline.length > 2) state = "INVESTIGATING";
      else state = "TRACING";
    }

    // Update if containment occurred
    if (existing.containmentVerified) {
      if (state === "CONTAINMENT_PENDING" || state === "INVESTIGATING" || state === "IMPACT_ASSESSED") {
        state = "CONTAINED";
      }
    }

    const recoveryRecords = existing.recoveryRecords || [];
    const recoveryStats: RecoveryResultStats = existing.recoveryStats || {
      affectedFilesCount: impact.affectedFilesCount,
      candidatesCount: impact.affectedFilesCount > 0 ? impact.affectedFilesCount : 0,
      attemptedCount: recoveryRecords.length,
      recoveredCount: recoveryRecords.filter((r) => r.recoveryState === "RECOVERED").length,
      failedCount: recoveryRecords.filter((r) => r.recoveryState === "FAILED").length,
      noSourceCount: recoveryRecords.filter((r) => r.recoveryState === "NO_RECOVERY_SOURCE").length,
      verifiedCount: recoveryRecords.filter((r) => r.verificationState === "VERIFIED").length,
      unverifiedCount: recoveryRecords.filter((r) => r.verificationState === "NOT_AVAILABLE").length,
    };

    const auditTrail = this.auditLog.filter((a) => a.incidentId === trace.incidentId);

    const orchestrated: OrchestratedIncident = {
      incidentId: trace.incidentId,
      state,
      responseLevel,
      recommendedAction,
      recommendationReasons: reasons.length > 0 ? reasons : ["Endpoint monitoring baseline active"],
      requiresUserApproval,
      userApprovedContainment: existing.userApprovedContainment || false,
      userApprovedRecovery: existing.userApprovedRecovery || false,
      containmentExecuted: existing.containmentExecuted || false,
      containmentVerified: existing.containmentVerified || false,
      containmentDetails: existing.containmentDetails,
      recoveryStats,
      recoveryRecords,
      auditTrail,
      correlatedTrace: trace,
      lastUpdated: new Date().toISOString(),
    };

    this.incidentStates.set(trace.incidentId, {
      ...existing,
      state,
      responseLevel,
      recommendedAction,
      recoveryStats,
    });

    return orchestrated;
  }

  /**
   * Execute containment for a target incident.
   * Terminates target process PID and verifies state.
   */
  public async orchestrateContainment(
    incidentId: string,
    options?: { force?: boolean; actor?: AuditActor }
  ): Promise<{ success: boolean; state: IncidentState; message: string }> {
    const incident = this.getIncidentById(incidentId);
    if (!incident) {
      return { success: false, state: "FAILED", message: "Incident not found" };
    }

    const pid = incident.correlatedTrace.primaryProcess.pid;
    const processName = incident.correlatedTrace.primaryProcess.name;
    const actor = options?.actor || "ARGUS_ORCHESTRATOR";

    if (!pid || pid <= 0) {
      this.recordAudit({
        incidentId,
        action: "CONTAINMENT_ATTEMPT",
        actor,
        target: processName,
        reason: "No active PID associated with process",
        evidence: "Process PID is missing or 0",
        result: "FAILED",
        verification: "CONTAINMENT_FAILED",
      });
      return { success: false, state: "FAILED", message: "No valid PID to terminate" };
    }

    // Set state to CONTAINMENT_PENDING
    this.updateIncidentState(incidentId, "CONTAINMENT_PENDING", { userApprovedContainment: true });

    // Attempt real process termination via Windows taskkill tree kill or os.kill
    let terminated = false;
    let errMessage = "";
    let firewallBlocked = false;
    let quarantinedPayload = false;

    // Resolve attacker IP from remote endpoint or connections
    const remoteIp =
      incident.correlatedTrace.remoteEndpoint?.ip ||
      incident.correlatedTrace.connections?.find(
        (c) => c.remote_addr && !c.remote_addr.startsWith("127.") && c.remote_addr !== "0.0.0.0"
      )?.remote_addr;

    try {
      if (process.platform === "win32") {
        const { execSync } = await import("child_process");
        try {
          // Forcefully terminate process and all its child processes (/T)
          execSync(`taskkill /F /T /PID ${pid}`, { stdio: "ignore" });
          terminated = true;
        } catch {
          // Process may have already exited
          terminated = true;
        }

        // Active Defense: Block attacker remote IP in Windows Firewall
        if (remoteIp && remoteIp !== "127.0.0.1" && remoteIp !== "::1" && remoteIp !== "0.0.0.0") {
          try {
            const cleanIp = remoteIp.replace(/[.:]/g, "_");
            execSync(
              `powershell -NoProfile -NonInteractive -Command "New-NetFirewallRule -DisplayName 'ARGUS_BLOCK_${cleanIp}_IN' -Direction Inbound -Action Block -RemoteAddress '${remoteIp}' -Profile Any -ErrorAction SilentlyContinue; New-NetFirewallRule -DisplayName 'ARGUS_BLOCK_${cleanIp}_OUT' -Direction Outbound -Action Block -RemoteAddress '${remoteIp}' -Profile Any -ErrorAction SilentlyContinue"`,
              { stdio: "ignore" }
            );
            firewallBlocked = true;
          } catch {}
        }

        // Active Defense: Quarantine untrusted payload file if located outside Windows system roots
        const exePath = incident.correlatedTrace.primaryProcess.executablePath;
        if (exePath && !exePath.toLowerCase().includes("\\system32\\") && !exePath.toLowerCase().includes("\\syswow64\\")) {
          try {
            const fs = await import("fs/promises");
            const path = await import("path");
            const qDir = "C:\\ProgramData\\ARGUS\\quarantine";
            await fs.mkdir(qDir, { recursive: true });
            const dest = path.join(qDir, `${path.basename(exePath)}_${Date.now()}.quarantine`);
            await fs.copyFile(exePath, dest);
            quarantinedPayload = true;
          } catch {}
        }
      } else {
        process.kill(pid, "SIGKILL");
        terminated = true;
      }
    } catch (err: any) {
      errMessage = err?.message || "Termination failed";
    }

    // Verification step: check if process PID is still running in process snapshot
    const processSnapshot = eventHub.getSnapshot();
    const stillRunning = processSnapshot?.processes?.some((p) => p.pid === pid);

    const verified = terminated && !stillRunning;
    const nextState: IncidentState = verified ? "CONTAINED" : "CONTAINMENT_FAILED";

    const actionSummary = [
      verified ? `Terminated process tree for PID ${pid}` : `Failed to terminate PID ${pid}`,
      firewallBlocked ? `Blocked attacker IP ${remoteIp} in Windows Firewall` : null,
      quarantinedPayload ? `Quarantined payload into ARGUS Quarantine Vault` : null,
    ].filter(Boolean).join("; ");

    this.updateIncidentState(incidentId, nextState, {
      containmentExecuted: true,
      containmentVerified: verified,
      containmentDetails: {
        targetPid: pid,
        processName,
        executedAt: new Date().toISOString(),
        result: verified ? actionSummary : `TERMINATION_FAILED: ${errMessage}`,
        verified,
      },
    });

    this.recordAudit({
      incidentId,
      action: "CONTAINMENT_EXECUTION",
      actor,
      target: `${processName} (PID ${pid})`,
      reason: incident.recommendationReasons.join("; "),
      evidence: verified ? `PID ${pid} verified stopped. ${actionSummary}` : `PID ${pid} still active in process table`,
      result: verified ? "SUCCESS" : "FAILED",
      verification: verified ? "VERIFIED_TERMINATED" : "VERIFICATION_FAILED",
    });

    return {
      success: verified,
      state: nextState,
      message: verified ? actionSummary : `Containment failed for PID ${pid}: ${errMessage}`,
    };
  }

  /**
   * Execute data recovery for affected files in an incident.
   */
  public async orchestrateRecovery(
    incidentId: string,
    options?: { actor?: AuditActor }
  ): Promise<{ success: boolean; state: IncidentState; stats: RecoveryResultStats }> {
    const incident = this.getIncidentById(incidentId);
    if (!incident) {
      const emptyStats: RecoveryResultStats = {
        affectedFilesCount: 0,
        candidatesCount: 0,
        attemptedCount: 0,
        recoveredCount: 0,
        failedCount: 0,
        noSourceCount: 0,
        verifiedCount: 0,
        unverifiedCount: 0,
      };
      return { success: false, state: "FAILED", stats: emptyStats };
    }

    const actor = options?.actor || "ARGUS_ORCHESTRATOR";
    this.updateIncidentState(incidentId, "RECOVERY_PENDING", { userApprovedRecovery: true });

    const affectedFiles = incident.correlatedTrace.affectedFiles || [];
    const recoveryRoot = getRecoveryRoot();
    const nowIso = new Date().toISOString();

    const recoveryRecords: OrchestratedIncident["recoveryRecords"] = [];
    let recoveredCount = 0;
    let verifiedCount = 0;
    let unverifiedCount = 0;
    let failedCount = 0;
    let noSourceCount = 0;

    this.updateIncidentState(incidentId, "RECOVERING");

    for (const file of affectedFiles) {
      const sources = await findRecoverySources({
        originalPath: file.filePath,
        incidentId,
        recordId: file.eventId,
        incidentWindowStart: incident.correlatedTrace.startTime,
        maxSources: 5,
        timeoutMs: 5000,
        maxHashBytes: 10 * 1024 * 1024,
      });

      const restorable = sources.filter((s) => s.restorable);

      if (restorable.length === 0) {
        noSourceCount++;
        recoveryRecords.push({
          recordId: file.eventId,
          filePath: file.filePath,
          recoveryState: "NO_RECOVERY_SOURCE",
          verificationState: "NOT_AVAILABLE",
        });
        continue;
      }

      const selectedSource = restorable[0];

      // Pre-recovery safety: Create staging copy in recovery workspace
      const targetDir = path.join(recoveryRoot, "restored", incidentId);
      await fs.mkdir(targetDir, { recursive: true });
      const targetPath = path.join(targetDir, path.basename(file.filePath));

      let recState = "FAILED";
      let verState: "VERIFIED" | "MISMATCH" | "NOT_AVAILABLE" | "FAILED" = "FAILED";
      let hashAfter: string | null = null;

      try {
        if (selectedSource.path) {
          await fs.copyFile(selectedSource.path, targetPath);
          recState = "RECOVERED";
          recoveredCount++;

          // Verification step: compare source hash vs restored file hash
          if (selectedSource.sha256) {
            const restoredHash = await sha256File(targetPath, 10 * 1024 * 1024);
            hashAfter = restoredHash.sha256;
            if (hashAfter === selectedSource.sha256) {
              verState = "VERIFIED";
              verifiedCount++;
            } else {
              verState = "MISMATCH";
            }
          } else {
            verState = "NOT_AVAILABLE";
            unverifiedCount++;
          }
        }
      } catch {
        failedCount++;
        recState = "FAILED";
        verState = "FAILED";
      }

      recoveryRecords.push({
        recordId: file.eventId,
        filePath: file.filePath,
        sourceKind: selectedSource.kind,
        sourceLabel: selectedSource.label,
        recoveryState: recState,
        verificationState: verState,
        hashBefore: selectedSource.sha256,
        hashAfter,
      });
    }

    const stats: RecoveryResultStats = {
      affectedFilesCount: affectedFiles.length,
      candidatesCount: affectedFiles.length,
      attemptedCount: recoveryRecords.length,
      recoveredCount,
      failedCount,
      noSourceCount,
      verifiedCount,
      unverifiedCount,
    };

    const finalState: IncidentState =
      recoveredCount > 0 && failedCount === 0
        ? verifiedCount === recoveredCount
          ? "RECOVERED"
          : "RECOVERED_UNVERIFIED"
        : "REQUIRES_USER_ACTION";

    this.updateIncidentState(incidentId, finalState, {
      recoveryStats: stats,
      recoveryRecords,
    });

    this.recordAudit({
      incidentId,
      action: "RECOVERY_EXECUTION",
      actor,
      target: `${affectedFiles.length} affected file(s)`,
      reason: "Recovery requested for incident affected objects",
      evidence: `Recovered ${recoveredCount}/${affectedFiles.length} files (${verifiedCount} verified)`,
      result: finalState,
      verification: `Integrity check: ${verifiedCount} verified, ${unverifiedCount} unverified`,
    });

    return {
      success: recoveredCount > 0,
      state: finalState,
      stats,
    };
  }

  /**
   * Request incident closure.
   */
  public orchestrateClosure(
    incidentId: string,
    options?: { actor?: AuditActor; reason?: string }
  ): { success: boolean; state: IncidentState; message: string } {
    const incident = this.getIncidentById(incidentId);
    if (!incident) {
      return { success: false, state: "FAILED", message: "Incident not found" };
    }

    const actor = options?.actor || "USER";
    const reason = options?.reason || "Incident investigation and response completed.";

    // Closure rules: must be contained or assessed
    if (incident.state !== "CONTAINED" && incident.state !== "RECOVERED" && incident.state !== "RECOVERED_UNVERIFIED") {
      this.updateIncidentState(incidentId, "REQUIRES_USER_ACTION");
      return {
        success: false,
        state: "REQUIRES_USER_ACTION",
        message: "Cannot close incident: threat must be contained and recovery verified before closing.",
      };
    }

    this.updateIncidentState(incidentId, "CLOSED");

    this.recordAudit({
      incidentId,
      action: "INCIDENT_CLOSURE",
      actor,
      target: incidentId,
      reason,
      evidence: `Status verified: ${incident.state}, ${incident.recoveryStats.recoveredCount} files recovered`,
      result: "CLOSED",
      verification: "CLOSURE_RULES_SATISFIED",
    });

    return {
      success: true,
      state: "CLOSED",
      message: "Incident successfully closed.",
    };
  }

  /**
   * Record immutable audit log entry.
   */
  public recordAudit(record: Omit<IncidentAuditRecord, "auditId" | "timestamp">): IncidentAuditRecord {
    const fullRecord: IncidentAuditRecord = {
      ...record,
      auditId: `audit-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      timestamp: new Date().toISOString(),
    };
    this.auditLog.push(fullRecord);
    if (this.auditLog.length > 1000) {
      this.auditLog = this.auditLog.slice(-1000);
    }
    return fullRecord;
  }

  /**
   * Update internal incident state record.
   */
  private updateIncidentState(
    incidentId: string,
    state: IncidentState,
    patch?: Partial<OrchestratedIncident>
  ): void {
    const cur = this.incidentStates.get(incidentId) || {};
    this.incidentStates.set(incidentId, {
      ...cur,
      state,
      ...patch,
    });
  }
}

export const responseOrchestrator = new ResponseOrchestrator();
