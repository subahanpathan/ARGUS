/**
 * ARGUS Live Attack Trace UI Page.
 *
 * Visualizes correlated incident attack chains derived from real endpoint telemetry:
 * Remote Endpoint → Network Connection → Process → Parent/Child Process → Detection → File Activity → Impact Analysis
 *
 * Integrated in Phase 5 & 6 with Automated Incident Response Orchestration and Verified Data Recovery & Closure.
 */

import { useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock,
  Cpu,
  Database,
  ExternalLink,
  Eye,
  FileCheck,
  FileCode,
  FileKey,
  FileSearch,
  FileText,
  GitBranch,
  Globe,
  HardDrive,
  Info,
  Layers,
  Link2,
  Lock,
  Network,
  Radio,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  XCircle,
  Zap,
  Compass,
} from "lucide-react";
import {
  useAttackTraces,
  type AffectedFileRecord,
  type AttackTraceNode,
  type CorrelatedIncident,
  type DataFlowStep,
  type ImpactAssessment,
  type IncidentTimelineEvent,
  type ObservationStatus,
} from "@/hooks/use-attack-traces";
import {
  useIncidents,
  type IncidentRecord,
  type IncidentLifecycleState,
  type ContainmentActionRecord,
  type RecoveryResultRecord,
  type IncidentAuditEntry,
} from "@/hooks/use-incidents";

function cn(...values: Array<string | false | undefined | null>) {
  return values.filter(Boolean).join(" ");
}

function Card({ children, className, style, onClick }: any) {
  return (
    <div className={cn("card", className)} style={style} onClick={onClick}>
      {children}
    </div>
  );
}

/** Formats observation status badge with strict color coding */
function ObservationBadge({ status }: { status: ObservationStatus }) {
  switch (status) {
    case "OBSERVED":
      return (
        <span
          className="badge"
          style={{
            background: "hsl(142 71% 16%)",
            color: "hsl(142 71% 70%)",
            border: "1px solid hsl(142 71% 30%)",
            fontSize: 10,
            padding: "2px 7px",
            fontWeight: 700,
          }}
          title="Directly verified by host OS telemetry sensor"
        >
          ● OBSERVED
        </span>
      );
    case "CORRELATED":
      return (
        <span
          className="badge"
          style={{
            background: "hsl(217 91% 16%)",
            color: "hsl(217 91% 75%)",
            border: "1px solid hsl(217 91% 32%)",
            fontSize: 10,
            padding: "2px 7px",
            fontWeight: 700,
          }}
          title="Correlated across process, network, and detection telemetry"
        >
          ◈ CORRELATED
        </span>
      );
    case "INFERRED":
      return (
        <span
          className="badge"
          style={{
            background: "hsl(38 92% 16%)",
            color: "hsl(38 92% 70%)",
            border: "1px solid hsl(38 92% 30%)",
            fontSize: 10,
            padding: "2px 7px",
            fontWeight: 700,
          }}
          title="Inferred relationship based on process socket and flow volume"
        >
          ▲ INFERRED
        </span>
      );
    default:
      return (
        <span
          className="badge badge-muted"
          style={{ fontSize: 10, padding: "2px 7px" }}
          title="Unverified telemetry"
        >
          ? UNKNOWN
        </span>
      );
  }
}

function SeverityBadge({ severity }: { severity: string }) {
  const sev = severity.toLowerCase();
  const cls =
    sev === "critical"
      ? "badge-critical"
      : sev === "high"
      ? "badge-high"
      : sev === "medium"
      ? "badge-medium"
      : "badge-low";
  return <span className={cn("badge", cls)}>{severity.toUpperCase()}</span>;
}

function StateBadge({ state }: { state: IncidentLifecycleState | string }) {
  let bg = "hsl(217 91% 16%)";
  let color = "hsl(217 91% 75%)";
  let label = state;

  if (state === "CONTAINED" || state === "RECOVERED" || state === "CLOSED") {
    bg = "hsl(142 71% 16%)";
    color = "hsl(142 71% 70%)";
  } else if (state === "CONTAINMENT_PENDING" || state === "RECOVERY_PENDING" || state === "REQUIRES_USER_ACTION") {
    bg = "hsl(38 92% 16%)";
    color = "hsl(38 92% 70%)";
  } else if (state === "FAILED") {
    bg = "hsl(0 84% 16%)";
    color = "hsl(0 84% 70%)";
  }

  return (
    <span
      className="badge"
      style={{
        background: bg,
        color: color,
        fontSize: 10,
        padding: "2px 8px",
        fontWeight: 700,
        textTransform: "uppercase",
      }}
    >
      ● {label}
    </span>
  );
}

function getNodeIcon(type: AttackTraceNode["type"]) {
  switch (type) {
    case "ENDPOINT":
    case "remote_endpoint":
      return Globe;
    case "CONNECTION":
    case "network_connection":
    case "outbound_socket":
      return Network;
    case "PROCESS":
    case "process":
    case "parent_process":
    case "child_process":
      return Terminal;
    case "DETECTION":
    case "detection":
      return ShieldAlert;
    case "FILE_ACTIVITY":
      return FileSearch;
    case "AFFECTED_FILES":
      return FileText;
    default:
      return Layers;
  }
}

function getNodeColorClass(type: AttackTraceNode["type"]) {
  switch (type) {
    case "ENDPOINT":
    case "remote_endpoint":
      return "hsl(280 75% 65%)";
    case "CONNECTION":
    case "network_connection":
    case "outbound_socket":
      return "hsl(199 89% 60%)";
    case "parent_process":
      return "hsl(215 85% 65%)";
    case "PROCESS":
    case "process":
      return "hsl(38 92% 55%)";
    case "child_process":
      return "hsl(15 85% 60%)";
    case "DETECTION":
    case "detection":
      return "hsl(0 84% 60%)";
    case "FILE_ACTIVITY":
      return "hsl(142 71% 55%)";
    case "AFFECTED_FILES":
      return "hsl(330 80% 60%)";
    default:
      return "hsl(var(--primary))";
  }
}

export default function AttackTracePage({
  toast,
  onNavigate,
}: {
  toast?: (title: string, body: string) => void;
  onNavigate?: (path: string) => void;
}) {
  const {
    connected,
    incidents: correlatedIncidents,
    selectedIncident,
    selectedNode,
    selectedTimelineEvent,
    selectIncident,
    selectNode,
    selectTimelineEvent,
    refresh,
  } = useAttackTraces();

  const {
    incidents: managedIncidents,
    triggerContainment,
    triggerRecovery,
    closeIncident,
    fetchIncidents: refreshManagedIncidents,
  } = useIncidents();

  const [activeTab, setActiveTab] = useState<
    "graph" | "timeline" | "impact" | "files" | "dataflow" | "orchestration" | "recovery"
  >("graph");
  const [preferredRecoverySource, setPreferredRecoverySource] = useState<string>("VSS_SHADOW_COPY");
  const [isProcessing, setIsProcessing] = useState(false);

  // Match current correlated incident with managed incident state record
  const currentManagedIncident: IncidentRecord | undefined = useMemo(() => {
    if (!selectedIncident) return undefined;
    return managedIncidents.find((i) => i.incidentId === selectedIncident.incidentId);
  }, [selectedIncident, managedIncidents]);

  // Format active duration
  const durationLabel = useMemo(() => {
    if (!selectedIncident) return "—";
    const duration = selectedIncident.durationSeconds;
    if (typeof duration === "number") {
      if (duration < 60) return `${duration}s`;
      return `${Math.floor(duration / 60)}m ${duration % 60}s`;
    }
    return "Live";
  }, [selectedIncident]);

  const primaryProcName =
    selectedIncident?.primaryProcess?.name || selectedIncident?.primaryProcessName || "Unknown Process";
  const primaryPidVal = selectedIncident?.primaryProcess?.pid || selectedIncident?.primaryPid || 0;
  const obsSourceLabel =
    typeof selectedIncident?.observableSource === "object"
      ? selectedIncident.observableSource.label
      : selectedIncident?.observableSource || "Process association unavailable";

  const graphNodes = selectedIncident?.graph?.nodes || selectedIncident?.nodes || [];
  const graphEdges = selectedIncident?.graph?.edges || selectedIncident?.edges || [];
  const impact = selectedIncident?.impactAssessment;
  const affectedFiles = selectedIncident?.affectedFiles || [];
  const dataFlow = selectedIncident?.dataFlowChain || [];

  const currentState = currentManagedIncident?.state || "INVESTIGATING";
  const responseLevel = currentManagedIncident?.responseLevel ?? 2;
  const responseLabel = currentManagedIncident?.responseLevelLabel || "CONTAIN_PROCESS_AND_FILE";

  const handleContainmentAction = async () => {
    if (!selectedIncident) return;
    setIsProcessing(true);
    toast?.("Executing Containment", `Initiating process termination and file quarantine for PID ${primaryPidVal}...`);
    const res = await triggerContainment(selectedIncident.incidentId);
    setIsProcessing(false);
    if (res.success) {
      toast?.("Containment Executed", res.message || "Process terminated & file quarantine completed.");
    } else {
      toast?.("Containment Alert", res.message || "Containment action required operator attention.");
    }
  };

  const handleRecoveryAction = async () => {
    if (!selectedIncident) return;
    setIsProcessing(true);
    toast?.("Initiating Verified Recovery", `Restoring files using ${preferredRecoverySource} source...`);
    const res = await triggerRecovery(selectedIncident.incidentId, {
      preferredSource: preferredRecoverySource,
      userApprovalGranted: true,
    });
    setIsProcessing(false);
    if (res.success) {
      toast?.("Recovery Completed", res.message || "Files recovered and verified with SHA-256 integrity check.");
    } else {
      toast?.("Recovery Notice", res.message || "Recovery completed with warnings.");
    }
  };

  const handleCloseIncidentAction = async () => {
    if (!selectedIncident) return;
    setIsProcessing(true);
    toast?.("Closing Incident", "Generating evidence summary report and archiving incident...");
    const res = await closeIncident(selectedIncident.incidentId, "Resolved & Verified by Endpoint Operator");
    setIsProcessing(false);
    if (res.success) {
      toast?.("Incident Closed", "Incident closed successfully with immutable audit trail.");
    } else {
      toast?.("Closure Error", res.message || "Failed to close incident.");
    }
  };

  return (
    <div className="animate-page-enter">
      {/* Page Heading */}
      <div className="page-heading">
        <div>
          <div className="eyebrow">
            Live Attack Correlation & Automated Response Engine · Endpoint Protection
          </div>
          <h1 className="page-title">Live Attack Trace, Response & Verified Recovery</h1>
          <p className="page-subtitle">
            Correlates process ancestry, sockets, detections, and file activity into explainable attack chains with automated response orchestration and SHA-256 verified data recovery.
          </p>
        </div>

        <div className="actions" style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <span
            className={cn("badge", connected ? "badge-low" : "badge-muted")}
            style={
              connected
                ? {
                    background: "hsl(142 71% 20%)",
                    color: "hsl(142 71% 70%)",
                    border: "1px solid hsl(142 71% 30%)",
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 5,
                  }
                : {}
            }
          >
            <Radio size={10} />
            {connected ? "CORRELATION STREAM ACTIVE" : "ENGINE DISCONNECTED"}
          </span>

          <button
            type="button"
            className="btn btn-primary"
            onClick={() => onNavigate?.("/backtrace")}
            style={{ fontSize: 11, padding: "4px 10px", height: 28 }}
          >
            <Compass size={12} style={{ marginRight: 5 }} /> 3D Backtrace Mode
          </button>

          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => {
              refresh();
              refreshManagedIncidents();
              toast?.("Attack Traces Refreshed", "Loaded latest correlated incident traces.");
            }}
            style={{ fontSize: 11, padding: "4px 10px", height: 28 }}
          >
            <RefreshCw size={12} style={{ marginRight: 5 }} /> Refresh
          </button>
        </div>
      </div>

      {/* Incident Switcher Bar */}
      {correlatedIncidents.length > 0 && (
        <section
          className="card card-pad"
          style={{
            marginBottom: 16,
            background: "linear-gradient(100deg, hsl(var(--card)) 60%, hsl(var(--muted) / 0.8))",
            border: "1px solid hsl(var(--border))",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <GitBranch size={16} style={{ color: "hsl(var(--primary))" }} />
              <span style={{ fontSize: 12, fontWeight: 700 }}>Correlated Incidents ({correlatedIncidents.length}):</span>
            </div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", flex: 1 }}>
              {correlatedIncidents.map((inc) => {
                const isSelected = selectedIncident?.incidentId === inc.incidentId;
                const procName = inc.primaryProcess?.name || inc.primaryProcessName || "process";
                const incManaged = managedIncidents.find((m) => m.incidentId === inc.incidentId);
                return (
                  <button
                    key={inc.incidentId}
                    type="button"
                    className={cn("btn btn-sm", isSelected ? "btn-primary" : "btn-ghost")}
                    style={{ fontSize: 11, padding: "3px 10px", height: 28 }}
                    onClick={() => selectIncident(inc.incidentId)}
                  >
                    <span className="mono">{inc.incidentId}</span>
                    <span style={{ marginLeft: 6, opacity: 0.8 }}>({procName})</span>
                    <SeverityBadge severity={inc.severity} />
                    {incManaged && <StateBadge state={incManaged.state} />}
                  </button>
                );
              })}
            </div>
          </div>
        </section>
      )}

      {/* Main Incident Display or Clean Empty State */}
      {!selectedIncident ? (
        /* Empty State */
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <section className="card card-pad" style={{ textAlign: "center", padding: "48px 24px" }}>
            <div
              style={{
                width: 54,
                height: 54,
                borderRadius: "50%",
                background: "hsl(var(--muted))",
                display: "inline-flex",
                alignItems: "center",
                justifyContent: "center",
                marginBottom: 16,
                color: "hsl(var(--accent))",
              }}
            >
              <ShieldCheck size={28} />
            </div>
            <h2 style={{ fontSize: 18, fontWeight: 700, marginBottom: 8 }}>
              No Active Hostile Incident
            </h2>
            <p
              className="muted"
              style={{ maxWidth: 540, margin: "0 auto 20px auto", fontSize: 13, lineHeight: 1.5 }}
            >
              The ARGUS Response Orchestrator & Attack Correlation Engine are actively monitoring process ancestry, network sockets, file activity, and VSS shadow copies. No hostile attack chain requires containment.
            </p>
            <div style={{ display: "flex", gap: 12, justifyContent: "center", flexWrap: "wrap" }}>
              <span
                className="badge badge-low"
                style={{
                  background: "hsl(142 71% 16%)",
                  color: "hsl(142 71% 70%)",
                  padding: "6px 12px",
                  fontSize: 11,
                }}
              >
                ● RESPONSE ORCHESTRATOR READY
              </span>
              <span
                className="badge badge-muted"
                style={{ padding: "6px 12px", fontSize: 11 }}
              >
                VSS SHADOW COPY ENGINE ACTIVE
              </span>
            </div>
          </section>

          {/* Active Sensor Status Summary */}
          <div className="grid metrics" style={{ gridTemplateColumns: "repeat(4, 1fr)" }}>
            <div className="card card-pad">
              <div className="metric-label">
                <Terminal size={13} style={{ marginRight: 6, verticalAlign: "middle" }} />
                Process Containment
              </div>
              <div className="metric-value signal-good">READY</div>
              <div className="metric-note">Empirical Win32 PID termination</div>
            </div>
            <div className="card card-pad">
              <div className="metric-label">
                <Lock size={13} style={{ marginRight: 6, verticalAlign: "middle" }} />
                File Quarantine Vault
              </div>
              <div className="metric-value signal-good">ACTIVE</div>
              <div className="metric-note">Isolation & write protection</div>
            </div>
            <div className="card card-pad">
              <div className="metric-label">
                <Database size={13} style={{ marginRight: 6, verticalAlign: "middle" }} />
                Verified Data Recovery
              </div>
              <div className="metric-value signal-good">VSS / STAGING</div>
              <div className="metric-note">SHA-256 hash match verification</div>
            </div>
            <div className="card card-pad">
              <div className="metric-label">
                <ShieldAlert size={13} style={{ marginRight: 6, verticalAlign: "middle" }} />
                Orchestrator Lifecycle
              </div>
              <div className="metric-value signal-good">12-STATE MACHINE</div>
              <div className="metric-note">Immutable audit logging</div>
            </div>
          </div>
        </div>
      ) : (
        /* Active Correlated Incident View */
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          {/* Incident Header Stats & Lifecycle State Machine */}
          <section className="card card-pad">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 16, flexWrap: "wrap", marginBottom: 16 }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
                  <span className="mono" style={{ fontSize: 18, fontWeight: 800 }}>
                    {selectedIncident.incidentId}
                  </span>
                  <SeverityBadge severity={selectedIncident.severity} />
                  <StateBadge state={currentState} />
                  <span
                    className="badge"
                    style={{
                      background: "hsl(280 75% 16%)",
                      color: "hsl(280 75% 75%)",
                      border: "1px solid hsl(280 75% 30%)",
                      fontSize: 10,
                    }}
                  >
                    LEVEL {responseLevel}: {responseLabel}
                  </span>
                </div>
                <div className="muted" style={{ fontSize: 12 }}>
                  Primary Entity: <b style={{ color: "hsl(var(--foreground))" }}>{primaryProcName}</b> (PID {primaryPidVal}) · Source: <b style={{ color: "hsl(var(--foreground))" }}>{obsSourceLabel}</b>
                </div>
              </div>

              <div style={{ display: "flex", gap: 16, alignItems: "center" }}>
                <div style={{ textAlign: "right" }}>
                  <div className="muted" style={{ fontSize: 10 }}>DAMAGE SCORE</div>
                  <div className="mono" style={{ fontSize: 16, fontWeight: 800, color: impact?.damageScore != null ? (impact.damageScore > 50 ? "hsl(var(--destructive))" : "hsl(var(--primary))") : "hsl(var(--muted-foreground))" }}>
                    {impact?.damageScore != null ? `${impact.damageScore} / 100` : "INCOMPLETE"}
                  </div>
                </div>
                <div style={{ textAlign: "right" }}>
                  <div className="muted" style={{ fontSize: 10 }}>CONFIDENCE SCORE</div>
                  <div className="mono" style={{ fontSize: 16, fontWeight: 700, color: "hsl(var(--primary))" }}>
                    {Math.round(selectedIncident.confidence * 100)}%
                  </div>
                </div>
                <div style={{ textAlign: "right" }}>
                  <div className="muted" style={{ fontSize: 10 }}>TRACE DURATION</div>
                  <div className="mono" style={{ fontSize: 16, fontWeight: 700 }}>
                    {durationLabel}
                  </div>
                </div>
                <div style={{ textAlign: "right" }}>
                  <div className="muted" style={{ fontSize: 10 }}>AFFECTED FILES</div>
                  <div className="mono" style={{ fontSize: 16, fontWeight: 700 }}>
                    {impact?.affectedFilesCount ?? affectedFiles.length}
                  </div>
                </div>
              </div>
            </div>

            {/* Lifecycle Machine Progress Bar */}
            <div style={{ borderTop: "1px solid hsl(var(--border))", paddingTop: 12 }}>
              <div className="muted" style={{ fontSize: 10, fontWeight: 700, marginBottom: 8, letterSpacing: "0.05em" }}>
                INCIDENT LIFECYCLE STATE MACHINE (PHASE 5 & 6)
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 4, flexWrap: "wrap" }}>
                {[
                  "DETECTED",
                  "TRACING",
                  "INVESTIGATING",
                  "IMPACT_ASSESSED",
                  "CONTAINMENT_PENDING",
                  "CONTAINED",
                  "RECOVERY_PENDING",
                  "RECOVERING",
                  "VERIFYING",
                  "RECOVERED",
                  "CLOSED",
                ].map((st, idx) => {
                  const statesOrder = [
                    "DETECTED",
                    "TRACING",
                    "INVESTIGATING",
                    "IMPACT_ASSESSED",
                    "CONTAINMENT_PENDING",
                    "CONTAINED",
                    "RECOVERY_PENDING",
                    "RECOVERING",
                    "VERIFYING",
                    "RECOVERED",
                    "CLOSED",
                  ];
                  const currentIdx = statesOrder.indexOf(currentState);
                  const isCurrent = currentState === st;
                  const isPassed = currentIdx >= idx;

                  return (
                    <div
                      key={st}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 4,
                        fontSize: 10,
                        padding: "3px 8px",
                        borderRadius: 4,
                        background: isCurrent
                          ? "hsl(var(--primary))"
                          : isPassed
                          ? "hsl(var(--muted))"
                          : "transparent",
                        color: isCurrent
                          ? "hsl(var(--primary-foreground))"
                          : isPassed
                          ? "hsl(var(--foreground))"
                          : "hsl(var(--muted-foreground))",
                        fontWeight: isCurrent ? 700 : 500,
                        border: isCurrent ? "1px solid hsl(var(--primary))" : "1px solid hsl(var(--border))",
                      }}
                    >
                      <span>{st}</span>
                      {idx < 10 && <ArrowRight size={10} style={{ opacity: 0.5 }} />}
                    </div>
                  );
                })}
              </div>
            </div>
          </section>

          {/* View Mode Selector Tabs */}
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button
              type="button"
              className={cn("btn", activeTab === "graph" ? "btn-primary" : "btn-ghost")}
              style={{ fontSize: 11, padding: "4px 12px" }}
              onClick={() => setActiveTab("graph")}
            >
              <GitBranch size={13} style={{ marginRight: 6 }} /> Attack Graph Chain
            </button>
            <button
              type="button"
              className={cn("btn", activeTab === "impact" ? "btn-primary" : "btn-ghost")}
              style={{ fontSize: 11, padding: "4px 12px" }}
              onClick={() => setActiveTab("impact")}
            >
              <ShieldAlert size={13} style={{ marginRight: 6 }} /> Impact Assessment
            </button>
            <button
              type="button"
              className={cn("btn", activeTab === "files" ? "btn-primary" : "btn-ghost")}
              style={{ fontSize: 11, padding: "4px 12px" }}
              onClick={() => setActiveTab("files")}
            >
              <FileText size={13} style={{ marginRight: 6 }} /> Affected Files ({affectedFiles.length})
            </button>
            <button
              type="button"
              className={cn("btn", activeTab === "dataflow" ? "btn-primary" : "btn-ghost")}
              style={{ fontSize: 11, padding: "4px 12px" }}
              onClick={() => setActiveTab("dataflow")}
            >
              <Layers size={13} style={{ marginRight: 6 }} /> Data Flow Pipeline
            </button>
            <button
              type="button"
              className={cn("btn", activeTab === "timeline" ? "btn-primary" : "btn-ghost")}
              style={{ fontSize: 11, padding: "4px 12px" }}
              onClick={() => setActiveTab("timeline")}
            >
              <Clock size={13} style={{ marginRight: 6 }} /> Timeline ({selectedIncident.timeline.length})
            </button>

            {/* Phase 5 & 6 Special Tabs */}
            <button
              type="button"
              className={cn("btn", activeTab === "orchestration" ? "btn-primary" : "btn-ghost")}
              style={{ fontSize: 11, padding: "4px 12px", background: activeTab === "orchestration" ? undefined : "hsl(38 92% 16%)", color: activeTab === "orchestration" ? undefined : "hsl(38 92% 75%)" }}
              onClick={() => setActiveTab("orchestration")}
            >
              <Zap size={13} style={{ marginRight: 6 }} /> Containment Orchestration
            </button>
            <button
              type="button"
              className={cn("btn", activeTab === "recovery" ? "btn-primary" : "btn-ghost")}
              style={{ fontSize: 11, padding: "4px 12px", background: activeTab === "recovery" ? undefined : "hsl(142 71% 16%)", color: activeTab === "recovery" ? undefined : "hsl(142 71% 75%)" }}
              onClick={() => setActiveTab("recovery")}
            >
              <Database size={13} style={{ marginRight: 6 }} /> Verified Recovery & Closure
            </button>
          </div>

          {/* Tab 1: Attack Graph Chain */}
          {activeTab === "graph" && (
            <div className="grid split-grid" style={{ gridTemplateColumns: "1fr 340px", gap: 16 }}>
              <Card className="card-pad" style={{ minHeight: 420 }}>
                <div className="panel-title" style={{ marginBottom: 16 }}>
                  <h2>Visual Attack Chain Graph</h2>
                  <span className="muted" style={{ fontSize: 11 }}>
                    Remote → Network → Process → Detection → File Activity → Impact
                  </span>
                </div>

                <div style={{ display: "flex", flexDirection: "column", gap: 12, padding: "16px 8px" }}>
                  {graphNodes.map((node, index) => {
                    const IconComponent = getNodeIcon(node.type);
                    const nodeColor = getNodeColorClass(node.type);
                    const isSelected = selectedNode?.id === node.id;
                    const nextEdge = graphEdges.find((e) => e.source === node.id);

                    return (
                      <div key={node.id} style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                        <div
                          className={cn("card", isSelected && "card-selected")}
                          style={{
                            padding: "12px 16px",
                            cursor: "pointer",
                            borderLeft: `4px solid ${nodeColor}`,
                            background: isSelected ? "hsl(var(--primary) / 0.12)" : "hsl(var(--card))",
                            transition: "all 0.15s ease",
                          }}
                          onClick={() => selectNode(node)}
                        >
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
                            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                              <div
                                style={{
                                  width: 32,
                                  height: 32,
                                  borderRadius: 6,
                                  background: `${nodeColor}22`,
                                  color: nodeColor,
                                  display: "flex",
                                  alignItems: "center",
                                  justifyContent: "center",
                                }}
                              >
                                <IconComponent size={16} />
                              </div>
                              <div>
                                <div style={{ fontSize: 13, fontWeight: 700 }}>
                                  {node.label}
                                </div>
                                <div className="muted mono" style={{ fontSize: 10 }}>
                                  {node.sublabel || `Type: ${node.type}`}
                                </div>
                              </div>
                            </div>

                            <ObservationBadge status={node.observationStatus} />
                          </div>
                        </div>

                        {index < graphNodes.length - 1 && (
                          <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8, padding: "2px 0" }}>
                            <div style={{ height: 16, width: 2, background: "hsl(var(--border))" }} />
                            {nextEdge && (
                              <div
                                className="mono muted"
                                style={{
                                  fontSize: 10,
                                  background: "hsl(var(--muted))",
                                  padding: "2px 8px",
                                  borderRadius: 10,
                                  border: "1px solid hsl(var(--border))",
                                }}
                              >
                                {nextEdge.relationship || nextEdge.label}
                              </div>
                            )}
                            <div style={{ height: 16, width: 2, background: "hsl(var(--border))" }} />
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </Card>

              {/* Node Inspector */}
              <Card className="card-pad" style={{ height: "fit-content" }}>
                <div className="panel-title" style={{ marginBottom: 12 }}>
                  <h2>Node Inspector</h2>
                </div>

                {!selectedNode ? (
                  <div className="muted" style={{ fontSize: 12, padding: "20px 0", textAlign: "center" }}>
                    <Info size={24} style={{ marginBottom: 8, opacity: 0.6 }} />
                    <p>Select any node in the graph to inspect exact process telemetry, socket state, file operations, or rule matches.</p>
                  </div>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                    <div>
                      <div className="eyebrow">{selectedNode.type}</div>
                      <h3 style={{ fontSize: 15, fontWeight: 700 }}>{selectedNode.label}</h3>
                      <div style={{ marginTop: 6 }}>
                        <ObservationBadge status={selectedNode.observationStatus} />
                      </div>
                    </div>

                    <div style={{ borderTop: "1px solid hsl(var(--border))", paddingTop: 10 }}>
                      <div style={{ fontSize: 11, fontWeight: 700, marginBottom: 6 }}>Node Metadata:</div>
                      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                        {selectedNode.pid && <div style={{ fontSize: 11 }}><span className="muted mono">PID: </span><span className="mono">{selectedNode.pid}</span></div>}
                        {selectedNode.processName && <div style={{ fontSize: 11 }}><span className="muted mono">Process: </span><span className="mono">{selectedNode.processName}</span></div>}
                        {selectedNode.executablePath && <div style={{ fontSize: 11 }}><span className="muted mono">Executable: </span><span className="mono" style={{ wordBreak: "break-all" }}>{selectedNode.executablePath}</span></div>}
                        {selectedNode.ip && <div style={{ fontSize: 11 }}><span className="muted mono">Remote IP: </span><span className="mono">{selectedNode.ip}:{selectedNode.port}</span></div>}
                        {selectedNode.ruleId && <div style={{ fontSize: 11 }}><span className="muted mono">Rule ID: </span><span className="mono">{selectedNode.ruleId}</span></div>}
                      </div>
                    </div>
                  </div>
                )}
              </Card>
            </div>
          )}

          {/* Tab 2: Impact Assessment & Score */}
          {activeTab === "impact" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div className="grid metrics" style={{ gridTemplateColumns: "repeat(6, 1fr)" }}>
                <div className="card card-pad">
                  <div className="metric-label">Affected Files</div>
                  <div className="metric-value signal-good">{impact?.affectedFilesCount ?? 0}</div>
                  <div className="metric-note">Total file events</div>
                </div>
                <div className="card card-pad">
                  <div className="metric-label">Modified</div>
                  <div className="metric-value signal-warn">{impact?.counts?.modified ?? 0}</div>
                  <div className="metric-note">Content updates</div>
                </div>
                <div className="card card-pad">
                  <div className="metric-label">Created</div>
                  <div className="metric-value signal-info">{impact?.counts?.created ?? 0}</div>
                  <div className="metric-note">New files</div>
                </div>
                <div className="card card-pad">
                  <div className="metric-label">Renamed</div>
                  <div className="metric-value signal-warn">{impact?.counts?.renamed ?? 0}</div>
                  <div className="metric-note">Path changes</div>
                </div>
                <div className="card card-pad">
                  <div className="metric-label">Deleted</div>
                  <div className="metric-value signal-danger">{impact?.counts?.deleted ?? 0}</div>
                  <div className="metric-note">File removals</div>
                </div>
                <div className="card card-pad">
                  <div className="metric-label">Sensitive Exposure</div>
                  <div className="metric-value signal-danger">{impact?.potentialSensitiveExposureCount ?? 0}</div>
                  <div className="metric-note">Potential exfiltration</div>
                </div>
              </div>

              <Card className="card-pad">
                <div className="panel-title" style={{ marginBottom: 14 }}>
                  <h2>Explainable Impact Assessment</h2>
                  <span className="badge badge-low" style={{ background: "hsl(217 91% 16%)", color: "hsl(217 91% 75%)" }}>
                    EVIDENCE CONFIDENCE: {impact?.evidenceConfidence || "INCOMPLETE"}
                  </span>
                </div>

                <div style={{ display: "flex", gap: 24, alignItems: "center", flexWrap: "wrap" }}>
                  <div
                    style={{
                      width: 110,
                      height: 110,
                      borderRadius: "50%",
                      border: `6px solid ${impact?.damageScore != null && impact.damageScore > 50 ? "hsl(var(--destructive))" : "hsl(var(--primary))"}`,
                      display: "flex",
                      flexDirection: "column",
                      alignItems: "center",
                      justifyContent: "center",
                      textAlign: "center",
                    }}
                  >
                    <span style={{ fontSize: 24, fontWeight: 800 }}>
                      {impact?.damageScore != null ? impact.damageScore : "—"}
                    </span>
                    <span className="muted" style={{ fontSize: 10 }}>DAMAGE SCORE</span>
                  </div>

                  <div style={{ flex: 1, minWidth: 280 }}>
                    <h3 style={{ fontSize: 15, fontWeight: 700, marginBottom: 6 }}>
                      Impact Rationale & Evidence Breakdown
                    </h3>
                    <p className="muted" style={{ fontSize: 13, lineHeight: 1.5, marginBottom: 10 }}>
                      {impact?.damageScoreExplanation || "Insufficient file telemetry to determine damage score."}
                    </p>

                    <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                      {impact?.encryptionSuspected && (
                        <span className="badge badge-critical">
                          ⚠️ ENCRYPTION / RANSOMWARE PATTERN SUSPECTED
                        </span>
                      )}
                      {impact?.potentialSensitiveExposureCount ? (
                        <span className="badge badge-high">
                          🛡️ POTENTIAL SENSITIVE DATA EXPOSURE PATH
                        </span>
                      ) : null}
                    </div>
                  </div>
                </div>
              </Card>
            </div>
          )}

          {/* Tab 3: Affected Files Table */}
          {activeTab === "files" && (
            <Card className="card-pad">
              <div className="panel-title" style={{ marginBottom: 14 }}>
                <h2>Affected Files Inventory</h2>
                <span className="muted" style={{ fontSize: 11 }}>
                  Real-time filesystem events linked to incident {selectedIncident.incidentId}
                </span>
              </div>

              {affectedFiles.length === 0 ? (
                <div className="muted" style={{ padding: "32px 0", textAlign: "center" }}>
                  No affected files recorded for this incident.
                </div>
              ) : (
                <div className="table-wrap">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Operation</th>
                        <th>File Path</th>
                        <th>Category</th>
                        <th>Impact State</th>
                        <th>Process (PID)</th>
                        <th>Observation</th>
                        <th>Hash Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {affectedFiles.map((file) => (
                        <tr key={file.eventId}>
                          <td className="mono">{new Date(file.timestamp).toLocaleTimeString()}</td>
                          <td>
                            <span className={cn("badge", file.operation === "DELETE" ? "badge-critical" : file.operation === "MODIFY" ? "badge-high" : "badge-low")}>
                              {file.operation}
                            </span>
                          </td>
                          <td className="mono" style={{ fontSize: 11, maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {file.filePath}
                            {file.oldFilePath && (
                              <div className="muted" style={{ fontSize: 10 }}>
                                (Renamed from {file.oldFilePath})
                              </div>
                            )}
                          </td>
                          <td>
                            <span className="badge badge-muted">{file.classification}</span>
                          </td>
                          <td>
                            <span className={cn("badge", file.impactState === "ENCRYPTION_SUSPECTED" ? "badge-critical" : "badge-medium")}>
                              {file.impactState}
                            </span>
                          </td>
                          <td className="mono">
                            {file.processName} (PID {file.pid || "—"})
                          </td>
                          <td>
                            <ObservationBadge status={file.observationStatus} />
                          </td>
                          <td className="mono" style={{ fontSize: 10 }}>
                            {file.hashStatus}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>
          )}

          {/* Tab 4: Data Flow Pipeline */}
          {activeTab === "dataflow" && (
            <Card className="card-pad">
              <div className="panel-title" style={{ marginBottom: 16 }}>
                <h2>Conceptual Data Flow Pipeline</h2>
                <span className="muted" style={{ fontSize: 11 }}>
                  Threat Entry → Process Execution → Data Access / Modification → Outbound Communication
                </span>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                {dataFlow.map((step, idx) => (
                  <div
                    key={idx}
                    style={{
                      display: "flex",
                      gap: 16,
                      alignItems: "flex-start",
                      borderLeft: "3px solid hsl(var(--primary))",
                      paddingLeft: 16,
                      paddingBottom: 8,
                    }}
                  >
                    <div
                      style={{
                        width: 28,
                        height: 28,
                        borderRadius: "50%",
                        background: "hsl(var(--primary) / 0.15)",
                        color: "hsl(var(--primary))",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        fontWeight: 800,
                        fontSize: 12,
                      }}
                    >
                      {idx + 1}
                    </div>

                    <div style={{ flex: 1 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
                        <span style={{ fontSize: 12, fontWeight: 700, letterSpacing: "0.05em" }} className="eyebrow">
                          {step.step}
                        </span>
                        <ObservationBadge status={step.status} />
                      </div>
                      <div style={{ fontSize: 14, fontWeight: 700 }}>{step.label}</div>
                      <div className="muted" style={{ fontSize: 12, marginTop: 2 }}>{step.detail}</div>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Tab 5: Timeline */}
          {activeTab === "timeline" && (
            <Card className="card-pad">
              <div className="panel-title" style={{ marginBottom: 14 }}>
                <h2>Chronological Incident Timeline</h2>
              </div>

              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Event Type</th>
                      <th>Process</th>
                      <th>Source / Details</th>
                      <th>Observation Status</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {selectedIncident.timeline.map((evt) => (
                      <tr
                        key={evt.eventId}
                        style={selectedTimelineEvent?.eventId === evt.eventId ? { background: "hsl(var(--primary) / 0.1)" } : undefined}
                      >
                        <td className="mono">{new Date(evt.timestamp).toLocaleTimeString()}</td>
                        <td>
                          <b>{evt.eventType}</b>
                          <div className="muted mono" style={{ fontSize: 10 }}>{evt.relationship}</div>
                        </td>
                        <td className="mono">
                          {evt.processName || primaryProcName} (PID {evt.pid || primaryPidVal})
                        </td>
                        <td className="mono" style={{ fontSize: 11, maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {evt.filePath ? evt.filePath : `${evt.source || ""} → ${evt.destination || ""}`}
                        </td>
                        <td>
                          <ObservationBadge status={evt.observationStatus} />
                        </td>
                        <td>
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm"
                            onClick={() => {
                              selectTimelineEvent(evt);
                              setActiveTab("graph");
                            }}
                          >
                            <Eye size={12} style={{ marginRight: 4 }} /> Inspect
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}

          {/* PHASE 5 TAB: Containment Orchestration */}
          {activeTab === "orchestration" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              {/* Response Decision Engine Card */}
              <Card className="card-pad">
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 16, flexWrap: "wrap", marginBottom: 16 }}>
                  <div>
                    <div className="eyebrow">Phase 5 — Automated Response Decision Engine</div>
                    <h2 style={{ fontSize: 16, fontWeight: 700 }}>
                      Response Level {responseLevel}: {responseLabel}
                    </h2>
                    <p className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                      Rule-based explainable decision based on severity ({selectedIncident.severity}), confidence ({Math.round(selectedIncident.confidence * 100)}%), damage score ({impact?.damageScore ?? "N/A"}), and file transformation events.
                    </p>
                  </div>

                  <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                    <button
                      type="button"
                      className="btn btn-primary"
                      disabled={isProcessing || currentState === "CONTAINED" || currentState === "RECOVERED" || currentState === "CLOSED"}
                      onClick={handleContainmentAction}
                      style={{ fontSize: 12, padding: "6px 14px" }}
                    >
                      <Zap size={14} style={{ marginRight: 6 }} />
                      {currentState === "CONTAINED" ? "Incident Already Contained" : "Execute Containment Action"}
                    </button>
                  </div>
                </div>

                {/* Rule Breakdown Matrix */}
                <div className="grid metrics" style={{ gridTemplateColumns: "repeat(5, 1fr)", gap: 10 }}>
                  {[
                    { level: 0, title: "LOG & MONITOR", desc: "Low severity / single event" },
                    { level: 1, title: "ISOLATE PROCESS", desc: "Medium severity, rule match" },
                    { level: 2, title: "CONTAIN & QUARANTINE", desc: "High severity process + file changes" },
                    { level: 3, title: "SYSTEM CONTAINMENT", desc: "Critical threat / bulk file mods" },
                    { level: 4, title: "EMERGENCY ISOLATION", desc: "Active ransomware encryption pattern" },
                  ].map((lvl) => {
                    const isActive = responseLevel === lvl.level;
                    return (
                      <div
                        key={lvl.level}
                        style={{
                          padding: 10,
                          borderRadius: 6,
                          border: isActive ? "2px solid hsl(var(--primary))" : "1px solid hsl(var(--border))",
                          background: isActive ? "hsl(var(--primary) / 0.1)" : "hsl(var(--muted) / 0.4)",
                        }}
                      >
                        <div className="mono" style={{ fontSize: 10, fontWeight: 800, color: isActive ? "hsl(var(--primary))" : "hsl(var(--muted-foreground))" }}>
                          LEVEL {lvl.level}
                        </div>
                        <div style={{ fontSize: 11, fontWeight: 700, marginTop: 2 }}>{lvl.title}</div>
                        <div className="muted" style={{ fontSize: 10, marginTop: 4 }}>{lvl.desc}</div>
                      </div>
                    );
                  })}
                </div>
              </Card>

              {/* Empirical Containment Actions & Post-Action Verification Table */}
              <Card className="card-pad">
                <div className="panel-title" style={{ marginBottom: 14 }}>
                  <h2>Executed Containment Actions & Empirical Verification</h2>
                  <span className="muted" style={{ fontSize: 11 }}>
                    Verifies PID termination via Win32 snapshot before confirming status
                  </span>
                </div>

                {!currentManagedIncident?.containmentActions || currentManagedIncident.containmentActions.length === 0 ? (
                  <div className="muted" style={{ padding: "24px 0", textAlign: "center" }}>
                    No containment actions have been executed yet. Click "Execute Containment Action" above to trigger.
                  </div>
                ) : (
                  <div className="table-wrap">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Time</th>
                          <th>Action Type</th>
                          <th>Target Entity</th>
                          <th>Execution Status</th>
                          <th>Verification Method</th>
                          <th>Empirical Verification</th>
                          <th>Details</th>
                        </tr>
                      </thead>
                      <tbody>
                        {currentManagedIncident.containmentActions.map((act, idx) => (
                          <tr key={idx}>
                            <td className="mono">{new Date(act.timestamp).toLocaleTimeString()}</td>
                            <td>
                              <b>{act.actionType}</b>
                            </td>
                            <td className="mono">
                              {act.processName || `PID ${act.pid}`}
                            </td>
                            <td>
                              <span className={cn("badge", act.status === "SUCCESS" ? "badge-low" : "badge-critical")}>
                                {act.status}
                              </span>
                            </td>
                            <td className="mono" style={{ fontSize: 11 }}>
                              {act.verificationMethod || "Win32 Process Snapshot"}
                            </td>
                            <td>
                              <span
                                className="badge"
                                style={{
                                  background: act.verificationResult === "VERIFIED" ? "hsl(142 71% 16%)" : "hsl(0 84% 16%)",
                                  color: act.verificationResult === "VERIFIED" ? "hsl(142 71% 70%)" : "hsl(0 84% 70%)",
                                  fontSize: 10,
                                }}
                              >
                                {act.verificationResult === "VERIFIED" ? "✓ VERIFIED (PID DEAD)" : "❌ UNVERIFIED"}
                              </span>
                            </td>
                            <td className="muted" style={{ fontSize: 11 }}>
                              {act.details}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </Card>
            </div>
          )}

          {/* PHASE 6 TAB: Verified Data Recovery & Incident Closure */}
          {activeTab === "recovery" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              {/* Recovery Control Panel */}
              <Card className="card-pad">
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 16, flexWrap: "wrap", marginBottom: 16 }}>
                  <div>
                    <div className="eyebrow">Phase 6 — Verified Data Recovery Engine</div>
                    <h2 style={{ fontSize: 16, fontWeight: 700 }}>
                      Shadow Copy & Vault Recovery Source Selector
                    </h2>
                    <p className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                      Restores damaged or modified files and compares pre-incident SHA-256 hashes against restored hashes.
                    </p>
                  </div>

                  <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                    <select
                      className="btn btn-ghost"
                      value={preferredRecoverySource}
                      onChange={(e) => setPreferredRecoverySource(e.target.value)}
                      style={{ fontSize: 12, padding: "4px 10px", height: 32, background: "hsl(var(--card))" }}
                    >
                      <option value="VSS_SHADOW_COPY">VSS Shadow Copy (Windows Volume Snapshot)</option>
                      <option value="STAGING_VAULT">ARGUS Staging Vault (Local Pre-write Vault)</option>
                      <option value="BACKUP_ROOT">System Backup Root</option>
                      <option value="BASELINE">Known Baseline Copy</option>
                    </select>

                    <button
                      type="button"
                      className="btn btn-primary"
                      disabled={isProcessing || currentState === "RECOVERED" || currentState === "CLOSED"}
                      onClick={handleRecoveryAction}
                      style={{ fontSize: 12, padding: "6px 14px", height: 32 }}
                    >
                      <Database size={14} style={{ marginRight: 6 }} />
                      {currentState === "RECOVERED" ? "Recovery Complete" : "Execute Verified Recovery"}
                    </button>

                    <button
                      type="button"
                      className="btn btn-ghost"
                      disabled={isProcessing || currentState === "CLOSED"}
                      onClick={handleCloseIncidentAction}
                      style={{ fontSize: 12, padding: "6px 14px", height: 32, borderColor: "hsl(142 71% 30%)", color: "hsl(142 71% 70%)" }}
                    >
                      <CheckCircle2 size={14} style={{ marginRight: 6 }} />
                      Close & Archive Incident
                    </button>
                  </div>
                </div>
              </Card>

              {/* SHA-256 Integrity Verification Results Table */}
              <Card className="card-pad">
                <div className="panel-title" style={{ marginBottom: 14 }}>
                  <h2>SHA-256 Hash Match Verification Results</h2>
                  <span className="muted" style={{ fontSize: 11 }}>
                    Strict cryptographic integrity matching (VERIFIED, MISMATCH, NOT_AVAILABLE, FAILED)
                  </span>
                </div>

                {!currentManagedIncident?.recoveryResults || currentManagedIncident.recoveryResults.length === 0 ? (
                  <div className="muted" style={{ padding: "24px 0", textAlign: "center" }}>
                    No recovery operations executed yet. Click "Execute Verified Recovery" to initiate SHA-256 verified restoration.
                  </div>
                ) : (
                  <div className="table-wrap">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Time</th>
                          <th>Target File</th>
                          <th>Recovery Source</th>
                          <th>Original SHA-256</th>
                          <th>Recovered SHA-256</th>
                          <th>Integrity Status</th>
                          <th>Restored Path</th>
                        </tr>
                      </thead>
                      <tbody>
                        {currentManagedIncident.recoveryResults.map((rec, idx) => (
                          <tr key={idx}>
                            <td className="mono">{new Date(rec.timestamp).toLocaleTimeString()}</td>
                            <td className="mono" style={{ fontSize: 11, maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                              {rec.filePath}
                            </td>
                            <td>
                              <span className="badge badge-muted">{rec.sourceUsed}</span>
                            </td>
                            <td className="mono muted" style={{ fontSize: 10 }}>
                              {rec.originalHash ? rec.originalHash.substring(0, 14) + "..." : "N/A"}
                            </td>
                            <td className="mono muted" style={{ fontSize: 10 }}>
                              {rec.recoveredHash ? rec.recoveredHash.substring(0, 14) + "..." : "N/A"}
                            </td>
                            <td>
                              <span
                                className="badge"
                                style={{
                                  background:
                                    rec.hashMatchStatus === "VERIFIED"
                                      ? "hsl(142 71% 16%)"
                                      : rec.hashMatchStatus === "MISMATCH"
                                      ? "hsl(0 84% 16%)"
                                      : "hsl(38 92% 16%)",
                                  color:
                                    rec.hashMatchStatus === "VERIFIED"
                                      ? "hsl(142 71% 70%)"
                                      : rec.hashMatchStatus === "MISMATCH"
                                      ? "hsl(0 84% 70%)"
                                      : "hsl(38 92% 70%)",
                                  fontSize: 10,
                                  fontWeight: 800,
                                }}
                              >
                                {rec.hashMatchStatus === "VERIFIED" ? "✓ HASH MATCH VERIFIED" : `● ${rec.hashMatchStatus}`}
                              </span>
                            </td>
                            <td className="mono muted" style={{ fontSize: 10, maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                              {rec.restoredToPath || rec.filePath}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </Card>

              {/* Immutable Audit Log Viewer */}
              <Card className="card-pad">
                <div className="panel-title" style={{ marginBottom: 14 }}>
                  <h2>Immutable Incident Audit Log</h2>
                  <span className="muted" style={{ fontSize: 11 }}>
                    Records all state machine transitions, triggers, and operator actions
                  </span>
                </div>

                {!currentManagedIncident?.auditLog || currentManagedIncident.auditLog.length === 0 ? (
                  <div className="muted" style={{ padding: "20px 0", textAlign: "center" }}>
                    No audit entries logged for this incident yet.
                  </div>
                ) : (
                  <div className="table-wrap">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Timestamp</th>
                          <th>Triggered By</th>
                          <th>State Transition</th>
                          <th>Action Taken</th>
                          <th>Evidence & Rationale</th>
                          <th>Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {currentManagedIncident.auditLog.map((log) => (
                          <tr key={log.auditId}>
                            <td className="mono">{new Date(log.timestamp).toLocaleTimeString()}</td>
                            <td>
                              <span className="badge badge-muted">{log.triggeredBy}</span>
                            </td>
                            <td className="mono" style={{ fontSize: 11 }}>
                              {log.stateBefore} → <b>{log.stateAfter}</b>
                            </td>
                            <td><b>{log.action}</b></td>
                            <td className="muted" style={{ fontSize: 11, maxWidth: 300 }}>
                              {log.evidenceSummary}
                            </td>
                            <td>
                              <span className={cn("badge", log.status === "SUCCESS" ? "badge-low" : "badge-warn")}>
                                {log.status}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </Card>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
