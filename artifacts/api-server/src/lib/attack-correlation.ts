/**
 * ARGUS Attack Correlation Engine.
 *
 * Converts real network, process, detection, and file telemetry into a normalized,
 * explainable incident/attack chain model.
 *
 * Extended in Phase 3 & 4:
 * Remote Endpoint -> Connection -> Process -> Parent/Child Process -> Detection -> File Activity -> Impact Analysis
 *
 * Core discipline:
 * - OBSERVED: Directly reported by OS telemetry.
 * - CORRELATED: Multiple real events linked by verified PID/process ancestry, socket ownership, or file activity window.
 * - INFERRED: Likely path based on temporal/identity context.
 * - UNKNOWN: Telemetry is insufficient.
 */

import { eventHub } from "./event-hub";
import type { ProcessEvent, NetworkConnection, TopologyConnection, FileActivityEvent } from "./event-hub";
import type { Detection } from "../detection/types";
import {
  classifyImpactState,
  classifySensitiveCategory,
  evaluateImpactAssessment,
  type AffectedFileRecord,
  type ImpactAssessment,
} from "./file-impact";

export type ObservationStatus = "OBSERVED" | "CORRELATED" | "INFERRED" | "UNKNOWN";

export type CorrelatedEvent = {
  eventId: string;
  timestamp: string;
  eventType: string;
  source: string;
  destination?: string;
  protocol?: string;
  sourcePort?: number;
  destinationPort?: number;
  pid?: number;
  processName?: string;
  parentPid?: number;
  parentProcessName?: string;
  executablePath?: string;
  commandLine?: string;
  connectionId?: string;
  detectionId?: string;
  ruleId?: string;
  filePath?: string;
  oldFilePath?: string;
  operation?: string;
  severity?: "critical" | "high" | "medium" | "low";
  confidence?: number;
  evidence: string;
  relationship: string;
  observationStatus: ObservationStatus;
  direction?: "INBOUND" | "OUTBOUND" | "LOCAL" | "UNKNOWN";
};

export type AttackGraphNode = {
  id: string;
  type: "ENDPOINT" | "CONNECTION" | "PROCESS" | "DETECTION" | "FILE_ACTIVITY" | "AFFECTED_FILES";
  label: string;
  sublabel?: string;
  pid?: number;
  processName?: string;
  executablePath?: string;
  commandLine?: string;
  parentPid?: number;
  parentProcessName?: string;
  ip?: string;
  port?: number;
  protocol?: string;
  direction?: "INBOUND" | "OUTBOUND" | "LOCAL";
  status?: string;
  severity?: "critical" | "high" | "medium" | "low";
  ruleId?: string;
  observationStatus: ObservationStatus;
  metadata?: Record<string, unknown>;
};

export type AttackGraphEdge = {
  id: string;
  source: string;
  target: string;
  label: string;
  relationship: string;
  observationStatus: ObservationStatus;
  evidence: string;
};

export type DataFlowStep = {
  step: string;
  label: string;
  detail: string;
  status: ObservationStatus;
};

export type CorrelatedIncident = {
  incidentId: string;
  title: string;
  status: "ACTIVE" | "CONTAINED" | "RESOLVED";
  severity: "critical" | "high" | "medium" | "low";
  detectionTime: string;
  startTime: string;
  lastUpdatedTime: string;
  durationSeconds: number;
  primaryProcess: {
    pid?: number;
    name: string;
    executablePath?: string;
    commandLine?: string;
    parentPid?: number;
    parentName?: string;
  };
  observableSource: {
    ip: string;
    port?: number;
    protocol?: string;
    label: string;
    firstSeen?: string;
    lastSeen?: string;
    connectionCount: number;
  };
  eventCount: number;
  connectionCount: number;
  timeline: CorrelatedEvent[];
  graph: {
    nodes: AttackGraphNode[];
    edges: AttackGraphEdge[];
  };
  evidenceSummary: Array<{
    relationship: string;
    evidence: string;
    observationStatus: ObservationStatus;
    score: number;
  }>;
  impactAssessment: ImpactAssessment;
  affectedFiles: AffectedFileRecord[];
  dataFlowChain: DataFlowStep[];
};

function isPrivateIp(ip: string): boolean {
  if (!ip || ip === "127.0.0.1" || ip === "0.0.0.0" || ip === "::1") return true;
  if (ip.startsWith("10.") || ip.startsWith("192.168.")) return true;
  if (ip.startsWith("172.")) {
    const second = parseInt(ip.split(".")[1] || "0", 10);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
}

export class AttackCorrelationEngine {
  /**
   * Produce all correlated attack incidents from live telemetry in EventHub.
   */
  public getCorrelatedIncidents(): CorrelatedIncident[] {
    const detections = eventHub.getDetections(100);
    const processSnapshot = eventHub.getSnapshot();
    const networkSnapshot = eventHub.getNetworkSnapshot();
    const topologySnapshot = eventHub.getTopologySnapshot();
    const recentProcessEvents = eventHub.getEvents(undefined, 200);
    const recentFileActivities = eventHub.getFileActivity(300);

    // Group detections by target PID or process name
    const groupedPids = new Map<number, Detection[]>();
    for (const det of detections) {
      if (det.pid && det.pid > 0) {
        const existing = groupedPids.get(det.pid) || [];
        existing.push(det);
        groupedPids.set(det.pid, existing);
      }
    }

    const incidents: CorrelatedIncident[] = [];

    for (const [pid, detList] of groupedPids.entries()) {
      const incident = this.buildIncidentForPid(
        pid,
        detList,
        processSnapshot,
        networkSnapshot,
        topologySnapshot,
        recentProcessEvents,
        recentFileActivities
      );
      if (incident) {
        incidents.push(incident);
      }
    }

    return incidents;
  }

  /**
   * Build a single correlated incident chain for a given target PID and detection list.
   */
  private buildIncidentForPid(
    pid: number,
    detections: Detection[],
    processSnapshot: ReturnType<typeof eventHub.getSnapshot>,
    networkSnapshot: ReturnType<typeof eventHub.getNetworkSnapshot>,
    topologySnapshot: ReturnType<typeof eventHub.getTopologySnapshot>,
    recentProcessEvents: ProcessEvent[],
    recentFileActivities: FileActivityEvent[]
  ): CorrelatedIncident | null {
    if (detections.length === 0) return null;

    const mainDet = detections[0];
    const highestSeverity = detections.reduce((highest, d) => {
      const rank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
      return rank[d.severity] > rank[highest] ? d.severity : highest;
    }, mainDet.severity);

    // 1. Process Ancestry Correlation
    const processesByPid = new Map<number, { pid: number; name: string; parentPid?: number; path?: string; cmd?: string }>();
    if (processSnapshot?.processes) {
      for (const p of processSnapshot.processes) {
        processesByPid.set(p.pid, {
          pid: p.pid,
          name: p.name,
          parentPid: p.parent_pid,
          path: p.executable_path,
          cmd: p.command_line,
        });
      }
    }

    for (const pe of recentProcessEvents) {
      if (pe.pid && !processesByPid.has(pe.pid)) {
        processesByPid.set(pe.pid, {
          pid: pe.pid,
          name: pe.process_name,
          parentPid: pe.parent_pid,
          path: pe.executable_path,
          cmd: pe.command_line,
        });
      }
    }

    const targetProc = processesByPid.get(pid) || {
      pid,
      name: mainDet.entity || mainDet.process_name || `PID-${pid}`,
      parentPid: mainDet.parent_pid ?? undefined,
      path: mainDet.executable_path ?? undefined,
      cmd: mainDet.command_line ?? undefined,
    };

    const parentProc = targetProc.parentPid ? processesByPid.get(targetProc.parentPid) : null;

    const childProcs: Array<{ pid: number; name: string; path?: string; cmd?: string }> = [];
    for (const p of processesByPid.values()) {
      if (p.parentPid === pid && p.pid !== pid) {
        childProcs.push(p);
      }
    }

    // 2. Network Sockets Correlation
    const relevantPids = new Set<number>([pid]);
    if (targetProc.parentPid) relevantPids.add(targetProc.parentPid);
    for (const cp of childProcs) relevantPids.add(cp.pid);

    const connections: NetworkConnection[] = [];
    if (networkSnapshot?.connections) {
      for (const c of networkSnapshot.connections) {
        if (c.pid && relevantPids.has(c.pid)) {
          connections.push(c);
        }
      }
    }
    if (topologySnapshot?.connections) {
      for (const tc of topologySnapshot.connections) {
        if (tc.pid && relevantPids.has(tc.pid) && !connections.some(c => c.connection_id === tc.connection_id)) {
          connections.push({
            process: tc.process_name || "",
            pid: tc.pid,
            connection_id: tc.connection_id,
            local_addr: tc.local_addr,
            local_port: tc.local_port,
            remote_addr: tc.remote_addr,
            remote_port: tc.remote_port,
            status: tc.status || tc.state,
            executable_path: tc.executable_path || tc.process_path,
            timestamp: tc.first_seen,
          });
        }
      }
    }

    // 3. File Activity Correlation (Phase 3 Extension)
    const correlatedFiles: FileActivityEvent[] = [];
    const detTimeMs = new Date(mainDet.timestamp).getTime();

    for (const fa of recentFileActivities) {
      let isMatch = false;
      let obsStatus: ObservationStatus = fa.observationStatus || "CORRELATED";

      if (fa.pid && relevantPids.has(fa.pid)) {
        isMatch = true;
        obsStatus = "OBSERVED";
      } else if (fa.processName && (fa.processName.toLowerCase() === targetProc.name.toLowerCase() || (parentProc && fa.processName.toLowerCase() === parentProc.name.toLowerCase()))) {
        isMatch = true;
        obsStatus = "CORRELATED";
      } else {
        // Temporal activity window check (within 120 seconds of detection)
        const faTimeMs = new Date(fa.timestamp).getTime();
        if (Math.abs(faTimeMs - detTimeMs) <= 120000) {
          // Check if file is executable or in suspicious temporary paths
          const normPath = fa.filePath.toLowerCase();
          if (normPath.includes("temp") || normPath.includes("downloads") || normPath.endsWith(".exe") || normPath.endsWith(".ps1") || normPath.endsWith(".zip")) {
            isMatch = true;
            obsStatus = fa.pid ? "CORRELATED" : "INFERRED";
          }
        }
      }

      if (isMatch) {
        correlatedFiles.push({
          ...fa,
          observationStatus: obsStatus,
          pid: fa.pid || pid,
          processName: fa.processName || targetProc.name,
        });
      }
    }

    // 4. Classify Observable Source
    let observableIp = "Process association unavailable";
    let observablePort: number | undefined;
    let observableProtocol = "TCP";
    let observableLabel = "Process association unavailable";
    let connectionCount = connections.length;
    let firstSeen: string | undefined;
    let lastSeen: string | undefined;

    const inboundConn = connections.find(c => c.remote_addr && c.remote_addr !== "0.0.0.0" && c.remote_addr !== "127.0.0.1");
    if (inboundConn) {
      observableIp = inboundConn.remote_addr || "127.0.0.1";
      observablePort = inboundConn.remote_port;
      observableProtocol = (inboundConn as any).protocol || "TCP";
      firstSeen = inboundConn.timestamp;
      lastSeen = inboundConn.timestamp;
      const isExt = !isPrivateIp(observableIp);
      observableLabel = `${observableIp}${isExt ? " (Last observable endpoint)" : " (Internal Endpoint)"}`;
    }

    // 5. Construct Timeline Entries
    const timeline: CorrelatedEvent[] = [];

    // Parent process
    if (parentProc) {
      timeline.push({
        eventId: `evt-parent-${parentProc.pid}`,
        timestamp: mainDet.timestamp,
        eventType: "PROCESS_STARTED",
        source: "endpoint_telemetry",
        pid: parentProc.pid,
        processName: parentProc.name,
        executablePath: parentProc.path,
        commandLine: parentProc.cmd,
        evidence: `Parent process ${parentProc.name} (PID ${parentProc.pid}) observed`,
        relationship: "PARENT_PROCESS",
        observationStatus: "OBSERVED",
        direction: "LOCAL",
      });
    }

    // Target process
    timeline.push({
      eventId: `evt-proc-${pid}`,
      timestamp: mainDet.event_timestamp || mainDet.timestamp,
      eventType: "PROCESS_STARTED",
      source: "endpoint_telemetry",
      pid,
      processName: targetProc.name,
      parentPid: targetProc.parentPid,
      parentProcessName: parentProc?.name,
      executablePath: targetProc.path,
      commandLine: targetProc.cmd,
      evidence: `Process ${targetProc.name} (PID ${pid}) spawned by ${parentProc?.name || targetProc.parentPid || "system"}`,
      relationship: "PRIMARY_PROCESS",
      observationStatus: "OBSERVED",
      direction: "LOCAL",
    });

    // Connections
    for (const c of connections) {
      const isOutbound = c.remote_port && [80, 443, 8080, 4444].includes(c.remote_port);
      const direction = isOutbound ? "OUTBOUND" : "INBOUND";
      const relName = isOutbound
        ? "Potential suspicious outbound communication"
        : "Inbound connection to process";

      timeline.push({
        eventId: c.connection_id || `conn-${c.pid}-${c.remote_port}`,
        timestamp: c.timestamp || mainDet.timestamp,
        eventType: isOutbound ? "OUTBOUND_COMMUNICATION" : "INBOUND_CONNECTION",
        source: `${c.local_addr || "127.0.0.1"}:${c.local_port || 0}`,
        destination: `${c.remote_addr || "0.0.0.0"}:${c.remote_port || 0}`,
        protocol: (c as any).protocol || "TCP",
        sourcePort: c.local_port,
        destinationPort: c.remote_port,
        pid: c.pid,
        processName: c.process || targetProc.name,
        executablePath: c.executable_path || targetProc.path,
        connectionId: c.connection_id,
        evidence: `PID ${c.pid} socket ${c.local_addr}:${c.local_port} -> ${c.remote_addr}:${c.remote_port} (${c.status || "ESTABLISHED"})`,
        relationship: relName,
        observationStatus: "CORRELATED",
        direction,
      });
    }

    // Child processes
    for (const cp of childProcs) {
      timeline.push({
        eventId: `evt-child-${cp.pid}`,
        timestamp: mainDet.timestamp,
        eventType: "PROCESS_STARTED",
        source: "endpoint_telemetry",
        pid: cp.pid,
        processName: cp.name,
        parentPid: pid,
        parentProcessName: targetProc.name,
        executablePath: cp.path,
        commandLine: cp.cmd,
        evidence: `Child process ${cp.name} (PID ${cp.pid}) spawned by ${targetProc.name} (PID ${pid})`,
        relationship: "CHILD_PROCESS",
        observationStatus: "OBSERVED",
        direction: "LOCAL",
      });
    }

    // Detections
    for (const d of detections) {
      timeline.push({
        eventId: `evt-det-${d.id}`,
        timestamp: d.timestamp,
        eventType: "DETECTION_TRIGGERED",
        source: "detection_engine",
        pid: d.pid,
        processName: d.entity,
        executablePath: d.executable_path ?? undefined,
        commandLine: d.command_line ?? undefined,
        detectionId: d.id,
        ruleId: d.rule_id,
        severity: d.severity,
        confidence: d.confidence,
        evidence: `Detection rule ${d.rule_id} (${d.title}) matched: ${d.explanation}`,
        relationship: "DETECTION_MATCH",
        observationStatus: "CORRELATED",
        direction: "LOCAL",
      });
    }

    // File Activity Timeline Events (Phase 3)
    for (const fa of correlatedFiles) {
      timeline.push({
        eventId: fa.eventId,
        timestamp: fa.timestamp,
        eventType: fa.eventType,
        source: fa.source || "filesystem_watch",
        filePath: fa.filePath,
        oldFilePath: fa.oldFilePath ?? undefined,
        operation: fa.operation,
        pid: fa.pid || pid,
        processName: fa.processName || targetProc.name,
        executablePath: fa.executablePath ?? undefined,
        evidence: `Filesystem operation ${fa.operation} on ${fa.filePath}${fa.oldFilePath ? ` (renamed from ${fa.oldFilePath})` : ""}`,
        relationship: "FILE_ACTIVITY",
        observationStatus: fa.observationStatus,
        direction: "LOCAL",
      });
    }

    timeline.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

    // 6. Construct Attack Graph
    const nodes: AttackGraphNode[] = [];
    const edges: AttackGraphEdge[] = [];

    // Remote Endpoint
    if (observableIp !== "Process association unavailable") {
      const nodeRemoteId = `node-remote-${observableIp}`;
      nodes.push({
        id: nodeRemoteId,
        type: "ENDPOINT",
        label: observableIp,
        sublabel: observableLabel,
        ip: observableIp,
        port: observablePort,
        protocol: observableProtocol,
        direction: "INBOUND",
        observationStatus: "CORRELATED",
      });

      const nodeConnId = `node-conn-${pid}`;
      nodes.push({
        id: nodeConnId,
        type: "CONNECTION",
        label: `Socket ${observableProtocol}:${observablePort || 0}`,
        sublabel: `PID ${pid} (${targetProc.name})`,
        ip: observableIp,
        port: observablePort,
        protocol: observableProtocol,
        direction: "INBOUND",
        observationStatus: "CORRELATED",
      });

      edges.push({
        id: `edge-remote-conn`,
        source: nodeRemoteId,
        target: nodeConnId,
        label: "Inbound traffic",
        relationship: "INBOUND_TRAFFIC",
        observationStatus: "CORRELATED",
        evidence: `Traffic from ${observableIp} to port ${observablePort || 0}`,
      });
    }

    // Parent Process
    let parentNodeId: string | null = null;
    if (parentProc) {
      parentNodeId = `node-proc-${parentProc.pid}`;
      nodes.push({
        id: parentNodeId,
        type: "PROCESS",
        label: parentProc.name,
        sublabel: `PID ${parentProc.pid}`,
        pid: parentProc.pid,
        processName: parentProc.name,
        executablePath: parentProc.path,
        commandLine: parentProc.cmd,
        direction: "LOCAL",
        observationStatus: "OBSERVED",
      });
    }

    // Primary Target Process
    const primaryNodeId = `node-proc-${pid}`;
    nodes.push({
      id: primaryNodeId,
      type: "PROCESS",
      label: targetProc.name,
      sublabel: `PID ${pid}`,
      pid,
      processName: targetProc.name,
      executablePath: targetProc.path,
      commandLine: targetProc.cmd,
      parentPid: targetProc.parentPid,
      parentProcessName: parentProc?.name,
      severity: highestSeverity,
      direction: "LOCAL",
      observationStatus: "OBSERVED",
    });

    if (parentNodeId) {
      edges.push({
        id: `edge-parent-target`,
        source: parentNodeId,
        target: primaryNodeId,
        label: "Spawned",
        relationship: "PARENT_SPAWNED_CHILD",
        observationStatus: "OBSERVED",
        evidence: `Parent process PID ${parentProc!.pid} created process PID ${pid}`,
      });
    }

    if (nodes.some(n => n.type === "CONNECTION")) {
      const connNode = nodes.find(n => n.type === "CONNECTION")!;
      edges.push({
        id: `edge-conn-proc`,
        source: connNode.id,
        target: primaryNodeId,
        label: "Assigned PID",
        relationship: "SOCKET_PID_OWNERSHIP",
        observationStatus: "CORRELATED",
        evidence: `Socket owned by PID ${pid} (${targetProc.name})`,
      });
    }

    // Child Processes
    for (const cp of childProcs) {
      const childNodeId = `node-proc-${cp.pid}`;
      nodes.push({
        id: childNodeId,
        type: "PROCESS",
        label: cp.name,
        sublabel: `PID ${cp.pid}`,
        pid: cp.pid,
        processName: cp.name,
        executablePath: cp.path,
        commandLine: cp.cmd,
        parentPid: pid,
        parentProcessName: targetProc.name,
        direction: "LOCAL",
        observationStatus: "OBSERVED",
      });

      edges.push({
        id: `edge-target-child-${cp.pid}`,
        source: primaryNodeId,
        target: childNodeId,
        label: "Spawned child",
        relationship: "PROCESS_SPAWNED_CHILD",
        observationStatus: "OBSERVED",
        evidence: `Process PID ${pid} spawned child PID ${cp.pid}`,
      });
    }

    // Detections
    for (const d of detections) {
      const detNodeId = `node-det-${d.id}`;
      nodes.push({
        id: detNodeId,
        type: "DETECTION",
        label: d.rule_id,
        sublabel: d.title,
        ruleId: d.rule_id,
        severity: d.severity,
        observationStatus: "CORRELATED",
        metadata: { explanation: d.explanation, confidence: d.confidence },
      });

      edges.push({
        id: `edge-proc-det-${d.id}`,
        source: primaryNodeId,
        target: detNodeId,
        label: `Triggered ${d.severity}`,
        relationship: "DETECTION_MATCH",
        observationStatus: "CORRELATED",
        evidence: `Matched detection rule ${d.rule_id} with confidence ${Math.round((d.confidence || 1) * 100)}%`,
      });
    }

    // File Activity Nodes (Phase 4 Extension)
    if (correlatedFiles.length > 0) {
      const fileActNodeId = `node-fa-${pid}`;
      nodes.push({
        id: fileActNodeId,
        type: "FILE_ACTIVITY",
        label: `Filesystem Activity`,
        sublabel: `${correlatedFiles.length} file event(s)`,
        observationStatus: "CORRELATED",
        metadata: { totalFiles: correlatedFiles.length },
      });

      edges.push({
        id: `edge-proc-fa-${pid}`,
        source: primaryNodeId,
        target: fileActNodeId,
        label: "File activity",
        relationship: "FILE_MODIFICATION",
        observationStatus: "CORRELATED",
        evidence: `Process PID ${pid} executed ${correlatedFiles.length} filesystem operation(s)`,
      });

      const affectedFilesNodeId = `node-affected-${pid}`;
      nodes.push({
        id: affectedFilesNodeId,
        type: "AFFECTED_FILES",
        label: "Affected Files & Impact",
        sublabel: `${correlatedFiles.length} object(s) impacted`,
        observationStatus: "CORRELATED",
      });

      edges.push({
        id: `edge-fa-affected-${pid}`,
        source: fileActNodeId,
        target: affectedFilesNodeId,
        label: "Impact summary",
        relationship: "FILESYSTEM_IMPACT",
        observationStatus: "CORRELATED",
        evidence: `Filesystem operations produced impact assessment for PID ${pid}`,
      });
    }

    // Outbound Socket Connections Nodes
    for (const c of connections) {
      if (c.remote_addr && c.remote_addr !== "0.0.0.0" && c.remote_addr !== "127.0.0.1") {
        const outNodeId = `node-out-${c.remote_addr}:${c.remote_port}`;
        if (!nodes.some(n => n.id === outNodeId)) {
          nodes.push({
            id: outNodeId,
            type: "ENDPOINT",
            label: `${c.remote_addr}:${c.remote_port}`,
            sublabel: "Potential suspicious outbound destination",
            ip: c.remote_addr,
            port: c.remote_port,
            direction: "OUTBOUND",
            observationStatus: "CORRELATED",
          });

          edges.push({
            id: `edge-proc-out-${c.remote_addr}:${c.remote_port}`,
            source: primaryNodeId,
            target: outNodeId,
            label: "Outbound socket",
            relationship: "OUTBOUND_SOCKET",
            observationStatus: "CORRELATED",
            evidence: `Process PID ${pid} opened socket to ${c.remote_addr}:${c.remote_port}`,
          });
        }
      }
    }

    // 7. Impact Assessment & Affected Files (Phase 4)
    const hasOutbound = connections.some(c => c.remote_addr && c.remote_addr !== "0.0.0.0" && c.remote_addr !== "127.0.0.1");
    const impactAssessment = evaluateImpactAssessment(correlatedFiles, hasOutbound);

    const affectedFiles: AffectedFileRecord[] = correlatedFiles.map((fa) => ({
      eventId: fa.eventId,
      timestamp: fa.timestamp,
      operation: fa.operation,
      filePath: fa.filePath,
      oldFilePath: fa.oldFilePath,
      classification: classifySensitiveCategory(fa.filePath),
      impactState: classifyImpactState(fa),
      processName: fa.processName || targetProc.name,
      pid: fa.pid || pid,
      observationStatus: fa.observationStatus,
      evidence: `Filesystem ${fa.operation} observed by ${fa.source || "watcher"}`,
      hashStatus: fa.hash ? "HASH_OBSERVED" : "HASH_NOT_AVAILABLE",
      hash: fa.hash || null,
    }));

    // 8. Conceptual Data Flow View (Phase 4)
    const dataFlowChain: DataFlowStep[] = [
      {
        step: "THREAT ENTRY",
        label: observableIp !== "Process association unavailable" ? `Inbound socket from ${observableIp}` : `Process execution (${targetProc.name})`,
        detail: observableIp !== "Process association unavailable" ? `Remote IP ${observableIp}:${observablePort} connected` : `Process spawned with PID ${pid}`,
        status: observableIp !== "Process association unavailable" ? "CORRELATED" : "OBSERVED",
      },
      {
        step: "PROCESS EXECUTION",
        label: `${targetProc.name} (PID ${pid})`,
        detail: targetProc.path ? `Binary path: ${targetProc.path}` : `Process active under PID ${pid}`,
        status: "OBSERVED",
      },
      {
        step: "DATA ACCESS / MODIFICATION",
        label: correlatedFiles.length > 0 ? `${correlatedFiles.length} file event(s) observed` : "No file activity observed",
        detail: correlatedFiles.length > 0 ? `${impactAssessment.counts.modified} modified, ${impactAssessment.counts.created} created, ${impactAssessment.counts.deleted} deleted` : "Baseline endpoint state",
        status: correlatedFiles.length > 0 ? "CORRELATED" : "UNKNOWN",
      },
      {
        step: "OUTBOUND COMMUNICATION",
        label: hasOutbound ? `Outbound socket established` : "No outbound sockets",
        detail: hasOutbound ? `Sockets established to remote endpoint(s)` : "Local execution only",
        status: hasOutbound ? "CORRELATED" : "UNKNOWN",
      },
    ];

    const incidentId = `INC-2026-${pid}`;
    const startTime = timeline[0]?.timestamp || mainDet.timestamp;
    const lastTime = timeline[timeline.length - 1]?.timestamp || mainDet.timestamp;
    const duration = Math.max(1, Math.round((new Date(lastTime).getTime() - new Date(startTime).getTime()) / 1000));

    return {
      incidentId,
      title: `${mainDet.title} (${targetProc.name})`,
      status: mainDet.status === "contained" ? "CONTAINED" : mainDet.status === "resolved" ? "RESOLVED" : "ACTIVE",
      severity: highestSeverity,
      detectionTime: mainDet.timestamp,
      startTime,
      lastUpdatedTime: lastTime,
      durationSeconds: duration,
      primaryProcess: {
        pid,
        name: targetProc.name,
        executablePath: targetProc.path,
        commandLine: targetProc.cmd,
        parentPid: targetProc.parentPid,
        parentName: parentProc?.name,
      },
      observableSource: {
        ip: observableIp,
        port: observablePort,
        protocol: observableProtocol,
        label: observableLabel,
        firstSeen,
        lastSeen,
        connectionCount,
      },
      eventCount: timeline.length,
      connectionCount,
      timeline,
      graph: { nodes, edges },
      evidenceSummary: [
        {
          relationship: "Process Ancestry",
          evidence: parentProc ? `Parent PID ${parentProc.pid} (${parentProc.name}) -> Child PID ${pid} (${targetProc.name})` : `Primary process PID ${pid} (${targetProc.name})`,
          observationStatus: "OBSERVED",
          score: 1.0,
        },
        {
          relationship: "Detection Engine Match",
          evidence: `Rule ${mainDet.rule_id} triggered: ${mainDet.explanation}`,
          observationStatus: "CORRELATED",
          score: mainDet.confidence ?? 0.95,
        },
        {
          relationship: "Filesystem Activity Correlation",
          evidence: correlatedFiles.length > 0 ? `${correlatedFiles.length} file operation(s) correlated with process PID ${pid}` : "No file activity linked",
          observationStatus: correlatedFiles.length > 0 ? "CORRELATED" : "UNKNOWN",
          score: correlatedFiles.length > 0 ? 0.85 : 0.0,
        },
        {
          relationship: "Socket Ownership",
          evidence: connections.length > 0 ? `Associated with ${connections.length} socket connection(s)` : "Process association unavailable",
          observationStatus: connections.length > 0 ? "CORRELATED" : "UNKNOWN",
          score: connections.length > 0 ? 0.9 : 0.0,
        },
      ],
      impactAssessment,
      affectedFiles,
      dataFlowChain,
    };
  }
}

export const attackCorrelationEngine = new AttackCorrelationEngine();
