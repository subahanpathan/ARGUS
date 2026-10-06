/**
 * useAttackTraces — React hook for consuming ARGUS Attack Correlation Engine telemetry.
 *
 * Extended in Phase 3 & 4 to support real-time file activity correlation,
 * impact classification, affected files inventory, and conceptual data flow chains.
 */

import { useCallback, useEffect, useRef, useState } from "react";

export type ObservationStatus = "OBSERVED" | "CORRELATED" | "INFERRED" | "UNKNOWN";

export type AttackTraceNodeType =
  | "ENDPOINT"
  | "CONNECTION"
  | "PROCESS"
  | "DETECTION"
  | "FILE_ACTIVITY"
  | "AFFECTED_FILES"
  | "remote_endpoint"
  | "network_connection"
  | "process"
  | "parent_process"
  | "child_process"
  | "detection"
  | "outbound_socket";

export type AttackTraceNode = {
  id: string;
  label: string;
  type: AttackTraceNodeType;
  sublabel?: string;
  observationStatus: ObservationStatus;
  details?: Record<string, any>;
  metadata?: Record<string, any>;
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
  severity?: "critical" | "high" | "medium" | "low";
  ruleId?: string;
};

export type AttackTraceEdge = {
  id?: string;
  source: string;
  target: string;
  relationship: string;
  label?: string;
  observationStatus: ObservationStatus;
  evidence?: string;
};

export type TimelineEvidence = {
  key?: string;
  description?: string;
  source?: string;
  detail?: string;
};

export type IncidentTimelineEvent = {
  eventId: string;
  timestamp: string;
  eventType: string;
  pid?: number;
  processName?: string;
  parentPid?: number | null;
  parentProcessName?: string | null;
  executablePath?: string | null;
  commandLine?: string | null;
  source?: string;
  destination?: string;
  sourcePort?: number;
  destinationPort?: number;
  protocol?: string;
  connectionId?: string;
  detectionId?: string;
  filePath?: string;
  oldFilePath?: string;
  operation?: string;
  severity?: "critical" | "high" | "medium" | "low";
  confidence?: number;
  evidence: string | TimelineEvidence[];
  relationship: string;
  observationStatus: ObservationStatus;
};

export type ImpactCounts = {
  created: number;
  modified: number;
  renamed: number;
  deleted: number;
  accessed: number;
  suspiciouslyTransformed: number;
};

export type ImpactAssessment = {
  affectedFilesCount: number;
  counts: ImpactCounts;
  potentialSensitiveExposureCount: number;
  suspiciousTransformationDetected: boolean;
  encryptionSuspected: boolean;
  evidenceConfidence: "HIGH" | "MEDIUM" | "LOW" | "INCOMPLETE";
  damageScore: number | null;
  damageScoreExplanation: string;
};

export type AffectedFileRecord = {
  eventId: string;
  timestamp: string;
  operation: string;
  filePath: string;
  oldFilePath?: string | null;
  classification: string;
  impactState: string;
  processName: string;
  pid?: number | null;
  observationStatus: ObservationStatus;
  evidence: string;
  hashStatus: "HASH_OBSERVED" | "HASH_NOT_AVAILABLE";
  hash?: string | null;
};

export type DataFlowStep = {
  step: string;
  label: string;
  detail: string;
  status: ObservationStatus;
};

export type CorrelatedIncident = {
  incidentId: string;
  title?: string;
  status?: "ACTIVE" | "CONTAINED" | "RESOLVED";
  timestamp?: string;
  detectionTime?: string;
  startTime?: string;
  lastUpdatedTime?: string;
  durationSeconds?: number;
  primaryPid?: number;
  primaryProcessName?: string;
  primaryProcess?: {
    pid?: number;
    name: string;
    executablePath?: string;
    commandLine?: string;
    parentPid?: number;
    parentName?: string;
  };
  severity: "critical" | "high" | "medium" | "low";
  confidence: number;
  observableSource?: string | {
    ip: string;
    port?: number;
    protocol?: string;
    label: string;
    firstSeen?: string;
    lastSeen?: string;
    connectionCount?: number;
  };
  eventCount?: number;
  totalEventsCount?: number;
  connectionCount?: number;
  totalConnectionsCount?: number;
  firstSeen?: string;
  lastSeen?: string;
  nodes?: AttackTraceNode[];
  edges?: AttackTraceEdge[];
  timeline: IncidentTimelineEvent[];
  graph: {
    nodes: AttackTraceNode[];
    edges: AttackTraceEdge[];
  };
  evidenceSummary?: Array<{
    relationship: string;
    evidence: string;
    observationStatus: ObservationStatus;
    score: number;
  }>;
  impactAssessment?: ImpactAssessment;
  affectedFiles?: AffectedFileRecord[];
  dataFlowChain?: DataFlowStep[];
};

export type AttackTracesState = {
  connected: boolean;
  hasData: boolean;
  incidents: CorrelatedIncident[];
  selectedIncident: CorrelatedIncident | null;
  selectedNode: AttackTraceNode | null;
  selectedTimelineEvent: IncidentTimelineEvent | null;
  lastUpdateTime: string | null;
  selectIncident: (id: string | null) => void;
  selectNode: (node: AttackTraceNode | null) => void;
  selectTimelineEvent: (event: IncidentTimelineEvent | null) => void;
  refresh: () => Promise<void>;
};

const RECONNECT_DELAY_MS = 3000;
const POLL_MS = 8000;

export function useAttackTraces(): AttackTracesState {
  const [connected, setConnected] = useState(false);
  const [hasData, setHasData] = useState(false);
  const [incidents, setIncidents] = useState<CorrelatedIncident[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<AttackTraceNode | null>(null);
  const [selectedTimelineEvent, setSelectedTimelineEvent] = useState<IncidentTimelineEvent | null>(null);
  const [lastUpdateTime, setLastUpdateTime] = useState<string | null>(null);

  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchList = useCallback(async () => {
    try {
      const resp = await fetch("/api/attack-traces");
      if (resp.ok) {
        const data = await resp.json();
        if (Array.isArray(data.incidents)) {
          setIncidents(data.incidents);
          setHasData(true);
          setLastUpdateTime(data.timestamp || new Date().toISOString());
        }
      }
    } catch {
      // Endpoint API offline
    }
  }, []);

  const selectIncident = useCallback((id: string | null) => {
    setSelectedIncidentId(id);
    setSelectedNode(null);
    setSelectedTimelineEvent(null);
  }, []);

  const selectNode = useCallback((node: AttackTraceNode | null) => {
    setSelectedNode(node);
  }, []);

  const selectTimelineEvent = useCallback((event: IncidentTimelineEvent | null) => {
    setSelectedTimelineEvent(event);
  }, []);

  useEffect(() => {
    let cancelled = false;

    function connect() {
      if (cancelled) return;
      try {
        const es = new EventSource("/api/attack-traces/stream");

        es.onopen = () => {
          if (!cancelled) setConnected(true);
        };

        es.onmessage = (msg) => {
          if (cancelled) return;
          try {
            const data = JSON.parse(msg.data);
            if (data.type === "attack_trace.snapshot" && Array.isArray(data.incidents)) {
              setIncidents(data.incidents);
              setHasData(true);
              setLastUpdateTime(data.timestamp);
            }
          } catch {
            // Ignore parse errors
          }
        };

        es.onerror = () => {
          if (!cancelled) {
            setConnected(false);
            es.close();
            reconnectTimerRef.current = setTimeout(connect, RECONNECT_DELAY_MS);
          }
        };

        eventSourceRef.current = es;
      } catch {
        if (!cancelled) {
          reconnectTimerRef.current = setTimeout(connect, RECONNECT_DELAY_MS);
        }
      }
    }

    connect();
    fetchList();
    const pollInterval = setInterval(fetchList, POLL_MS);

    return () => {
      cancelled = true;
      eventSourceRef.current?.close();
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      clearInterval(pollInterval);
    };
  }, [fetchList]);

  const selectedIncident =
    (selectedIncidentId ? incidents.find((i) => i.incidentId === selectedIncidentId) : null) ||
    incidents[0] ||
    null;

  return {
    connected,
    hasData,
    incidents,
    selectedIncident,
    selectedNode,
    selectedTimelineEvent,
    lastUpdateTime,
    selectIncident,
    selectNode,
    selectTimelineEvent,
    refresh: fetchList,
  };
}
