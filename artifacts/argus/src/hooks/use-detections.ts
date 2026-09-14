/**
 * useDetections — React hook for consuming detections produced by the ARGUS
 * detection engine.
 *
 * Fetches the buffered detection list and streams live updates via SSE.
 * Falls back to unavailable state when the API is not running.
 */

import { useCallback, useEffect, useRef, useState } from "react";

export type DetectionSeverity = "critical" | "high" | "medium" | "low";

export type DetectionStatus =
  | "observed"
  | "detected"
  | "investigated"
  | "contained"
  | "resolved";

export type DetectionEvidence = {
  key: string;
  description: string;
  source: "process" | "command_line" | "executable_path" | "parent" | "ancestry" | "network" | "connection" | "port" | "file" | "path";
  detail?: string;
};

export type DetectionAncestryNode = {
  pid: number;
  process_name: string;
  executable_path?: string | null;
  command_line?: string | null;
  username?: string | null;
};

export type DetectionRule = {
  rule_id: string;
  rule_name: string;
  description: string;
};

export type Detection = {
  id: string;
  rule_id: string;
  rule_name: string;
  title: string;
  severity: DetectionSeverity;
  confidence: number;
  status: DetectionStatus;
  timestamp: string;
  event_timestamp: string;
  entity: string;
  pid: number;
  executable_path?: string | null;
  command_line?: string | null;
  parent_pid?: number | null;
  parent_process_name?: string | null;
  username?: string | null;
  hostname: string | null;
  evidence: DetectionEvidence[];
  explanation: string;
  recommended_action: string;
  correlated_rules?: string[];
  ancestry: DetectionAncestryNode[];
  related_event_id?: string | null;
};

/** Lightweight view of the current process context returned by the detail endpoint. */
export type DetectionProcessContext = {
  pid?: number;
  name?: string;
  executable_path?: string | null;
  command_line?: string | null;
  parent_pid?: number | null;
  parent_name?: string | null;
  username?: string | null;
  cpu_percent?: number;
  memory_bytes?: number;
  status?: string;
  access_error?: string;
} | null;

export type DetectionDetail = {
  detection: Detection;
  related: Detection[];
  process: DetectionProcessContext;
  ancestry: DetectionAncestryNode[];
};

export type DetectionFilters = {
  severity?: DetectionSeverity;
  status?: DetectionStatus;
  rule_id?: string;
};

export type DetectionState = {
  /** Whether the SSE connection is active */
  connected: boolean;
  /** Whether we've ever received data from the API */
  hasData: boolean;
  /** Buffered detections from the engine, newest first */
  detections: Detection[];
  /** Catalog of active detection rules */
  rules: DetectionRule[];
  /** Single detection loaded via the detail endpoint */
  selected: DetectionDetail | null;
  /** Rules applied to the live list (query params) */
  filters: DetectionFilters;
  /** Timestamp of the last received update */
  lastUpdateTime: string | null;
  /** Load a single detection detail (including related + ancestry). */
  loadDetail: (id: string) => Promise<void>;
  /** Update the lifecycle status of a detection. */
  updateStatus: (id: string, status: DetectionStatus) => Promise<boolean>;
  /** Merge additional filters into the live list query. */
  setFilter: (filters: DetectionFilters) => void;
};

const MAX_ITEMS = 300;
const RECONNECT_DELAY_MS = 3000;
const POLL_MS = 10000;

function applyDetections(prev: Detection[], incoming: Detection[]): Detection[] {
  if (!incoming.length) return prev;
  const seen = new Map<string, Detection>();
  for (const d of prev) seen.set(d.id, d);
  for (const d of incoming) seen.set(d.id, d);
  const merged = [...seen.values()]
    .sort((a, b) => (a.timestamp < b.timestamp ? 1 : a.timestamp > b.timestamp ? -1 : 0))
    .slice(0, MAX_ITEMS);
  return merged;
}

export function useDetections(): DetectionState {
  const [connected, setConnected] = useState(false);
  const [hasData, setHasData] = useState(false);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [selected, setSelected] = useState<DetectionDetail | null>(null);
  const [filters, setFilters] = useState<DetectionFilters>({});
  const [lastUpdateTime, setLastUpdateTime] = useState<string | null>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const applyOne = useCallback((detection: Detection) => {
    setDetections((prev) => applyDetections(prev, [detection]));
    setLastUpdateTime(detection.timestamp);
    setHasData(true);
  }, []);

  const fetchList = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      if (filters.severity) params.set("severity", filters.severity);
      if (filters.status) params.set("status", filters.status);
      if (filters.rule_id) params.set("rule_id", filters.rule_id);
      const qs = params.toString();
      const resp = await fetch(`/api/detections${qs ? `?${qs}` : ""}`);
      if (resp.ok) {
        const data = await resp.json();
        if (Array.isArray(data.detections)) {
          setDetections((prev) => applyDetections(prev, data.detections));
          setHasData(true);
        }
        if (Array.isArray(data.rules)) {
          setRules(data.rules);
        }
      }
    } catch {
      // API not reachable — expected when engine is not running
    }
  }, [filters]); // eslint-disable-line react-hooks/exhaustive-deps

  const loadDetail = useCallback(async (id: string) => {
    try {
      const resp = await fetch(`/api/detections/${encodeURIComponent(id)}`);
      if (resp.ok) {
        const data = await resp.json();
        if (data && data.detection) {
          setSelected(data);
        }
      }
    } catch {
      // API not reachable
    }
  }, []);

  const updateStatus = useCallback(async (id: string, status: DetectionStatus) => {
    try {
      const resp = await fetch(`/api/detections/${encodeURIComponent(id)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status }),
      });
      if (resp.ok) {
        const data = await resp.json();
        if (data && data.detection) {
          setDetections((prev) => applyDetections(prev, [data.detection]));
          setSelected((cur) => (cur && cur.detection.id === id ? { ...cur, detection: data.detection } : cur));
        }
        return true;
      }
    } catch {
      // API not reachable
    }
    return false;
  }, []);

  const setFilter = useCallback((next: DetectionFilters) => {
    setFilters((cur) => {
      const merged = { ...cur, ...next };
      for (const key of Object.keys(merged)) {
        const k = key as keyof DetectionFilters;
        if (!merged[k]) delete merged[k];
      }
      return merged;
    });
  }, []);

  useEffect(() => {
    let cancelled = false;

    function connect() {
      if (cancelled) return;

      try {
        const es = new EventSource("/api/detections/stream");

        es.onopen = () => {
          if (!cancelled) {
            setConnected(true);
          }
        };

        es.onmessage = (msg) => {
          if (cancelled) return;
          try {
            const data = JSON.parse(msg.data);

            if (data.type === "connected") {
              if (Array.isArray(data.detections)) {
                setDetections((prev) => applyDetections(prev, data.detections));
                setHasData(true);
              }
              return;
            }

            if (data.type === "detection" && data.detection) {
              applyOne(data.detection);
              return;
            }

            if (data.type === "detection.updated" && data.detection) {
              const updated = data.detection;
              setDetections((prev) => applyDetections(prev, [updated]));
              setSelected((cur) =>
                cur && cur.detection.id === updated.id ? { ...cur, detection: updated } : cur,
              );
            }
          } catch {
            // Ignore parse errors (heartbeat lines etc.)
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

    // Poll for the buffered list so fresh loads see latest state.
    fetchList();
    const pollInterval = setInterval(fetchList, POLL_MS);

    return () => {
      cancelled = true;
      eventSourceRef.current?.close();
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      clearInterval(pollInterval);
    };
  }, [fetchList]);

  return { connected, hasData, detections, rules, selected, filters, lastUpdateTime, loadDetail, updateStatus, setFilter };
}