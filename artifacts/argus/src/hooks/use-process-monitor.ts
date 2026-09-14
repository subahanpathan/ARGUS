/**
 * useProcessMonitor — React hook for consuming real-time process events via SSE.
 *
 * Connects to the ARGUS API SSE endpoint and provides real process data.
 * Falls back to unavailable state when the API is not running.
 */

import { useCallback, useEffect, useRef, useState } from "react";

export type RealProcessEvent = {
  id: string;
  event_type: "PROCESS_STARTED" | "PROCESS_TERMINATED" | "SNAPSHOT";
  timestamp: string;
  pid: number;
  process_name: string;
  executable_path?: string;
  parent_pid?: number;
  parent_process_name?: string;
  source: string;
  observed: boolean;
  metadata?: Record<string, unknown>;
};

export type RealProcessInfo = {
  pid: number;
  name: string;
  executable_path?: string;
  parent_pid?: number;
  parent_name?: string;
  creation_time?: string;
  cpu_percent?: number;
  memory_bytes?: number;
  memory_percent?: number;
  username?: string;
  status?: string;
  access_error?: string;
};

export type ProcessMonitorState = {
  /** Whether the SSE connection is active */
  connected: boolean;
  /** Whether we've ever received data from the API */
  hasData: boolean;
  /** Recent process events (start/terminate) */
  events: RealProcessEvent[];
  /** Current process snapshot (all running processes) */
  snapshot: RealProcessInfo[];
  /** Total number of events received */
  eventCount: number;
  /** Timestamp of last received event */
  lastEventTime: string | null;
};

const MAX_EVENTS = 200;
const RECONNECT_DELAY_MS = 3000;
const SNAPSHOT_POLL_MS = 10000;

export function useProcessMonitor(): ProcessMonitorState {
  const [connected, setConnected] = useState(false);
  const [hasData, setHasData] = useState(false);
  const [events, setEvents] = useState<RealProcessEvent[]>([]);
  const [snapshot, setSnapshot] = useState<RealProcessInfo[]>([]);
  const [eventCount, setEventCount] = useState(0);
  const [lastEventTime, setLastEventTime] = useState<string | null>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchSnapshot = useCallback(async () => {
    try {
      const resp = await fetch("/api/processes");
      if (resp.ok) {
        const data = await resp.json();
        if (data.processes && Array.isArray(data.processes)) {
          setSnapshot(data.processes);
          setHasData(true);
        }
      }
    } catch {
      // API not reachable — this is expected when engine is not running
    }
  }, []);

  useEffect(() => {
    let cancelled = false;

    function connect() {
      if (cancelled) return;

      try {
        const es = new EventSource("/api/events/process/stream");

        es.onopen = () => {
          if (!cancelled) {
            setConnected(true);
          }
        };

        es.onmessage = (msg) => {
          if (cancelled) return;
          try {
            const data = JSON.parse(msg.data);

            // Connection confirmation
            if (data.type === "connected") return;

            // Process event
            if (data.event_type && data.pid) {
              setEvents((prev) => {
                const next = [...prev, data];
                return next.length > MAX_EVENTS ? next.slice(-MAX_EVENTS) : next;
              });
              setEventCount((c) => c + 1);
              setLastEventTime(data.timestamp);
              setHasData(true);
            }
          } catch {
            // Ignore parse errors (heartbeat lines etc.)
          }
        };

        es.onerror = () => {
          if (!cancelled) {
            setConnected(false);
            es.close();
            // Reconnect after delay
            reconnectTimerRef.current = setTimeout(connect, RECONNECT_DELAY_MS);
          }
        };

        eventSourceRef.current = es;
      } catch {
        // EventSource not supported or other error
        if (!cancelled) {
          reconnectTimerRef.current = setTimeout(connect, RECONNECT_DELAY_MS);
        }
      }
    }

    connect();

    // Also poll for snapshot periodically
    fetchSnapshot();
    const snapshotInterval = setInterval(fetchSnapshot, SNAPSHOT_POLL_MS);

    return () => {
      cancelled = true;
      eventSourceRef.current?.close();
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      clearInterval(snapshotInterval);
    };
  }, [fetchSnapshot]);

  return { connected, hasData, events, snapshot, eventCount, lastEventTime };
}
