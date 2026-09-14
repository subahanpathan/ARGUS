/**
 * usePortIntelligence — React hook for consuming real-time Windows port
 * intelligence via SSE.
 *
 * Provides TCP listening ports, UDP endpoints, lifecycle events
 * (PORT_OPENED / PORT_CLOSED / PORT_CHANGED), and summary statistics from
 * the ARGUS security engine.
 */

import { useCallback, useEffect, useRef, useState } from "react";

export type PortInfo = {
  port_id?: string;
  protocol?: string;
  address_family?: string;
  local_addr?: string;
  local_port?: number;
  state?: string;
  pid?: number;
  process_name?: string;
  executable_path?: string;
  binding_type?: string;
  local_role?: string;
  first_seen?: string;
  last_seen?: string;
  associated_connection_ids?: string[];
};

export type PortEvent = {
  event_type?: string;
  timestamp?: string;
  port_id?: string;
  protocol?: string;
  address_family?: string;
  local_addr?: string;
  local_port?: number;
  state?: string;
  pid?: number;
  process_name?: string;
  executable_path?: string;
  binding_type?: string;
  previous_pid?: number;
  previous_process_name?: string;
  previous_state?: string;
  change_details?: string;
};

export type PortSummary = {
  tcp_listening_count?: number;
  udp_endpoint_count?: number;
  ipv4_listening_count?: number;
  ipv6_listening_count?: number;
  loopback_count?: number;
  wildcard_count?: number;
  interface_count?: number;
  active_tcp_connections?: number;
  unique_processes?: number;
};

export type PortIntelligenceData = {
  timestamp: string;
  tcp_listening?: PortInfo[];
  udp_endpoints?: PortInfo[];
  port_events?: PortEvent[];
  summary?: PortSummary;
  active_tcp_connections?: number;
};

export type PortIntelligenceState = {
  /** Whether the SSE connection is active */
  connected: boolean;
  /** Whether we've ever received port data */
  hasData: boolean;
  /** Latest port intelligence snapshot (null = never received) */
  snapshot: PortIntelligenceData | null;
  /** ISO timestamp of last received snapshot */
  lastSnapshotTime: string | null;
  /** Accumulated port lifecycle events (bounded session history) */
  events: PortEvent[];
};

const RECONNECT_DELAY_MS = 3000;
const POLL_MS = 5000;
const MAX_CLIENT_EVENTS = 300;

/** Append port events to client history, de-duplicating by (timestamp, port_id). */
function appendPortEvents(prev: PortEvent[], incoming: PortEvent[]): PortEvent[] {
  if (!incoming.length) return prev;
  const keyOf = (e: PortEvent) =>
    `${e.timestamp}|${e.event_type ?? ""}|${e.port_id ?? ""}|${e.local_addr ?? ""}|${e.local_port ?? ""}`;
  const known = new Set(prev.map(keyOf));
  const fresh = incoming.filter((e) => !known.has(keyOf(e)));
  if (!fresh.length) return prev;
  return [...prev, ...fresh].slice(-MAX_CLIENT_EVENTS);
}

export function usePortIntelligence(): PortIntelligenceState {
  const [connected, setConnected] = useState(false);
  const [hasData, setHasData] = useState(false);
  const [snapshot, setSnapshot] = useState<PortIntelligenceData | null>(null);
  const [lastSnapshotTime, setLastSnapshotTime] = useState<string | null>(null);
  const [events, setEvents] = useState<PortEvent[]>([]);
  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchPorts = useCallback(async () => {
    try {
      const resp = await fetch("/api/network/ports");
      if (resp.ok) {
        const data = await resp.json();
        if (data && data.timestamp) {
          setSnapshot(data);
          setLastSnapshotTime(data.timestamp);
          setHasData(true);
          setEvents((prev) => appendPortEvents(prev, data.port_events ?? []));
        }
      }
    } catch {
      // API not reachable — expected when engine is not running
    }
  }, []);

  const fetchPortEvents = useCallback(async () => {
    try {
      const resp = await fetch("/api/network/ports/events?limit=300");
      if (resp.ok) {
        const data = await resp.json();
        if (data && Array.isArray(data.events)) {
          setEvents(data.events);
        }
      }
    } catch {
      // API not reachable — expected when engine is not running
    }
  }, []);

  useEffect(() => {
    let cancelled = false;

    function connect() {
      if (cancelled) return;

      try {
        const es = new EventSource("/api/network/ports/stream");

        es.onopen = () => {
          if (!cancelled) {
            setConnected(true);
          }
        };

        es.onmessage = (msg) => {
          if (cancelled) return;
          try {
            const data = JSON.parse(msg.data);

            // Connection confirmation — may include initial snapshot
            if (data.type === "connected") {
              if (data.snapshot && data.snapshot.timestamp) {
                setSnapshot(data.snapshot);
                setLastSnapshotTime(data.snapshot.timestamp);
                setHasData(true);
              }
              fetchPortEvents();
              return;
            }

            // Typed port-event broadcast (PORT_OPENED/PORT_CLOSED/PORT_CHANGED)
            if (typeof data.type === "string" && data.type.startsWith("network.port") && data.event) {
              setEvents((prev) => appendPortEvents(prev, [data.event]));
              return;
            }

            // Full port intelligence snapshot
            if (data.timestamp && Array.isArray(data.tcp_listening)) {
              setSnapshot(data);
              setLastSnapshotTime(data.timestamp);
              setHasData(true);
              setEvents((prev) => appendPortEvents(prev, data.port_events ?? []));
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

    // Also poll for initial state
    fetchPorts();
    fetchPortEvents();
    const pollInterval = setInterval(fetchPorts, POLL_MS);

    return () => {
      cancelled = true;
      eventSourceRef.current?.close();
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      clearInterval(pollInterval);
    };
  }, [fetchPorts, fetchPortEvents]);

  return { connected, hasData, snapshot, lastSnapshotTime, events };
}