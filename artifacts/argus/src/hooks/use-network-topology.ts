/**
 * useNetworkTopology — React hook for consuming real-time Windows network
 * topology via SSE.
 *
 * Provides interface, gateway, DNS, connection and traffic-rate data from
 * the ARGUS security engine. The visualization and connection table consume
 * this single source of truth.
 */

import { useCallback, useEffect, useRef, useState } from "react";

export type TopologyInterface = {
  name: string;
  friendly_name?: string;
  interface_type?: string;
  is_up?: boolean;
  is_running?: boolean;
  mtu?: number;
  speed?: number;
  mac_address?: string;
  addresses?: string[];
  bytes_sent?: number;
  bytes_recv?: number;
};

export type TopologyGateway = {
  next_hop?: string;
  interface?: string;
  metric?: number;
};

export type TopologyDns = {
  interface?: string;
  servers?: string[];
};

export type TopologyConnection = {
  id?: string;
  connection_id?: string;
  pid?: number;
  process_name?: string;
  process_path?: string;
  executable_path?: string;
  local_addr?: string;
  local_port?: number;
  remote_addr?: string;
  remote_port?: number;
  remote_hostname?: string;
  protocol?: string;
  address_family?: string;
  state?: string;
  status?: string;
  local_role?: string;
  remote_role?: string;
  first_seen?: string;
  last_seen?: string;
};

export type TopologyTrafficRate = {
  interface?: string;
  bytes_sent?: number;
  bytes_recv?: number;
  bytes_sent_rate?: number;
  bytes_recv_rate?: number;
};

export type TopologyNeighbor = {
  ip?: string;
  mac?: string;
  interface?: string;
  state?: string;
  hostname?: string;
};

export type TopologyConnectionEvent = {
  event_type?: string;
  timestamp?: string;
  connection_id?: string;
  process_name?: string;
  pid?: number;
  protocol?: string;
  address_family?: string;
  local_addr?: string;
  local_port?: number;
  remote_addr?: string;
  remote_port?: number;
  state?: string;
  previous_state?: string;
  local_role?: string;
  remote_role?: string;
  /** Human-readable message for infrastructure events (GATEWAY_CHANGE, DNS_CHANGE, etc.) */
  message?: string;
};

export type NetworkTopologyData = {
  timestamp: string;
  hostname?: string;
  interfaces?: TopologyInterface[];
  default_gateway?: TopologyGateway;
  dns_servers?: TopologyDns[];
  connections?: TopologyConnection[];
  traffic_rates?: TopologyTrafficRate[];
  neighbors?: TopologyNeighbor[];
  connection_events?: TopologyConnectionEvent[];
  public_ip?: string;
  udp_endpoints?: number;
  tcp_listening?: number;
  total_connections?: number;
  established_count?: number;
  listen_count?: number;
  tcp_count?: number;
  udp_count?: number;
  time_wait_count?: number;
  other_state_count?: number;
  ipv4_count?: number;
  ipv6_count?: number;
  unique_remote_ips?: number;
  unique_processes?: number;
};

export type NetworkTopologyState = {
  /** Whether the SSE connection is active */
  connected: boolean;
  /** Whether we've ever received topology data */
  hasData: boolean;
  /** Latest topology snapshot (null = never received) */
  snapshot: NetworkTopologyData | null;
  /** ISO timestamp of last received topology */
  lastSnapshotTime: string | null;
  /** Accumulated connection lifecycle events (bounded session history) */
  events: TopologyConnectionEvent[];
  /** Number of events observed on the server (including before this client connected) */
  eventCount: number;
};

const RECONNECT_DELAY_MS = 3000;
const POLL_MS = 5000;
const MAX_CLIENT_EVENTS = 500;

/** Append events to client history, de-duplicating by (timestamp, event key). */
function appendEvents(prev: TopologyConnectionEvent[], incoming: TopologyConnectionEvent[]): TopologyConnectionEvent[] {
  if (!incoming.length) return prev;
  const keyOf = (e: TopologyConnectionEvent) =>
    `${e.timestamp}|${e.event_type ?? ""}|${e.connection_id ?? ""}|${e.local_addr ?? ""}|${e.remote_port ?? ""}|${e.local_port ?? ""}|${e.state ?? ""}`;
  const known = new Set(prev.map(keyOf));
  const fresh = incoming.filter((e) => !known.has(keyOf(e)));
  if (!fresh.length) return prev;
  return [...prev, ...fresh].slice(-MAX_CLIENT_EVENTS);
}

/** True when the endpoint is in LISTEN state (not a client connection). */
export function isListening(conn: TopologyConnection): boolean {
  return conn.state === "LISTEN" || conn.state === "BOUND";
}

/** True when the connection is an active established client session. */
export function isEstablished(conn: TopologyConnection): boolean {
  return conn.state === "ESTABLISHED";
}

/** True when this interface is the likely active WAN-facing adapter. */
export function isActiveInterface(iface: TopologyInterface): boolean {
  if (!iface.is_up || !iface.is_running) return false;
  return (iface.addresses || []).some((a) => /^\d+\.\d+\.\d+\.\d+$/.test(a) && !a.startsWith("169.254."));
}

export function useNetworkTopology(): NetworkTopologyState {
  const [connected, setConnected] = useState(false);
  const [hasData, setHasData] = useState(false);
  const [snapshot, setSnapshot] = useState<NetworkTopologyData | null>(null);
  const [lastSnapshotTime, setLastSnapshotTime] = useState<string | null>(null);
  const [events, setEvents] = useState<TopologyConnectionEvent[]>([]);
  const [eventCount, setEventCount] = useState(0);
  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchTopology = useCallback(async () => {
    try {
      const resp = await fetch("/api/network/topology");
      if (resp.ok) {
        const data = await resp.json();
        if (data && data.timestamp && Array.isArray(data.interfaces)) {
          setSnapshot(data);
          setLastSnapshotTime(data.timestamp);
          setHasData(true);
          // Carry over any events seen so far when the snapshot is refreshed.
          setEvents((prev) => appendEvents(prev, data.connection_events ?? []));
        }
      }
    } catch {
      // API not reachable — expected when engine is not running
    }
  }, []);

  const fetchEvents = useCallback(async () => {
    try {
      const resp = await fetch("/api/network/events?limit=500");
      if (resp.ok) {
        const data = await resp.json();
        if (data && Array.isArray(data.events)) {
          setEvents(data.events);
          setEventCount(data.count ?? data.events.length);
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
        const es = new EventSource("/api/network/topology/stream");

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
              fetchEvents();
              return;
            }

            // Typed connection-event broadcast (NEW/CLOSED/STATE_CHANGE/infra)
            if (typeof data.type === "string" && (data.type === "network.event" || data.type === "network.infrastructure_event" || data.type.startsWith("network.connection")) && data.event) {
              setEvents((prev) => appendEvents(prev, [data.event]));
              return;
            }

            // Full topology snapshot
            if (data.timestamp && Array.isArray(data.interfaces)) {
              setSnapshot(data);
              setLastSnapshotTime(data.timestamp);
              setHasData(true);
              setEvents((prev) => appendEvents(prev, data.connection_events ?? []));
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
    fetchTopology();
    fetchEvents();
    const pollInterval = setInterval(fetchTopology, POLL_MS);

    return () => {
      cancelled = true;
      eventSourceRef.current?.close();
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      clearInterval(pollInterval);
    };
  }, [fetchTopology, fetchEvents]);

  return { connected, hasData, snapshot, lastSnapshotTime, events, eventCount };
}