/**
 * useNetworkMonitor — React hook for consuming real-time network connection
 * data via SSE.
 *
 * Connects to the ARGUS API network SSE endpoint and provides live
 * connection data (process, remote address, protocol, status).
 * Falls back to unavailable state when the API is not running.
 */

import { useCallback, useEffect, useRef, useState } from "react";

export type RealNetworkConnection = {
  process: string;
  pid?: number;
  connection_id?: string;
  local_addr?: string;
  local_port?: number;
  remote_addr?: string;
  remote_port?: number;
  family?: string;
  address_family?: string;
  type?: string;
  status?: string;
  local_role?: string;
  remote_role?: string;
  executable_path?: string;
  timestamp?: string;
};

export type RealNetworkSnapshot = {
  timestamp: string;
  total_count: number;
  established_count: number;
  listen_count: number;
  listening_count?: number;
  tcp_count?: number;
  udp_count?: number;
  time_wait_count?: number;
  other_state_count?: number;
  ipv4_count?: number;
  ipv6_count?: number;
  unique_remote_ips?: number;
  unique_processes?: number;
  connections: RealNetworkConnection[];
};

export type NetworkMonitorState = {
  /** Whether the SSE connection is active */
  connected: boolean;
  /** Whether we've ever received data from the API */
  hasData: boolean;
  /** Current network snapshot */
  snapshot: RealNetworkSnapshot | null;
  /** Timestamp of last received snapshot */
  lastSnapshotTime: string | null;
};

const RECONNECT_DELAY_MS = 3000;
const POLL_MS = 5000;

export function useNetworkMonitor(): NetworkMonitorState {
  const [connected, setConnected] = useState(false);
  const [hasData, setHasData] = useState(false);
  const [snapshot, setSnapshot] = useState<RealNetworkSnapshot | null>(null);
  const [lastSnapshotTime, setLastSnapshotTime] = useState<string | null>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchSnapshot = useCallback(async () => {
    try {
      const resp = await fetch("/api/network/connections");
      if (resp.ok) {
        const data = await resp.json();
        if (data && data.timestamp && Array.isArray(data.connections)) {
          setSnapshot(data);
          setLastSnapshotTime(data.timestamp);
          setHasData(true);
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
        const es = new EventSource("/api/network/connections/stream");

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
              if (data.snapshot && data.snapshot.timestamp && !Array.isArray(data.snapshot.interfaces)) {
                setSnapshot(data.snapshot);
                setLastSnapshotTime(data.snapshot.timestamp);
                setHasData(true);
              }
              return;
            }

            // Full network snapshot
            // Guard: a topology snapshot also carries a 'connections' array, so
            // require the connection-specific shape and absence of topology-only keys.
            if (data.timestamp && Array.isArray(data.connections) && !Array.isArray(data.interfaces)) {
              setSnapshot(data);
              setLastSnapshotTime(data.timestamp);
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
    fetchSnapshot();
    const pollInterval = setInterval(fetchSnapshot, POLL_MS);

    return () => {
      cancelled = true;
      eventSourceRef.current?.close();
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      clearInterval(pollInterval);
    };
  }, [fetchSnapshot]);

  return { connected, hasData, snapshot, lastSnapshotTime };
}
