/**
 * useTelemetryStream — React hook for consuming real-time Windows system
 * telemetry via SSE.
 *
 * Connects to the ARGUS API telemetry SSE endpoint and provides live
 * CPU, memory, disk, process count, uptime, and network state.
 * Falls back to unavailable/offline state when the API is not running.
 */

import { useCallback, useEffect, useRef, useState } from "react";

export type TelemetryCpu = {
  percent?: number;
  count?: number;
  physical_count?: number;
} | null;

export type TelemetryMemory = {
  total_bytes?: number;
  available_bytes?: number;
  used_bytes?: number;
  percent?: number;
} | null;

export type TelemetryDisk = {
  mount?: string;
  total_bytes?: number;
  used_bytes?: number;
  free_bytes?: number;
  percent?: number;
} | null;

export type TelemetryProcesses = {
  running?: number;
} | null;

export type TelemetrySystem = {
  uptime_seconds?: number;
  boot_time?: number;
} | null;

export type TelemetryNetworkInterface = {
  name?: string;
  is_up?: boolean;
  is_running?: boolean;
  mtu?: number;
  speed?: number;
  addresses?: string[];
  bytes_sent?: number;
  bytes_recv?: number;
};

export type TelemetryNetwork = {
  interfaces?: TelemetryNetworkInterface[];
  active_count?: number;
  total_count?: number;
} | null;

export type SystemTelemetryData = {
  timestamp: string;
  source: string;
  observed: boolean;
  cpu?: TelemetryCpu;
  memory?: TelemetryMemory;
  disk?: TelemetryDisk;
  processes?: TelemetryProcesses;
  system?: TelemetrySystem;
  network?: TelemetryNetwork;
};

export type TelemetryStreamState = {
  /** Whether the SSE connection is active */
  connected: boolean;
  /** Whether we've ever received telemetry data */
  hasData: boolean;
  /** The latest telemetry snapshot (null = never received) */
  telemetry: SystemTelemetryData | null;
  /** ISO timestamp of last received telemetry */
  lastUpdateTime: string | null;
};

const RECONNECT_DELAY_MS = 3000;
const POLL_MS = 5000;

export function useTelemetryStream(): TelemetryStreamState {
  const [connected, setConnected] = useState(false);
  const [hasData, setHasData] = useState(false);
  const [telemetry, setTelemetry] = useState<SystemTelemetryData | null>(null);
  const [lastUpdateTime, setLastUpdateTime] = useState<string | null>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchTelemetry = useCallback(async () => {
    try {
      const resp = await fetch("/api/system/telemetry");
      if (resp.ok) {
        const data = await resp.json();
        if (data && data.timestamp && data.source) {
          setTelemetry(data);
          setLastUpdateTime(data.timestamp);
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
        const es = new EventSource("/api/system/telemetry/stream");

        es.onopen = () => {
          if (!cancelled) {
            setConnected(true);
          }
        };

        es.onmessage = (msg) => {
          if (cancelled) return;
          try {
            const data = JSON.parse(msg.data);

            // Connection confirmation — may include initial telemetry
            if (data.type === "connected") {
              if (data.telemetry && data.telemetry.timestamp) {
                setTelemetry(data.telemetry);
                setLastUpdateTime(data.telemetry.timestamp);
                setHasData(true);
              }
              return;
            }

            // Full telemetry snapshot
            if (data.timestamp && data.source) {
              setTelemetry(data);
              setLastUpdateTime(data.timestamp);
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
    fetchTelemetry();
    const pollInterval = setInterval(fetchTelemetry, POLL_MS);

    return () => {
      cancelled = true;
      eventSourceRef.current?.close();
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      clearInterval(pollInterval);
    };
  }, [fetchTelemetry]);

  return { connected, hasData, telemetry, lastUpdateTime };
}
