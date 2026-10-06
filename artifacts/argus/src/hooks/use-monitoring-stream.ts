/**
 * useMonitoringStream — React hook for the unified ARGUS Monitoring stream.
 *
 * Consumes the aggregated /api/monitoring/stream SSE endpoint plus the
 * monitoring snapshot / scan / events REST endpoints. Every value it
 * exposes comes from real backend telemetry; absent sources are reported as
 * explicit "unavailable" states, never fabricated.
 */

import { useCallback, useEffect, useRef, useState } from "react";

export type MonitoringHealth = "live" | "degraded" | "partial" | "offline";

export type MonitoringSourceHealth = {
  source: string;
  state: "live" | "stale" | "unavailable";
  lastUpdate: string | null;
};

export type MonitoringEndpoint = {
  hostname: string | null;
  platform: string | null;
  platform_release: string | null;
  uptime_seconds: number | null;
  boot_time: number | null;
  cpu_percent: number | null;
  cpu_count: number | null;
  physical_cpu_count: number | null;
  memory_percent: number | null;
  memory_total_bytes: number | null;
  memory_used_bytes: number | null;
  memory_available_bytes: number | null;
};

export type MonitoringDisk = {
  drive: string;
  total_bytes?: number;
  used_bytes?: number;
  free_bytes?: number;
  percent?: number;
};

export type MonitoringScanState = {
  state: string;
  scan_type?: string;
  started_at?: string | null;
  updated_at?: string | null;
  completed_at?: string | null;
  folders_discovered?: number;
  files_discovered?: number;
  folders_scanned?: number;
  files_scanned?: number;
  bytes_scanned?: number;
  errors?: number;
  skipped?: number;
  current_path?: string;
  current_operation?: string;
  roots?: string[];
};

export type MonitoringSnapshot = {
  generatedAt: string;
  health: MonitoringHealth;
  healthDetail: MonitoringSourceHealth[];
  endpoint: MonitoringEndpoint;
  processes: { observed: boolean; total_count: number; access_denied_count: number };
  network: {
    observed: boolean;
    total_count: number;
    established_count: number;
    listen_count: number;
    interfaces: number;
    active_interfaces: number;
  };
  ports: {
    observed: boolean;
    tcp_listening: number;
    udp_endpoints: number;
    active_tcp_connections: number;
  };
  files: { observed: boolean; findings: number; files_hashed: number; directories_scanned: number };
  services: {
    observed: boolean;
    total_count: number;
    running_count: number;
    stopped_count: number;
  };
  disks: MonitoringDisk[];
  scan: MonitoringScanState | null;
  lastTel: string | null;
};

export type AggregatedMonitorEvent = {
  timestamp: string;
  type: string;
  source: string;
  title: string;
  detail: string;
};

export type MonitoringStreamState = {
  /** Whether the SSE connection is active */
  connected: boolean;
  /** Whether we've ever received a monitoring snapshot */
  hasData: boolean;
  /** Latest normalized monitoring snapshot (null = never received) */
  snapshot: MonitoringSnapshot | null;
  /** ISO timestamp of last received snapshot */
  lastSnapshotTime: string | null;
  /** Latest filesystem scan state (null = never received) */
  scan: MonitoringScanState | null;
  /** Bounded merged event feed from every source */
  events: AggregatedMonitorEvent[];
};

const RECONNECT_DELAY_MS = 3000;
const POLL_MS = 5000;
const MAX_EVENTS = 240;

export function useMonitoringStream(): MonitoringStreamState {
  const [connected, setConnected] = useState(false);
  const [hasData, setHasData] = useState(false);
  const [snapshot, setSnapshot] = useState<MonitoringSnapshot | null>(null);
  const [lastSnapshotTime, setLastSnapshotTime] = useState<string | null>(null);
  const [scan, setScan] = useState<MonitoringScanState | null>(null);
  const [events, setEvents] = useState<AggregatedMonitorEvent[]>([]);
  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const appendEvents = useCallback((incoming: AggregatedMonitorEvent[]) => {
    if (!incoming.length) return;
    setEvents((prev) => {
      const known = new Set(prev.map((e) => `${e.timestamp}|${e.type}|${e.source}|${e.detail}`));
      const fresh = incoming.filter((e) => !known.has(`${e.timestamp}|${e.type}|${e.source}|${e.detail}`));
      if (!fresh.length) return prev;
      return [...prev, ...fresh].slice(-MAX_EVENTS);
    });
  }, []);

  const applySnapshot = useCallback((data: MonitoringSnapshot | null | undefined) => {
    if (!data || !data.generatedAt) return;
    setSnapshot(data);
    setLastSnapshotTime(data.generatedAt);
    setHasData(true);
  }, []);

  const fetchSnapshot = useCallback(async () => {
    try {
      const resp = await fetch("/api/monitoring");
      if (resp.ok) {
        const data = await resp.json();
        applySnapshot(data);
      }
    } catch {
      // API not reachable — expected when engine/server is not running
    }
  }, [applySnapshot]);

  const fetchScan = useCallback(async () => {
    try {
      const resp = await fetch("/api/monitoring/scan");
      if (resp.ok) {
        const data = await resp.json();
        if (data && typeof data.state === "string") setScan(data);
      }
    } catch {
      // ignore
    }
  }, []);

  const fetchEvents = useCallback(async () => {
    try {
      const resp = await fetch("/api/monitoring/events?limit=100");
      if (resp.ok) {
        const data = await resp.json();
        if (data && Array.isArray(data.events)) appendEvents(data.events);
      }
    } catch {
      // ignore
    }
  }, [appendEvents]);

  useEffect(() => {
    let cancelled = false;

    function connect() {
      if (cancelled) return;

      try {
        const es = new EventSource("/api/monitoring/stream");

        es.onopen = () => {
          if (!cancelled) setConnected(true);
        };

        es.onmessage = (msg) => {
          if (cancelled) return;
          try {
            const data = JSON.parse(msg.data);

            if (data.type === "connected") {
              if (data.snapshot && data.snapshot.generatedAt) applySnapshot(data.snapshot);
              fetchScan();
              fetchEvents();
              return;
            }

            if (data.type === "monitoring" && data.snapshot) {
              applySnapshot(data.snapshot);
              if (data.snapshot.scan) setScan(data.snapshot.scan);
              return;
            }

            if (data.type === "monitoring.scan" && data.scan) {
              setScan(data.scan);
              return;
            }
          } catch {
            // ignore parse errors (heartbeats, partial frames)
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

    // Poll-based fallback for initial state + recovery.
    fetchSnapshot();
    fetchScan();
    fetchEvents();
    const pollInterval = setInterval(() => {
      fetchSnapshot();
      fetchEvents();
    }, POLL_MS);

    return () => {
      cancelled = true;
      eventSourceRef.current?.close();
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      clearInterval(pollInterval);
    };
  }, [fetchSnapshot, fetchScan, fetchEvents, applySnapshot]);

  return { connected, hasData, snapshot, lastSnapshotTime, scan, events };
}