/**
 * useFileScan — React hook for consuming real filesystem threat scan
 * results from the ARGUS security engine.
 *
 * Connects to the ARGUS API file-scan SSE endpoint and provides live
 * detection results produced by the engine's file scanner (real files,
 * real SHA-256 hashes). Falls back to unavailable state when offline.
 */

import { useCallback, useEffect, useRef, useState } from "react";

export type RealFileFinding = {
  id: string;
  path: string;
  name: string;
  extension?: string;
  size_bytes?: number;
  modified?: string;
  hash?: string;
  severity: "critical" | "high" | "medium" | "low";
  className: string;
  reason: string;
  category?: string;
  is_running?: boolean;
  source?: string;
  timestamp?: string;
};

export type RealFileScanSnapshot = {
  timestamp: string | null;
  directories_scanned?: number;
  files_candidates?: number;
  files_hashed?: number;
  files_read?: number;
  total_count: number;
  findings: RealFileFinding[];
};

export type FileScanState = {
  /** Whether the SSE connection is active */
  connected: boolean;
  /** Whether we've ever received a file scan snapshot */
  hasData: boolean;
  /** Current file scan snapshot */
  snapshot: RealFileScanSnapshot | null;
  /** Findings from the latest scan */
  findings: RealFileFinding[];
  /** Timestamp of last received scan */
  lastScanTime: string | null;
};

const RECONNECT_DELAY_MS = 3000;
const POLL_MS = 10000;

export function useFileScan(): FileScanState {
  const [connected, setConnected] = useState(false);
  const [hasData, setHasData] = useState(false);
  const [snapshot, setSnapshot] = useState<RealFileScanSnapshot | null>(null);
  const [findings, setFindings] = useState<RealFileFinding[]>([]);
  const [lastScanTime, setLastScanTime] = useState<string | null>(null);
  const eventSourceRef = useRef<EventSource | null>(null);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const applySnapshot = useCallback((data: RealFileScanSnapshot) => {
    if (data && Array.isArray(data.findings)) {
      setSnapshot(data);
      setFindings(data.findings);
      setLastScanTime(data.timestamp);
      if (data.timestamp) {
        setHasData(true);
      }
    }
  }, []);

  const fetchSnapshot = useCallback(async () => {
    try {
      const resp = await fetch("/api/files/scan");
      if (resp.ok) {
        const data = await resp.json();
        if (data && Array.isArray(data.findings)) {
          applySnapshot(data);
        }
      }
    } catch {
      // API not reachable — expected when engine is not running
    }
  }, [applySnapshot]);

  useEffect(() => {
    let cancelled = false;

    function connect() {
      if (cancelled) return;

      try {
        const es = new EventSource("/api/files/scan/stream");

        es.onopen = () => {
          if (!cancelled) {
            setConnected(true);
          }
        };

        es.onmessage = (msg) => {
          if (cancelled) return;
          try {
            const data = JSON.parse(msg.data);

            // Connection confirmation — may include initial scan
            if (data.type === "connected") {
              if (data.scan && Array.isArray(data.scan.findings)) {
                applySnapshot(data.scan);
              }
              return;
            }

            // Full file scan snapshot
            if (data.timestamp && Array.isArray(data.findings)) {
              applySnapshot(data);
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
  }, [fetchSnapshot, applySnapshot]);

  return { connected, hasData, snapshot, findings, lastScanTime };
}