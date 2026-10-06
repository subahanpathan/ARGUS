import { useCallback, useEffect, useRef, useState } from 'react';

export type SubsystemState = {
  state: 'running' | 'starting' | 'degraded' | 'unavailable' | 'stopped';
  lastUpdate?: string | null;
  processCount?: number;
  connectionCount?: number;
  providerCount?: number;
  rulesLoaded?: number;
  available?: boolean;
};

export type AgentHealthData = {
  state: 'STARTING' | 'RUNNING' | 'DEGRADED' | 'STOPPED' | 'ERROR';
  protected: boolean;
  live: boolean;
  endpointId: string | null;
  agentVersion: string;
  uptimeSeconds: number;
  timestamp: string;
  lastHeartbeat: string | null;
  componentFailures: Record<string, string>;
  subsystems: {
    agent: SubsystemState;
    telemetry: SubsystemState;
    process_monitor: SubsystemState;
    network_monitor: SubsystemState;
    file_monitor: SubsystemState;
    security_providers: SubsystemState;
    detection_engine: SubsystemState;
    recovery_subsystem: SubsystemState;
  };
};

const DEFAULT_STOPPED_STATE: AgentHealthData = {
  state: 'STOPPED',
  protected: false,
  live: false,
  endpointId: null,
  agentVersion: '1.0.0',
  uptimeSeconds: 0,
  timestamp: new Date().toISOString(),
  lastHeartbeat: null,
  componentFailures: {},
  subsystems: {
    agent: { state: 'stopped', live: false },
    telemetry: { state: 'unavailable', lastUpdate: null },
    process_monitor: { state: 'unavailable', lastUpdate: null, processCount: 0 },
    network_monitor: { state: 'unavailable', lastUpdate: null, connectionCount: 0 },
    file_monitor: { state: 'unavailable', lastUpdate: null },
    security_providers: { state: 'unavailable', lastUpdate: null, providerCount: 0 },
    detection_engine: { state: 'running', available: true, rulesLoaded: 24 },
    recovery_subsystem: { state: 'running', available: true },
  },
};

export function useAgentHealth() {
  const [health, setHealth] = useState<AgentHealthData>(DEFAULT_STOPPED_STATE);
  const [connected, setConnected] = useState(false);
  const eventSourceRef = useRef<EventSource | null>(null);

  const fetchHealth = useCallback(async () => {
    try {
      const resp = await fetch('/api/agent/health');
      if (resp.ok) {
        const data = (await resp.json()) as AgentHealthData;
        setHealth(data);
        setConnected(true);
      } else {
        setHealth((prev) => ({ ...prev, state: 'STOPPED', live: false, protected: false }));
      }
    } catch {
      setHealth((prev) => ({ ...prev, state: 'STOPPED', live: false, protected: false }));
      setConnected(false);
    }
  }, []);

  useEffect(() => {
    void fetchHealth();
    const interval = setInterval(() => {
      void fetchHealth();
    }, 4000);

    return () => clearInterval(interval);
  }, [fetchHealth]);

  // Connect to SSE stream for live agent heartbeat broadcasts
  useEffect(() => {
    try {
      const es = new EventSource('/api/monitoring/stream');
      eventSourceRef.current = es;

      es.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'monitoring.agent' || data.type === 'monitoring.health') {
            void fetchHealth();
          }
        } catch {
          // ignore
        }
      };

      es.onerror = () => {
        // SSE error, fallback to polling
      };

      return () => {
        es.close();
      };
    } catch {
      return undefined;
    }
  }, [fetchHealth]);

  return {
    ...health,
    serverConnected: connected,
    refresh: fetchHealth,
  };
}
