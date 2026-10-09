/**
 * useSimulations — React hook for ARGUS Controlled Simulation Lifecycle.
 *
 * Interfaces with /api/simulations endpoints to:
 * - List approved scenario allowlists (/api/simulations/scenarios)
 * - List all simulation run records (/api/simulations)
 * - Start a scenario run (POST /api/simulations)
 * - Track active simulation progress and metrics (GET /api/simulations/:id)
 * - Safely stop/cancel active simulation (POST /api/simulations/:id/stop)
 */

import { useCallback, useEffect, useState } from 'react';

export type SimulationScenario = {
  id: string;
  name: string;
  description: string;
  safetyLevel: string;
  expectedRules: string[];
  phaseCount: number;
  estimatedDurationMs: number;
};

export type SimulationStatus = 'idle' | 'running' | 'completed' | 'cancelled' | 'failed';

export type SimulationRun = {
  simulationId: string;
  scenarioId: string;
  scenarioName: string;
  status: SimulationStatus;
  startedAt: string;
  completedAt?: string;
  currentPhase: string;
  totalPhases: number;
  phaseLogs: string[];
  firedRules: string[];
  matchedRules: string[];
  missedRules: string[];
  extraRules: string[];
  detectionRate: number;
  passed: boolean;
  groundTruth?: Array<{
    id?: string;
    phase: string;
    timestamp: string;
    detail: string;
    expectedRule?: string | null;
  }>;
};

export type UseSimulationsResult = {
  scenarios: SimulationScenario[];
  simulations: SimulationRun[];
  activeSimulation: SimulationRun | null;
  selectedScenarioId: string;
  setSelectedScenarioId: (id: string) => void;
  isRunning: boolean;
  loading: boolean;
  error: string | null;
  startSimulation: (scenarioId?: string) => Promise<{ success: boolean; simulation?: SimulationRun; error?: string }>;
  stopSimulation: (simulationId?: string) => Promise<{ success: boolean; error?: string }>;
  refresh: () => Promise<void>;
};

const DEFAULT_SCENARIOS: SimulationScenario[] = [
  {
    id: 'reverse_shell_exfiltration',
    name: 'Reverse Shell & Staged Exfiltration',
    description: 'Safe loopback interactive PowerShell shell followed by staged synthetic file exfiltration.',
    safetyLevel: 'SAFE_LAB_ONLY',
    expectedRules: ['NET-008-REVERSE-SHELL', 'NET-009-DATA-EXFILTRATION', 'PROC-007-LOLBIN-EXECUTION'],
    phaseCount: 4,
    estimatedDurationMs: 4200,
  },
  {
    id: 'suspicious_process_spawn',
    name: 'Suspicious Process Spawn (LOLBin Abuse)',
    description: 'Benign certutil.exe download command spawned from script host in isolated lab directory.',
    safetyLevel: 'SAFE_LAB_ONLY',
    expectedRules: ['PROC-007-LOLBIN-EXECUTION'],
    phaseCount: 3,
    estimatedDurationMs: 3000,
  },
  {
    id: 'simulated_network_transfer',
    name: 'Simulated Network Transfer',
    description: 'Synthetic outbound TCP connection directed at private RFC1918 test endpoint.',
    safetyLevel: 'SAFE_LAB_ONLY',
    expectedRules: ['NET-009-DATA-EXFILTRATION'],
    phaseCount: 3,
    estimatedDurationMs: 2500,
  },
  {
    id: 'test_file_integrity',
    name: 'Test File Integrity & Ransomware Pattern',
    description: 'Synthetic test files written with entropy marker in isolated workspace to test integrity hashes.',
    safetyLevel: 'SAFE_LAB_ONLY',
    expectedRules: ['FILE-006-RANSOMWARE-EXT'],
    phaseCount: 3,
    estimatedDurationMs: 3000,
  },
  {
    id: 'benign_browser_activity',
    name: 'Benign Host Activity (False Positive Control)',
    description: 'Benign browser network request to verify zero false-positive detection behavior.',
    safetyLevel: 'SAFE_LAB_ONLY',
    expectedRules: [],
    phaseCount: 2,
    estimatedDurationMs: 2000,
  },
];

export function useSimulations(): UseSimulationsResult {
  const [scenarios, setScenarios] = useState<SimulationScenario[]>(DEFAULT_SCENARIOS);
  const [simulations, setSimulations] = useState<SimulationRun[]>([]);
  const [activeSimulation, setActiveSimulation] = useState<SimulationRun | null>(null);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>(DEFAULT_SCENARIOS[0].id);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Fetch allowlisted scenarios
  const fetchScenarios = useCallback(async () => {
    try {
      const res = await fetch('/api/simulations/scenarios');
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data.scenarios) && data.scenarios.length > 0) {
          setScenarios(data.scenarios);
          if (!selectedScenarioId) {
            setSelectedScenarioId(data.scenarios[0].id);
          }
        }
      }
    } catch {
      // Use DEFAULT_SCENARIOS fallback if API server is offline
    }
  }, [selectedScenarioId]);

  // Fetch simulation runs and track active simulation
  const fetchSimulations = useCallback(async () => {
    try {
      const res = await fetch('/api/simulations');
      if (res.ok) {
        const data = await res.json();
        const runs: SimulationRun[] = Array.isArray(data.simulations) ? data.simulations : [];
        setSimulations(runs);

        // Find the currently running simulation, or the most recent one
        const runningRun = runs.find((r) => r.status === 'running');
        if (runningRun) {
          // Poll specific status for the active run
          const detailRes = await fetch(`/api/simulations/${runningRun.simulationId}`);
          if (detailRes.ok) {
            const detailData = await detailRes.json();
            setActiveSimulation(detailData.simulation || runningRun);
          } else {
            setActiveSimulation(runningRun);
          }
        } else if (runs.length > 0) {
          // If none running, display the latest recorded run
          setActiveSimulation(runs[0]);
        }
        setError(null);
      }
    } catch (err: any) {
      // API not yet running
    }
  }, []);

  useEffect(() => {
    fetchScenarios();
    fetchSimulations();
  }, [fetchScenarios, fetchSimulations]);

  // Polling loop when simulation is running or on interval
  useEffect(() => {
    const isRunning = activeSimulation?.status === 'running';
    const intervalMs = isRunning ? 500 : 3000;

    const timer = setInterval(() => {
      fetchSimulations();
    }, intervalMs);

    return () => clearInterval(timer);
  }, [activeSimulation?.status, fetchSimulations]);

  const startSimulation = useCallback(
    async (scenarioId?: string) => {
      const targetId = scenarioId || selectedScenarioId;
      setLoading(true);
      setError(null);

      try {
        const res = await fetch('/api/simulations', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scenarioId: targetId }),
        });

        const data = await res.json();
        if (res.ok && data.simulation) {
          setActiveSimulation(data.simulation);
          await fetchSimulations();
          return { success: true, simulation: data.simulation };
        } else {
          const err = data.message || data.error || `HTTP error ${res.status}`;
          setError(err);
          return { success: false, error: err };
        }
      } catch (err: any) {
        const msg = err?.message || 'Failed to start simulation';
        setError(msg);
        return { success: false, error: msg };
      } finally {
        setLoading(false);
      }
    },
    [selectedScenarioId, fetchSimulations],
  );

  const stopSimulation = useCallback(
    async (simulationId?: string) => {
      const targetId = simulationId || activeSimulation?.simulationId;
      if (!targetId) return { success: false, error: 'No active simulation to stop' };

      try {
        const res = await fetch(`/api/simulations/${targetId}/stop`, {
          method: 'POST',
        });
        const data = await res.json();
        if (res.ok) {
          await fetchSimulations();
          return { success: true };
        } else {
          const err = data.message || data.error || 'Failed to stop simulation';
          setError(err);
          return { success: false, error: err };
        }
      } catch (err: any) {
        const msg = err?.message || 'Failed to stop simulation';
        setError(msg);
        return { success: false, error: msg };
      }
    },
    [activeSimulation?.simulationId, fetchSimulations],
  );

  return {
    scenarios,
    simulations,
    activeSimulation,
    selectedScenarioId,
    setSelectedScenarioId,
    isRunning: activeSimulation?.status === 'running',
    loading,
    error,
    startSimulation,
    stopSimulation,
    refresh: fetchSimulations,
  };
}
