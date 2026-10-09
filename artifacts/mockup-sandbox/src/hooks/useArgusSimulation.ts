import { useState, useCallback, useRef } from 'react';
import { SimulationPhase, SimulatedFile, SCENARIOS, ScenarioDef } from '../lib/scenarios';

export interface LogEntry {
  id: string;
  timestamp: Date;
  message: string;
  level: 'info' | 'warn' | 'critical' | 'success';
}

export interface Metrics {
  detectTimeMs: number | null;
  containTimeMs: number | null;
  totalResponseTimeMs: number | null;
}

export const useArgusSimulation = () => {
  const [phase, setPhase] = useState<SimulationPhase>('IDLE');
  const [scenario, setScenario] = useState<ScenarioDef>(SCENARIOS[0]);
  const [files, setFiles] = useState<SimulatedFile[]>(SCENARIOS[0].initialFiles);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [metrics, setMetrics] = useState<Metrics>({ detectTimeMs: null, containTimeMs: null, totalResponseTimeMs: null });
  const [isPaused, setIsPaused] = useState(false);

  // Timers and tracking
  const timersRef = useRef<NodeJS.Timeout[]>([]);
  const startTimeRef = useRef<number | null>(null);
  const detectTimeRef = useRef<number | null>(null);

  const addLog = useCallback((message: string, level: LogEntry['level'] = 'info') => {
    setLogs(prev => [...prev, { id: Math.random().toString(36).substr(2, 9), timestamp: new Date(), message, level }]);
  }, []);

  const clearTimers = () => {
    timersRef.current.forEach(clearTimeout);
    timersRef.current = [];
  };

  const reset = useCallback(() => {
    clearTimers();
    setPhase('IDLE');
    setFiles(scenario.initialFiles);
    setLogs([]);
    setMetrics({ detectTimeMs: null, containTimeMs: null, totalResponseTimeMs: null });
    setIsPaused(false);
  }, [scenario]);

  const selectScenario = useCallback((scenarioId: string) => {
    const s = SCENARIOS.find(x => x.id === scenarioId) || SCENARIOS[0];
    setScenario(s);
    setFiles(s.initialFiles);
    setPhase('IDLE');
    setLogs([]);
  }, []);

  const startSimulation = useCallback(() => {
    reset();
    setPhase('ATTACK');
    startTimeRef.current = performance.now();

    addLog(`INITIALIZING: Simulated Scenario '${scenario.name}' on Endpoint-01`, 'info');

    let cumulativeDelay = 1000;

    // 1. Attack sequence
    scenario.steps.forEach((step, index) => {
      cumulativeDelay += step.delayMs;
      const t = setTimeout(() => {
        addLog(`[ATTACK] ${step.title}: ${step.description}`, 'warn');
        if (index === 0) {
            setFiles(prev => [...prev, { id: 'mal1', name: 'payload.exe', status: 'malware', type: 'executable', hash: 'unknown' }]);
        }
      }, cumulativeDelay);
      timersRef.current.push(t);
    });

    // 2. Detection (happens shortly after last step starts)
    cumulativeDelay += 800;
    const tDetect = setTimeout(() => {
      detectTimeRef.current = performance.now();
      const detectMs = detectTimeRef.current - (startTimeRef.current || 0);
      setMetrics(prev => ({ ...prev, detectTimeMs: detectMs }));
      setPhase('DETECTED');
      addLog(`ARGUS DETECTION TRIGGERED: Behavioral anomaly matches ${scenario.family} ruleset.`, 'critical');
    }, cumulativeDelay);
    timersRef.current.push(tDetect);

    // 3. Containment
    cumulativeDelay += 1200;
    const tContain = setTimeout(() => {
      const containEnd = performance.now();
      const containMs = containEnd - (detectTimeRef.current || 0);
      setMetrics(prev => ({ ...prev, containTimeMs: containMs, totalResponseTimeMs: containEnd - (startTimeRef.current || 0) }));
      setPhase('CONTAINED');

      // Update file status - isolate malware
      setFiles(prev => prev.map(f => f.type === 'executable' && f.status === 'malware' ? { ...f, status: 'deleted' } : f));
      addLog(`CONTAINMENT SUCCESSFUL: Malicious processes terminated. Payload isolated and removed.`, 'success');
    }, cumulativeDelay);
    timersRef.current.push(tContain);

    // 4. Leak Assessment
    cumulativeDelay += 1500;
    const tLeak = setTimeout(() => {
      setPhase('LEAK_ASSESSMENT');
      addLog(`ASSESSMENT: Scanning file integrity for access during the exposure window.`, 'info');

      setFiles(prev => prev.map(f => {
        if (scenario.id === 's-001' && f.type === 'sensitive') return { ...f, status: 'leaked' };
        if (scenario.id === 's-001' && f.type === 'image') return { ...f, status: 'corrupted' };
        return f;
      }));
    }, cumulativeDelay);
    timersRef.current.push(tLeak);

  }, [scenario, addLog, reset]);

  const reportToCyberCell = useCallback(() => {
    setPhase('REPORTING');
    addLog(`USER ACTION: Authorized incident report submission to Cyber Cell.`, 'info');
    setTimeout(() => {
        addLog(`SYSTEM: Report transmitted successfully with telemetry payload.`, 'success');
        setPhase('INVESTIGATING');
        addLog(`FORENSICS: Generating attack graph and mapping to MITRE ATT&CK matrix...`, 'info');
    }, 1500);
  }, [addLog]);

  const startAdaptation = useCallback(() => {
    setPhase('ADAPTING');
    addLog(`DEFENSE: Analyzing semantic signature...`, 'info');
    setTimeout(() => {
        addLog(`DEFENSE: New behavioral rule pushed to Endpoint-01. Future variants blocked.`, 'success');
        setPhase('RECOVERED');
        addLog(`RECOVERY: Rolling back affected files from secure shadow copy.`, 'info');
        setFiles(prev => prev.map(f => {
            if (f.status === 'corrupted' || f.status === 'leaked') return { ...f, status: 'recovered' };
            return f;
        }));
        addLog(`VERIFICATION: File integrity checks passed. Incident resolved.`, 'success');
    }, 2000);
  }, [addLog]);


  return {
    phase,
    scenario,
    files,
    logs,
    metrics,
    isPaused,
    SCENARIOS,
    selectScenario,
    startSimulation,
    reset,
    reportToCyberCell,
    startAdaptation
  };
}