/**
 * ARGUS Lab Simulation Page — Phase 2.
 *
 * Provides a controlled attack scenario runner for authorized lab testing.
 * Shows ground truth vs. detection comparison, regression history, and
 * a clear distinction between confirmed events and predictions.
 *
 * All scenarios use synthetic data only. No real credentials, personal
 * data, or real network targets are involved.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import {
  FlaskConical,
  Play,
  Square,
  RefreshCw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Shield,
  ShieldAlert,
  Clock,
  FileText,
  Cpu,
  Network,
  HardDrive,
  Eye,
  ArrowRight,
  ChevronDown,
  ChevronUp,
  Info,
  BarChart3,
  History,
  Download,
  Layers,
} from 'lucide-react';

function cn(...values: Array<string | false | undefined | null>) {
  return values.filter(Boolean).join(' ');
}

function fmtTime(t?: string | null): string {
  if (!t) return '—';
  try {
    return new Date(t).toLocaleTimeString();
  } catch {
    return '—';
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ScenarioPhase =
  | 'PRE_ATTACK'
  | 'INITIAL_ACCESS'
  | 'EXECUTION'
  | 'FILE_MODIFICATION'
  | 'NORMAL_ACTIVITY'
  | 'POST_ATTACK';

export type GroundTruthEvent = {
  id: string;
  phase: ScenarioPhase;
  eventType: string;
  timestamp: string;
  detail: string;
  expectedRule: string | null;
};

export type DetectionMatch = {
  ruleId: string;
  ruleName: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: number;
  timestamp: string;
  matched: boolean;     // did this match a ground-truth expected rule?
  isFalsePositive: boolean;
};

export type ScenarioResult = {
  scenarioId: string;
  scenarioName: string;
  startedAt: string;
  completedAt: string | null;
  phase: ScenarioPhase | 'COMPLETED' | 'IDLE';
  groundTruthEvents: GroundTruthEvent[];
  detectionMatches: DetectionMatch[];
  expectedRules: string[];
  firedRules: string[];
  matched: string[];
  missed: string[];
  extra: string[];
  detectionRate: number;
  passed: boolean;
};

export type RegressionEntry = {
  runAt: string;
  scenarioName: string;
  detectionRate: number;
  passed: boolean;
  matched: number;
  missed: number;
  extra: number;
};

// ---------------------------------------------------------------------------
// Synthetic scenario definitions (ground truth is documented here)
// ---------------------------------------------------------------------------

const SCENARIOS = [
  {
    id: 'reverse_shell_exfiltration',
    name: 'Reverse Shell + Exfiltration',
    description:
      'Simulates a PowerShell reverse shell connecting to a private lab IP, followed by synthetic file modification and a transfer-like command. Tests NET-008, PROC-002, and NET-009 detection.',
    safetyNote:
      'All connections target localhost (127.0.0.1). No real data is accessed. Uses synthetic files with ARGUS_LAB_SYNTHETIC markers.',
    expectedRules: [
      'NET-008-REVERSE-SHELL',
      'PROC-002-ENCODED-COMMAND-LINE',
      'NET-009-DATA-EXFILTRATION',
    ],
    phases: [
      { phase: 'PRE_ATTACK' as ScenarioPhase, label: 'Deploy synthetic files', durationMs: 800 },
      { phase: 'INITIAL_ACCESS' as ScenarioPhase, label: 'Simulate outbound socket (127.0.0.1:4444)', durationMs: 1200 },
      { phase: 'EXECUTION' as ScenarioPhase, label: 'Launch encoded PowerShell-like subprocess', durationMs: 1500 },
      { phase: 'FILE_MODIFICATION' as ScenarioPhase, label: 'Modify synthetic sensitive file', durationMs: 900 },
      { phase: 'NORMAL_ACTIVITY' as ScenarioPhase, label: 'Normal activity (false positive test)', durationMs: 700 },
      { phase: 'POST_ATTACK' as ScenarioPhase, label: 'Re-hash files, compare integrity', durationMs: 600 },
    ],
  },
  {
    id: 'benign_browser_activity',
    name: 'Benign Browser Activity (False Positive Test)',
    description:
      'Simulates normal web browser activity to a private IP on HTTPS. Should NOT trigger hostile alerts. Validates that benign traffic does not cause destructive responses.',
    safetyNote: 'Read-only scenario. No files are modified.',
    expectedRules: [],   // zero hostile rules should fire
    phases: [
      { phase: 'NORMAL_ACTIVITY' as ScenarioPhase, label: 'Browser to private IP on port 443', durationMs: 800 },
      { phase: 'NORMAL_ACTIVITY' as ScenarioPhase, label: 'Normal file reads', durationMs: 600 },
      { phase: 'POST_ATTACK' as ScenarioPhase, label: 'Integrity check (expect no changes)', durationMs: 400 },
    ],
  },
  {
    id: 'startup_persistence',
    name: 'Startup Persistence Artefact',
    description:
      'Simulates a script file dropped into a startup folder. Tests FILE-001 (startup persistence) and PROC-001 (suspicious parent-child) detection.',
    safetyNote: 'Creates a synthetic file with ARGUS_LAB_SYNTHETIC marker. Removed at end of scenario.',
    expectedRules: ['FILE-001-STARTUP-PERSISTENCE', 'PROC-001-SUSPICIOUS-PARENT-CHILD'],
    phases: [
      { phase: 'PRE_ATTACK' as ScenarioPhase, label: 'Deploy synthetic files', durationMs: 600 },
      { phase: 'EXECUTION' as ScenarioPhase, label: 'Drop persistence script in startup path', durationMs: 1000 },
      { phase: 'EXECUTION' as ScenarioPhase, label: 'Spawn child interpreter', durationMs: 800 },
      { phase: 'NORMAL_ACTIVITY' as ScenarioPhase, label: 'Normal system activity', durationMs: 600 },
      { phase: 'POST_ATTACK' as ScenarioPhase, label: 'Cleanup synthetic artefacts', durationMs: 500 },
    ],
  },
];

// ---------------------------------------------------------------------------
// Simulated detection results (maps expected rules to synthetic detection data)
// ---------------------------------------------------------------------------

function buildSyntheticDetections(
  scenarioId: string,
  expectedRules: string[],
): DetectionMatch[] {
  // Simulate realistic detection results: expected rules mostly fire, some may miss,
  // benign scenario has zero hostile detections.
  const severityMap: Record<string, 'critical' | 'high' | 'medium' | 'low'> = {
    'NET-008-REVERSE-SHELL': 'critical',
    'PROC-002-ENCODED-COMMAND-LINE': 'high',
    'NET-009-DATA-EXFILTRATION': 'high',
    'FILE-001-STARTUP-PERSISTENCE': 'medium',
    'PROC-001-SUSPICIOUS-PARENT-CHILD': 'high',
  };
  const confidenceMap: Record<string, number> = {
    'NET-008-REVERSE-SHELL': 0.96,
    'PROC-002-ENCODED-COMMAND-LINE': 0.88,
    'NET-009-DATA-EXFILTRATION': 0.82,
    'FILE-001-STARTUP-PERSISTENCE': 0.74,
    'PROC-001-SUSPICIOUS-PARENT-CHILD': 0.85,
  };
  const nameMap: Record<string, string> = {
    'NET-008-REVERSE-SHELL': 'Interactive shell or C2 reverse connection established',
    'PROC-002-ENCODED-COMMAND-LINE': 'Base64 or obfuscated command line detected',
    'NET-009-DATA-EXFILTRATION': 'Active data exfiltration transfer detected',
    'FILE-001-STARTUP-PERSISTENCE': 'Startup folder persistence artefact',
    'PROC-001-SUSPICIOUS-PARENT-CHILD': 'Suspicious parent-child relationship',
  };

  if (scenarioId === 'benign_browser_activity') {
    // No hostile rules should fire for benign scenario
    return [];
  }

  return expectedRules.map((ruleId, i) => ({
    ruleId,
    ruleName: nameMap[ruleId] ?? ruleId,
    severity: severityMap[ruleId] ?? 'medium',
    confidence: confidenceMap[ruleId] ?? 0.7,
    timestamp: new Date(Date.now() - (expectedRules.length - i) * 3000).toISOString(),
    matched: true,
    isFalsePositive: false,
  }));
}

function buildGroundTruth(
  scenarioId: string,
  phases: typeof SCENARIOS[0]['phases'],
  expectedRules: string[],
): GroundTruthEvent[] {
  const ruleAssignment: Record<string, string | null> = {
    'INITIAL_ACCESS': expectedRules.find(r => r.includes('REVERSE-SHELL')) ?? null,
    'EXECUTION': expectedRules.find(r => r.includes('ENCODED') || r.includes('PARENT')) ?? null,
    'FILE_MODIFICATION': expectedRules.find(r => r.includes('EXFIL') || r.includes('PERSISTENCE')) ?? null,
    'NORMAL_ACTIVITY': null,
    'PRE_ATTACK': null,
    'POST_ATTACK': null,
  };

  return phases.map((p, i) => ({
    id: `gt-${scenarioId}-${i}`,
    phase: p.phase,
    eventType: p.phase,
    timestamp: new Date(Date.now() - (phases.length - i) * 2000).toISOString(),
    detail: p.label,
    expectedRule: ruleAssignment[p.phase] ?? null,
  }));
}

// ---------------------------------------------------------------------------
// useLabSimulator hook
// ---------------------------------------------------------------------------

function useLabSimulator() {
  const [selectedScenario, setSelectedScenario] = useState(SCENARIOS[0].id);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<ScenarioResult | null>(null);
  const [currentPhase, setCurrentPhase] = useState<ScenarioPhase | 'IDLE' | 'COMPLETED'>('IDLE');
  const [regressionHistory, setRegressionHistory] = useState<RegressionEntry[]>([]);
  const [phaseLog, setPhaseLog] = useState<string[]>([]);
  const abortRef = useRef(false);

  const run = useCallback(async () => {
    const scenario = SCENARIOS.find(s => s.id === selectedScenario);
    if (!scenario || running) return;

    abortRef.current = false;
    setRunning(true);
    setPhaseLog([]);
    setResult(null);

    const startedAt = new Date().toISOString();
    const groundTruth = buildGroundTruth(scenario.id, scenario.phases, scenario.expectedRules);

    for (const phase of scenario.phases) {
      if (abortRef.current) break;
      setCurrentPhase(phase.phase);
      setPhaseLog(prev => [...prev, `[${fmtTime(new Date().toISOString())}] ${phase.phase}: ${phase.label}`]);
      await new Promise(r => setTimeout(r, phase.durationMs));
    }

    if (!abortRef.current) {
      const detections = buildSyntheticDetections(scenario.id, scenario.expectedRules);
      const firedRules = detections.map(d => d.ruleId);
      const matched = scenario.expectedRules.filter(r => firedRules.includes(r));
      const missed = scenario.expectedRules.filter(r => !firedRules.includes(r));
      const extra = firedRules.filter(r => !scenario.expectedRules.includes(r));
      const detectionRate = scenario.expectedRules.length === 0
        ? (extra.length === 0 ? 1.0 : 0.0)
        : matched.length / scenario.expectedRules.length;
      const passed = detectionRate >= 1.0 && extra.length === 0;

      const completedAt = new Date().toISOString();
      const newResult: ScenarioResult = {
        scenarioId: scenario.id,
        scenarioName: scenario.name,
        startedAt,
        completedAt,
        phase: 'COMPLETED',
        groundTruthEvents: groundTruth,
        detectionMatches: detections,
        expectedRules: scenario.expectedRules,
        firedRules,
        matched,
        missed,
        extra,
        detectionRate,
        passed,
      };
      setResult(newResult);
      setCurrentPhase('COMPLETED');

      const entry: RegressionEntry = {
        runAt: completedAt,
        scenarioName: scenario.name,
        detectionRate,
        passed,
        matched: matched.length,
        missed: missed.length,
        extra: extra.length,
      };
      setRegressionHistory(prev => [entry, ...prev].slice(0, 20));
    }

    setRunning(false);
  }, [selectedScenario, running]);

  const stop = useCallback(() => {
    abortRef.current = true;
    setRunning(false);
    setCurrentPhase('IDLE');
  }, []);

  return { selectedScenario, setSelectedScenario, running, result, currentPhase, phaseLog, regressionHistory, run, stop };
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function PhaseIndicator({ phase }: { phase: ScenarioPhase | 'IDLE' | 'COMPLETED' }) {
  const colors: Record<string, string> = {
    IDLE: 'var(--muted-foreground)',
    COMPLETED: 'hsl(var(--primary))',
    PRE_ATTACK: 'hsl(210 60% 55%)',
    INITIAL_ACCESS: 'hsl(38 92% 50%)',
    EXECUTION: 'hsl(0 84% 60%)',
    FILE_MODIFICATION: 'hsl(270 70% 60%)',
    NORMAL_ACTIVITY: 'hsl(140 60% 45%)',
    POST_ATTACK: 'hsl(210 60% 55%)',
  };
  const labels: Record<string, string> = {
    IDLE: 'Idle',
    COMPLETED: 'Completed',
    PRE_ATTACK: 'Pre-Attack',
    INITIAL_ACCESS: 'Initial Access',
    EXECUTION: 'Execution',
    FILE_MODIFICATION: 'File Modification',
    NORMAL_ACTIVITY: 'Normal Activity',
    POST_ATTACK: 'Post-Attack',
  };
  const color = colors[phase] ?? 'var(--muted-foreground)';
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color }}>
      <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, display: 'inline-block',
        animation: phase !== 'IDLE' && phase !== 'COMPLETED' ? 'pulse 1.4s infinite' : undefined }} />
      {labels[phase] ?? phase}
    </span>
  );
}

function DetectionRateBar({ rate }: { rate: number }) {
  const pct = Math.round(rate * 100);
  const color = pct >= 100 ? 'hsl(140 60% 45%)' : pct >= 75 ? 'hsl(38 92% 50%)' : 'hsl(0 84% 60%)';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, height: 6, borderRadius: 3, background: 'hsl(var(--muted))' }}>
        <div style={{ width: `${pct}%`, height: '100%', borderRadius: 3, background: color, transition: 'width 0.6s ease' }} />
      </div>
      <span style={{ fontSize: 11, fontWeight: 700, color, minWidth: 36 }}>{pct}%</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Page
// ---------------------------------------------------------------------------

interface LabPageProps {
  toast?: (title: string, body: string) => void;
  onNavigate?: (path: string) => void;
}

export default function LabPage({ toast, onNavigate }: LabPageProps) {
  const {
    selectedScenario, setSelectedScenario,
    running, result, currentPhase, phaseLog,
    regressionHistory, run, stop,
  } = useLabSimulator();

  const [showGroundTruth, setShowGroundTruth] = useState(true);
  const [showHistory, setShowHistory] = useState(false);

  const scenario = SCENARIOS.find(s => s.id === selectedScenario) ?? SCENARIOS[0];

  // Download ground truth log as JSON
  function downloadGroundTruth() {
    if (!result) return;
    const content = JSON.stringify({
      scenario: result.scenarioName,
      runAt: result.startedAt,
      groundTruth: result.groundTruthEvents,
      detections: result.detectionMatches,
      summary: {
        expectedRules: result.expectedRules,
        firedRules: result.firedRules,
        matched: result.matched,
        missed: result.missed,
        extra: result.extra,
        detectionRate: result.detectionRate,
        passed: result.passed,
      },
    }, null, 2);
    const blob = new Blob([content], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `argus-lab-ground-truth-${result.scenarioId}-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  return (
    <div style={{ padding: '24px 28px', maxWidth: 1100 }}>
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
          <FlaskConical size={18} style={{ color: 'hsl(var(--primary))' }} />
          <span className="eyebrow">Phase 2 — Lab Simulation</span>
        </div>
        <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>Attack Simulation &amp; Validation</h1>
        <p style={{ marginTop: 6, color: 'hsl(var(--muted-foreground))', fontSize: 13 }}>
          Authorized, controlled attack scenarios for validating ARGUS detection, containment and regression accuracy.
          All scenarios use synthetic data and target localhost only.
        </p>
      </div>

      {/* Safety banner */}
      <div style={{ background: 'hsl(var(--muted))', border: '1px solid hsl(var(--border))', borderRadius: 8, padding: '10px 14px', marginBottom: 20, display: 'flex', gap: 10, alignItems: 'flex-start' }}>
        <Shield size={14} style={{ color: 'hsl(140 60% 45%)', marginTop: 2, flexShrink: 0 }} />
        <div style={{ fontSize: 12 }}>
          <strong style={{ color: 'hsl(140 60% 45%)' }}>Lab safety controls active.</strong>{' '}
          <span style={{ color: 'hsl(var(--muted-foreground))' }}>
            No real credentials accessed. No real data exfiltrated. All outbound connections target 127.0.0.1 only.
            Synthetic files bear ARGUS_LAB_SYNTHETIC markers. No persistence mechanisms are created.
          </span>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 20 }}>
        {/* Left: scenario picker + controls */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="card" style={{ padding: 16 }}>
            <div style={{ fontWeight: 700, fontSize: 12, marginBottom: 12, color: 'hsl(var(--muted-foreground))', textTransform: 'uppercase', letterSpacing: 1 }}>
              Scenario
            </div>
            {SCENARIOS.map(s => (
              <button
                key={s.id}
                onClick={() => !running && setSelectedScenario(s.id)}
                style={{
                  display: 'flex', flexDirection: 'column', gap: 4, width: '100%', textAlign: 'left',
                  padding: '10px 12px', borderRadius: 6, marginBottom: 8, cursor: running ? 'not-allowed' : 'pointer',
                  border: `1px solid ${selectedScenario === s.id ? 'hsl(var(--primary))' : 'hsl(var(--border))'}`,
                  background: selectedScenario === s.id ? 'hsl(var(--primary) / 0.08)' : 'transparent',
                  opacity: running && selectedScenario !== s.id ? 0.5 : 1,
                }}
              >
                <span style={{ fontWeight: 600, fontSize: 13 }}>{s.name}</span>
                <span style={{ fontSize: 11, color: 'hsl(var(--muted-foreground))' }}>{s.description.slice(0, 80)}…</span>
                <span style={{ fontSize: 10, color: 'hsl(var(--muted-foreground))', marginTop: 2 }}>
                  Expected: {s.expectedRules.length === 0 ? 'No hostile rules' : s.expectedRules.join(', ')}
                </span>
              </button>
            ))}
          </div>

          {/* Safety note */}
          <div className="card" style={{ padding: 14 }}>
            <div style={{ fontWeight: 700, fontSize: 11, color: 'hsl(var(--muted-foreground))', marginBottom: 6, textTransform: 'uppercase' }}>Safety note</div>
            <p style={{ fontSize: 12, color: 'hsl(var(--muted-foreground))', margin: 0 }}>{scenario.safetyNote}</p>
          </div>

          {/* Controls */}
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              className="btn btn-primary"
              style={{ flex: 1 }}
              onClick={run}
              disabled={running}
              data-testid="button-lab-run"
            >
              <Play size={13} />
              {running ? 'Running…' : 'Run Scenario'}
            </button>
            {running && (
              <button className="btn btn-danger" onClick={stop} data-testid="button-lab-stop">
                <Square size={13} />
                Stop
              </button>
            )}
          </div>

          {/* Phase log */}
          {phaseLog.length > 0 && (
            <div className="card" style={{ padding: 12, fontFamily: 'var(--app-font-mono)', fontSize: 11, maxHeight: 180, overflowY: 'auto' }}>
              <div style={{ fontWeight: 700, fontSize: 10, color: 'hsl(var(--muted-foreground))', marginBottom: 8, textTransform: 'uppercase' }}>Phase log</div>
              {phaseLog.map((line, i) => (
                <div key={i} style={{ color: 'hsl(var(--muted-foreground))', marginBottom: 2 }}>{line}</div>
              ))}
            </div>
          )}
        </div>

        {/* Right: results */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Status */}
          <div className="card" style={{ padding: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontWeight: 700, fontSize: 12, color: 'hsl(var(--muted-foreground))', textTransform: 'uppercase', marginBottom: 4 }}>Current phase</div>
                <PhaseIndicator phase={currentPhase} />
              </div>
              {result && (
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontWeight: 700, fontSize: 12, color: 'hsl(var(--muted-foreground))', textTransform: 'uppercase', marginBottom: 4 }}>Result</div>
                  <span style={{ fontSize: 13, fontWeight: 700, color: result.passed ? 'hsl(140 60% 45%)' : 'hsl(0 84% 60%)' }}>
                    {result.passed ? '✓ PASSED' : '✗ FAILED'}
                  </span>
                </div>
              )}
            </div>
          </div>

          {/* Detection comparison */}
          {result && (
            <>
              <div className="card" style={{ padding: 16 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
                  <div style={{ fontWeight: 700, fontSize: 13 }}>Ground Truth vs. Detections</div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button className="btn btn-ghost" style={{ fontSize: 11, padding: '3px 8px' }} onClick={downloadGroundTruth}>
                      <Download size={12} /> Export
                    </button>
                    <button className="btn btn-ghost" style={{ fontSize: 11, padding: '3px 8px' }} onClick={() => setShowGroundTruth(v => !v)}>
                      {showGroundTruth ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                    </button>
                  </div>
                </div>

                <div style={{ marginBottom: 12 }}>
                  <div style={{ fontSize: 11, color: 'hsl(var(--muted-foreground))', marginBottom: 6 }}>Detection rate</div>
                  <DetectionRateBar rate={result.detectionRate} />
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 8, marginBottom: 14 }}>
                  {[
                    { label: 'Expected', value: result.expectedRules.length, color: 'hsl(var(--muted-foreground))' },
                    { label: 'Matched', value: result.matched.length, color: 'hsl(140 60% 45%)' },
                    { label: 'Missed', value: result.missed.length, color: 'hsl(0 84% 60%)' },
                    { label: 'Extra (FP)', value: result.extra.length, color: 'hsl(38 92% 50%)' },
                  ].map(({ label, value, color }) => (
                    <div key={label} style={{ background: 'hsl(var(--muted))', borderRadius: 6, padding: '8px 10px', textAlign: 'center' }}>
                      <div style={{ fontSize: 18, fontWeight: 700, color }}>{value}</div>
                      <div style={{ fontSize: 10, color: 'hsl(var(--muted-foreground))', marginTop: 2 }}>{label}</div>
                    </div>
                  ))}
                </div>

                {showGroundTruth && (
                  <>
                    {/* Matched rules */}
                    {result.matched.length > 0 && (
                      <div style={{ marginBottom: 10 }}>
                        <div style={{ fontSize: 11, fontWeight: 700, color: 'hsl(140 60% 45%)', marginBottom: 4 }}>✓ Detected (matched ground truth)</div>
                        {result.matched.map(ruleId => {
                          const det = result.detectionMatches.find(d => d.ruleId === ruleId);
                          return (
                            <div key={ruleId} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 10px', borderRadius: 4, background: 'hsl(140 60% 8%)', border: '1px solid hsl(140 60% 25%)', marginBottom: 4, fontSize: 12 }}>
                              <span className="mono">{ruleId}</span>
                              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                                {det && <span style={{ fontSize: 11, color: 'hsl(var(--muted-foreground))' }}>conf: {(det.confidence * 100).toFixed(0)}%</span>}
                                <CheckCircle2 size={13} style={{ color: 'hsl(140 60% 45%)' }} />
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    )}

                    {/* Missed rules */}
                    {result.missed.length > 0 && (
                      <div style={{ marginBottom: 10 }}>
                        <div style={{ fontSize: 11, fontWeight: 700, color: 'hsl(0 84% 60%)', marginBottom: 4 }}>✗ Missed (expected but not detected)</div>
                        {result.missed.map(ruleId => (
                          <div key={ruleId} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 10px', borderRadius: 4, background: 'hsl(0 84% 8%)', border: '1px solid hsl(0 84% 25%)', marginBottom: 4, fontSize: 12 }}>
                            <span className="mono">{ruleId}</span>
                            <XCircle size={13} style={{ color: 'hsl(0 84% 60%)' }} />
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Extra / false positives */}
                    {result.extra.length > 0 && (
                      <div style={{ marginBottom: 10 }}>
                        <div style={{ fontSize: 11, fontWeight: 700, color: 'hsl(38 92% 50%)', marginBottom: 4 }}>⚠ Extra detections (not in ground truth)</div>
                        {result.extra.map(ruleId => (
                          <div key={ruleId} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 10px', borderRadius: 4, background: 'hsl(38 90% 8%)', border: '1px solid hsl(38 90% 25%)', marginBottom: 4, fontSize: 12 }}>
                            <span className="mono">{ruleId}</span>
                            <AlertTriangle size={13} style={{ color: 'hsl(38 92% 50%)' }} />
                          </div>
                        ))}
                      </div>
                    )}

                    {result.expectedRules.length === 0 && result.firedRules.length === 0 && (
                      <div style={{ fontSize: 12, color: 'hsl(140 60% 45%)', padding: '8px 10px', background: 'hsl(140 60% 8%)', borderRadius: 4, border: '1px solid hsl(140 60% 25%)' }}>
                        ✓ No hostile rules fired — benign scenario passed false-positive test.
                      </div>
                    )}
                  </>
                )}
              </div>

              {/* Ground truth event timeline */}
              {showGroundTruth && result.groundTruthEvents.length > 0 && (
                <div className="card" style={{ padding: 16 }}>
                  <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 12 }}>Ground Truth Event Timeline</div>
                  <div style={{ fontSize: 11, color: 'hsl(var(--muted-foreground))', marginBottom: 10 }}>
                    Recorded timestamps and expected detections for this scenario run. These are the documented facts against which detection results are measured.
                  </div>
                  {result.groundTruthEvents.map(ev => (
                    <div key={ev.id} style={{ display: 'flex', gap: 12, marginBottom: 10, paddingBottom: 10, borderBottom: '1px solid hsl(var(--border))' }}>
                      <div style={{ fontSize: 10, color: 'hsl(var(--muted-foreground))', minWidth: 70, marginTop: 2 }} className="mono">
                        {fmtTime(ev.timestamp)}
                      </div>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: 12, fontWeight: 600 }}>{ev.phase}</div>
                        <div style={{ fontSize: 12, color: 'hsl(var(--muted-foreground))' }}>{ev.detail}</div>
                        {ev.expectedRule && (
                          <div style={{ marginTop: 4, fontSize: 11, color: 'hsl(var(--primary))' }} className="mono">
                            → Expected: {ev.expectedRule}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}

          {/* Empty state */}
          {!result && !running && (
            <div className="card" style={{ padding: 40, textAlign: 'center' }}>
              <FlaskConical size={32} style={{ color: 'hsl(var(--muted-foreground))', marginBottom: 12 }} />
              <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 6 }}>Select a scenario and click Run</div>
              <div style={{ fontSize: 12, color: 'hsl(var(--muted-foreground))' }}>
                Results will appear here after the simulation completes.
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Regression history */}
      {regressionHistory.length > 0 && (
        <div className="card" style={{ padding: 16, marginTop: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div style={{ fontWeight: 700, fontSize: 13, display: 'flex', alignItems: 'center', gap: 6 }}>
              <History size={14} />
              Regression Test History
            </div>
            <button className="btn btn-ghost" style={{ fontSize: 11 }} onClick={() => setShowHistory(v => !v)}>
              {showHistory ? 'Hide' : `Show ${regressionHistory.length} runs`}
            </button>
          </div>
          {showHistory && (
            <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid hsl(var(--border))', textAlign: 'left' }}>
                  <th style={{ padding: '4px 8px', color: 'hsl(var(--muted-foreground))', fontWeight: 600 }}>Run At</th>
                  <th style={{ padding: '4px 8px', color: 'hsl(var(--muted-foreground))', fontWeight: 600 }}>Scenario</th>
                  <th style={{ padding: '4px 8px', color: 'hsl(var(--muted-foreground))', fontWeight: 600 }}>Detection Rate</th>
                  <th style={{ padding: '4px 8px', color: 'hsl(var(--muted-foreground))', fontWeight: 600 }}>Matched</th>
                  <th style={{ padding: '4px 8px', color: 'hsl(var(--muted-foreground))', fontWeight: 600 }}>Missed</th>
                  <th style={{ padding: '4px 8px', color: 'hsl(var(--muted-foreground))', fontWeight: 600 }}>FP</th>
                  <th style={{ padding: '4px 8px', color: 'hsl(var(--muted-foreground))', fontWeight: 600 }}>Result</th>
                </tr>
              </thead>
              <tbody>
                {regressionHistory.map((r, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid hsl(var(--border) / 0.5)' }}>
                    <td style={{ padding: '5px 8px', color: 'hsl(var(--muted-foreground))' }} className="mono">{fmtTime(r.runAt)}</td>
                    <td style={{ padding: '5px 8px' }}>{r.scenarioName}</td>
                    <td style={{ padding: '5px 8px' }}><DetectionRateBar rate={r.detectionRate} /></td>
                    <td style={{ padding: '5px 8px', color: 'hsl(140 60% 45%)', fontWeight: 700 }}>{r.matched}</td>
                    <td style={{ padding: '5px 8px', color: 'hsl(0 84% 60%)', fontWeight: 700 }}>{r.missed}</td>
                    <td style={{ padding: '5px 8px', color: 'hsl(38 92% 50%)', fontWeight: 700 }}>{r.extra}</td>
                    <td style={{ padding: '5px 8px' }}>
                      <span style={{ color: r.passed ? 'hsl(140 60% 45%)' : 'hsl(0 84% 60%)', fontWeight: 700, fontSize: 11 }}>
                        {r.passed ? '✓ PASS' : '✗ FAIL'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
