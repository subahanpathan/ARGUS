/**
 * useAutonomousDemo — centralized controller for the ARGUS Autonomous Demo
 * Mode (Phase 1).
 *
 * The controller owns a small step machine, drives the existing dashboard
 * `phase`/`demoState` so current dashboard visuals animate with synthetic
 * data, performs the automatic route hand-off after the 10-second dashboard
 * stage, and is the single owner of all demo timers.
 *
 * Timer model: one `setInterval` tick that derives everything from timestamps,
 * so there are never duplicated timers, drift is impossible, and pausing is
 * just "remember now, shift deadlines on resume".
 *
 * Safety: this hook never touches OS processes, Win32 APIs, or the shell. It
 * only mutates React state and navigates inside the ARGUS app.
 */

import { useCallback, useEffect, useRef, useState } from 'react';

/** Mirrors the demo lifecycle the rest of the app already understands. */
export type DemoRunState = 'idle' | 'running' | 'paused' | 'completed';

/** Autonomous demo steps. Phase 1 only drives IDLE → DASHBOARD → THREAT_DETECTION. */
export const DEMO_STEP = {
  IDLE: 'IDLE',
  DASHBOARD: 'DASHBOARD',
  THREAT_DETECTION: 'THREAT_DETECTION',
  INVESTIGATION: 'INVESTIGATION',
  CONTAINMENT: 'CONTAINMENT',
  PROCESS_TERMINATION: 'PROCESS_TERMINATION',
  PROCESSES: 'PROCESSES',
  NETWORK_UNIVERSE: 'NETWORK_UNIVERSE',
  NEXT_CONNECTION: 'NEXT_CONNECTION',
  LOOP: 'LOOP',
} as const;

export type DemoStep = (typeof DEMO_STEP)[keyof typeof DEMO_STEP];

export const DEMO_DASHBOARD_DURATION_MS = 10_000;

/** Duration of each staged step in Phase 1. Later steps are no-ops for now. */
export const DEMO_STEP_DURATION_MS: Partial<Record<DemoStep, number>> = {
  DASHBOARD: DEMO_DASHBOARD_DURATION_MS,
};

/** Scripted dashboard progression shown during the 10-second stage. */
export type DashboardScriptPoint = { at: number; label: string; phase: number };

export const DEMO_DASHBOARD_SCRIPT: DashboardScriptPoint[] = [
  { at: 0, label: 'System initializing...', phase: 1 },
  { at: 2000, label: 'Telemetry active', phase: 2 },
  { at: 4000, label: 'Suspicious activity detected', phase: 3 },
  { at: 6000, label: 'Risk score increases', phase: 4 },
  { at: 8000, label: 'Critical threat identified', phase: 5 },
  { at: DEMO_DASHBOARD_DURATION_MS, label: 'Investigation required', phase: 5 },
];

const TICK_MS = 250;

export type AutonomousDemoState = {
  /** Autonomous demo presentation is active (indicator + stop control shown). */
  demoMode: boolean;
  /** Timers are live (false while paused or stopped). */
  demoRunning: boolean;
  /** Current autonomous step. */
  demoStep: DemoStep;
  /** Wall-clock when the demo session started. */
  demoStartedAt: number | null;
  /** Wall-clock when the current step started. */
  demoStepStartedAt: number | null;
  /** Whole seconds left in the current step (0 when not counting). */
  demoRemainingSeconds: number;
  /** Human-facing scripted label for the current dashboard moment. */
  demoStatusLabel: string;
  /** Mirrors the legacy dashboard `phase` so existing visuals animate. */
  demoPhaseIndex: number;
  /** True once the automatic transition to threat detection has fired. */
  demoReached: boolean;
};

export type AutonomousDemoDeps = {
  setPhase: (phase: number) => void;
  setDemoState: (state: DemoRunState) => void;
  navigate: (path: string) => void;
  resetIncident: () => void;
  notify: (title: string, body: string) => void;
};

const INITIAL_STATE: AutonomousDemoState = {
  demoMode: false,
  demoRunning: false,
  demoStep: DEMO_STEP.IDLE,
  demoStartedAt: null,
  demoStepStartedAt: null,
  demoRemainingSeconds: 0,
  demoStatusLabel: '',
  demoPhaseIndex: 0,
  demoReached: false,
};

function dashboardPointForElapsed(elapsed: number): DashboardScriptPoint {
  let point = DEMO_DASHBOARD_SCRIPT[0];
  for (const candidate of DEMO_DASHBOARD_SCRIPT) {
    if (elapsed >= candidate.at) point = candidate;
    else break;
  }
  return point;
}

export function useAutonomousDemo(deps: AutonomousDemoDeps) {
  const [state, setState] = useState<AutonomousDemoState>(INITIAL_STATE);

  // Deps are recreated every render (AppContent plain functions); keep the
  // latest copy in a ref so the single interval never captures a stale one.
  const depsRef = useRef(deps);
  depsRef.current = deps;

  // Mirrors of state used inside the interval callback to avoid stale closures.
  const modeRef = useRef(false);
  const stepRef = useRef<DemoStep>(DEMO_STEP.IDLE);
  const phaseRef = useRef(0);
  const intervalRef = useRef<number | null>(null);
  const stepStartRef = useRef(0);
  const stepDeadlineRef = useRef(0);
  const pausedAtRef = useRef<number | null>(null);

  const clearIntervalRef = useCallback(() => {
    if (intervalRef.current != null) {
      window.clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
  }, []);

  const handleTick = useCallback(() => {
    if (stepRef.current !== DEMO_STEP.DASHBOARD) return;
    const now = Date.now();
    const elapsed = now - stepStartRef.current;
    const remaining = Math.max(0, Math.ceil((stepDeadlineRef.current - now) / 1000));
    const point = dashboardPointForElapsed(elapsed);
    const curr = depsRef.current;

    setState((prev) => ({
      ...prev,
      demoRemainingSeconds: remaining,
      demoStatusLabel: point.label,
    }));

    if (point.phase !== phaseRef.current) {
      phaseRef.current = point.phase;
      curr.setPhase(point.phase);
      setState((prev) => ({ ...prev, demoPhaseIndex: point.phase }));
    }

    if (now >= stepDeadlineRef.current) {
      // Automatic hand-off: DASHBOARD → THREAT_DETECTION.
      clearIntervalRef();
      stepRef.current = DEMO_STEP.THREAT_DETECTION;
      setState((prev) => ({
        ...prev,
        demoStep: DEMO_STEP.THREAT_DETECTION,
        demoStepStartedAt: now,
        demoRemainingSeconds: 0,
        demoStatusLabel: 'Investigation required',
        demoReached: true,
      }));
      curr.setDemoState('running');
      curr.navigate('/threats');
      curr.notify('Autonomous demo · investigation required', 'Presentation advanced to threat detection automatically.');
    }
  }, [clearIntervalRef]);

  // Single cleanup point: everything is cancelled on unmount and on stop.
  useEffect(() => clearIntervalRef, [clearIntervalRef]);

  const start = useCallback(() => {
    clearIntervalRef();
    const now = Date.now();
    const curr = depsRef.current;

    // Reset the synthetic incident, then re-arm it for the presentation.
    curr.resetIncident();

    modeRef.current = true;
    stepRef.current = DEMO_STEP.DASHBOARD;
    phaseRef.current = DEMO_DASHBOARD_SCRIPT[0].phase;
    stepStartRef.current = now;
    stepDeadlineRef.current = now + (DEMO_STEP_DURATION_MS.DASHBOARD ?? DEMO_DASHBOARD_DURATION_MS);
    pausedAtRef.current = null;

    curr.setPhase(phaseRef.current);
    curr.setDemoState('running');
    curr.navigate('/dashboard');

    setState({
      demoMode: true,
      demoRunning: true,
      demoStep: DEMO_STEP.DASHBOARD,
      demoStartedAt: now,
      demoStepStartedAt: now,
      demoRemainingSeconds: 10,
      demoStatusLabel: DEMO_DASHBOARD_SCRIPT[0].label,
      demoPhaseIndex: phaseRef.current,
      demoReached: false,
    });

    intervalRef.current = window.setInterval(handleTick, TICK_MS);
    curr.notify('Autonomous Demo Mode started', 'Dashboard presentation will run for 10 seconds, then hand off to threat detection automatically.');
  }, [clearIntervalRef, handleTick]);

  const stop = useCallback(() => {
    clearIntervalRef();
    pausedAtRef.current = null;
    const wasActive = modeRef.current;
    modeRef.current = false;
    stepRef.current = DEMO_STEP.IDLE;
    phaseRef.current = 0;

    setState(INITIAL_STATE);
    depsRef.current.resetIncident();
    depsRef.current.setDemoState('idle');
    if (wasActive) {
      depsRef.current.notify('Autonomous demo stopped', 'Timers cleared and control returned to the workspace.');
    }
  }, [clearIntervalRef]);

  const pause = useCallback(() => {
    if (!modeRef.current || pausedAtRef.current != null) return;
    const now = Date.now();
    pausedAtRef.current = now;
    clearIntervalRef();
    setState((prev) => ({ ...prev, demoRunning: false }));
    depsRef.current.setDemoState('paused');
    depsRef.current.notify('Autonomous demo paused', 'Presentation timers are paused. Resume when ready.');
  }, [clearIntervalRef]);

  const resume = useCallback(() => {
    if (!modeRef.current || pausedAtRef.current == null) return;
    const now = Date.now();
    const shift = now - pausedAtRef.current;
    pausedAtRef.current = null;

    // Shift step timestamps forward by the pause length so the scripted
    // storyline and countdown continue from where they were paused.
    if (stepRef.current === DEMO_STEP.DASHBOARD) {
      stepStartRef.current += shift;
      stepDeadlineRef.current += shift;
      if (intervalRef.current == null) {
        intervalRef.current = window.setInterval(handleTick, TICK_MS);
      }
    }

    setState((prev) => ({
      ...prev,
      demoRunning: true,
      demoStepStartedAt: prev.demoStepStartedAt != null ? prev.demoStepStartedAt + shift : prev.demoStepStartedAt,
    }));
    depsRef.current.setDemoState('running');
    depsRef.current.notify('Autonomous demo resumed', 'Presentation timers restarted.');
  }, [handleTick]);

  return { state, start, stop, pause, resume };
}