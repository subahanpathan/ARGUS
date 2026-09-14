import { useEffect, useRef, useState } from 'react';

/**
 * Subscribes to the OS `prefers-reduced-motion` preference and returns whether
 * decorative motion should be suppressed. Updates live if the preference
 * changes while the app is open.
 *
 * Always use this alongside the CSS `@media (prefers-reduced-motion: reduce)`
 * block, so JS-driven animations and CSS animations agree.
 */
export function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState<boolean>(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return false;
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  });

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return;
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    const onChange = (e: MediaQueryListEvent) => setReduced(e.matches);
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, []);

  return reduced;
}

/**
 * Runs a rAF loop while `active` is true and stops it (with full cleanup) as
 * soon as it becomes false. This is deliberately small and reusable so every
 * JS animation in ARGUS cleans up after itself.
 */
export function useRafLoop(callback: (now: number, delta: number) => void, active: boolean) {
  const cbRef = useRef(callback);
  cbRef.current = callback;

  useEffect(() => {
    if (!active) return undefined;
    let raf = 0;
    let last = performance.now();

    const loop = (now: number) => {
      const delta = Math.min(now - last, 60);
      last = now;
      cbRef.current(now, delta);
      raf = requestAnimationFrame(loop);
    };

    raf = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(raf);
  }, [active]);
}

/** Eased interpolation helpers shared by JS animation loops. */
export function easedOutCubic(t: number): number {
  return 1 - Math.pow(1 - Math.min(Math.max(t, 0), 1), 3);
}

/** Named export alias so consumers can import { easeOutCubic }. */
export const easeOutCubic = easedOutCubic;