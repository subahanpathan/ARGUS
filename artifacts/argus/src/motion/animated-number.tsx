import { useEffect, useRef } from 'react';
import { usePrefersReducedMotion } from './use-reduced-motion';
import { SETTLE_MS } from './tokens';

type AnimatedNumberProps = {
  /** Numeric value to reflect. Null renders nothing / placeholder. */
  value: number | null | undefined;
  /** Stable formatter — memoize it; the component re-reads it via ref. */
  format: (n: number) => string;
  /** Fallback text when value is nullish. */
  placeholder?: string;
  /** Animation length in ms. */
  duration?: number;
  /** e.g. `cpu`, used for aria-label */
  ariaLabel?: string;
};

/**
 * Smooth value display for live telemetry.
 *
 * Uses direct DOM text mutation inside a requestAnimationFrame loop, so a
 * 1 Hz telemetry stream never causes a React re-render just to redraw a number.
 * Stops the loop as soon as the value settles, keeping idle CPU at zero.
 * Respects prefers-reduced-motion by jumping straight to the final value.
 */
export function AnimatedNumber({ value, format, placeholder = '—', duration = SETTLE_MS, ariaLabel }: AnimatedNumberProps) {
  const reduced = usePrefersReducedMotion();
  const ref = useRef<HTMLSpanElement>(null);
  const fromRef = useRef(value ?? 0);
  const rafRef = useRef(0);
  const formatRef = useRef(format);
  formatRef.current = format;
  const reducedRef = useRef(reduced);
  reducedRef.current = reduced;

  useEffect(() => {
    const el = ref.current;
    const next = value;
    if (next == null) {
      fromRef.current = 0;
      if (el) el.textContent = placeholder;
      return;
    }
    if (reducedRef.current) {
      fromRef.current = next;
      if (el) el.textContent = formatRef.current(next);
      return;
    }
    if (next === fromRef.current) {
      if (el) el.textContent = formatRef.current(next);
      return;
    }

    const from = fromRef.current;
    const start = performance.now();
    cancelAnimationFrame(rafRef.current);

    const step = (now: number) => {
      const t = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - t, 3);
      const current = from + (next - from) * eased;
      if (el) el.textContent = formatRef.current(current);
      if (t < 1) {
        rafRef.current = requestAnimationFrame(step);
      } else {
        fromRef.current = next;
      }
    };

    rafRef.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(rafRef.current);
  }, [value, duration, placeholder]);

  return (
    <span ref={ref} aria-label={ariaLabel}>
      {value == null ? placeholder : format(value)}
    </span>
  );
}