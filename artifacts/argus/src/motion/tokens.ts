/**
 * ARGUS motion design tokens.
 *
 * Single source of truth for easing curves and durations so every animation
 * in the product shares one physical feel:
 *   - instant   → 0ms, used only for preference-driven no-motion
 *   - micro     → hover / press / focus rings (fast, non-layout)
 *   - fast      → small state changes (badges, pills, chips)
 *   - base      → panels, cards, grid settle
 *   - slow      → major state changes (containment, investigation state)
 *   - entrance  → page / modal / panel entry
 *
 * The identical curves/durations are exposed as CSS custom properties in
 * index.css (--ease-* / --dur-*) so CSS animations and JS-driven animation
 * stay consistent by construction.
 */

export const EASE = {
  /** snappy, no bounce — used for tiny interactions */
  fast: 'cubic-bezier(0.25, 0.8, 0.25, 1)',
  /** strong deceleration — panels settling, graph settling, expansions */
  out: 'cubic-bezier(0.16, 1, 0.3, 1)',
  /** standard UI cadence */
  standard: 'cubic-bezier(0.4, 0, 0.2, 1)',
  /** controlled slowdown for large surfaces */
  inOut: 'cubic-bezier(0.65, 0, 0.35, 1)',
} as const;

export const DURATION = {
  instant: 0,
  micro: 120,
  fast: 180,
  base: 260,
  slow: 460,
  entrance: 300,
} as const;

/** Physical easing used by the JS-driven interpolation loops. */
export const EASE_OUT_CUBIC = (t: number) => 1 - Math.pow(1 - t, 3);

/** Linear ramp used when the OS has reduced motion enabled. */
export const EASE_LINEAR = (t: number) => t;

/** Standard settle time for interpolated telemetry values (ms). */
export const SETTLE_MS = 480;

/** How long a containment / quarantine state transition lasts (ms). */
export const CONTAINMENT_MS = 620;

/** How long an investigation-state change transition lasts (ms). */
export const STATE_TRANSITION_MS = 400;