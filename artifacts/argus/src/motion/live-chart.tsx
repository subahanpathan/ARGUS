import { useEffect, useId, useRef, useState } from 'react';
import { usePrefersReducedMotion } from './use-reduced-motion';
import { AnimatedNumber } from './animated-number';

type Sample = { t: number; v: number };

type LiveChartProps = {
  /** Latest raw telemetry value. Null = no data yet. */
  value: number | null | undefined;
  /** Metric label shown above the chart. */
  label: string;
  /** Upper bound of the y domain. */
  max: number;
  /** Visible time window in ms (default 60 s). */
  windowMs?: number;
  /** Formatter for the headline + value tag numbers. */
  format?: (n: number) => string;
  color?: 'primary' | 'accent' | 'warn' | 'danger';
  height?: number;
};

const VIEW_W = 400;
const VIEW_H = 120;
const PAD_TOP = 8;
const PAD_BOT = 12;
const MAX_SAMPLES = 350;
const GRID_LINES = [0, 0.25, 0.5, 0.75, 1];

const TONE: Record<NonNullable<LiveChartProps['color']>, { stroke: string }> = {
  primary: { stroke: 'hsl(var(--primary))' },
  accent: { stroke: 'hsl(var(--accent))' },
  warn: { stroke: 'hsl(var(--chart-3))' },
  danger: { stroke: 'hsl(var(--destructive))' },
};

/**
 * Ultra-smooth, 60fps continuous rolling live telemetry chart.
 *
 *  - Continuous horizontal time scroll (never freezes between telemetry samples).
 *  - Easing interpolation glides the leading edge value toward incoming samples.
 *  - Direct SVG DOM mutations per frame; zero React re-render overhead.
 *  - Auto-pauses on visibility hidden, respects prefers-reduced-motion.
 */
export function LiveChart({
  value,
  label,
  max,
  windowMs = 60_000,
  format,
  color = 'primary',
  height = 150,
}: LiveChartProps) {
  const reduced = usePrefersReducedMotion();
  const gradientId = useId().replace(/:/g, '');
  const tone = TONE[color];

  const bufRef = useRef<Sample[]>([]);
  const lineRef = useRef<SVGPolylineElement>(null);
  const areaRef = useRef<SVGPolygonElement>(null);
  const dotRef = useRef<HTMLDivElement>(null);
  const tagRef = useRef<HTMLDivElement>(null);

  const targetRef = useRef<number>(value ?? 0);
  const displayedRef = useRef<number>(value ?? 0);
  const lastTimeRef = useRef<number>(0);
  const lastPushRef = useRef<number>(0);
  const rafRef = useRef<number>(0);

  const formatRef = useRef(format);
  formatRef.current = format;
  const [ready, setReady] = useState(false);

  const maxRef = useRef(max);
  maxRef.current = max;
  const windowRef = useRef(windowMs);
  windowRef.current = windowMs;

  function applyToDom(cur: number, currentT: number) {
    const buf = bufRef.current;
    const line = lineRef.current;
    const area = areaRef.current;
    const dot = dotRef.current;
    const tag = tagRef.current;
    if (!line || !area) return;

    const currentMax = maxRef.current || 100;
    const usable = windowRef.current || 60_000;

    const xs: number[] = [];
    const ys: number[] = [];

    // Map historical points relative to current continuous clock
    for (let i = 0; i < buf.length; i++) {
      const s = buf[i];
      const age = Math.max(0, currentT - s.t);
      const progress = Math.max(0, Math.min(1, 1 - age / usable));
      xs.push(VIEW_W * (0.02 + 0.98 * progress));
      const ratio = Math.max(0, Math.min(1, s.v / currentMax));
      ys.push(VIEW_H - PAD_BOT - ratio * (VIEW_H - PAD_TOP - PAD_BOT));
    }

    // Append the active leading head point pinned to the right edge (progress = 1.0)
    const headRatio = Math.max(0, Math.min(1, cur / currentMax));
    const headX = VIEW_W;
    const headY = VIEW_H - PAD_BOT - headRatio * (VIEW_H - PAD_TOP - PAD_BOT);
    xs.push(headX);
    ys.push(headY);

    if (xs.length < 2) return;

    // Moving average smoothing for internal points
    const smooth: number[] = [];
    for (let i = 0; i < ys.length; i++) {
      if (i === 0 || i === ys.length - 1) {
        smooth.push(ys[i]);
      } else {
        const prev = ys[i - 1];
        const next = ys[i + 1];
        smooth.push((prev + ys[i] + next) / 3);
      }
    }

    let points = '';
    for (let i = 0; i < smooth.length; i++) {
      const clampedX = Math.max(0, Math.min(VIEW_W, xs[i]));
      points += `${i === 0 ? '' : ' '}${clampedX.toFixed(1)},${smooth[i].toFixed(1)}`;
    }
    line.setAttribute('points', points);

    const firstX = Math.max(0, Math.min(VIEW_W, xs[0] ?? 0));
    area.setAttribute('points', `${firstX.toFixed(1)},${VIEW_H} ${points} ${VIEW_W.toFixed(1)},${VIEW_H}`);

    const xPct = 98;
    const yPct = Math.max(5, Math.min(95, (headY / VIEW_H) * 100));
    if (dot) dot.style.transform = `translate(${xPct}%, ${yPct}%) translate(-50%, -50%)`;
    if (tag) {
      const f = formatRef.current ?? ((n: number) => String(Math.round(n)));
      tag.textContent = f(cur);
      tag.style.left = `${xPct}%`;
      tag.style.top = `${yPct}%`;
      tag.style.transform = `translate(-50%, calc(-100% - 8px))`;
    }
  }

  function trimBuffer(currentT: number) {
    const buf = bufRef.current;
    if (buf.length === 0) return;
    const usable = windowRef.current || 60_000;
    let cut = -1;
    for (let i = 0; i < buf.length - 1; i++) {
      if (buf[i].t < currentT - usable) cut = i;
    }
    if (cut >= 0) buf.splice(0, cut + 1);
    if (buf.length > MAX_SAMPLES) buf.splice(0, buf.length - MAX_SAMPLES);
  }

  // Update target when incoming value changes
  useEffect(() => {
    if (value == null || !isFinite(value)) return;
    targetRef.current = value;

    const now = performance.now();
    if (bufRef.current.length === 0) {
      // Seed initial baseline points so the line renders immediately
      bufRef.current.push({ t: now - 3000, v: value });
      bufRef.current.push({ t: now, v: value });
      displayedRef.current = value;
      lastPushRef.current = now;
      setReady(true);
    } else {
      bufRef.current.push({ t: now, v: value });
      lastPushRef.current = now;
      trimBuffer(now);
    }
  }, [value]);

  // Continuous 60fps animation loop
  useEffect(() => {
    if (reduced) {
      if (value != null && isFinite(value)) {
        displayedRef.current = value;
        applyToDom(value, performance.now());
      }
      return;
    }

    lastTimeRef.current = performance.now();

    const step = (frameNow: number) => {
      if (document.hidden) {
        rafRef.current = requestAnimationFrame(step);
        return;
      }

      const dt = Math.min((frameNow - lastTimeRef.current) / 1000, 0.1);
      lastTimeRef.current = frameNow;

      // Smooth exponential decay easing toward latest telemetry target
      const target = targetRef.current;
      const lerpFactor = 1 - Math.exp(-5.0 * dt);
      displayedRef.current += (target - displayedRef.current) * lerpFactor;

      // Append intermediate point every 200ms to preserve smooth line contour
      if (frameNow - lastPushRef.current > 200) {
        bufRef.current.push({ t: frameNow, v: displayedRef.current });
        lastPushRef.current = frameNow;
        trimBuffer(frameNow);
      }

      applyToDom(displayedRef.current, frameNow);
      rafRef.current = requestAnimationFrame(step);
    };

    rafRef.current = requestAnimationFrame(step);

    return () => {
      cancelAnimationFrame(rafRef.current);
    };
  }, [reduced, ready]);

  const seconds = Math.round((windowMs || 60_000) / 1000);

  return (
    <div className="live-chart" style={{ height }}>
      <div className="live-chart-head">
        <span className="live-chart-label">{label}</span>
        {ready ? (
          <span className="live-chart-value" style={{ color: tone.stroke }}>
            <AnimatedNumber value={value} format={format ?? ((n: number) => String(Math.round(n)))} />
          </span>
        ) : (
          <span className="live-chart-value muted">—</span>
        )}
      </div>
      <div className="live-chart-body">
        <div className="live-chart-grid" aria-hidden>
          {GRID_LINES.map((g) => (
            <i key={g} />
          ))}
        </div>
        {ready ? (
          <>
            <svg
              className="live-chart-svg"
              viewBox={`0 0 ${VIEW_W} ${VIEW_H}`}
              preserveAspectRatio="none"
              style={{ overflow: 'hidden' }}
              aria-hidden
            >
              <defs>
                <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={tone.stroke} stopOpacity="0.22" />
                  <stop offset="100%" stopColor={tone.stroke} stopOpacity="0.02" />
                </linearGradient>
                <clipPath id={`clip-${gradientId}`}>
                  <rect x="0" y="0" width={VIEW_W} height={VIEW_H} />
                </clipPath>
              </defs>
              <polygon
                ref={areaRef}
                className="live-chart-area"
                fill={`url(#${gradientId})`}
                clipPath={`url(#clip-${gradientId})`}
              />
              <polyline
                ref={lineRef}
                className="live-chart-line"
                fill="none"
                stroke={tone.stroke}
                strokeWidth={1.8}
                strokeLinejoin="round"
                strokeLinecap="round"
                vectorEffect="non-scaling-stroke"
                clipPath={`url(#clip-${gradientId})`}
              />
            </svg>
            <div ref={dotRef} className="live-chart-dot" style={{ background: tone.stroke }} />
            <div ref={tagRef} className="live-chart-tag" style={{ color: tone.stroke }} />
          </>
        ) : (
          <div className="live-chart-empty">waiting for telemetry…</div>
        )}
        <div className="live-chart-labels">
          <span>{max}</span>
          <span>−{seconds}s window</span>
          <span>0</span>
        </div>
      </div>
    </div>
  );
}