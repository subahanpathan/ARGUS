import { useEffect, useId, useRef, useState } from 'react';
import { usePrefersReducedMotion, easeOutCubic } from './use-reduced-motion';
import { AnimatedNumber } from './animated-number';
import { SETTLE_MS } from './tokens';

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
const MAX_SAMPLES = 320;
const GRID_LINES = [0, 0.25, 0.5, 0.75, 1];

const TONE: Record<NonNullable<LiveChartProps['color']>, { stroke: string }> = {
  primary: { stroke: 'hsl(var(--primary))' },
  accent: { stroke: 'hsl(var(--accent))' },
  warn: { stroke: 'hsl(var(--chart-3))' },
  danger: { stroke: 'hsl(var(--destructive))' },
};

/**
 * Premium live telemetry chart.
 *
 *  - Incoming values are appended to a time-ordered ring buffer.
 *  - The newest point is eased from the previously displayed value toward the
 *    new value over a short settle time — never a jump.
 *  - A requestAnimationFrame loop drives the path and stops as soon as the
 *    value settles, so idle CPU is effectively zero. Bursts of data restart
 *    the interpolation from the currently displayed value, so the line
 *    follows smoothly without snapping.
 *  - Path updates happen through direct DOM attribute mutation per frame;
 *    no React re-render is triggered by the animation loop.
 *  - prefers-reduced-motion: values are reflected instantly, no rAF loop.
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
  const animRef = useRef<{ from: number; to: number; start: number } | null>(null);
  const displayedRef = useRef(0);
  const rafRef = useRef(0);
  const formatRef = useRef(format);
  formatRef.current = format;
  const [ready, setReady] = useState(false);

  const maxRef = useRef(max);
  maxRef.current = max;
  const windowRef = useRef(windowMs);
  windowRef.current = windowMs;

  function applyToDom(cur: number) {
    const buf = bufRef.current;
    const line = lineRef.current;
    const area = areaRef.current;
    const dot = dotRef.current;
    const tag = tagRef.current;
    if (!line || !area || buf.length === 0) return;

    const currentMax = maxRef.current || 100;
    const usable = windowRef.current || 60_000;
    const lastT = buf[buf.length - 1].t;

    const xs: number[] = [];
    const ys: number[] = [];
    for (let i = 0; i < buf.length; i++) {
      const s = buf[i];
      const age = Math.max(0, lastT - s.t);
      xs.push(VIEW_W * (0.04 + 0.96 * (1 - age / usable)));
      const ratio = Math.max(0, Math.min(1, s.v / currentMax));
      ys.push(VIEW_H - PAD_BOT - ratio * (VIEW_H - PAD_TOP - PAD_BOT));
    }

    // Light 3-point moving average keeps the trace smooth without adding lag.
    const smooth: number[] = [];
    for (let i = 0; i < ys.length; i++) {
      if (i === ys.length - 1) {
        smooth.push(cur);
        continue;
      }
      const prev = ys[i - 1] ?? ys[i];
      const next = ys[i + 1] ?? ys[i];
      smooth.push((prev + ys[i] + next) / 3);
    }

    let points = '';
    for (let i = 0; i < smooth.length; i++) {
      points += `${i === 0 ? '' : ' '}${xs[i].toFixed(1)},${smooth[i].toFixed(1)}`;
    }
    line.setAttribute('points', points);
    area.setAttribute('points', `0,${VIEW_H} ${points} ${VIEW_W},${VIEW_H}`);

    const lastX = xs[smooth.length - 1] ?? VIEW_W;
    const lastY = smooth[smooth.length - 1] ?? 0;
    const xPct = (lastX / VIEW_W) * 100;
    const yPct = (lastY / VIEW_H) * 100;
    if (dot) dot.style.transform = `translate(${xPct}%, ${yPct}%) translate(-50%, -50%)`;
    if (tag) {
      const f = formatRef.current ?? ((n: number) => String(Math.round(n)));
      tag.textContent = f(cur);
      tag.style.left = `${xPct}%`;
      tag.style.top = `${yPct}%`;
      tag.style.transform = `translate(-50%, calc(-100% - 8px))`;
    }
  }

  function trimBuffer() {
    const buf = bufRef.current;
    if (buf.length === 0) return;
    const usable = windowRef.current || 60_000;
    const newest = buf[buf.length - 1].t;
    let cut = -1;
    for (let i = 0; i < buf.length - 1; i++) {
      if (buf[i].t < newest - usable * 1.25) cut = i;
    }
    if (cut >= 0) buf.splice(0, cut + 1);
    if (buf.length > MAX_SAMPLES) buf.splice(0, buf.length - MAX_SAMPLES);
  }

  useEffect(() => {
    const next = value;
    if (next == null || !isFinite(next)) return;

    const now = performance.now();
    bufRef.current.push({ t: now, v: next });
    trimBuffer();
    if (!ready && bufRef.current.length > 0) setReady(true);

    if (reduced) {
      displayedRef.current = next;
      applyToDom(next);
      return;
    }

    animRef.current = { from: displayedRef.current, to: next, start: now };
    cancelAnimationFrame(rafRef.current);

    const step = (frameNow: number) => {
      const anim = animRef.current;
      if (!anim) return;
      const t = Math.min((frameNow - anim.start) / SETTLE_MS, 1);
      const eased = easeOutCubic(t);
      const cur = anim.from + (anim.to - anim.from) * eased;
      displayedRef.current = cur;
      applyToDom(cur);
      if (t >= 1) {
        animRef.current = null;
        return;
      }
      rafRef.current = requestAnimationFrame(step);
    };
    rafRef.current = requestAnimationFrame(step);

    return () => {
      cancelAnimationFrame(rafRef.current);
      animRef.current = null;
    };
  }, [value, reduced]);

  // Draw once the SVG has mounted (first buffer write happens before render).
  useEffect(() => {
    if (ready && bufRef.current.length > 0) applyToDom(displayedRef.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ready]);

  // Redraw when geometry/domain props change (static redraw, not animation).
  useEffect(() => {
    if (bufRef.current.length > 0) applyToDom(displayedRef.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [max, windowMs, height]);

  useEffect(() => () => cancelAnimationFrame(rafRef.current), []);

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
              aria-hidden
            >
              <defs>
                <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={tone.stroke} stopOpacity="0.22" />
                  <stop offset="100%" stopColor={tone.stroke} stopOpacity="0.02" />
                </linearGradient>
              </defs>
              <polygon ref={areaRef} className="live-chart-area" fill={`url(#${gradientId})`} />
              <polyline
                ref={lineRef}
                className="live-chart-line"
                fill="none"
                stroke={tone.stroke}
                strokeWidth={1.6}
                strokeLinejoin="round"
                strokeLinecap="round"
                vectorEffect="non-scaling-stroke"
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