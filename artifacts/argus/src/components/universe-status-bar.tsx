/**
 * UniverseStatusBar — top status bar showing live network metrics.
 */

import type { UniverseStats } from "./network-universe-types";

function fmtBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}

function fmtRate(bytesPerSec: number): string {
  if (!bytesPerSec || bytesPerSec <= 0) return "0 B/s";
  return `${fmtBytes(bytesPerSec)}/s`;
}

export function UniverseStatusBar({
  stats,
  isLive,
  lastUpdate,
}: {
  stats: UniverseStats;
  isLive: boolean;
  lastUpdate: string;
}) {
  return (
    <div className="universe-status-bar" data-testid="universe-status-bar">
      <div className="universe-status-left">
        <span className="universe-status-title">
          NETWORK UNIVERSE
        </span>
        <span className={`universe-status-live ${isLive ? "live" : "offline"}`}>
          {isLive ? "● LIVE" : "○ OFFLINE"}
        </span>
      </div>

      <div className="universe-status-metrics">
        <div className="universe-status-metric">
          <span className="mono muted" style={{ fontSize: 9 }}>INTERFACES</span>
          <span className="mono" style={{ fontSize: 13, fontWeight: 700 }}>{stats.interfaces}</span>
        </div>
        <div className="universe-status-metric">
          <span className="mono muted" style={{ fontSize: 9 }}>PROCESSES</span>
          <span className="mono" style={{ fontSize: 13, fontWeight: 700 }}>{stats.processes}</span>
        </div>
        <div className="universe-status-metric">
          <span className="mono muted" style={{ fontSize: 9 }}>CONNECTIONS</span>
          <span className="mono" style={{ fontSize: 13, fontWeight: 700 }}>{stats.connections}</span>
        </div>
        <div className="universe-status-metric">
          <span className="mono muted" style={{ fontSize: 9 }}>LISTENING</span>
          <span className="mono" style={{ fontSize: 13, fontWeight: 700, color: "hsl(var(--accent))" }}>{stats.listeningPorts}</span>
        </div>
        <div className="universe-status-metric">
          <span className="mono muted" style={{ fontSize: 9 }}>UDP</span>
          <span className="mono" style={{ fontSize: 13, fontWeight: 700, color: "hsl(var(--chart-5))" }}>{stats.udpEndpoints}</span>
        </div>
      </div>

      <div className="universe-status-traffic">
        <div className="universe-status-rate">
          <span className="mono" style={{ fontSize: 10, color: "hsl(200 80% 60%)" }}>↓</span>
          <span className="mono" style={{ fontSize: 13, fontWeight: 700 }}>{fmtRate(stats.downloadRate)}</span>
        </div>
        <div className="universe-status-rate">
          <span className="mono" style={{ fontSize: 10, color: "hsl(280 60% 70%)" }}>↑</span>
          <span className="mono" style={{ fontSize: 13, fontWeight: 700 }}>{fmtRate(stats.uploadRate)}</span>
        </div>
      </div>

      <div className="universe-status-right">
        <span className="mono muted" style={{ fontSize: 9 }}>LAST UPDATE</span>
        <span className="mono" style={{ fontSize: 11 }}>{lastUpdate}</span>
      </div>
    </div>
  );
}
