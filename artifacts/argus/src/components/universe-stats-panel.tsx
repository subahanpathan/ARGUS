/**
 * UniverseStatsPanel — network statistics overview with compact cards.
 */

import type { NetworkTopologyData } from "@/hooks/use-network-topology";

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

function StatCard({ label, value, note, color }: { label: string; value: string; note?: string; color?: string }) {
  return (
    <div className="card card-pad" style={{ padding: 12 }}>
      <div className="mono muted" style={{ fontSize: 9, textTransform: "uppercase", letterSpacing: ".08em" }}>{label}</div>
      <div style={{ fontSize: 22, fontWeight: 800, margin: "4px 0 2px", color: color || "hsl(var(--foreground))" }}>{value}</div>
      {note && <div className="mono muted" style={{ fontSize: 9 }}>{note}</div>}
    </div>
  );
}

export function UniverseStatsPanel({ data, isLive }: { data: NetworkTopologyData | null; isLive: boolean }) {
  if (!data || !data.timestamp) {
    return (
      <div className="empty">
        <h3>No network statistics</h3>
        <p>Start the security engine to see real network statistics.</p>
      </div>
    );
  }

  const conns = data.connections ?? [];
  const ifaces = data.interfaces ?? [];
  const neighbors = data.neighbors ?? [];
  const rates = data.traffic_rates ?? [];
  const activeIface = ifaces.find((i) =>
    i.is_up && i.is_running && (i.addresses || []).some((a) => /^\d+\.\d+\.\d+\.\d+$/.test(a) && !a.startsWith("169.254."))
  );
  const activeRate = rates.find((t) => t.interface === activeIface?.name);

  const tcpConns = conns.filter((c) => c.protocol === "TCP" || c.protocol === "TCP6");
  const udpConns = conns.filter((c) => c.protocol === "UDP" || c.protocol === "UDP6");
  const listening = conns.filter((c) => c.state === "LISTEN");
  const established = conns.filter((c) => c.state === "ESTABLISHED");
  const timeWait = conns.filter((c) => c.state === "TIME_WAIT");
  const otherStates = tcpConns.length - established.length - listening.length - timeWait.length;
  const ipv4 = conns.filter((c) => c.address_family === "IPv4").length;
  const ipv6 = conns.filter((c) => c.address_family === "IPv6").length;

  // Prefer server-computed counters from the engine snapshot; fall back to
  // deriving them client-side when the engine predates Phase 2 stats.
  const timeWaitCount = data.time_wait_count ?? timeWait.length;
  const otherStateCount = data.other_state_count ?? Math.max(0, otherStates);
  const ipv4Count = data.ipv4_count ?? ipv4;
  const ipv6Count = data.ipv6_count ?? ipv6;
  const uniqueRemoteIps = data.unique_remote_ips ?? new Set(conns.filter((c) => c.remote_addr).map((c) => c.remote_addr)).size;
  const uniqueProcesses = data.unique_processes ?? new Set(conns.filter((c) => c.pid).map((c) => c.pid)).size;

  return (
    <div data-testid="universe-stats-panel">
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8, marginBottom: 12 }}>
        <StatCard label="Active Connections" value={String(established.length)} note={`${conns.length} total`} color="hsl(var(--primary))" />
        <StatCard label="Listening Ports" value={String(listening.length)} note="TCP listening" color="hsl(var(--accent))" />
        <StatCard label="TIME_WAIT" value={String(timeWaitCount)} note="Closing connections" color="hsl(28 80% 60%)" />
        <StatCard label="Other States" value={String(otherStateCount)} note="SYN_SENT, CLOSE_WAIT, …" />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8, marginBottom: 12 }}>
        <StatCard label="TCP Endpoints" value={String(tcpConns.length)} note={`TCP/UDP ${tcpConns.length}/${udpConns.length}`} />
        <StatCard label="IPv4 / IPv6" value={`${ipv4Count} / ${ipv6Count}`} note="Snapshot sockets" />
        <StatCard label="Unique Remote IPs" value={String(uniqueRemoteIps)} note="External endpoints" />
        <StatCard label="Network Processes" value={String(uniqueProcesses)} note={`${ifaces.length} interfaces`} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8, marginBottom: 12 }}>
        <StatCard label="Neighbors" value={String(neighbors.length)} note="ARP/NDP entries" color="hsl(var(--chart-3))" />
        <StatCard label="Current Download" value={fmtRate(activeRate?.bytes_recv_rate ?? 0)} note="Interface rate" color="hsl(200 80% 60%)" />
        <StatCard label="Current Upload" value={fmtRate(activeRate?.bytes_sent_rate ?? 0)} note="Interface rate" color="hsl(280 60% 70%)" />
        <StatCard label="Public IP" value={data.public_ip || "—"} note={data.public_ip ? "Detected via safe lookup" : "Lookup pending"} color={data.public_ip ? "hsl(var(--accent))" : "hsl(var(--muted-foreground))"} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8 }}>
        <StatCard label="Total Downloaded" value={fmtBytes(activeRate?.bytes_recv ?? 0)} note="Since monitoring started" />
        <StatCard label="Total Uploaded" value={fmtBytes(activeRate?.bytes_sent ?? 0)} note="Since monitoring started" />
        <StatCard label="UDP Endpoints" value={String(udpConns.length)} note="DNS and other UDP" color="hsl(var(--chart-5))" />
        <StatCard label="Snapshot ID" value={data.timestamp ? new Date(data.timestamp).toTimeString().slice(0, 8) : "—"} note="Counters overridden by engine stats" />
      </div>
    </div>
  );
}
