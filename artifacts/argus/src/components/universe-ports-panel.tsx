/**
 * UniversePortsPanel — dedicated ports/connections view showing all observed
 * listening ports, established connections, UDP endpoints with filtering.
 */

import { useMemo, useState } from "react";
import type { TopologyConnection } from "@/hooks/use-network-topology";

function BadgeTone({ value }: { value: string }) {
  const v = value.toLowerCase();
  const cls = v === "established" ? "badge-low" : v === "listen" || v === "bound" ? "badge-medium" : v === "time_wait" || v === "close_wait" || v === "fin_wait2" ? "badge-high" : "badge-muted";
  return <span className={`badge ${cls}`}>{value}</span>;
}

function fmtWhen(iso: string | undefined): string {
  if (!iso) return "—";
  try { return new Date(iso).toLocaleTimeString(); } catch { return "—"; }
}

type PortFilter = "all" | "listening" | "established" | "udp" | "tcp" | "time_wait" | "close_wait";

export function UniversePortsPanel({
  connections,
  isLive,
  onSelectConnection,
}: {
  connections: TopologyConnection[];
  isLive: boolean;
  onSelectConnection: (c: TopologyConnection) => void;
}) {
  const [filter, setFilter] = useState<PortFilter>("all");
  const [query, setQuery] = useState("");

  const stats = useMemo(() => {
    const all = connections;
    const listening = all.filter((c) => c.state === "LISTEN");
    const established = all.filter((c) => c.state === "ESTABLISHED");
    const tcp = all.filter((c) => c.protocol === "TCP" || c.protocol === "TCP6");
    const udp = all.filter((c) => c.protocol === "UDP" || c.protocol === "UDP6");
    const timeWait = all.filter((c) => c.state === "TIME_WAIT");
    const closeWait = all.filter((c) => c.state === "CLOSE_WAIT");
    return { all: all.length, listening: listening.length, established: established.length, tcp: tcp.length, udp: udp.length, timeWait: timeWait.length, closeWait: closeWait.length };
  }, [connections]);

  const filtered = useMemo(() => {
    const q = query.toLowerCase();
    return connections.filter((c) => {
      if (filter === "listening" && c.state !== "LISTEN") return false;
      if (filter === "established" && c.state !== "ESTABLISHED") return false;
      if (filter === "udp" && c.protocol !== "UDP" && c.protocol !== "UDP6") return false;
      if (filter === "tcp" && c.protocol !== "TCP" && c.protocol !== "TCP6") return false;
      if (filter === "time_wait" && c.state !== "TIME_WAIT") return false;
      if (filter === "close_wait" && c.state !== "CLOSE_WAIT") return false;
      if (q) {
        const hay = `${c.process_name ?? ""} ${c.local_addr ?? ""} ${c.remote_addr ?? ""} ${c.local_port ?? ""} ${c.remote_port ?? ""} ${c.state ?? ""} ${c.protocol ?? ""} ${c.address_family ?? ""} ${c.local_role ?? ""} ${c.remote_role ?? ""} ${c.executable_path ?? ""}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [connections, filter, query]);

  const filters: Array<{ key: PortFilter; label: string; count: number }> = [
    { key: "all", label: "All", count: stats.all },
    { key: "listening", label: "Listening", count: stats.listening },
    { key: "established", label: "Established", count: stats.established },
    { key: "tcp", label: "TCP", count: stats.tcp },
    { key: "udp", label: "UDP", count: stats.udp },
    { key: "time_wait", label: "TIME_WAIT", count: stats.timeWait },
    { key: "close_wait", label: "CLOSE_WAIT", count: stats.closeWait },
  ];

  return (
    <div data-testid="universe-ports-panel">
      {/* Summary cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8, marginBottom: 14 }}>
        <div className="card card-pad" style={{ padding: 10 }}>
          <div className="mono muted" style={{ fontSize: 9, textTransform: "uppercase" }}>Total Ports</div>
          <div style={{ fontSize: 20, fontWeight: 800 }}>{stats.all}</div>
        </div>
        <div className="card card-pad" style={{ padding: 10 }}>
          <div className="mono muted" style={{ fontSize: 9, textTransform: "uppercase" }}>TCP Listening</div>
          <div style={{ fontSize: 20, fontWeight: 800, color: "hsl(var(--accent))" }}>{stats.listening}</div>
        </div>
        <div className="card card-pad" style={{ padding: 10 }}>
          <div className="mono muted" style={{ fontSize: 9, textTransform: "uppercase" }}>TCP Established</div>
          <div style={{ fontSize: 20, fontWeight: 800, color: "hsl(var(--primary))" }}>{stats.established}</div>
        </div>
        <div className="card card-pad" style={{ padding: 10 }}>
          <div className="mono muted" style={{ fontSize: 9, textTransform: "uppercase" }}>UDP Endpoints</div>
          <div style={{ fontSize: 20, fontWeight: 800, color: "hsl(var(--chart-5))" }}>{stats.udp}</div>
        </div>
      </div>

      {/* Filters */}
      <div className="filterbar" style={{ padding: "8px 0" }}>
        {filters.map((f) => (
          <button
            key={f.key}
            type="button"
            className={`btn btn-sm ${filter === f.key ? "btn-primary" : ""}`}
            onClick={() => setFilter(f.key)}
          >
            {f.label} <span className="mono" style={{ opacity: 0.6 }}>({f.count})</span>
          </button>
        ))}
        <div className="search-wrap" style={{ marginLeft: "auto" }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ opacity: 0.5, position: "absolute", left: 11, top: 9 }}>
            <circle cx="11" cy="11" r="8" />
            <path d="m21 21-4.3-4.3" />
          </svg>
          <input
            className="search"
            style={{ width: 200 }}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search port, IP, process…"
          />
        </div>
      </div>

      {/* Table */}
      <div className="table-wrap" style={{ maxHeight: 320, overflowY: "auto" }}>
        <table className="data-table" style={{ minWidth: 1100 }}>
          <thead>
            <tr>
              <th>Process</th>
              <th>PID</th>
              <th>Proto</th>
              <th>Family</th>
              <th>Local Address</th>
              <th>Port</th>
              <th>Remote Address</th>
              <th>Remote Port</th>
              <th>Remote Hostname</th>
              <th>State</th>
              <th>Roles (L→R)</th>
              <th>First Seen</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 100).map((c) => {
              const rowId = `${c.connection_id ?? ""}:${c.pid}:${c.local_addr}:${c.local_port}:${c.remote_addr}:${c.remote_port}`;
              return (
                <tr
                  key={rowId}
                  onClick={() => onSelectConnection(c)}
                  style={{ cursor: "pointer" }}
                >
                  <td><b>{c.process_name || "—"}</b></td>
                  <td className="mono">{c.pid ?? "—"}</td>
                  <td>{c.protocol || "—"}</td>
                  <td className="mono muted">{c.address_family || "—"}</td>
                  <td className="mono">{c.local_addr || "—"}</td>
                  <td className="mono">{c.local_port ?? "—"}</td>
                  <td className="mono">{c.remote_addr || "—"}</td>
                  <td className="mono">{c.remote_port ?? "—"}</td>
                  <td className="mono" style={{ maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={c.remote_hostname && c.remote_hostname !== "UNRESOLVED" ? c.remote_hostname : ""}>
                    {c.remote_hostname && c.remote_hostname !== "UNRESOLVED" ? c.remote_hostname : "—"}
                  </td>
                  <td><BadgeTone value={c.state || "—"} /></td>
                  <td className="mono muted">{c.local_role || "—"} → {c.remote_role || "—"}</td>
                  <td className="mono muted">{fmtWhen(c.first_seen)}</td>
                  <td className="mono muted">{fmtWhen(c.last_seen)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div className="empty" style={{ padding: 24 }}>
            <h3>{connections.length ? "No matching connections" : "No connections observed"}</h3>
            <p>{isLive ? "Waiting for telemetry data." : "Start the security engine to see real ports."}</p>
          </div>
        )}
      </div>
    </div>
  );
}
