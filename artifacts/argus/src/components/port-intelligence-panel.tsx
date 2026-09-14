/**
 * Port Intelligence Center — real-time view of Windows listening ports and
 * UDP endpoints with lifecycle tracking.
 *
 * Distinguishes:
 *   TCP LISTENING PORT  — socket in LISTEN state
 *   UDP ENDPOINT        — stateless UDP socket (always labeled UDP, never ESTABLISHED)
 *   LOOPBACK BINDING    — bound to 127.0.0.1 / ::1
 *   WILDCARD BINDING    — bound to 0.0.0.0 / ::
 */

import { useMemo, useState } from "react";
import type {
  PortInfo,
  PortEvent,
  PortIntelligenceData,
} from "@/hooks/use-port-intelligence";

function BindingBadge({ bindingType }: { bindingType?: string }) {
  const b = (bindingType || "—").toLowerCase();
  if (b === "loopback") return <span className="badge badge-low">LOOPBACK</span>;
  if (b === "wildcard") return <span className="badge badge-medium">WILDCARD</span>;
  if (b === "interface") return <span className="badge badge-muted">INTERFACE</span>;
  return <span className="badge badge-muted">{bindingType || "—"}</span>;
}

function StateBadge({ port, state }: { port: PortInfo; state?: string }) {
  const s = (state || port.state || "—").toLowerCase();
  const isUdp = (port.protocol || "").startsWith("UDP");
  if (isUdp) return <span className="badge badge-medium">UDP</span>;
  if (s === "listening") return <span className="badge badge-low">LISTENING</span>;
  return <span className="badge badge-muted">{s}</span>;
}

function ProtocolBadge({ protocol }: { protocol?: string }) {
  const p = (protocol || "—").toUpperCase();
  const isTcp = p.startsWith("TCP");
  return <span className={`badge ${isTcp ? "badge-low" : "badge-medium"}`}>{p}</span>;
}

function FamilyBadge({ family }: { family?: string }) {
  const f = (family || "—").toUpperCase();
  return <span className={`badge ${f.includes("6") ? "badge-medium" : "badge-muted"}`}>{f}</span>;
}

function fmtWhen(iso: string | undefined): string {
  if (!iso) return "—";
  try { return new Date(iso).toLocaleString(); } catch { return "—"; }
}

function fmtWhenShort(iso: string | undefined): string {
  if (!iso) return "—";
  try { return new Date(iso).toLocaleTimeString(); } catch { return "—"; }
}

type PortFilter =
  | "all"
  | "tcp_listening"
  | "udp"
  | "ipv4"
  | "ipv6"
  | "loopback"
  | "wildcard";

function StatCard({ label, value, color, note }: { label: string; value: number | string; color?: string; note?: string }) {
  return (
    <div className="card card-pad" style={{ padding: 12 }}>
      <div className="mono muted" style={{ fontSize: 9, textTransform: "uppercase", letterSpacing: ".08em" }}>{label}</div>
      <div style={{ fontSize: 22, fontWeight: 800, margin: "4px 0 2px", color: color || "hsl(var(--foreground))" }}>{value}</div>
      {note && <div className="mono muted" style={{ fontSize: 9 }}>{note}</div>}
    </div>
  );
}

function EventBadge({ type }: { type: string }) {
  const cls = type === "PORT_OPENED" ? "badge-low"
    : type === "PORT_CLOSED" ? "badge-high"
    : type === "PORT_CHANGED" ? "badge-medium"
    : "badge-muted";
  return <span className={`badge ${cls}`}>{type}</span>;
}

/** Live port lifecycle event feed — PORT_OPENED / PORT_CLOSED / PORT_CHANGED */
export function PortEventFeed({
  events,
  isLive,
  maxEvents = 40,
}: {
  events: PortEvent[];
  isLive: boolean;
  maxEvents?: number;
}) {
  const visible = events.slice(-maxEvents).reverse();

  return (
    <div data-testid="port-event-feed">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <div>
          <div style={{ fontSize: 13, fontWeight: 700 }}>Live Port Events</div>
          <div className="mono muted" style={{ fontSize: 10 }}>
            {isLive ? `${events.length} events this session` : "No live events"}
          </div>
        </div>
        {isLive && (
          <span className="badge badge-low" style={{ background: "hsl(142 71% 20%)", color: "hsl(142 71% 70%)", border: "1px solid hsl(142 71% 30%)" }}>
            STREAMING
          </span>
        )}
      </div>

      <div style={{ maxHeight: 320, overflowY: "auto" }}>
        {visible.length === 0 ? (
          <div className="empty" style={{ padding: 24 }}>
            <h3>{isLive ? "Waiting for port events..." : "No port events"}</h3>
            <p>{isLive ? "PORT_OPENED / PORT_CLOSED / PORT_CHANGED events will appear here." : "Start the security engine to see live port events."}</p>
          </div>
        ) : (
          visible.map((evt, i) => (
            <div
              key={`${evt.timestamp}-${evt.port_id}-${evt.event_type}-${i}`}
              className="event-row"
            >
              <div
                className="event-dot"
                style={{
                  background: evt.event_type === "PORT_OPENED"
                    ? "hsl(var(--accent))"
                    : evt.event_type === "PORT_CLOSED"
                    ? "hsl(var(--destructive))"
                    : "hsl(var(--chart-5))",
                  boxShadow: "none",
                }}
              />
              <div className="event-copy">
                <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 3 }}>
                  <EventBadge type={evt.event_type || "—"} />
                  <span className="mono" style={{ fontSize: 10, color: "hsl(var(--muted-foreground))" }}>
                    {evt.protocol} {evt.local_addr}:{evt.local_port}
                  </span>
                </div>
                <div style={{ fontSize: 10, color: "hsl(var(--muted-foreground))" }}>
                  {evt.process_name || "—"} {evt.pid ? `(PID ${evt.pid})` : ""}
                  {evt.address_family ? ` · ${evt.address_family}` : ""}
                  {evt.binding_type ? ` · ${evt.binding_type}` : ""}
                  {evt.change_details ? ` · changed: ${evt.change_details}` : ""}
                  {evt.previous_state && evt.state ? ` · ${evt.previous_state} → ${evt.state}` : ""}
                </div>
              </div>
              <div className="event-time">{fmtWhenShort(evt.timestamp)}</div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

/** Port inspector — details for a single selected port. */
export function PortInspector({ port }: { port: PortInfo | null }) {
  if (!port) {
    return (
      <div className="empty" data-testid="port-inspector-empty">
        <h3>Select a port</h3>
        <p>Click any row in the port table to inspect it here.</p>
      </div>
    );
  }

  const Rows: Array<[string, string]> = [
    ["Port", String(port.local_port ?? "—")],
    ["Protocol", port.protocol || "—"],
    ["Address", port.local_addr || "—"],
    ["Address Family", port.address_family || "—"],
    ["State", port.state || "—"],
    ["PID", port.pid != null && port.pid > 0 ? String(port.pid) : "—"],
    ["Process", port.process_name || "—"],
    ["Executable", port.executable_path || "Unavailable"],
    ["Binding", port.binding_type || "—"],
    ["First Seen", fmtWhen(port.first_seen)],
    ["Last Seen", fmtWhen(port.last_seen)],
    ["Port ID", port.port_id?.slice(0, 18) || "—"],
  ];

  return (
    <div data-testid="port-inspector">
      <div className="eyebrow">PORT INSPECTOR</div>
      <h2 style={{ margin: "8px 0" }}>
        <ProtocolBadge protocol={port.protocol} />{" "}
        <span className="mono">{port.local_addr}:{port.local_port}</span>
      </h2>
      {Rows.map(([label, value]) => (
        <div className="kpi-line" key={label}>
          <span className="muted">{label}</span>
          <b><span className="mono" style={{ fontSize: 10 }}>{value}</span></b>
        </div>
      ))}
    </div>
  );
}

/**
 * Port Intelligence Center — summary cards, filterable table, inspector,
 * and live event feed.
 */
export function PortIntelligencePanel({
  data,
  events,
  isLive,
}: {
  data: PortIntelligenceData | null;
  events: PortEvent[];
  isLive: boolean;
}) {
  const [filter, setFilter] = useState<PortFilter>("all");
  const [query, setQuery] = useState("");
  const [selectedPort, setSelectedPort] = useState<PortInfo | null>(null);

  const tcp = data?.tcp_listening ?? [];
  const udp = data?.udp_endpoints ?? [];
  const summary = data?.summary;

  // All observed ports (TCP listening + UDP endpoints) with a kind marker.
  const allPorts: Array<PortInfo & { kind: "tcp" | "udp" }> = useMemo(() => {
    const t = tcp.map((p) => ({ ...p, kind: "tcp" as const }));
    const u = udp.map((p) => ({ ...p, kind: "udp" as const }));
    return [...t, ...u];
  }, [tcp, udp]);

  const filtered = useMemo(() => {
    const q = query.toLowerCase();
    return allPorts.filter((p) => {
      if (filter === "tcp_listening" && p.kind !== "tcp") return false;
      if (filter === "udp" && p.kind !== "udp") return false;
      if (filter === "ipv4" && p.address_family !== "IPv4") return false;
      if (filter === "ipv6" && p.address_family !== "IPv6") return false;
      if (filter === "loopback" && p.binding_type !== "LOOPBACK") return false;
      if (filter === "wildcard" && p.binding_type !== "WILDCARD") return false;
      if (q) {
        const hay = `${p.local_addr ?? ""} ${p.local_port ?? ""} ${p.pid ?? ""} ${p.process_name ?? ""} ${p.protocol ?? ""} ${p.address_family ?? ""} ${p.executable_path ?? ""}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [allPorts, filter, query]);

  const filters: Array<{ key: PortFilter; label: string; count: number }> = [
    { key: "all", label: "ALL", count: allPorts.length },
    { key: "tcp_listening", label: "TCP LISTENING", count: tcp.length },
    { key: "udp", label: "UDP", count: udp.length },
    { key: "ipv4", label: "IPv4", count: allPorts.filter((p) => p.address_family === "IPv4").length },
    { key: "ipv6", label: "IPv6", count: allPorts.filter((p) => p.address_family === "IPv6").length },
    { key: "loopback", label: "LOOPBACK", count: allPorts.filter((p) => p.binding_type === "LOOPBACK").length },
    { key: "wildcard", label: "WILDCARD", count: allPorts.filter((p) => p.binding_type === "WILDCARD").length },
  ];

  return (
    <div data-testid="port-intelligence-panel">
      {/* Summary cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8, marginBottom: 14 }}>
        <StatCard label="TCP Listening Ports" value={summary?.tcp_listening_count ?? tcp.length} color="hsl(var(--accent))" note="Sockets in LISTEN state" />
        <StatCard label="UDP Endpoints" value={summary?.udp_endpoint_count ?? udp.length} color="hsl(var(--chart-5))" note="Stateless UDP sockets" />
        <StatCard label="IPv4 / IPv6" value={`${summary?.ipv4_listening_count ?? 0} / ${summary?.ipv6_listening_count ?? 0}`} note="Listening address families" />
        <StatCard label="Loopback" value={summary?.loopback_count ?? 0} note="127.0.0.1 / ::1 bindings" />
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8, marginBottom: 14 }}>
        <StatCard label="Wildcard" value={summary?.wildcard_count ?? 0} note="0.0.0.0 / :: bindings" color="hsl(var(--chart-3))" />
        <StatCard label="Interface Bound" value={summary?.interface_count ?? 0} note="Specific interface listeners" />
        <StatCard label="Active TCP Connections" value={summary?.active_tcp_connections ?? data?.active_tcp_connections ?? 0} color="hsl(var(--primary))" note="ESTABLISHED + others" />
        <StatCard label="Unique Processes" value={summary?.unique_processes ?? 0} note="Resolved owning PIDs" />
      </div>

      {/* Filters + search */}
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
            style={{ width: 220 }}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search port, PID, process, address..."
          />
        </div>
      </div>

      {/* Port table + inspector */}
      <div className="grid split-grid" style={{ gridTemplateColumns: "minmax(0, 2.2fr) minmax(260px, 0.8fr)" }}>
        <div>
          <div className="table-wrap" style={{ maxHeight: 420, overflowY: "auto" }}>
            <table className="data-table" style={{ minWidth: 1080 }}>
              <thead>
                <tr>
                  <th>State</th>
                  <th>Protocol</th>
                  <th>Address</th>
                  <th>Port</th>
                  <th>Family</th>
                  <th>PID</th>
                  <th>Process</th>
                  <th>Executable</th>
                  <th>Binding</th>
                  <th>First Seen</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {filtered.slice(0, 200).map((p) => (
                  <tr
                    key={p.port_id || `${p.protocol}-${p.local_addr}-${p.local_port}-${p.pid}`}
                    onClick={() => setSelectedPort(p)}
                    style={{ cursor: "pointer", background: selectedPort?.port_id === p.port_id ? "hsl(var(--muted)/.6)" : undefined }}
                  >
                    <td><StateBadge port={p} /></td>
                    <td><ProtocolBadge protocol={p.protocol} /></td>
                    <td className="mono">{p.local_addr || "—"}</td>
                    <td className="mono"><b>{p.local_port ?? "—"}</b></td>
                    <td><FamilyBadge family={p.address_family} /></td>
                    <td className="mono">{p.pid != null && p.pid > 0 ? p.pid : "—"}</td>
                    <td><b>{p.process_name || "—"}</b></td>
                    <td className="mono muted" style={{ maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={p.executable_path || ""}>
                      {p.executable_path || "Unavailable"}
                    </td>
                    <td><BindingBadge bindingType={p.binding_type} /></td>
                    <td className="mono muted">{fmtWhenShort(p.first_seen)}</td>
                    <td className="mono muted">{fmtWhenShort(p.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filtered.length === 0 && (
              <div className="empty" style={{ padding: 24 }}>
                <h3>{allPorts.length ? "No matching ports" : "No ports observed"}</h3>
                <p>{isLive ? "Waiting for telemetry data." : "Start the security engine to see real ports."}</p>
              </div>
            )}
          </div>

          <div style={{ marginTop: 14 }}>
            <PortEventFeed events={events} isLive={isLive} />
          </div>
        </div>

        <div>
          <div className="card card-pad sticky" style={{ position: "sticky", top: 12 }}>
            <PortInspector port={selectedPort} />
          </div>
        </div>
      </div>
    </div>
  );
}