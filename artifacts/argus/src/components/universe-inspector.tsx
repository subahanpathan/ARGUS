/**
 * UniverseInspector — detailed inspection panel for any selected node
 * in the 3D Network Universe. Shows real telemetry data.
 */

import type { UniverseNode, NetworkTopologyData, TopologyConnection } from "./network-universe-types";

function Row({ label, value, tone }: { label: string; value: string; tone?: "good" | "warn" | "bad" }) {
  return (
    <div className="kpi-line">
      <span className="muted">{label}</span>
      <b className={tone === "bad" ? "signal-danger" : tone === "warn" ? "signal-warn" : tone === "good" ? "signal-good" : undefined}>
        <span className="mono">{value}</span>
      </b>
    </div>
  );
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ marginTop: 16, marginBottom: 8, color: "hsl(var(--primary))", font: "500 9px var(--app-font-mono)", textTransform: "uppercase", letterSpacing: ".1em" }}>
      {children}
    </div>
  );
}

function fmtBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}

function fmtRate(bytesPerSec: number): string {
  if (!bytesPerSec || bytesPerSec <= 0) return "idle";
  return `${fmtBytes(bytesPerSec)}/s`;
}

function fmtWhen(iso: string | undefined): string {
  if (!iso) return "—";
  try { return new Date(iso).toLocaleTimeString(); } catch { return "—"; }
}

export function UniverseInspector({
  node,
  data,
  isLive,
  onSelectNode,
}: {
  node: UniverseNode | null;
  data: NetworkTopologyData | null;
  isLive: boolean;
  onSelectNode: (n: UniverseNode | null) => void;
}) {
  if (!node) {
    return (
      <div className="empty" data-testid="universe-inspector-empty">
        <h3>Select a node</h3>
        <p>Click any object in the 3D universe to inspect its real telemetry.</p>
      </div>
    );
  }

  const d = node.data as Record<string, any>;

  if (node.type === "laptop") {
    return (
      <div data-testid="universe-inspector-laptop">
        <div className="eyebrow">LAPTOP · {isLive ? "REAL TELEMETRY" : "OFFLINE"}</div>
        <h2 style={{ margin: "8px 0" }}>{d.hostname || node.label}</h2>
        <Row label="Network status" value={d.activeInterface ? "Connected" : "Disconnected"} tone={d.activeInterface ? "good" : "bad"} />
        <Row label="Active interface" value={d.activeInterfaceFriendly || d.activeInterface || "Unavailable"} />
        <Row label="Interface type" value={d.activeInterfaceType || "Unknown"} />
        <Row label="Local IP" value={d.localIp || "Unavailable"} />
        <Row label="Gateway" value={d.gateway || "Unavailable"} />
        <Row label="DNS servers" value={d.dns?.length ? d.dns.slice(0, 3).join(", ") : "Unavailable"} />
        <Row label="MAC address" value={d.macAddress ? d.macAddress.toUpperCase() : "Unavailable"} />
        <Row label="Public IP" value={d.publicIp || "Unavailable (safe lookup)"} tone={d.publicIp ? "good" : "warn"} />
        <Row label="Upload rate" value={fmtRate(d.uploadRate)} />
        <Row label="Download rate" value={fmtRate(d.downloadRate)} />
        <Row label="Total uploaded" value={fmtBytes(d.totalUpload)} />
        <Row label="Total downloaded" value={fmtBytes(d.totalDownload)} />
        <Row label="Interfaces" value={String(d.interfaceCount ?? "—")} />
        <Row label="Active connections" value={String(node.connections)} />
        <div style={{ marginTop: 14, padding: 12, borderRadius: 5, fontSize: 11, lineHeight: 1.5, background: isLive ? "hsl(142 71% 20% / .08)" : "hsl(var(--chart-3)/.08)", color: isLive ? "hsl(142 71% 70%)" : "hsl(var(--chart-3))" }}>
          {isLive ? "Observed live from the Windows networking stack." : "No live telemetry — start the security engine."}
        </div>
      </div>
    );
  }

  if (node.type === "adapter") {
    return (
      <div data-testid="universe-inspector-adapter">
        <div className="eyebrow">NETWORK ADAPTER · {isLive ? "REAL" : "OFFLINE"}</div>
        <h2 style={{ margin: "8px 0" }}>{d.friendlyName || d.name || node.label}</h2>
        {d.friendlyName && <Row label="System name" value={d.name || "—"} />}
        <Row label="Adapter type" value={d.interfaceType || "Unknown"} />
        <Row label="Status" value={d.isUp ? "Up" : "Down"} tone={d.isUp ? "good" : "bad"} />
        <Row label="Running" value={d.isRunning ? "Yes" : "No"} />
        <Row label="MAC address" value={d.mac ? d.mac.toUpperCase() : "Unavailable"} />
        <Row label="IPv4" value={d.addresses?.filter((a: string) => /^\d+\.\d+\.\d+\.\d+$/.test(a))[0] || "Unavailable"} />
        <Row label="IPv6" value={d.addresses?.filter((a: string) => a.includes(":"))[0] || "Unavailable"} />
        <Row label="MTU" value={d.mtu != null ? String(d.mtu) : "Unavailable"} />
        <Row label="Speed" value={d.speed ? `${d.speed} Mbps` : "Unavailable"} />
        <Row label="Bytes sent" value={fmtBytes(d.bytesSent ?? 0)} />
        <Row label="Bytes received" value={fmtBytes(d.bytesRecv ?? 0)} />
        <Row label="Upload rate" value={fmtRate(d.uploadRate ?? 0)} />
        <Row label="Download rate" value={fmtRate(d.downloadRate ?? 0)} />
      </div>
    );
  }

  if (node.type === "gateway") {
    return (
      <div data-testid="universe-inspector-gateway">
        <div className="eyebrow">GATEWAY / ROUTER · {isLive ? "REAL" : "OFFLINE"}</div>
        <h2 style={{ margin: "8px 0" }}>{d.ip || node.label}</h2>
        <Row label="Gateway IP" value={d.ip || "Unavailable"} tone="good" />
        <Row label="Interface" value={d.interface || "Unavailable"} />
        <Row label="Route metric" value={d.metric != null ? String(d.metric) : "Unavailable"} />
        <Row label="Connection type" value="Default route" />
        <Row label="Local subnet" value={d.localSubnet || "Unavailable"} />
        <div style={{ marginTop: 14, padding: 12, borderRadius: 5, fontSize: 11, lineHeight: 1.5, background: "hsl(var(--chart-3)/.08)", color: "hsl(var(--chart-3))" }}>
          The gateway is the first hop observed upstream. Intermediate routers beyond it are not directly observable without traceroute.
        </div>
      </div>
    );
  }

  if (node.type === "neighbor") {
    return (
      <div data-testid="universe-inspector-neighbor">
        <div className="eyebrow">LOCAL NETWORK NEIGHBOR · ARP</div>
        <h2 style={{ margin: "8px 0" }}>{d.ip || node.label}</h2>
        <Row label="IP address" value={d.ip || "Unavailable"} tone="good" />
        <Row label="MAC address" value={d.mac ? d.mac.toUpperCase() : "Unavailable"} />
        <Row label="Interface" value={d.interface || "Unavailable"} />
        <Row label="State" value={d.state || "Unavailable"} />
        <Row label="Hostname" value={d.hostname || "Not resolved"} />
        <div style={{ marginTop: 14, padding: 12, borderRadius: 5, fontSize: 11, lineHeight: 1.5, background: "hsl(var(--chart-3)/.08)", color: "hsl(var(--chart-3))" }}>
          Discovered from the local ARP/neighbor table. No active scanning was performed.
        </div>
      </div>
    );
  }

  if (node.type === "process") {
    return (
      <div data-testid="universe-inspector-process">
        <div className="eyebrow">LOCAL PROCESS · {isLive ? "REAL" : "OFFLINE"}</div>
        <h2 style={{ margin: "8px 0" }}>{d.name || node.label}</h2>
        <Row label="PID" value={String(d.pid ?? "—")} />
        <Row label="Executable path" value={d.path || "Unavailable"} />
        <Row label="Network connections" value={String(d.connectionCount ?? node.connections)} />
        <Row label="Listening ports" value={d.listeningPorts?.length ? d.listeningPorts.join(", ") : "None"} />
        {d.remoteEndpoints?.length > 0 && (
          <>
            <SectionTitle>Remote endpoints</SectionTitle>
            {d.remoteEndpoints.slice(0, 8).map((ep: string, i: number) => (
              <div key={i} className="kpi-line" style={{ cursor: "pointer" }}>
                <span className="mono" style={{ fontSize: 10 }}>{ep}</span>
              </div>
            ))}
            {d.remoteEndpoints.length > 8 && (
              <div className="muted" style={{ fontSize: 10, marginTop: 4 }}>+{d.remoteEndpoints.length - 8} more</div>
            )}
          </>
        )}
        <div style={{ marginTop: 14, padding: 12, borderRadius: 5, fontSize: 11, lineHeight: 1.5, background: "hsl(var(--chart-3)/.08)", color: "hsl(var(--chart-3))" }}>
          Per-process byte counters are not exposed by the Windows connection table. Traffic shown is interface-level totals only.
        </div>
      </div>
    );
  }

  if (node.type === "remote") {
    return (
      <div data-testid="universe-inspector-remote">
        <div className="eyebrow">REMOTE ENDPOINT · {isLive ? "REAL" : "OFFLINE"}</div>
        <h2 style={{ margin: "8px 0" }}>{d.ip}:{d.port}</h2>
        <Row label="IP address" value={d.ip || "Unavailable"} tone="good" />
        <Row label="Port" value={d.port ? String(d.port) : "—"} />
        <Row label="Hostname" value={d.hostname && d.hostname !== "UNRESOLVED" ? d.hostname : "Not resolved"} tone={d.hostname && d.hostname !== "UNRESOLVED" ? "good" : "warn"} />
        <Row label="Protocol" value={d.protocol || "Unavailable"} />
        <Row label="State" value={d.state || "Unavailable"} tone={d.state === "ESTABLISHED" ? "good" : undefined} />
        <Row label="Owning process" value={d.owningProcess ? `${d.owningProcess} (PID ${d.owningPid})` : "Unavailable"} />
        <div style={{ marginTop: 14, padding: 12, borderRadius: 5, fontSize: 11, lineHeight: 1.5, background: "hsl(var(--chart-3)/.08)", color: "hsl(var(--chart-3))" }}>
          {d.hostname && d.hostname !== "UNRESOLVED"
            ? "Hostname resolved via reverse-DNS. The owning organization is not asserted."
            : "This is the observable remote endpoint. No claim about intermediate hops."}
        </div>
      </div>
    );
  }

  if (node.type === "dns") {
    return (
      <div data-testid="universe-inspector-dns">
        <div className="eyebrow">DNS SERVER</div>
        <h2 style={{ margin: "8px 0" }}>{d.ip || node.label}</h2>
        <Row label="IP address" value={d.ip || "Unavailable"} tone="good" />
        <Row label="Port" value={String(d.port ?? 53)} />
        <Row label="Protocol" value={d.protocol || "DNS"} />
        <Row label="Interface" value={d.interface || "Unavailable"} />
        <div style={{ marginTop: 14, padding: 12, borderRadius: 5, fontSize: 11, lineHeight: 1.5, background: "hsl(var(--chart-3)/.08)", color: "hsl(var(--chart-3))" }}>
          DNS server configured in Windows. Used for resolving hostnames during reverse-DNS lookups and connection resolution.
        </div>
      </div>
    );
  }

  if (node.type === "port") {
    return (
      <div data-testid="universe-inspector-port">
        <div className="eyebrow">LOCAL PORT · {isLive ? "REAL" : "OFFLINE"}</div>
        <h2 style={{ margin: "8px 0" }}>{d.protocol || "TCP"} :{d.port}</h2>
        <Row label="Local address" value={d.localAddress || "0.0.0.0"} />
        <Row label="State" value={d.state || "BOUND"} tone={d.state === "LISTEN" ? "good" : undefined} />
        <Row label="Owning process" value={d.pid ? `${d.processName} (PID ${d.pid})` : "Unavailable"} />
        <Row label="Executable path" value={d.processPath || "Unavailable"} />
        {d.bindingType && <Row label="Binding type" value={String(d.bindingType)} />}
        <Row label="First seen" value={fmtWhen(d.firstSeen)} />
        <Row label="Last seen" value={fmtWhen(d.lastSeen)} />
        <div style={{ marginTop: 14, padding: 12, borderRadius: 5, fontSize: 11, lineHeight: 1.5, background: "hsl(var(--chart-3)/.08)", color: "hsl(var(--chart-3))" }}>
          Observed from the Windows socket table. A LISTEN socket accepts new connections; a BOUND endpoint is an open local socket without an accepted peer.
        </div>
      </div>
    );
  }

  if (node.type === "internet") {
    return (
      <div data-testid="universe-inspector-internet">
        <div className="eyebrow">INTERNET · EXTERNAL</div>
        <h2 style={{ margin: "8px 0" }}>Internet</h2>
        <Row label="Status" value={data?.interfaces?.some((i) => i.is_up) ? "Reachable" : "Unreachable"} tone={data?.interfaces?.some((i) => i.is_up) ? "good" : "bad"} />
        <Row label="Public IP" value={d.publicIp || "Unavailable"} />
        <Row label="Outbound flows" value={String(node.connections)} />
        <Row label="Intermediate hops" value="Not directly observed" tone="warn" />
        <div style={{ marginTop: 14, padding: 12, borderRadius: 5, fontSize: 11, lineHeight: 1.5, background: "hsl(var(--chart-3)/.08)", color: "hsl(var(--chart-3))" }}>
          ARGUS observes laptop → gateway → remote-endpoint. Full Internet path visibility requires traceroute.
        </div>
      </div>
    );
  }

  return null;
}

export function ConnectionInspector({
  connection,
  data,
}: {
  connection: TopologyConnection | null;
  data: NetworkTopologyData | null;
}) {
  if (!connection) {
    return (
      <div className="empty" data-testid="universe-connection-inspector-empty">
        <h3>No connection selected</h3>
        <p>Select a connection from the Ports panel to inspect it here.</p>
      </div>
    );
  }

  const c = connection;

  return (
    <div data-testid="universe-connection-inspector">
      <div className="eyebrow">CONNECTION DETAIL</div>
      <h2 style={{ margin: "8px 0" }}>
        {c.process_name || "—"}
      </h2>
      <Row label="State" value={c.state || "—"} tone={c.state === "ESTABLISHED" ? "good" : undefined} />
      <Row label="Protocol" value={c.protocol || "—"} />
      <Row label="PID" value={String(c.pid ?? "—")} />
      <Row label="Process path" value={c.process_path || "—"} />
      <Row label="Local" value={`${c.local_addr || "0.0.0.0"}:${c.local_port ?? "—"}`} />
      <Row label="Remote" value={`${c.remote_addr || "—"}:${c.remote_port ?? "—"}`} />
      <Row label="Remote hostname" value={c.remote_hostname && c.remote_hostname !== "UNRESOLVED" ? c.remote_hostname : "Not resolved"} tone={c.remote_hostname && c.remote_hostname !== "UNRESOLVED" ? "good" : "warn"} />
      <Row label="First seen" value={c.first_seen ? fmtWhen(c.first_seen) : "—"} />
      <Row label="Last seen" value={c.last_seen ? fmtWhen(c.last_seen) : "—"} />
    </div>
  );
}
