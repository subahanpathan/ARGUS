/**
 * Normalization layer for the NET detection domain: converts real network
 * connection snapshots and port-intelligence snapshots (pushed by the security
 * engine) into NetworkViewEvents that the NET rules evaluate. Every event is
 * stamped with the real hostname and flagged as real ("observed") telemetry.
 */

import { HOSTNAME } from "../normalize";
import type { NetworkSnapshot, PortIntelligenceSnapshot } from "../../lib/event-hub";
import type { NetworkViewEvent } from "../types";

/**
 * Derive a stable, deterministic key that identifies a socket across sampling
 * cycles. Preferred: the engine's own connection/port id; fallback: a hash of
 * the 5-tuple so duplicates pipelines (poll + snapshot) de-duplicate cleanly.
 */
function staleId(...parts: Array<string | number | null | undefined>): string {
  let hash = 5381;
  const joined = parts.map((p) => (p === null || p === undefined ? "" : String(p))).join("|");
  for (let i = 0; i < joined.length; i++) {
    hash = (hash * 33) ^ joined.charCodeAt(i);
  }
  return (hash >>> 0).toString(36);
}

function stableConnectionKey(conn: {
  protocol?: string;
  address_family?: string;
  local_addr?: string;
  local_port?: number;
  remote_addr?: string;
  remote_port?: number;
  pid?: number;
}): string {
  if (typeof conn.pid === "number" && conn.pid > 0) {
    return staleId(conn.protocol, conn.address_family, conn.local_addr, conn.local_port, conn.remote_addr, conn.remote_port, conn.pid);
  }
  return staleId(conn.protocol, conn.address_family, conn.local_addr, conn.local_port, conn.remote_addr, conn.remote_port);
}

/**
 * Normalize every connection in a network snapshot into a NetworkViewEvent.
 * Connections that are purely local infra (no remote side) are retained —
 * individual rules decide what is interesting.
 */
export function normalizeNetworkConnections(snapshot: NetworkSnapshot): NetworkViewEvent[] {
  if (!snapshot || !Array.isArray(snapshot.connections)) return [];
  const timestamp = snapshot.timestamp || new Date().toISOString();

  return snapshot.connections.map((conn) => {
    const pid = typeof conn.pid === "number" && conn.pid > 0 ? conn.pid : 0;
    const key = conn.connection_id || stableConnectionKey(conn);
    return {
      id: `net:${key}`,
      type: "NETWORK_CONNECTION",
      origin: "snapshot",
      timestamp,
      source: "windows_network_monitor",
      hostname: HOSTNAME,
      pid,
      process_name: conn.process || (pid > 0 ? `pid-${pid}` : "system"),
      executable_path: conn.executable_path ?? null,
      protocol: conn.type === "SOCK_STREAM" ? "TCP" : conn.type === "SOCK_DGRAM" ? "UDP" : undefined,
      address_family: conn.address_family,
      local_addr: conn.local_addr,
      local_port: conn.local_port,
      remote_addr: conn.remote_addr,
      remote_port: conn.remote_port,
      local_role: conn.local_role,
      remote_role: conn.remote_role,
      state: (conn.status || "").toUpperCase() || undefined,
      connection_id: key,
      metadata: { stableKey: `net:${key}` },
    };
  });
}

/** Normalize a single port record (listener or UDP endpoint) into an event. */
function portToEvent(
  port: {
    port_id?: string;
    protocol?: string;
    address_family?: string;
    local_addr?: string;
    local_port?: number;
    state?: string;
    pid?: number;
    process_name?: string;
    executable_path?: string;
    binding_type?: string;
    local_role?: string;
  },
  timestamp: string,
): NetworkViewEvent {
  const pid = typeof port.pid === "number" && port.pid > 0 ? port.pid : 0;
  const key = port.port_id || staleId(port.protocol, port.address_family, port.local_addr, port.local_port);
  return {
    id: `port:${key}`,
    type: "NETWORK_PORT",
    origin: "snapshot",
    timestamp,
    source: "windows_port_monitor",
    hostname: HOSTNAME,
    pid,
    process_name: port.process_name || (pid > 0 ? `pid-${pid}` : "system"),
    executable_path: port.executable_path ?? null,
    protocol: port.protocol,
    address_family: port.address_family,
    local_addr: port.local_addr,
    local_port: port.local_port,
    local_role: port.local_role,
    state: (port.state || "").toUpperCase() || undefined,
    binding_type: port.binding_type,
    port_id: key,
    metadata: { stableKey: `port:${key}` },
  };
}

/** Normalize each port event (PORT_OPENED / PORT_CLOSED / PORT_CHANGED). */
function portEventToEvent(
  evt: {
    port_id?: string;
    event_type?: string;
    timestamp?: string;
    protocol?: string;
    address_family?: string;
    local_addr?: string;
    local_port?: number;
    state?: string;
    pid?: number;
    process_name?: string;
    executable_path?: string;
    binding_type?: string;
  },
  fallbackTimestamp: string,
): NetworkViewEvent {
  const pid = typeof evt.pid === "number" && evt.pid > 0 ? evt.pid : 0;
  const key = evt.port_id || staleId(evt.protocol, evt.address_family, evt.local_addr, evt.local_port);
  return {
    id: `port:${key}:${evt.event_type || "EVENT"}`,
    type: "NETWORK_PORT",
    origin: "snapshot",
    timestamp: evt.timestamp || fallbackTimestamp,
    source: "windows_port_monitor",
    hostname: HOSTNAME,
    pid,
    process_name: evt.process_name || (pid > 0 ? `pid-${pid}` : "system"),
    executable_path: evt.executable_path ?? null,
    protocol: evt.protocol,
    address_family: evt.address_family,
    local_addr: evt.local_addr,
    local_port: evt.local_port,
    local_role: "LOCAL",
    state: (evt.state || "").toUpperCase() || undefined,
    binding_type: evt.binding_type,
    port_id: key,
    event_type: (evt.event_type || "").toUpperCase() || undefined,
    metadata: { stableKey: `port:${key}` },
  };
}

/**
 * Normalize a port-intelligence snapshot into NetworkViewEvents: current
 * listeners/endpoints plus the PORT_OPENED lifecycle events (the strong signal
 * for a newly exposed service).
 */
export function normalizePortSnapshot(snapshot: PortIntelligenceSnapshot): NetworkViewEvent[] {
  if (!snapshot) return [];
  const timestamp = snapshot.timestamp || new Date().toISOString();
  const out: NetworkViewEvent[] = [];

  for (const port of snapshot.tcp_listening ?? []) out.push(portToEvent(port, timestamp));
  for (const port of snapshot.udp_endpoints ?? []) out.push(portToEvent(port, timestamp));
  for (const evt of snapshot.port_events ?? []) {
    if (evt.event_type === "PORT_OPENED") out.push(portEventToEvent(evt, timestamp));
  }
  return out;
}

/** A per-process aggregation of outbound remote destinations in one snapshot. */
export type RemoteFanOut = {
  pid: number;
  process_name: string;
  remote_ips: string[];
  count: number;
};

/**
 * Aggregate a network snapshot into per-pid remote fan-out records for NET-007.
 * Only connections that actually reach the internet (role REMOTE) count.
 */
export function aggregateRemoteFanOut(snapshot: NetworkSnapshot): RemoteFanOut[] {
  if (!snapshot || !Array.isArray(snapshot.connections)) return [];
  const byPid = new Map<number, { name: string; ips: Set<string> }>();

  for (const conn of snapshot.connections) {
    const pid = typeof conn.pid === "number" && conn.pid > 0 ? conn.pid : 0;
    if (pid <= 0) continue;
    if (conn.remote_role !== "REMOTE") continue;
    if (!conn.remote_addr) continue;

    let entry = byPid.get(pid);
    if (!entry) {
      entry = { name: conn.process || `pid-${pid}`, ips: new Set() };
      byPid.set(pid, entry);
    }
    entry.ips.add(conn.remote_addr);
  }

  const records: RemoteFanOut[] = [];
  for (const [pid, entry] of byPid) {
    records.push({ pid, process_name: entry.name, remote_ips: [...entry.ips], count: entry.ips.size });
  }
  return records.sort((a, b) => b.count - a.count);
}