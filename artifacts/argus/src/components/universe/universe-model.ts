/**
 * universe-model.ts — builds the ARGUS Network Universe scene model from
 * real phase 1–5 telemetry (topology snapshot + port intelligence).
 *
 * Spatial language (premium hierarchy with real depth):
 *
 *   INTERNET (far atmosphere, z≈-15)
 *      │
 *   REMOTE HOSTS (outer shell, spherical band)
 *      │  (purple external layer)
 *   GATEWAY / DNS  (infrastructure band, behind the laptop)
 *      │
 *   PROCESSES + PORTS (application shell around the endpoint)
 *      │
 *   LAPTOP (core) + ADAPTERS (lower ring) + NEIGHBORS (LAN ring)
 *
 * EVERY position is derived deterministically from entity identity so a
 * node never teleports across polling cycles. A session-scoped store
 * freezes previously placed objects; new entities settle around them.
 * Real telemetry payloads pass through unchanged.
 */

import type {
  NetworkTopologyData,
  TopologyConnection,
  UniverseNode,
  UniverseLink,
  UniverseModel,
  UniverseStats,
  PortIntelligenceData,
  SecurityState,
  NodeTier,
} from "../network-universe-types";
import {
  C,
  GAL,
  classifyProcess,
  hf,
  clamp,
  isLocalAddr,
  isPublicRemote,
  connKey,
} from "./universe-theme";

type V3 = { x: number; y: number; z: number };

export function defaultStats(): UniverseStats {
  return {
    interfaces: 0,
    processes: 0,
    connections: 0,
    listeningPorts: 0,
    udpEndpoints: 0,
    establishedCount: 0,
    neighbors: 0,
    uploadRate: 0,
    downloadRate: 0,
    totalUpload: 0,
    totalDownload: 0,
    tcpListening: 0,
    dnsServers: 0,
    ports: 0,
  };
}

function tierForType(type: string): NodeTier {
  switch (type) {
    case "laptop": return "core";
    case "adapter":
    case "gateway":
    case "dns": return "infrastructure";
    case "process":
    case "port": return "application";
    case "neighbor": return "endpoint";
    case "remote":
    case "internet": return "external";
    default: return "endpoint";
  }
}

/* ------------------------------------------------------------------ */
/* Session-stable position store                                       */
/* ------------------------------------------------------------------ */

const positionStore = new Map<string, V3>();

function settled(id: string, intent: V3): V3 {
  const existing = positionStore.get(id);
  if (existing) return existing;
  const fresh = { ...intent };
  positionStore.set(id, fresh);
  return fresh;
}

type SettleItem = { id: string; intent: V3; radius: number; frozen?: boolean };

/**
 * Deterministic collision relaxation. Previously placed ("frozen") objects
 * barely move; newcomers push away from each other and from the frozen set.
 * Currently unknown IDs are re-seeded from intent each pass.
 */
function settle(items: SettleItem[], iterations = 16): void {
  if (!items.length) return;
  const known = (id: string) => positionStore.has(id);
  const pos: V3[] = items.map((it) => {
    const existing = positionStore.get(it.id);
    if (existing) return existing;
    const fresh = { ...it.intent };
    positionStore.set(it.id, fresh);
    return fresh;
  });

  // Hard anchor: keep the whole cluster off the laptop core.
  for (let iter = 0; iter < iterations; iter++) {
    let moved = false;
    for (let i = 0; i < items.length; i++) {
      const a = pos[i];
      const da = Math.hypot(a.x, a.z);
      const nearCore = Math.abs(a.y - 0) < 1.8 && da < 1.7 - items[i].radius;
      if (nearCore) {
        const scale = (1.7 + items[i].radius) / Math.max(da, 0.001);
        a.x *= scale;
        a.z *= scale;
        moved = true;
      }
      for (let j = i + 1; j < items.length; j++) {
        const b = pos[j];
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const dz = b.z - a.z;
        const dist = Math.sqrt(dx * dx + dy * dy + dz * dz);
        const minDist = items[i].radius + items[j].radius + 0.28;
        if (dist < minDist && dist > 0.001) {
          const push = (minDist - dist) * 0.2;
          const nx = dx / dist;
          const ny = dy / dist;
          const nz = dz / dist;
          const fa = known(items[i].id) ? 0.05 : 1;
          const fb = known(items[j].id) ? 0.05 : 1;
          a.x -= nx * push * fa;
          a.y -= ny * push * fa * 0.5;
          a.z -= nz * push * fa;
          b.x += nx * push * fb;
          b.y += ny * push * fb * 0.5;
          b.z += nz * push * fb;
          moved = true;
        }
      }
    }
    if (!moved) break;
  }
}

/* ------------------------------------------------------------------ */
/* Node / link helpers                                                 */
/* ------------------------------------------------------------------ */

type Builder = {
  nodes: UniverseNode[];
  links: UniverseLink[];
  byId: Map<string, UniverseNode>;
  addNode: (n: UniverseNode) => UniverseNode;
  addLink: (l: UniverseLink) => void;
};

function makeBuilder(): Builder {
  const nodes: UniverseNode[] = [];
  const links: UniverseLink[] = [];
  const byId = new Map<string, UniverseNode>();
  return {
    nodes,
    links,
    byId,
    addNode(n) {
      nodes.push(n);
      byId.set(n.id, n);
      return n;
    },
    addLink(l) {
      links.push(l);
    },
  };
}

/* ------------------------------------------------------------------ */
/* Main builder                                                        */
/* ------------------------------------------------------------------ */

export function buildUniverseModel(
  data: NetworkTopologyData | null,
  ports?: PortIntelligenceData | null,
): UniverseModel {
  if (!data || !data.timestamp) {
    return { nodes: [], links: [], stats: defaultStats() };
  }

  const conns = data.connections ?? [];
  const ifaces = data.interfaces ?? [];
  const neighbors = data.neighbors ?? [];
  const rates = data.traffic_rates ?? [];
  const dnsServers = data.dns_servers ?? [];

  const activeIface = ifaces.find((i) =>
    i.is_up && i.is_running && (i.addresses || []).some((a) => /^\d+\.\d+\.\d+\.\d+$/.test(a) && !a.startsWith("169.254."))
  );
  const activeRate = rates.find((t) => t.interface === activeIface?.name);
  const laptopRate = (activeRate?.bytes_recv_rate ?? 0) + (activeRate?.bytes_sent_rate ?? 0);
  const hasFlow = laptopRate > 0 || conns.some((c) => c.state === "ESTABLISHED");

  const b = makeBuilder();

  const portList = [
    ...(ports?.tcp_listening ?? []).map((p) => ({ ...p, listening: true })),
    ...(ports?.udp_endpoints ?? []).map((p) => ({ ...p, listening: false })),
  ];

  /* ------------------------- LAPTOP (core) ------------------------- */
  b.addNode({
    id: "laptop",
    label: data.hostname || "LOCAL",
    type: "laptop",
    detail: activeIface
      ? `${activeIface.friendly_name || activeIface.name} · ${(activeIface.addresses ?? []).filter((a) => /^\d+\.\d+\.\d+\.\d+$/.test(a))[0] ?? ""}`
      : "No active interface",
    x: 0,
    y: 0,
    z: 0,
    activityRate: laptopRate,
    connections: conns.filter((c) => c.state === "ESTABLISHED").length,
    gallery: "browsing",
    glyph: "shield",
    weight: 1,
    tier: "core",
    secState: hasFlow ? "active" : "normal",
    data: {
      hostname: data.hostname,
      activeInterface: activeIface?.name,
      activeInterfaceFriendly: activeIface?.friendly_name || "",
      activeInterfaceType: activeIface?.interface_type || "",
      localIp: (activeIface?.addresses ?? []).filter((a) => /^\d+\.\d+\.\d+\.\d+$/.test(a))[0],
      gateway: data.default_gateway?.next_hop,
      dns: (data.dns_servers ?? []).flatMap((d) => d.servers ?? []).filter((s) => /^\d+\.\d+\.\d+\.\d+$/.test(s)),
      uploadRate: activeRate?.bytes_sent_rate ?? 0,
      downloadRate: activeRate?.bytes_recv_rate ?? 0,
      totalUpload: activeRate?.bytes_sent ?? 0,
      totalDownload: activeRate?.bytes_recv ?? 0,
      publicIp: data.public_ip,
      macAddress: activeIface?.mac_address,
      interfaceCount: ifaces.length,
      protocolCount: new Set(conns.map((c) => c.protocol)).size,
      stateCount: new Set(conns.map((c) => c.state)).size,
    },
  });

  /* ------------------------ ADAPTERS (lower ring) ------------------- */
  const visibleIfaces = ifaces.slice(0, 7);
  const adapterSettle: SettleItem[] = [];
  visibleIfaces.forEach((iface) => {
    const key = `adapter-${iface.name}`;
    const isActive = iface === activeIface;
    const ifaceRate = rates.find((t) => t.interface === iface.name);
    const displayName = iface.friendly_name || iface.name;
    const ang = hf(key) * Math.PI * 2;
    const rad = 2.15 + hf(key + "r") * 0.75;
    const intent: V3 = {
      x: Math.cos(ang) * rad,
      y: -0.8 + hf(key + "y") * 0.45,
      z: Math.sin(ang) * rad,
    };
    adapterSettle.push({ id: key, intent, radius: 0.34 });
    const node: UniverseNode = {
      id: key,
      label: displayName.length > 20 ? displayName.slice(0, 18) + "…" : displayName,
      type: "adapter",
      detail: `${iface.interface_type || iface.name} · ${iface.is_up ? "UP" : "DOWN"}${iface.speed ? ` · ${iface.speed} Mbps` : ""}`,
      x: intent.x,
      y: intent.y,
      z: intent.z,
      activityRate: (ifaceRate?.bytes_sent_rate ?? 0) + (ifaceRate?.bytes_recv_rate ?? 0),
      connections: isActive ? conns.length : 0,
      gallery: "system",
      glyph: "server",
      weight: isActive ? 0.9 : 0.55,
      tier: "infrastructure",
      secState: isActive && hasFlow ? "active" : "normal",
      data: {
        name: iface.name,
        friendlyName: iface.friendly_name,
        interfaceType: iface.interface_type,
        isUp: iface.is_up,
        isRunning: iface.is_running,
        mac: iface.mac_address,
        addresses: iface.addresses,
        mtu: iface.mtu,
        speed: iface.speed,
        bytesSent: iface.bytes_sent,
        bytesRecv: iface.bytes_recv,
        uploadRate: ifaceRate?.bytes_sent_rate ?? 0,
        downloadRate: ifaceRate?.bytes_recv_rate ?? 0,
      },
    };
    b.addNode(node);
    b.addLink({
      id: `laptop-adapter-${iface.name}`,
      from: "laptop",
      to: key,
      intensity: isActive ? 0.55 : 0.14,
      state: isActive && hasFlow ? "flowing" : "idle",
      direction: "outbound",
      edge: "lan",
      secState: isActive && hasFlow ? "active" : "normal",
    });
  });
  settle(adapterSettle);
  // apply settled positions back
  for (const s of adapterSettle) {
    const p = positionStore.get(s.id);
    const n = b.byId.get(s.id);
    if (p && n) {
      n.x = p.x;
      n.y = p.y;
      n.z = p.z;
    }
  }

  /* ------------------------ GATEWAY (infrastructure) --------------- */
  if (data.default_gateway?.next_hop) {
    const gwNode: UniverseNode = {
      id: "gateway",
      label: data.default_gateway.next_hop,
      type: "gateway",
      detail: data.default_gateway.interface ? `via ${data.default_gateway.interface}` : "Default gateway",
      x: 0,
      y: 4.5,
      z: -3.6,
      activityRate: laptopRate,
      connections: conns.length,
      gallery: "system",
      glyph: "server",
      weight: 1,
      tier: "infrastructure",
      secState: hasFlow ? "active" : "normal",
      data: {
        ip: data.default_gateway.next_hop,
        interface: data.default_gateway.interface,
        metric: data.default_gateway.metric,
        localSubnet: activeIface ? activeIface.addresses?.[0] : undefined,
      },
    };
    b.addNode(gwNode);

    const gwFrom = activeIface ? `adapter-${activeIface.name}` : "laptop";
    b.addLink({
      id: `gw-up-${data.default_gateway.next_hop}`,
      from: gwFrom,
      to: "gateway",
      intensity: hasFlow ? 0.8 : 0.25,
      state: hasFlow ? "flowing" : "idle",
      direction: "inbound",
      edge: "infra",
      secState: hasFlow ? "active" : "normal",
    });
  }

  /* ------------------------- DNS (infra band) ----------------------- */
  const allDnsIps = [...new Set(dnsServers.flatMap((d) => d.servers ?? []).filter((s) => /^\d+\.\d+\.\d+\.\d+$/.test(s)))];
  const dnsSettle: SettleItem[] = [];
  allDnsIps.slice(0, 3).forEach((dnsIp, i) => {
    const key = `dns-${dnsIp}`;
    const ang = 1.1 + (i / 3) * 2.6 + hf(key) * 0.3;
    const intent: V3 = { x: Math.cos(ang) * 2.0, y: 3.9, z: Math.sin(ang) * 2.0 - 4.2 };
    dnsSettle.push({ id: key, intent, radius: 0.3 });
    const dnsNode: UniverseNode = {
      id: key,
      label: dnsIp,
      type: "dns",
      detail: "DNS server",
      x: intent.x,
      y: intent.y,
      z: intent.z,
      activityRate: 0,
      connections: conns.filter((c) => c.remote_addr === dnsIp && (c.protocol === "UDP" || c.protocol === "UDP6")).length,
      gallery: "cloud",
      glyph: "globe",
      weight: 0.6,
      tier: "infrastructure",
      secState: "normal",
      data: {
        ip: dnsIp,
        port: 53,
        protocol: "DNS",
        interface: dnsServers.find((d) => (d.servers ?? []).includes(dnsIp))?.interface || "",
      },
    };
    b.addNode(dnsNode);
    b.addLink({
      id: `gateway-dns-${dnsIp}`,
      from: b.byId.has("gateway") ? "gateway" : "laptop",
      to: key,
      intensity: 0.3,
      state: "idle",
      direction: "outbound",
      edge: "infra",
      protocol: "UDP",
      remotePort: 53,
      secState: "normal",
    });
  });
  settle(dnsSettle);
  for (const s of dnsSettle) {
    const p = positionStore.get(s.id);
    const n = b.byId.get(s.id);
    if (p && n) {
      n.x = p.x;
      n.y = p.y;
      n.z = p.z;
    }
  }

  /* ----------------------- NEIGHBORS (LAN ring) -------------------- */
  const seenNeighbors = new Set<string>();
  const neighborSettle: SettleItem[] = [];
  neighbors.forEach((n) => {
    if (!n.ip || seenNeighbors.has(n.ip)) return;
    seenNeighbors.add(n.ip);
    const key = `neighbor-${n.ip}`;
    const ang = hf(key) * Math.PI * 2;
    const rad = 3.4 + hf(key + "r") * 1.3;
    const intent: V3 = { x: Math.cos(ang) * rad, y: -1.1 + hf(key + "y") * 0.6, z: Math.sin(ang) * rad };
    neighborSettle.push({ id: key, intent, radius: 0.3 });
    const node: UniverseNode = {
      id: key,
      label: n.hostname && n.hostname !== "UNRESOLVED"
        ? (n.hostname.length > 16 ? n.hostname.slice(0, 14) + "…" : n.hostname)
        : n.ip,
      type: "neighbor",
      detail: n.mac ? `MAC: ${n.mac}` : n.state || "local neighbor",
      x: intent.x,
      y: intent.y,
      z: intent.z,
      activityRate: 0,
      connections: 0,
      gallery: "system",
      glyph: "bud",
      weight: 0.4,
      tier: "endpoint",
      secState: "normal",
      data: { ip: n.ip, mac: n.mac, interface: n.interface, state: n.state, hostname: n.hostname },
    };
    b.addNode(node);
    const aNode = activeIface ? `adapter-${activeIface.name}` : null;
    b.addLink({
      id: `lan-${n.ip}`,
      from: aNode || "laptop",
      to: key,
      intensity: 0.14,
      state: "idle",
      direction: "outbound",
      edge: "lan",
      secState: "normal",
    });
  });
  settle(neighborSettle);
  for (const s of neighborSettle) {
    const p = positionStore.get(s.id);
    const n = b.byId.get(s.id);
    if (p && n) {
      n.x = p.x;
      n.y = p.y;
      n.z = p.z;
    }
  }

  /* ----------------------- PROCESS grouping ------------------------ */
  const procMap = new Map<number, { name: string; path: string; conns: TopologyConnection[] }>();
  for (const c of conns) {
    if (!c.pid) continue;
    if (c.state === "LISTEN") continue;
    const existing = procMap.get(c.pid);
    if (existing) existing.conns.push(c);
    else procMap.set(c.pid, { name: c.process_name || `<pid-${c.pid}>`, path: c.process_path || c.process_name || "", conns: [c] });
  }
  const procs = [...procMap.entries()].sort((a, b) => b[1].conns.length - a[1].conns.length);
  const visibleProcs = procs.slice(0, MAX_PROCESSES);

  const processOrder = new Map(visibleProcs.map(([pid], i) => [pid, i]));

  const portByPid = new Map<number, Array<{ port: number; protocol: string; localAddress: string; listening: boolean; path: string; raw: Record<string, unknown> }>>();
  for (const p of portList) {
    const pid = p.pid ?? 0;
    if (!pid) continue;
    const entry = {
      port: p.local_port ?? 0,
      protocol: p.protocol || "TCP",
      localAddress: p.local_addr || "0.0.0.0",
      listening: !!(p as { listening?: boolean }).listening,
      path: p.executable_path || p.process_name || "",
      raw: { ...p },
    };
    if (!portByPid.has(pid)) portByPid.set(pid, []);
    portByPid.get(pid)!.push(entry);
  }

  /* ----------------------- PROCESS placement ----------------------- */
  const procSettle: SettleItem[] = [];
  visibleProcs.forEach(([pid, proc]) => {
    const key = `proc-${pid}`;
    const az = hf(key + "a") * Math.PI * 2;
    const elev = 0.55 + hf(key + "e") * 2.1;
    const rad = 3.4 + hf(key + "r") * 2.0;
    const intent: V3 = { x: Math.cos(az) * rad, y: elev, z: Math.sin(az) * rad - 0.4 };
    procSettle.push({ id: key, intent, radius: 0.55 });
  });
  settle(procSettle);

  /* ----------------------- PORT placement -------------------------- */
  const portPositions = new Map<string, V3>();
  visibleProcs.forEach(([pid, proc], i) => {
    const key = `proc-${pid}`;
    const procPos = positionStore.get(key) || procSettle[i]?.intent || { x: 0, y: 1, z: 0 };
    const ownedPorts = portByPid.get(pid) || [];
    const portSettle: SettleItem[] = [];
    ownedPorts.forEach((p, j) => {
      const pkey = `port-${p.protocol}-${p.localAddress}-${p.port}-${pid}`;
      const pa = (j / Math.max(ownedPorts.length, 1)) * Math.PI * 2 + hf(pkey) * 0.7;
      const pr = 0.7 + (j % 3) * 0.14 + hf(pkey) * 0.12;
      portSettle.push({
        id: pkey,
        intent: {
          x: procPos.x + Math.cos(pa) * pr,
          y: procPos.y + Math.sin(pa) * pr * 0.4 + 0.4,
          z: procPos.z + Math.sin(pa) * pr,
        },
        radius: 0.2,
      });
    });
    settle(portSettle);
    for (const s of portSettle) {
      const p = positionStore.get(s.id);
      if (p) portPositions.set(s.id, p);
    }
  });

  /* ----------------------- PROCESS nodes + links ------------------- */
  const dnsIps = new Set<string>(allDnsIps);
  visibleProcs.forEach(([pid, proc]) => {
    const key = `proc-${pid}`;
    const pos = positionStore.get(key) || { x: 0, y: 1, z: 0 };
    const listeningCount = conns.filter((c) => c.pid === pid && c.state === "LISTEN").length;
    const ownedPorts = portByPid.get(pid) || [];
    const established = proc.conns.filter((c) => c.state === "ESTABLISHED").length;
    const cls = classifyProcess(proc.name);
    const node: UniverseNode = {
      id: key,
      label: proc.name.replace(".exe", ""),
      type: "process",
      detail: `PID ${pid} · ${proc.conns.length} connections`,
      x: pos.x,
      y: pos.y,
      z: pos.z,
      activityRate: established,
      connections: proc.conns.length,
      gallery: cls.gallery,
      glyph: cls.glyph,
      weight: 0.85,
      tier: "application",
      secState: established > 0 ? "active" : "normal",
      data: {
        pid,
        name: proc.name,
        path: proc.path,
        executablePath: proc.path,
        connectionCount: proc.conns.length,
        established,
        listeningCount,
        listeningPorts: [...new Set(conns.filter((c) => c.pid === pid && c.state === "LISTEN").map((c) => c.local_port))],
        remoteEndpoints: [...new Set(proc.conns.filter((c) => c.remote_addr && !isLocalAddr(c.remote_addr)).map((c) => `${c.remote_addr}:${c.remote_port}`))],
        protocols: [...new Set(proc.conns.map((c) => c.protocol))],
        states: [...new Set(proc.conns.map((c) => c.state))],
        ports: ownedPorts.map((p) => `${p.protocol}:${p.port}`),
      },
    };
    b.addNode(node);
    b.addLink({
      id: `laptop-proc-${pid}`,
      from: "laptop",
      to: key,
      intensity: established > 0 ? 0.5 : 0.18,
      state: established > 0 ? "flowing" : "idle",
      direction: "outbound",
      edge: "proc",
      secState: established > 0 ? "active" : "normal",
    });

    ownedPorts.forEach((p) => {
      const pkey = `port-${p.protocol}-${p.localAddress}-${p.port}-${pid}`;
      const ppos = portPositions.get(pkey);
      if (!ppos) return;
      const pnode: UniverseNode = {
        id: pkey,
        label: `${p.port}`,
        type: "port",
        detail: `${p.protocol} ${p.localAddress}:${p.port}`,
        x: ppos.x,
        y: ppos.y,
        z: ppos.z,
        activityRate: p.listening ? 0.35 : 0.2,
        connections: 1,
        gallery: "terminal",
        glyph: "bud",
        listening: p.listening,
        weight: 0.45,
        tier: "application",
        secState: p.listening ? "active" : "normal",
        data: {
          port: p.port,
          protocol: p.protocol,
          localAddress: p.localAddress,
          state: p.listening ? "LISTEN" : "BOUND",
          pid,
          processName: proc.name,
          processPath: p.path,
          bindingType: (p.raw as { binding_type?: string }).binding_type ?? "",
          firstSeen: (p.raw as { first_seen?: string }).first_seen ?? "",
          lastSeen: (p.raw as { last_seen?: string }).last_seen ?? "",
        },
      };
      b.addNode(pnode);
      b.addLink({
        id: `proc-port-${pid}-${p.protocol}-${p.port}`,
        from: key,
        to: pkey,
        intensity: p.listening ? 0.45 : 0.2,
        state: p.listening ? "flowing" : "idle",
        direction: "outbound",
        edge: "port",
        protocol: p.protocol,
        localPort: p.port,
        secState: p.listening ? "active" : "normal",
      });
    });
  });

  /* ----------------------- REMOTE endpoints ------------------------ */
  const remoteMap = new Map<string, { ip: string; port: number; hostname: string; protocol: string; state: string; pid: number; processName: string; localPorts: Set<number> }>();
  for (const c of conns) {
    if (isLocalAddr(c.remote_addr || "") || !c.remote_addr) continue;
    if (c.state === "LISTEN") continue;
    const key = `${c.remote_addr}:${c.remote_port ?? 0}`;
    const existing = remoteMap.get(key);
    if (existing) {
      if (c.local_port != null) existing.localPorts.add(c.local_port);
      existing.pid = existing.pid || c.pid || 0;
      existing.processName = existing.processName || c.process_name || "";
      if (c.state === "ESTABLISHED") existing.state = "ESTABLISHED";
    } else {
      remoteMap.set(key, {
        ip: c.remote_addr,
        port: c.remote_port ?? 0,
        hostname: c.remote_hostname || "",
        protocol: c.protocol || "",
        state: c.state || "",
        pid: c.pid ?? 0,
        processName: c.process_name || "",
        localPorts: c.local_port != null ? new Set([c.local_port]) : new Set(),
      });
    }
  }
  let remotes = [...remoteMap.values()];
  remotes.sort((a, b) => {
    const ea = a.state === "ESTABLISHED" ? 0 : 1;
    const eb = b.state === "ESTABLISHED" ? 0 : 1;
    return ea - eb || a.ip.localeCompare(b.ip);
  });
  remotes = remotes.slice(0, MAX_REMOTES);

  const remoteSettle: SettleItem[] = [];
  for (const r of remotes) {
    const key = `remote-${r.ip}-${r.port}`;
    const procNode = processOrder.has(r.pid) ? b.byId.get(`proc-${r.pid}`) : undefined;
    const anchorAz = procNode ? Math.atan2(procNode.z, procNode.x) : hf(key) * Math.PI * 2;
    const az = anchorAz + (hf(key) * 2 - 1) * 0.85;
    const elev = 1.2 + hf(key + "y") * 5.2;
    const rad = 8.2 + hf(key + "rad") * 2.8;
    remoteSettle.push({
      id: key,
      intent: { x: Math.cos(az) * rad, y: elev, z: Math.sin(az) * rad - 1.4 },
      radius: 0.42,
    });
  }
  settle(remoteSettle);

  remotes.forEach((r) => {
    const key = `remote-${r.ip}-${r.port}`;
    const pos = positionStore.get(key) || { x: 0, y: 2, z: -8 };
    const secState: SecurityState =
      r.state === "ESTABLISHED"
        ? (r.protocol === "UDP" && r.port === 53 && !dnsIps.has(r.ip) ? "suspicious" : "active")
        : (["CLOSE_WAIT", "FIN_WAIT_1", "CLOSING", "TIME_WAIT", "LAST_ACK"].includes(r.state) ? "blocked" : "normal");
    const procNode = processOrder.has(r.pid) ? b.byId.get(`proc-${r.pid}`) : undefined;
    const node: UniverseNode = {
      id: key,
      label: r.hostname && r.hostname !== "UNRESOLVED"
        ? (r.hostname.length > 24 ? r.hostname.slice(0, 22) + "…" : r.hostname)
        : r.ip,
      type: "remote",
      detail: `${r.ip}:${r.port}`,
      x: pos.x,
      y: pos.y,
      z: pos.z,
      activityRate: r.state === "ESTABLISHED" ? 1 : 0,
      connections: 1,
      gallery: "cloud",
      glyph: "grid",
      weight: 0.6,
      tier: "external",
      secState,
      data: {
        ip: r.ip,
        port: r.port,
        hostname: r.hostname,
        protocol: r.protocol,
        state: r.state,
        owningProcess: r.processName,
        owningPid: r.pid,
        localPorts: [...r.localPorts],
        connectionKey: connKey("", 0, r.ip, r.port, r.protocol),
      },
    };
    b.addNode(node);
    const sourceId = procNode ? procNode.id : "laptop";
    b.addLink({
      id: `remote-${r.ip}-${r.port}`,
      from: sourceId,
      to: key,
      intensity: r.state === "ESTABLISHED" ? 0.85 : 0.22,
      state: r.state === "ESTABLISHED" ? "flowing" : "idle",
      direction: "outbound",
      protocol: r.protocol,
      remotePort: r.port,
      edge: "remote",
      connectionKey: connKey("", 0, r.ip, r.port, r.protocol),
      bundle: (procNode?.connections ?? 1) > 1,
      secState,
    });
  });

  /* ----------------------- INTERNET (far band) --------------------- */
  b.addNode({
    id: "internet",
    label: "INTERNET",
    type: "internet",
    detail: "External network region",
    x: 0,
    y: 5.2,
    z: -15,
    activityRate: 0,
    connections: new Set(conns.filter((c) => isPublicRemote(c.remote_addr || "")).map((c) => `${c.remote_addr}:${c.remote_port}`)).size,
    gallery: "cloud",
    glyph: "globe",
    weight: 0.9,
    tier: "external",
    secState: hasFlow ? "active" : "normal",
    data: { publicIp: data.public_ip },
  });
  if (b.byId.has("gateway")) {
    b.addLink({
      id: "gateway-internet",
      from: "gateway",
      to: "internet",
      intensity: hasFlow ? 0.75 : 0.18,
      state: hasFlow ? "flowing" : "idle",
      direction: "outbound",
      edge: "infra",
      secState: hasFlow ? "active" : "normal",
    });
  }

  /* ----------------------- STATS (real telemetry) ------------------ */
  const allRemoteConns = conns.filter((c) => c.remote_addr && !isLocalAddr(c.remote_addr) && c.state !== "LISTEN");
  const stats: UniverseStats = {
    interfaces: ifaces.length,
    processes: procs.length,
    connections: allRemoteConns.length,
    listeningPorts: conns.filter((c) => c.state === "LISTEN").length,
    udpEndpoints: allRemoteConns.filter((c) => c.protocol === "UDP" || c.protocol === "UDP6").length,
    establishedCount: conns.filter((c) => c.state === "ESTABLISHED").length,
    neighbors: neighbors.length,
    uploadRate: activeRate?.bytes_sent_rate ?? 0,
    downloadRate: activeRate?.bytes_recv_rate ?? 0,
    totalUpload: activeRate?.bytes_sent ?? 0,
    totalDownload: activeRate?.bytes_recv ?? 0,
    tcpListening: conns.filter((c) => c.state === "LISTEN").length,
    dnsServers: allDnsIps.length,
    ports: portList.length,
  };

  return { nodes: b.nodes, links: b.links, stats };
}

const MAX_PROCESSES = 20;
const MAX_REMOTES = 44;

/** Node radius used by the renderer for sizing + label offsets. */
export function nodeRadius(type: string): number {
  switch (type) {
    case "laptop": return 0.78;
    case "gateway": return 0.5;
    case "process": return 0.55;
    case "remote": return 0.34;
    case "internet": return 1.0;
    case "dns": return 0.28;
    case "adapter": return 0.34;
    case "neighbor": return 0.26;
    case "port": return 0.16;
    default: return 0.32;
  }
}

/** Entity → color family for legend + glows (controlled palette). */
export function nodeTint(type: string): string {
  switch (type) {
    case "laptop": return C.cyan;
    case "adapter": return C.cyan;
    case "gateway": return C.blue;
    case "dns": return C.purple;
    case "neighbor": return C.cyanDeep;
    case "process": return C.green;
    case "port": return C.cyan;
    case "remote": return C.purple;
    case "internet": return C.purple;
    default: return C.slate;
  }
}

export { GAL, classifyProcess, clamp };