/**
 * useSimulatedNetwork — real-time telemetry synthesizer.
 *
 * When the ARGUS security engine is offline, this hook produces a continuous
 * stream of topology snapshots, connection lifecycle events, port snapshots
 * and port events in EXACTLY the same shapes the live SSE hooks emit
 * (`NetworkTopologyData`, `PortIntelligenceData`, `TopologyConnectionEvent`,
 * `PortEvent`). The 3D Network Universe therefore stays alive, animated and
 * "actively working" even when no engine telemetry is flowing.
 *
 * The simulation is honest by construction:
 *   - it only runs while the engine has no data (NetworkPage opts in),
 *   - the UI labels it SIMULATED, never LIVE,
 *   - identifiers are stable across ticks so the scene grows / settles
 *     naturally, and public IPs use RFC 5737 TEST-NET ranges.
 */

import { useEffect, useRef, useState } from "react";
import type {
  NetworkTopologyData,
  TopologyConnection,
  TopologyConnectionEvent,
  TopologyInterface,
  TopologyNeighbor,
  TopologyTrafficRate,
} from "./use-network-topology";
import type {
  PortIntelligenceData,
  PortInfo,
  PortEvent,
} from "./use-port-intelligence";

export type NetworkMode = "live" | "simulated" | "offline";

export type SimulatedNetworkState = {
  /** Whether the synthesizer is currently producing data. */
  active: boolean;
  /** Latest synthetic topology snapshot. */
  data: NetworkTopologyData | null;
  /** Accumulated synthetic connection lifecycle events (bounded). */
  events: TopologyConnectionEvent[];
  /** Latest synthetic port intelligence snapshot. */
  ports: PortIntelligenceData | null;
  /** Accumulated synthetic port lifecycle events (bounded). */
  portEvents: PortEvent[];
};

/* ------------------------------------------------------------------ */
/* Static scene profile (stable identities → stable 3D placement)      */
/* ------------------------------------------------------------------ */

const CFG = {
  hostname: "DEMO-HOST",
  publicIp: "203.0.113.44",
  localIp: "192.168.1.27",
  gateway: "192.168.1.1",
  gwInterface: "Ethernet",
  dnsServers: ["1.1.1.1", "8.8.8.8"],
};

type Remote = { ip: string; port: number; host?: string; proto?: string; lan?: boolean };
type ProcProfile = { pid: number; name: string; path: string; remotes: Remote[] };

const PROCS: ProcProfile[] = [
  {
    pid: 1472,
    name: "chrome.exe",
    path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    remotes: [
      { ip: "142.250.72.14", port: 443, host: "www.google.com", proto: "TCP" },
      { ip: "151.101.2.137", port: 443, host: "stackoverflow.com", proto: "TCP" },
      { ip: "104.244.42.129", port: 443, host: "x.com", proto: "TCP" },
    ],
  },
  {
    pid: 1896,
    name: "msedge.exe",
    path: "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    remotes: [
      { ip: "13.107.4.50", port: 443, host: "windowsupdate.com", proto: "TCP" },
      { ip: "131.253.33.200", port: 443, host: "login.live.com", proto: "TCP" },
    ],
  },
  {
    pid: 512,
    name: "svchost.exe",
    path: "C:\\Windows\\System32\\svchost.exe",
    remotes: [
      { ip: "192.168.1.12", port: 445, host: "FILE-SRV-01", proto: "TCP", lan: true },
      { ip: "1.1.1.1", port: 53, host: "one.one.one.one", proto: "UDP" },
      { ip: "239.255.255.250", port: 1900, host: "", proto: "UDP" },
    ],
  },
  {
    pid: 2844,
    name: "OneDrive.exe",
    path: "C:\\Users\\demo\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
    remotes: [{ ip: "13.107.136.9", port: 443, host: "onedrive.live.com", proto: "TCP" }],
  },
  {
    pid: 2216,
    name: "Code.exe",
    path: "C:\\Users\\demo\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
    remotes: [
      { ip: "140.82.112.4", port: 443, host: "github.com", proto: "TCP" },
      { ip: "140.82.121.5", port: 443, host: "api.github.com", proto: "TCP" },
    ],
  },
  {
    pid: 3012,
    name: "spotify.exe",
    path: "C:\\Users\\demo\\AppData\\Roaming\\Spotify\\Spotify.exe",
    remotes: [{ ip: "35.186.224.25", port: 443, host: "gew1-spclient.spotify.com", proto: "TCP" }],
  },
  {
    pid: 904,
    name: "powershell.exe",
    path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    remotes: [{ ip: "8.8.8.8", port: 53, host: "dns.google", proto: "UDP" }],
  },
];

type SimConn = {
  id: string;
  pid: number;
  processName: string;
  processPath: string;
  localAddr: string;
  localPort: number;
  remoteAddr: string;
  remotePort: number;
  remoteHost: string;
  proto: string;
  state: string;
  lan: boolean;
  firstSeen: number;
  lastSeen: number;
};

const TRANSIENT_STATES = ["SYN_SENT", "ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT"];

function hf(s: string): number {
  let x = 2166136261;
  for (let i = 0; i < s.length; i++) {
    x ^= s.charCodeAt(i);
    x = Math.imul(x, 16777619);
  }
  return (x >>> 0) / 4294967295;
}

function ts(host: string, port: number): string {
  return `${host}:${port}`;
}

function buildConnection(proc: ProcProfile, remote: Remote, index: number, tick: number): SimConn {
  const localPort = 40000 + ((proc.pid * 137) % 9000) + index * 2;
  const state =
    remote.proto === "UDP" ? "ESTABLISHED"
      : remote.lan ? "ESTABLISHED"
      : hf(`init-${proc.pid}-${remote.ip}-${remote.port}#${tick}`) < 0.18
        ? TRANSIENT_STATES[Math.floor(hf(`trans-${proc.pid}-${remote.ip}-${remote.port}#${tick}`) * TRANSIENT_STATES.length)]
        : "ESTABLISHED";
  return {
    id: `conn-${proc.pid}-${remote.proto}-${ts(remote.ip, remote.port)}-${localPort}`,
    pid: proc.pid,
    processName: proc.name,
    processPath: proc.path,
    localAddr: CFG.localIp,
    localPort,
    remoteAddr: remote.ip,
    remotePort: remote.port,
    remoteHost: remote.host || "",
    proto: remote.proto || "TCP",
    state,
    lan: !!remote.lan,
    firstSeen: Date.now(),
    lastSeen: Date.now(),
  };
}

function buildNetwork(conns: SimConn[], tick: number, novel: SimConn | null): NetworkTopologyData {
  const now = new Date().toISOString();
  const established = conns.filter((c) => c.state === "ESTABLISHED").length;

  const wobble = 0.75 + hf(`wobble-${tick}`) * 0.5;
  const downloadRate = Math.round(established * (18000 * wobble) + 12000 * hf(`d-${tick}`) + 9000);
  const uploadRate = Math.round(downloadRate * (0.15 + hf(`u-${tick}`) * 0.3) + 4000);

  const interfaces: TopologyInterface[] = [
    {
      name: "Ethernet",
      friendly_name: "Intel(R) Ethernet Connection",
      interface_type: "Ethernet",
      is_up: true,
      is_running: true,
      mtu: 1500,
      speed: 1000,
      mac_address: "0C:54:A5:3B:22:9F",
      addresses: [CFG.localIp, "fe80::7c54:a5ff:fe3b:229f"],
      bytes_sent: Math.round(uploadRate * tick * 1.2),
      bytes_recv: Math.round(downloadRate * tick * 1.2),
    },
    {
      name: "Wi-Fi",
      friendly_name: "Intel(R) Wi-Fi 6 AX201",
      interface_type: "Wireless80211",
      is_up: false,
      is_running: true,
      mtu: 1500,
      speed: 866,
      mac_address: "A4:77:33:8F:0B:61",
      addresses: [],
      bytes_sent: 0,
      bytes_recv: 0,
    },
    {
      name: "Loopback Pseudo-Interface 1",
      friendly_name: "Loopback",
      interface_type: "Software Loopback",
      is_up: true,
      is_running: true,
      mtu: 65536,
      speed: 0,
      mac_address: "",
      addresses: ["127.0.0.1", "::1"],
      bytes_sent: 0,
      bytes_recv: 0,
    },
  ];

  const traffic_rates: TopologyTrafficRate[] = [
    { interface: "Ethernet", bytes_sent: interfaces[0].bytes_sent, bytes_recv: interfaces[0].bytes_recv, bytes_sent_rate: uploadRate, bytes_recv_rate: downloadRate },
    { interface: "Wi-Fi", bytes_sent: 0, bytes_recv: 0, bytes_sent_rate: 0, bytes_recv_rate: 0 },
    { interface: "Loopback Pseudo-Interface 1", bytes_sent: 0, bytes_recv: 0, bytes_sent_rate: 0, bytes_recv_rate: 0 },
  ];

  const neighbors: TopologyNeighbor[] = [
    { ip: CFG.gateway, mac: "AA:BB:CC:DD:EE:01", interface: "Ethernet", state: "REACHABLE", hostname: "router.lan" },
    { ip: "192.168.1.12", mac: "10:7C:61:44:22:33", interface: "Ethernet", state: "REACHABLE", hostname: "FILE-SRV-01" },
  ];

  const udpCount = conns.filter((c) => c.proto === "UDP").length;
  return {
    timestamp: now,
    hostname: CFG.hostname,
    interfaces,
    default_gateway: { next_hop: CFG.gateway, interface: "Ethernet", metric: 25 },
    dns_servers: [{ interface: "Ethernet", servers: CFG.dnsServers }],
    connections: conns.map((c) => toTopologyConnection(c)),
    traffic_rates,
    neighbors,
    connection_events: [],
    public_ip: CFG.publicIp,
    udp_endpoints: udpCount,
    tcp_listening: 5,
    total_connections: conns.length,
    established_count: established,
    listen_count: 5,
    tcp_count: conns.filter((c) => c.proto === "TCP").length,
    unique_remote_ips: new Set(conns.map((c) => c.remoteAddr).filter((a) => a !== "239.255.255.250")).size + (novel ? 1 : 0),
    unique_processes: new Set(conns.map((c) => c.pid)).size,
  };
}

function toTopologyConnection(c: SimConn): TopologyConnection {
  return {
    connection_id: c.id,
    id: c.id,
    pid: c.pid,
    process_name: c.processName,
    process_path: c.processPath,
    executable_path: c.processPath,
    local_addr: c.localAddr,
    local_port: c.localPort,
    remote_addr: c.remoteAddr,
    remote_port: c.remotePort,
    remote_hostname: c.remoteHost,
    protocol: c.proto,
    address_family: c.remoteAddr.includes(":") ? "IPv6" : "IPv4",
    state: c.state,
    status: c.state === "ESTABLISHED" ? "active" : "idle",
    local_role: "CLIENT",
    remote_role: "SERVER",
    first_seen: new Date(c.firstSeen).toISOString(),
    last_seen: new Date(c.lastSeen).toISOString(),
  };
}

function makeNovel(tick: number): SimConn {
  return {
    id: `conn-novel-${tick}`,
    pid: 904,
    processName: "powershell.exe",
    processPath: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    localAddr: CFG.localIp,
    localPort: 51000 + (tick % 900),
    remoteAddr: "45.134.26.12",
    remotePort: 8080,
    remoteHost: "",
    proto: "TCP",
    state: "ESTABLISHED",
    lan: false,
    firstSeen: Date.now(),
    lastSeen: Date.now(),
  };
}

function buildEvents(prev: Map<string, SimConn>, next: Map<string, SimConn>, now: string): TopologyConnectionEvent[] {
  const events: TopologyConnectionEvent[] = [];
  for (const [id, nc] of next) {
    const pc = prev.get(id);
    if (!pc) {
      events.push({
        event_type: "NEW",
        timestamp: now,
        connection_id: id,
        process_name: nc.processName,
        pid: nc.pid,
        protocol: nc.proto,
        address_family: nc.remoteAddr.includes(":") ? "IPv6" : "IPv4",
        local_addr: nc.localAddr,
        local_port: nc.localPort,
        remote_addr: nc.remoteAddr,
        remote_port: nc.remotePort,
        state: nc.state,
      });
    } else if (nc.state !== pc.state) {
      events.push({
        event_type: "STATE_CHANGE",
        timestamp: now,
        connection_id: id,
        process_name: nc.processName,
        pid: nc.pid,
        protocol: nc.proto,
        address_family: nc.remoteAddr.includes(":") ? "IPv6" : "IPv4",
        local_addr: nc.localAddr,
        local_port: nc.localPort,
        remote_addr: nc.remoteAddr,
        remote_port: nc.remotePort,
        state: nc.state,
        previous_state: pc.state,
      });
    }
  }
  for (const [id, pc] of prev) {
    if (!next.has(id)) {
      events.push({
        event_type: "CLOSED",
        timestamp: now,
        connection_id: id,
        process_name: pc.processName,
        pid: pc.pid,
        protocol: pc.proto,
        address_family: pc.remoteAddr.includes(":") ? "IPv6" : "IPv4",
        local_addr: pc.localAddr,
        local_port: pc.localPort,
        remote_addr: pc.remoteAddr,
        remote_port: pc.remotePort,
        state: "CLOSED",
        previous_state: pc.state,
      });
    }
  }
  return events;
}

/* ------------------------------------------------------------------ */
/* Static / dynamic port profile                                       */
/* ------------------------------------------------------------------ */

const STATIC_TCP: Array<Pick<PortInfo, "protocol" | "local_addr" | "local_port" | "state" | "pid" | "process_name" | "executable_path">> = [
  { protocol: "TCP", local_addr: "0.0.0.0", local_port: 135, state: "LISTEN", pid: 700, process_name: "svchost.exe", executable_path: "C:\\Windows\\System32\\svchost.exe" },
  { protocol: "TCP", local_addr: "0.0.0.0", local_port: 445, state: "LISTEN", pid: 700, process_name: "svchost.exe", executable_path: "C:\\Windows\\System32\\svchost.exe" },
  { protocol: "TCP", local_addr: "0.0.0.0", local_port: 5040, state: "LISTEN", pid: 700, process_name: "svchost.exe", executable_path: "C:\\Windows\\System32\\svchost.exe" },
  { protocol: "TCP", local_addr: "127.0.0.1", local_port: 9229, state: "LISTEN", pid: 2216, process_name: "Code.exe", executable_path: "C:\\Users\\demo\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe" },
  { protocol: "TCP", local_addr: "127.0.0.1", local_port: 5432, state: "LISTEN", pid: 1520, process_name: "postgres.exe", executable_path: "C:\\Program Files\\PostgreSQL\\16\\bin\\postgres.exe" },
];

const STATIC_UDP: Array<Pick<PortInfo, "protocol" | "local_addr" | "local_port" | "state" | "pid" | "process_name" | "executable_path">> = [
  { protocol: "UDP", local_addr: "0.0.0.0", local_port: 137, state: "BOUND", pid: 700, process_name: "svchost.exe", executable_path: "C:\\Windows\\System32\\svchost.exe" },
  { protocol: "UDP", local_addr: "0.0.0.0", local_port: 5353, state: "BOUND", pid: 700, process_name: "svchost.exe", executable_path: "C:\\Windows\\System32\\svchost.exe" },
  { protocol: "UDP", local_addr: "0.0.0.0", local_port: 1900, state: "BOUND", pid: 700, process_name: "svchost.exe", executable_path: "C:\\Windows\\System32\\svchost.exe" },
  { protocol: "UDP", local_addr: "0.0.0.0", local_port: 5355, state: "BOUND", pid: 700, process_name: "svchost.exe", executable_path: "C:\\Windows\\System32\\svchost.exe" },
];

function toPortInfo(p: Pick<PortInfo, "protocol" | "local_addr" | "local_port" | "state" | "pid" | "process_name" | "executable_path">): PortInfo {
  const localAddr = p.local_addr ?? "0.0.0.0";
  return {
    port_id: `p-${p.protocol}-${localAddr}:${p.local_port}-${p.pid ?? 0}`,
    protocol: p.protocol,
    address_family: localAddr.includes(":") ? "IPv6" : "IPv4",
    local_addr: localAddr,
    local_port: p.local_port,
    state: p.state,
    pid: p.pid,
    process_name: p.process_name,
    executable_path: p.executable_path,
    binding_type: localAddr === "0.0.0.0" ? "wildcard" : "specific",
    local_role: "LISTEN",
  };
}

const TICK_MS = 1400;
const MAX_EVENTS = 500;
const WARMUP_TICKS = 5;

export function useSimulatedNetwork(active: boolean): SimulatedNetworkState {
  const [data, setData] = useState<NetworkTopologyData | null>(null);
  const [events, setEvents] = useState<TopologyConnectionEvent[]>([]);
  const [ports, setPorts] = useState<PortIntelligenceData | null>(null);
  const [portEvents, setPortEvents] = useState<PortEvent[]>([]);
  const tickRef = useRef(0);
  const connRef = useRef<Map<string, SimConn>>(new Map());
  const novelRef = useRef<{ conn: SimConn; held: number } | null>(null);
  const extraPortRef = useRef<{ info: Pick<PortInfo, "protocol" | "local_addr" | "local_port" | "state" | "pid" | "process_name" | "executable_path">; held: number } | null>(null);
  const openRef = useRef(false);

  useEffect(() => {
    if (!active) return;
    openRef.current = true;
    tickRef.current = 0;

    const tick = () => {
      if (!openRef.current) return;
      const n = ++tickRef.current;
      const now = new Date().toISOString();

      // ---- connections state ----------------------------------------
      const conns: SimConn[] = [];
      const spawn = n >= WARMUP_TICKS ? 1 : Math.min(1, (n / WARMUP_TICKS) * 1.25);
      PROCS.forEach((proc) => {
        proc.remotes.forEach((remote, ri) => {
          const key = `seed-${proc.pid}-${remote.ip}-${remote.port}`;
          if (hf(key) >= spawn) return;
          conns.push(buildConnection(proc, remote, ri, n));
        });
      });

      // state churn after warmup
      if (n > WARMUP_TICKS + 2) {
        for (const c of conns) {
          if (c.proto !== "TCP" || c.lan) continue;
          const roll = hf(`churn-${c.id}#${n}`);
          if (roll < 0.07) c.state = "TIME_WAIT";
          else if (roll < 0.1) c.state = "CLOSE_WAIT";
          else if (roll < 0.13 && n % 6 !== 0) c.state = "SYN_SENT";
          else c.state = "ESTABLISHED";
        }
      }

      // novel "first-seen" remote that appears then closes (drives drama)
      if (!novelRef.current && n >= 9 && hf(`novel-${n}`) < 0.5) {
        novelRef.current = { conn: makeNovel(n), held: 3 + Math.floor(hf(`hold-${n}`) * 4) };
      } else if (novelRef.current) {
        novelRef.current.held -= 1;
        if (novelRef.current.held <= 0) novelRef.current = null;
      }
      if (novelRef.current) conns.push(novelRef.current.conn);

      const nextMap = new Map(conns.map((c) => [c.id, c]));

      // ---- connection events ----------------------------------------
      const evs = buildEvents(connRef.current, nextMap, now);
      connRef.current = nextMap;
      if (evs.length) {
        setEvents((prev) => [...prev, ...evs].slice(-MAX_EVENTS));
      }

      // ---- topology snapshot ----------------------------------------
      setData(buildNetwork(conns, n, novelRef.current?.conn ?? null));

      // ---- ports -----------------------------------------------------
      let opened: PortInfo | null = null;
      let closed: PortInfo | null = null;

      if (!extraPortRef.current) {
        if (n >= 6 && hf(`extra-${n}`) < 0.35) {
          extraPortRef.current = {
            info: {
              protocol: "TCP",
              local_addr: "127.0.0.1",
              local_port: n % 3 === 0 ? 9090 : 1630,
              state: "LISTEN",
              pid: n % 3 === 0 ? 918 : 904,
              process_name: n % 3 === 0 ? "metricbeat.exe" : "powershell.exe",
              executable_path: n % 3 === 0 ? "C:\\Program Files\\Elastic\\Agent\\data\\metricbeat.exe" : "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            },
            held: 4,
          };
          opened = toPortInfo(extraPortRef.current.info);
        }
      } else {
        extraPortRef.current.held -= 1;
        if (extraPortRef.current.held <= 0) {
          closed = toPortInfo(extraPortRef.current.info);
          extraPortRef.current = null;
        }
      }

      const tcpListening = [...STATIC_TCP.map(toPortInfo), ...(extraPortRef.current ? [toPortInfo(extraPortRef.current.info)] : [])];
      const udpEndpoints = STATIC_UDP.map(toPortInfo);

      const pevs: PortEvent[] = [];
      if (opened) {
        pevs.push({
          event_type: "PORT_OPENED",
          timestamp: now,
          port_id: opened.port_id,
          protocol: opened.protocol,
          address_family: opened.address_family,
          local_addr: opened.local_addr,
          local_port: opened.local_port,
          state: "LISTEN",
          pid: opened.pid,
          process_name: opened.process_name,
          executable_path: opened.executable_path,
        });
      }
      if (closed) {
        pevs.push({
          event_type: "PORT_CLOSED",
          timestamp: now,
          port_id: closed.port_id,
          protocol: closed.protocol,
          address_family: closed.address_family,
          local_addr: closed.local_addr,
          local_port: closed.local_port,
          state: "CLOSED",
          pid: closed.pid,
          process_name: closed.process_name,
          executable_path: closed.executable_path,
          previous_state: "LISTEN",
        });
      }
      if (pevs.length) {
        setPortEvents((prev) => [...prev, ...pevs].slice(-300));
      }

      setPorts({
        timestamp: now,
        tcp_listening: tcpListening,
        udp_endpoints: udpEndpoints,
        port_events: pevs,
        summary: {
          tcp_listening_count: tcpListening.length,
          udp_endpoint_count: udpEndpoints.length,
          ipv4_listening_count: tcpListening.filter((p) => !p.local_addr?.includes(":")).length,
          ipv6_listening_count: tcpListening.filter((p) => p.local_addr?.includes(":")).length,
          loopback_count: tcpListening.filter((p) => p.local_addr === "127.0.0.1").length,
          wildcard_count: tcpListening.filter((p) => p.local_addr === "0.0.0.0").length,
          active_tcp_connections: conns.filter((c) => c.proto === "TCP" && c.state === "ESTABLISHED").length,
          unique_processes: new Set(tcpListening.map((p) => p.pid)).size,
        },
        active_tcp_connections: conns.filter((c) => c.proto === "TCP" && c.state === "ESTABLISHED").length,
      });
    };

    const timer = window.setInterval(tick, TICK_MS);
    return () => {
      openRef.current = false;
      window.clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active]);

  return { active, data, events, ports, portEvents };
}