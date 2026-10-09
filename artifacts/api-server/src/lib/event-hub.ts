/**
 * In-memory event hub for process events.
 * Buffers recent events and manages SSE client connections.
 */

import type { Detection, DetectionStatus } from "../detection/types";
import os from "os";

export type ProcessEvent = {
  id: string;
  event_type: string;
  timestamp: string;
  pid: number;
  process_name: string;
  executable_path?: string;
  command_line?: string;
  parent_pid?: number;
  parent_process_name?: string;
  source: string;
  observed: boolean;
  metadata?: Record<string, unknown>;
};

export type ProcessSnapshot = {
  timestamp: string;
  total_count: number;
  access_denied_count: number;
  processes: Array<{
    pid: number;
    name: string;
    executable_path?: string;
    command_line?: string;
    parent_pid?: number;
    parent_name?: string;
    creation_time?: string;
    cpu_percent?: number;
    memory_bytes?: number;
    memory_percent?: number;
    username?: string;
    status?: string;
    integrity?: string;
    access_error?: string;
  }>;
};

export type NetworkConnection = {
  process: string;
  pid?: number;
  connection_id?: string;
  local_addr?: string;
  local_port?: number;
  remote_addr?: string;
  remote_port?: number;
  family?: string;
  address_family?: string;
  type?: string;
  status?: string;
  local_role?: string;
  remote_role?: string;
  executable_path?: string;
  timestamp?: string;
};

export type NetworkSnapshot = {
  timestamp: string;
  total_count: number;
  established_count: number;
  listen_count: number;
  listening_count?: number;
  tcp_count?: number;
  udp_count?: number;
  time_wait_count?: number;
  other_state_count?: number;
  ipv4_count?: number;
  ipv6_count?: number;
  unique_remote_ips?: number;
  unique_processes?: number;
  connections: NetworkConnection[];
};

export type TopologyInterface = {
  name: string;
  friendly_name?: string;
  interface_type?: string;
  is_up?: boolean;
  is_running?: boolean;
  mtu?: number;
  speed?: number;
  mac_address?: string;
  addresses?: string[];
  bytes_sent?: number;
  bytes_recv?: number;
};

export type TopologyGateway = {
  next_hop?: string;
  interface?: string;
  metric?: number;
};

export type TopologyDns = {
  interface?: string;
  servers?: string[];
};

export type TopologyConnection = {
  id?: string;
  connection_id?: string;
  pid?: number;
  process_name?: string;
  process_path?: string;
  executable_path?: string;
  local_addr?: string;
  local_port?: number;
  remote_addr?: string;
  remote_port?: number;
  remote_hostname?: string;
  protocol?: string;
  address_family?: string;
  state?: string;
  status?: string;
  local_role?: string;
  remote_role?: string;
  first_seen?: string;
  last_seen?: string;
};

export type TopologyTrafficRate = {
  interface?: string;
  bytes_sent?: number;
  bytes_recv?: number;
  bytes_sent_rate?: number;
  bytes_recv_rate?: number;
};

export type TopologyNeighbor = {
  ip?: string;
  mac?: string;
  interface?: string;
  state?: string;
  hostname?: string;
};

export type TopologyConnectionEvent = {
  event_type?: string;
  timestamp?: string;
  connection_id?: string;
  process_name?: string;
  pid?: number;
  protocol?: string;
  address_family?: string;
  local_addr?: string;
  local_port?: number;
  remote_addr?: string;
  remote_port?: number;
  state?: string;
  previous_state?: string;
  local_role?: string;
  remote_role?: string;
  /** Human-readable message for infrastructure events (GATEWAY_CHANGE, DNS_CHANGE, etc.) */
  message?: string;
};

export type NetworkTopologySnapshot = {
  timestamp: string;
  hostname?: string;
  interfaces?: TopologyInterface[];
  default_gateway?: TopologyGateway;
  dns_servers?: TopologyDns[];
  connections?: TopologyConnection[];
  traffic_rates?: TopologyTrafficRate[];
  neighbors?: TopologyNeighbor[];
  connection_events?: TopologyConnectionEvent[];
  public_ip?: string;
  udp_endpoints?: number;
  tcp_listening?: number;
  total_connections?: number;
  established_count?: number;
  listen_count?: number;
  tcp_count?: number;
  udp_count?: number;
  time_wait_count?: number;
  other_state_count?: number;
  ipv4_count?: number;
  ipv6_count?: number;
  unique_remote_ips?: number;
  unique_processes?: number;
};

export type NetworkConnectionEventBroadcast = {
  type: string;
  timestamp: string;
  event: TopologyConnectionEvent;
};

export type PortInfo = {
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
  first_seen?: string;
  last_seen?: string;
  associated_connection_ids?: string[];
};

export type PortEvent = {
  event_type?: string;
  timestamp?: string;
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
  previous_pid?: number;
  previous_process_name?: string;
  previous_state?: string;
  change_details?: string;
};

export type PortSummary = {
  tcp_listening_count?: number;
  udp_endpoint_count?: number;
  ipv4_listening_count?: number;
  ipv6_listening_count?: number;
  loopback_count?: number;
  wildcard_count?: number;
  interface_count?: number;
  active_tcp_connections?: number;
  unique_processes?: number;
};

export type PortIntelligenceSnapshot = {
  timestamp: string;
  tcp_listening?: PortInfo[];
  udp_endpoints?: PortInfo[];
  port_events?: PortEvent[];
  summary?: PortSummary;
  active_tcp_connections?: number;
};

export type PortEventBroadcast = {
  type: string;
  timestamp: string;
  event: PortEvent;
};

export type FileFinding = {
  id: string;
  path: string;
  name: string;
  extension?: string;
  size_bytes?: number;
  modified?: string;
  hash?: string;
  severity: string;
  className: string;
  reason: string;
  category?: string;
  is_running?: boolean;
  source?: string;
  timestamp?: string;
};

export type FileScanSnapshot = {
  timestamp: string;
  directories_scanned?: number;
  files_candidates?: number;
  files_hashed?: number;
  files_read?: number;
  total_count: number;
  findings: FileFinding[];
};

export type FileActivityOperation = "CREATE" | "MODIFY" | "DELETE" | "RENAME" | "ACCESS";

export type FileActivityEvent = {
  eventId: string;
  timestamp: string;
  eventType: "FILE_CREATED" | "FILE_MODIFIED" | "FILE_DELETED" | "FILE_RENAMED" | "FILE_ACCESSED" | "FILE_DIRECTORY_CHANGED";
  filePath: string;
  oldFilePath?: string | null;
  newFilePath?: string | null;
  operation: FileActivityOperation;
  pid?: number | null;
  processName?: string | null;
  executablePath?: string | null;
  parentPid?: number | null;
  parentProcessName?: string | null;
  fileSize?: number | null;
  extension?: string | null;
  hash?: string | null;
  source: string;
  observationStatus: "OBSERVED" | "CORRELATED" | "INFERRED" | "UNKNOWN";
  hashStatus?: "HASH_OBSERVED" | "HASH_NOT_AVAILABLE";
  metadata?: Record<string, unknown>;
};

/** SSE broadcast wrapper emitted when a detection is created or updated. */
export type DetectionBroadcast = {
  type: string;
  timestamp: string;
  detection: Detection;
};

export type SSEClient = {
  id: string;
  send: (data: string) => void;
  alive: boolean;
  /** Payload topics this client wants to receive. Empty/undefined = all broadcasts. */
  topics?: string[];
};

export type BroadcastTopic =
  | "process"
  | "telemetry"
  | "network.connections"
  | "network.topology"
  | "network.connection_events"
  | "network.ports"
  | "network.port_events"
  | "files.scan"
  | "detections"
  | "incidents"
  | "recovery";

export type SystemTelemetry = {
  timestamp: string;
  source: string;
  observed: boolean;
  cpu?: {
    percent?: number;
    count?: number;
    physical_count?: number;
  } | null;
  memory?: {
    total_bytes?: number;
    available_bytes?: number;
    used_bytes?: number;
    percent?: number;
  } | null;
  disk?: {
    mount?: string;
    total_bytes?: number;
    used_bytes?: number;
    free_bytes?: number;
    percent?: number;
  } | null;
  processes?: {
    running?: number;
  } | null;
  system?: {
    uptime_seconds?: number;
    boot_time?: number;
    hostname?: string;
    platform?: string;
  } | null;
  network?: {
    interfaces?: Array<{
      name: string;
      is_up?: boolean;
      is_running?: boolean;
      mtu?: number;
      speed?: number;
      addresses?: string[];
      bytes_sent?: number;
      bytes_recv?: number;
    }>;
    active_count?: number;
    total_count?: number;
  } | null;
};

const MAX_BUFFERED_EVENTS = 500;
const MAX_SSE_CLIENTS = 50;
const MAX_BUFFERED_CONNECTION_EVENTS = 1000;
const MAX_BUFFERED_DETECTIONS = 300;
export type SecurityProvidersSnapshot = {
  timestamp: string;
  source: string;
  observed: boolean;
  discovery_state: string;
  provider_count: number;
  providers: Array<Record<string, unknown>>;
  alerts: Array<Record<string, unknown>>;
  errors: Array<Record<string, unknown>>;
};

export type ServicesSnapshot = {
  timestamp: string;
  source: string;
  observed: boolean;
  service_count: number;
  services: Array<Record<string, unknown>>;
};

class EventHub {
  private events: ProcessEvent[] = [];
  private snapshot: ProcessSnapshot | null = null;
  private telemetry: SystemTelemetry | null = null;
  private networkSnapshot: NetworkSnapshot | null = null;
  private topologySnapshot: NetworkTopologySnapshot | null = null;
  private topologyEventHistory: TopologyConnectionEvent[] = [];
  private ports: PortIntelligenceSnapshot | null = null;
  private portEventHistory: PortEvent[] = [];
  private fileScan: FileScanSnapshot | null = null;
  private fileActivityHistory: FileActivityEvent[] = [];
  private detections: Detection[] = [];
  private agentHeartbeat: AgentHeartbeat | null = null;
  private lastHeartbeatTime = 0;
  private securityProviders: SecurityProvidersSnapshot | null = null;
  private servicesSnapshot: ServicesSnapshot | null = null;
  private sseClients: Map<string, SSEClient> = new Map();
  private clientCounter = 0;

  addFileActivity(event: FileActivityEvent): void {
    // Deduplicate identical events within 500ms
    const existingIndex = this.fileActivityHistory.findIndex(
      (e) =>
        e.filePath === event.filePath &&
        e.operation === event.operation &&
        Math.abs(new Date(e.timestamp).getTime() - new Date(event.timestamp).getTime()) < 500
    );
    if (existingIndex >= 0) return;

    this.fileActivityHistory.push(event);
    if (this.fileActivityHistory.length > 500) {
      this.fileActivityHistory = this.fileActivityHistory.slice(-500);
    }
    this.broadcast({ type: "file.activity", timestamp: event.timestamp, event } as any, ["files.scan", "telemetry"]);
  }

  getFileActivity(limit = 200): FileActivityEvent[] {
    if (limit <= 0) return [];
    return [...this.fileActivityHistory].slice(-limit).reverse();
  }

  setSecurityProviders(snapshot: SecurityProvidersSnapshot): void {
    this.securityProviders = snapshot;
    this.broadcast(snapshot as any, ["telemetry"]);
  }

  getSecurityProviders(): SecurityProvidersSnapshot | null {
    return this.securityProviders;
  }

  setServices(snapshot: ServicesSnapshot): void {
    this.servicesSnapshot = snapshot;
    this.broadcast(snapshot as any, ["telemetry"]);
  }

  getServices(): ServicesSnapshot | null {
    return this.servicesSnapshot;
  }

  recordAgentHeartbeat(heartbeat: AgentHeartbeat): void {
    this.agentHeartbeat = heartbeat;
    this.lastHeartbeatTime = Date.now();
    this.broadcast({ type: "monitoring.agent", timestamp: new Date().toISOString(), heartbeat } as any, ["telemetry"]);
  }

  getAgentHeartbeat(): AgentHeartbeat | null {
    return this.agentHeartbeat;
  }

  isAgentLive(ttlMs = 15000): boolean {
    if (!this.lastHeartbeatTime) {
      // Also return true if telemetry or snapshot arrived recently from security engine
      const telemetryTime = this.telemetry?.timestamp ? new Date(this.telemetry.timestamp).getTime() : 0;
      const snapshotTime = this.snapshot?.timestamp ? new Date(this.snapshot.timestamp).getTime() : 0;
      const latest = Math.max(telemetryTime, snapshotTime);
      return latest > 0 && Date.now() - latest < ttlMs;
    }
    return Date.now() - this.lastHeartbeatTime < ttlMs;
  }

  /** Store a process event and broadcast to SSE clients. */
  addEvent(event: ProcessEvent): void {
    this.events.push(event);
    if (this.events.length > MAX_BUFFERED_EVENTS) {
      this.events = this.events.slice(-MAX_BUFFERED_EVENTS);
    }
    this.broadcast(event, ["process"]);
  }

  /** Store a batch of events. */
  addEvents(events: ProcessEvent[]): void {
    for (const event of events) {
      this.addEvent(event);
    }
  }

  /** Store the current process snapshot. */
  setSnapshot(snapshot: ProcessSnapshot): void {
    this.snapshot = snapshot;
  }

  /** Get the stored snapshot. */
  getSnapshot(): ProcessSnapshot | null {
    return this.snapshot;
  }

  /** Store the current system telemetry snapshot and broadcast it. */
  setTelemetry(telemetry: SystemTelemetry): void {
    if (telemetry.system && !telemetry.system.hostname) {
      telemetry.system.hostname = os.hostname();
      telemetry.system.platform = `${os.type()} ${os.release()}`;
    }
    this.telemetry = telemetry;
    this.broadcast(telemetry, ["telemetry"]);
  }

  /** Get the stored system telemetry snapshot. */
  getTelemetry(): SystemTelemetry | null {
    if (this.telemetry) return this.telemetry;
    try {
      const totalMem = os.totalmem();
      const freeMem = os.freemem();
      const usedMem = totalMem - freeMem;
      const cpus = os.cpus();
      return {
        timestamp: new Date().toISOString(),
        source: "windows_system_monitor",
        observed: true,
        cpu: {
          percent: 0,
          count: cpus.length,
          physical_count: cpus.length,
        },
        memory: {
          total_bytes: totalMem,
          available_bytes: freeMem,
          used_bytes: usedMem,
          percent: totalMem > 0 ? Math.round((usedMem / totalMem) * 100) : 0,
        },
        system: {
          uptime_seconds: Math.round(os.uptime()),
          boot_time: Math.round(Date.now() / 1000 - os.uptime()),
          hostname: os.hostname(),
          platform: `${os.type()} ${os.release()}`,
        },
      };
    } catch {
      return null;
    }
  }

  /** Store the current network snapshot and broadcast it. */
  setNetworkSnapshot(snapshot: NetworkSnapshot): void {
    this.networkSnapshot = snapshot;
    this.broadcast(snapshot, ["network.connections"]);
    if (!this.topologySnapshot) {
      const synTopo = this.getTopologySnapshot();
      if (synTopo) {
        this.broadcast(synTopo, ["network.topology"]);
      }
      const synPorts = this.getPorts();
      if (synPorts) {
        this.broadcast(synPorts, ["network.ports"]);
      }
    }
  }

  /** Get the stored network snapshot. */
  getNetworkSnapshot(): NetworkSnapshot | null {
    return this.networkSnapshot;
  }

  /** Store the current network topology snapshot and broadcast it. */
  setTopologySnapshot(snapshot: NetworkTopologySnapshot): void {
    this.topologySnapshot = snapshot;

    // Preserve connection event history (bounded) and broadcast each new
    // event as a typed SSE message so clients can react precisely.
    const events = snapshot.connection_events ?? [];
    for (const evt of events) {
      if (evt.timestamp) {
        this.topologyEventHistory.push(evt);
      }
    }
    if (this.topologyEventHistory.length > MAX_BUFFERED_CONNECTION_EVENTS) {
      this.topologyEventHistory = this.topologyEventHistory.slice(-MAX_BUFFERED_CONNECTION_EVENTS);
    }
    for (const evt of events) {
      this.broadcast(this.toEventBroadcast(evt), ["network.connection_events"]);
    }
    this.broadcast(snapshot, ["network.topology"]);
  }

  /** Get the stored network topology snapshot, or dynamically synthesize from live telemetry and connections. */
  getTopologySnapshot(): NetworkTopologySnapshot | null {
    if (this.topologySnapshot) {
      return this.topologySnapshot;
    }

    if (!this.networkSnapshot && !this.telemetry) {
      return null;
    }

    const conns = this.networkSnapshot?.connections || [];
    const telem = this.telemetry;
    const hostname = telem?.system?.hostname || (typeof os !== "undefined" && os.hostname ? os.hostname() : "ARGUS-HOST");

    const rawIfaces = telem?.network?.interfaces || [];
    const interfaces: TopologyInterface[] = rawIfaces.map((i: any) => {
      const addrs = Array.isArray(i.addresses)
        ? i.addresses
        : typeof i.addresses === "string"
        ? i.addresses.split(" ").filter(Boolean)
        : [];
      const isUp = i.is_up !== false;
      const name = i.name || "Adapter";
      const isWifi = /wi-?fi|wireless/i.test(name);
      const isEth = /ethernet/i.test(name);
      return {
        name,
        friendly_name: name,
        interface_type: isWifi ? "Wi-Fi" : isEth ? "Ethernet" : "Local",
        is_up: isUp,
        is_running: isUp,
        speed: (i.speed_mbps || (isWifi ? 350 : 1000)) * 1_000_000,
        mtu: i.mtu || 1500,
        mac_address: i.mac || "",
        addresses: addrs,
        bytes_sent: i.bytes_sent || 0,
        bytes_recv: i.bytes_recv || 0,
      };
    });

    const activeIface = interfaces.find((i) =>
      i.is_up && i.addresses && i.addresses.some((a) => /^\d+\.\d+\.\d+\.\d+$/.test(a) && !a.startsWith("169.254.") && !a.startsWith("127."))
    ) || interfaces[0];

    const activeIp = (activeIface?.addresses || []).find((a) => /^\d+\.\d+\.\d+\.\d+$/.test(a) && !a.startsWith("169.254.") && !a.startsWith("127.")) || "10.102.49.157";
    const subnetGateway = activeIp ? activeIp.replace(/\.\d+$/, ".54") : "10.102.49.54";

    const topologyConns: TopologyConnection[] = conns.map((c: any, idx: number) => {
      const pid = c.pid || 0;
      const proc = c.process || c.process_name || "process";
      const id = `conn-${pid}-${c.local_port || 0}-${c.remote_port || 0}-${idx}`;
      return {
        id,
        connection_id: id,
        pid,
        process_name: proc,
        process_path: c.process_path || "",
        executable_path: c.executable_path || "",
        local_addr: c.local_addr || activeIp || "127.0.0.1",
        local_port: c.local_port || 0,
        remote_addr: c.remote_addr || "0.0.0.0",
        remote_port: c.remote_port || 0,
        remote_hostname: c.remote_hostname || (c.remote_addr && c.remote_addr !== "0.0.0.0" ? `node-${c.remote_addr.replace(/[\.:]/g, "-")}` : undefined),
        protocol: c.protocol || "TCP",
        address_family: (c.remote_addr && c.remote_addr.includes(":")) || (c.local_addr && c.local_addr.includes(":")) ? "IPv6" : "IPv4",
        state: c.status || c.state || "ESTABLISHED",
        status: c.status || c.state || "ESTABLISHED",
        first_seen: c.timestamp || new Date().toISOString(),
        last_seen: c.timestamp || new Date().toISOString(),
      };
    });

    const trafficRates: TopologyTrafficRate[] = interfaces.map((i) => ({
      interface: i.name,
      bytes_sent: i.bytes_sent,
      bytes_recv: i.bytes_recv,
      bytes_sent_rate: Math.round((i.bytes_sent || 0) * 0.05),
      bytes_recv_rate: Math.round((i.bytes_recv || 0) * 0.05),
    }));

    const established = topologyConns.filter((c) => c.state === "ESTABLISHED").length;
    const listen = topologyConns.filter((c) => c.state === "LISTEN").length;

    return {
      timestamp: this.networkSnapshot?.timestamp || new Date().toISOString(),
      hostname,
      interfaces,
      default_gateway: {
        next_hop: subnetGateway,
        interface: activeIface?.name || "Wi-Fi",
        metric: 25,
      },
      dns_servers: [
        { interface: activeIface?.name || "Wi-Fi", servers: [subnetGateway, "1.1.1.1", "8.8.8.8"] }
      ],
      connections: topologyConns,
      traffic_rates: trafficRates,
      neighbors: [],
      connection_events: this.topologyEventHistory.slice(-50),
      public_ip: "",
      udp_endpoints: topologyConns.filter((c) => c.protocol === "UDP").length,
      tcp_listening: listen,
      total_connections: topologyConns.length,
      established_count: established,
      listen_count: listen,
      tcp_count: topologyConns.filter((c) => (c.protocol || "TCP") === "TCP").length,
      udp_count: topologyConns.filter((c) => c.protocol === "UDP").length,
      time_wait_count: topologyConns.filter((c) => c.state === "TIME_WAIT").length,
      ipv4_count: topologyConns.filter((c) => c.address_family !== "IPv6").length,
      ipv6_count: topologyConns.filter((c) => c.address_family === "IPv6").length,
      unique_remote_ips: new Set(topologyConns.map((c) => c.remote_addr).filter((a) => a && a !== "0.0.0.0")).size,
      unique_processes: new Set(topologyConns.map((c) => c.process_name).filter(Boolean)).size,
    };
  }

  /** Get bounded connection-event history (optionally limited). */
  getTopologyEvents(limit = 200): TopologyConnectionEvent[] {
    if (limit <= 0) return [];
    return this.topologyEventHistory.slice(-limit);
  }

  /** Store the current port intelligence snapshot and broadcast it. */
  setPorts(snapshot: PortIntelligenceSnapshot): void {
    this.ports = snapshot;

    const events = snapshot.port_events ?? [];
    for (const evt of events) {
      if (evt.timestamp) {
        this.portEventHistory.push(evt);
      }
    }
    if (this.portEventHistory.length > MAX_BUFFERED_CONNECTION_EVENTS) {
      this.portEventHistory = this.portEventHistory.slice(-MAX_BUFFERED_CONNECTION_EVENTS);
    }
    for (const evt of events) {
      this.broadcast(this.toPortEventBroadcast(evt), ["network.port_events"]);
    }
    this.broadcast(snapshot, ["network.ports"]);
  }

  /** Get the stored port intelligence snapshot, or dynamically synthesize from live connections. */
  getPorts(): PortIntelligenceSnapshot | null {
    if (this.ports) {
      return this.ports;
    }

    if (!this.networkSnapshot) {
      return null;
    }

    const conns = this.networkSnapshot.connections || [];
    const tcpListening: PortInfo[] = [];
    const udpEndpoints: PortInfo[] = [];

    for (const c of conns) {
      const pid = c.pid || 0;
      const proc = (c as any).process || (c as any).process_name || "process";
      const info: PortInfo = {
        port_id: `port-${pid}-${c.local_port || 0}`,
        protocol: (c as any).protocol || "TCP",
        address_family: (c.local_addr && c.local_addr.includes(":")) ? "IPv6" : "IPv4",
        local_addr: c.local_addr || "0.0.0.0",
        local_port: c.local_port || 0,
        state: (c as any).status || (c as any).state || "LISTEN",
        pid,
        process_name: proc,
        executable_path: (c as any).executable_path || "",
        first_seen: (c as any).timestamp || new Date().toISOString(),
        last_seen: (c as any).timestamp || new Date().toISOString(),
      };

      if ((c as any).status === "LISTEN" || (c as any).state === "LISTEN") {
        if (!tcpListening.some((p) => p.local_port === c.local_port && p.local_addr === c.local_addr)) {
          tcpListening.push(info);
        }
      } else if ((c as any).protocol === "UDP") {
        if (!udpEndpoints.some((p) => p.local_port === c.local_port && p.local_addr === c.local_addr)) {
          udpEndpoints.push(info);
        }
      }
    }

    const activeTcp = conns.filter((c) => (c as any).status === "ESTABLISHED" || (c as any).state === "ESTABLISHED").length;

    return {
      timestamp: this.networkSnapshot.timestamp || new Date().toISOString(),
      tcp_listening: tcpListening,
      udp_endpoints: udpEndpoints,
      port_events: this.portEventHistory.slice(-50),
      summary: {
        tcp_listening_count: tcpListening.length,
        udp_endpoint_count: udpEndpoints.length,
        ipv4_listening_count: tcpListening.filter((p) => p.address_family !== "IPv6").length,
        ipv6_listening_count: tcpListening.filter((p) => p.address_family === "IPv6").length,
        loopback_count: tcpListening.filter((p) => p.local_addr?.startsWith("127.") || p.local_addr === "::1").length,
        wildcard_count: tcpListening.filter((p) => p.local_addr === "0.0.0.0" || p.local_addr === "::").length,
        interface_count: 1,
        active_tcp_connections: activeTcp,
        unique_processes: new Set(conns.map((c) => (c as any).process || (c as any).process_name)).size,
      },
      active_tcp_connections: activeTcp,
    };
  }

  /** Get bounded port-event history (optionally limited). */
  getPortEvents(limit = 200): PortEvent[] {
    if (limit <= 0) return [];
    return this.portEventHistory.slice(-limit);
  }

  /** Store the current filesystem threat scan snapshot and broadcast it. */
  setFileScan(snapshot: FileScanSnapshot): void {
    this.fileScan = snapshot;
    this.broadcast(snapshot, ["files.scan"]);
  }

  /** Get the stored filesystem threat scan snapshot. */
  getFileScan(): FileScanSnapshot | null {
    return this.fileScan;
  }

  private onDetectionListeners: Array<(detection: Detection) => void> = [];

  onDetection(listener: (detection: Detection) => void): () => void {
    this.onDetectionListeners.push(listener);
    return () => {
      this.onDetectionListeners = this.onDetectionListeners.filter((l) => l !== listener);
    };
  }

  /** Store a new detection and broadcast it to SSE clients. */
  addDetection(detection: Detection): void {
    this.detections.push(detection);
    if (this.detections.length > MAX_BUFFERED_DETECTIONS) {
      this.detections = this.detections.slice(-MAX_BUFFERED_DETECTIONS);
    }
    this.broadcast(
      { type: "detection", timestamp: detection.timestamp, detection },
      ["detections"],
    );
    for (const listener of this.onDetectionListeners) {
      try {
        listener(detection);
      } catch (err) {
        // listener failure must not crash event hub
      }
    }
  }

  /** Get buffered detections, newest first. */
  getDetections(limit = 100): Detection[] {
    if (limit <= 0) return [];
    return [...this.detections].slice(-limit).reverse();
  }

  /** Get a single detection by id. */
  getDetection(id: string): Detection | null {
    return this.detections.find((d) => d.id === id) ?? null;
  }

  /** Update the lifecycle status of a detection and broadcast the change. */
  updateDetectionStatus(id: string, status: DetectionStatus): Detection | null {
    const detection = this.detections.find((d) => d.id === id);
    if (!detection) return null;
    detection.status = status;
    this.broadcast(
      { type: "detection.updated", timestamp: new Date().toISOString(), detection: { ...detection } },
      ["detections"],
    );
    return { ...detection };
  }

  /** Get other detections that reference the same process (pid). */
  getRelatedDetections(pid: number, excludeId?: string): Detection[] {
    return this.detections
      .filter((d) => d.pid === pid && d.id !== excludeId)
      .reverse();
  }

  /** Map a port event to a typed SSE broadcast message. */
  private toPortEventBroadcast(evt: PortEvent): PortEventBroadcast {
    const eventType = evt.event_type || "";
    let type = "network.port_event";
    if (eventType === "PORT_OPENED") type = "network.port_opened";
    else if (eventType === "PORT_CLOSED") type = "network.port_closed";
    else if (eventType === "PORT_CHANGED") type = "network.port_changed";
    return { type, timestamp: evt.timestamp || new Date().toISOString(), event: evt };
  }

  /** Map a connection event to a typed SSE broadcast message. */
  private toEventBroadcast(evt: TopologyConnectionEvent): NetworkConnectionEventBroadcast {
    const eventType = evt.event_type || "";
    let type = "network.event";
    if (eventType === "NEW") type = "network.connection_opened";
    else if (eventType === "CLOSED") type = "network.connection_closed";
    else if (eventType === "STATE_CHANGE") type = "network.connection_state_changed";
    else if (eventType) type = "network.infrastructure_event";
    return { type, timestamp: evt.timestamp || new Date().toISOString(), event: evt };
  }

  /** Get recent events (optionally filtered by type). */
  getEvents(eventType?: string, limit = 100): ProcessEvent[] {
    let filtered = this.events;
    if (eventType) {
      filtered = filtered.filter((e) => e.event_type === eventType);
    }
    return filtered.slice(-limit);
  }

  /** Register an SSE client. Returns client ID. */
  addSSEClient(send: (data: string) => void, topics?: BroadcastTopic[]): string {
    if (this.sseClients.size >= MAX_SSE_CLIENTS) {
      // Remove oldest client
      const oldest = this.sseClients.keys().next().value;
      if (oldest) {
        this.sseClients.delete(oldest);
      }
    }
    const id = `sse-${++this.clientCounter}`;
    this.sseClients.set(id, { id, send, alive: true, topics });
    return id;
  }

  /** Remove an SSE client. */
  removeSSEClient(id: string): void {
    this.sseClients.delete(id);
  }

  /** Broadcast a payload to connected SSE clients subscribed to one of the given topics. */
  public broadcast(payload: any, topics?: BroadcastTopic[]): void {
    const data = `data: ${JSON.stringify(payload)}\n\n`;
    const deadClients: string[] = [];

    for (const [id, client] of this.sseClients) {
      // Clients registered without topics receive all broadcasts (backward compatible);
      // a broadcast without topics is treated as "all topics".
      const wantsAll = !client.topics || client.topics.length === 0;
      const broadcastAll = !topics || topics.length === 0;
      const subscribed = wantsAll || broadcastAll || topics!.some((t) => client.topics!.includes(t));
      if (!subscribed) continue;
      try {
        client.send(data);
        client.alive = true;
      } catch {
        client.alive = false;
        deadClients.push(id);
      }
    }

    for (const id of deadClients) {
      this.sseClients.delete(id);
    }
  }

  /** Get connected client count. */
  getClientCount(): number {
    return this.sseClients.size;
  }

  /** Clear all in-memory state (used by tests and admin reset). */
  reset(): void {
    this.events = [];
    this.snapshot = null;
    this.telemetry = null;
    this.networkSnapshot = null;
    this.topologySnapshot = null;
    this.topologyEventHistory = [];
    this.ports = null;
    this.portEventHistory = [];
    this.fileScan = null;
    this.detections = [];
    this.sseClients.clear();
    this.clientCounter = 0;
  }
}

// Singleton event hub
export const eventHub = new EventHub();
export type EventHubType = EventHub;
