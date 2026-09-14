/**
 * In-memory event hub for process events.
 * Buffers recent events and manages SSE client connections.
 */

import type { Detection, DetectionStatus } from "../detection/types";

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
  | "detections";

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
  private detections: Detection[] = [];
  private sseClients: Map<string, SSEClient> = new Map();
  private clientCounter = 0;

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
    this.telemetry = telemetry;
    this.broadcast(telemetry, ["telemetry"]);
  }

  /** Get the stored system telemetry snapshot. */
  getTelemetry(): SystemTelemetry | null {
    return this.telemetry;
  }

  /** Store the current network snapshot and broadcast it. */
  setNetworkSnapshot(snapshot: NetworkSnapshot): void {
    this.networkSnapshot = snapshot;
    this.broadcast(snapshot, ["network.connections"]);
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

  /** Get the stored network topology snapshot. */
  getTopologySnapshot(): NetworkTopologySnapshot | null {
    return this.topologySnapshot;
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

  /** Get the stored port intelligence snapshot. */
  getPorts(): PortIntelligenceSnapshot | null {
    return this.ports;
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
  private broadcast(payload: ProcessEvent | SystemTelemetry | NetworkSnapshot | NetworkTopologySnapshot | NetworkConnectionEventBroadcast | PortIntelligenceSnapshot | PortEventBroadcast | FileScanSnapshot | DetectionBroadcast, topics?: BroadcastTopic[]): void {
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
