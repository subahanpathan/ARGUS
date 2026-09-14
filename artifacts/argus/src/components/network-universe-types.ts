import type {
  NetworkTopologyData,
  TopologyInterface,
  TopologyConnection,
  TopologyNeighbor,
  TopologyConnectionEvent,
  TopologyTrafficRate,
  TopologyGateway,
  TopologyDns,
} from "@/hooks/use-network-topology";
import type {
  PortIntelligenceData,
  PortInfo,
  PortEvent,
} from "@/hooks/use-port-intelligence";

export type {
  NetworkTopologyData,
  TopologyInterface,
  TopologyConnection,
  TopologyNeighbor,
  TopologyConnectionEvent,
  TopologyTrafficRate,
  TopologyGateway,
  TopologyDns,
  PortIntelligenceData,
  PortInfo,
  PortEvent,
};

export type UniverseNodeType =
  | "laptop"
  | "adapter"
  | "gateway"
  | "neighbor"
  | "process"
  | "remote"
  | "dns"
  | "internet"
  | "port";

export type SecurityState =
  | "normal"
  | "active"
  | "suspicious"
  | "threat"
  | "blocked"
  | "quarantined"
  | "resolved";

export type NodeTier = "core" | "infrastructure" | "application" | "endpoint" | "external";

export type UniverseNode = {
  id: string;
  label: string;
  type: UniverseNodeType;
  detail: string;
  x: number;
  y: number;
  z: number;
  activityRate: number;
  connections: number;
  data: Record<string, unknown>;
  gallery: string;
  glyph: string;
  weight: number;
  listening?: boolean;
  secState?: SecurityState;
  tier?: NodeTier;
  spawnTime?: number;
  fadeIn?: number;
};

export type UniverseLinkState = "active" | "idle" | "flowing" | "closing";

export type UniverseLink = {
  id: string;
  from: string;
  to: string;
  intensity: number;
  state: UniverseLinkState;
  direction: "outbound" | "inbound";
  protocol?: string;
  localPort?: number;
  remotePort?: number;
  connectionKey?: string;
  edge: "proc" | "port" | "remote" | "infra" | "lan";
  bundle?: boolean;
  secState?: SecurityState;
  formTime?: number;
};

export type UniverseModel = {
  nodes: UniverseNode[];
  links: UniverseLink[];
  stats: UniverseStats;
};

export type UniverseStats = {
  interfaces: number;
  processes: number;
  connections: number;
  listeningPorts: number;
  udpEndpoints: number;
  establishedCount: number;
  neighbors: number;
  uploadRate: number;
  downloadRate: number;
  totalUpload: number;
  totalDownload: number;
  tcpListening: number;
  dnsServers: number;
  ports: number;
};

export type NetworkEvent = {
  id: string;
  timestamp: string;
  type: string;
  process?: string;
  pid?: number;
  protocol?: string;
  localAddr?: string;
  localPort?: number;
  remoteAddr?: string;
  remotePort?: number;
  state?: string;
  previousState?: string;
};
