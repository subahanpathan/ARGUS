"""Normalized data models for network connection monitoring."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

from .connections import compute_connection_stats


@dataclass
class NetworkConnection:
    """A single observed network connection."""

    process: str
    pid: int | None = None
    connection_id: str = ""  # stable deterministic identifier
    local_addr: str = ""
    local_port: int | None = None
    remote_addr: str = ""
    remote_port: int | None = None
    family: str = ""  # AF_INET, AF_INET6
    address_family: str = ""  # IPv4, IPv6
    type: str = ""  # SOCK_STREAM, SOCK_DGRAM
    status: str = ""  # ESTABLISHED, LISTEN, TIME_WAIT, etc.
    local_role: str = ""  # LOCAL, LOOPBACK, PRIVATE, LINK_LOCAL, REMOTE, UNKNOWN
    remote_role: str = ""
    executable_path: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None and v != ""}


@dataclass
class NetworkSnapshot:
    """A point-in-time collection of all observed network connections."""

    connections: list[NetworkConnection]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_count: int = 0
    established_count: int = 0
    listen_count: int = 0
    listening_count: int = 0
    tcp_count: int = 0
    udp_count: int = 0
    time_wait_count: int = 0
    other_state_count: int = 0
    ipv4_count: int = 0
    ipv6_count: int = 0
    unique_remote_ips: int = 0
    unique_processes: int = 0

    def __post_init__(self) -> None:
        stats = compute_connection_stats(self.connections)
        self.total_count = stats["total_count"]
        self.established_count = stats["established_count"]
        self.listen_count = stats["listen_count"]
        self.listening_count = stats["listening_count"]
        self.tcp_count = stats["tcp_count"]
        self.udp_count = stats["udp_count"]
        self.time_wait_count = stats["time_wait_count"]
        self.other_state_count = stats["other_state_count"]
        self.ipv4_count = stats["ipv4_count"]
        self.ipv6_count = stats["ipv6_count"]
        self.unique_remote_ips = stats["unique_remote_ips"]
        self.unique_processes = stats["unique_processes"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "total_count": self.total_count,
            "established_count": self.established_count,
            "listen_count": self.listen_count,
            "listening_count": self.listening_count,
            "tcp_count": self.tcp_count,
            "udp_count": self.udp_count,
            "time_wait_count": self.time_wait_count,
            "other_state_count": self.other_state_count,
            "ipv4_count": self.ipv4_count,
            "ipv6_count": self.ipv6_count,
            "unique_remote_ips": self.unique_remote_ips,
            "unique_processes": self.unique_processes,
            "connections": [c.to_dict() for c in self.connections],
        }


@dataclass
class NetworkInterfaceInfo:
    """Detailed information about a single network interface."""

    name: str
    friendly_name: str = ""
    interface_type: str = ""  # Wi-Fi, Ethernet, Loopback, Tunnel, etc.
    is_up: bool = False
    is_running: bool = False
    mtu: int | None = None
    speed: int | None = None  # Mbps
    mac_address: str = ""
    addresses: list[str] = field(default_factory=list)
    bytes_sent: int = 0
    bytes_recv: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None and v != "" and v != [] and v != 0}


@dataclass
class GatewayInfo:
    """Default gateway information."""

    next_hop: str = ""
    interface: str = ""
    metric: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None and v != ""}


@dataclass
class DnsInfo:
    """DNS server information."""

    interface: str = ""
    servers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        if self.interface:
            d["interface"] = self.interface
        if self.servers:
            d["servers"] = self.servers
        return d


@dataclass
class ProcessConnectionInfo:
    """Enhanced connection with process mapping and traffic data."""

    id: str = ""
    connection_id: str = ""  # stable deterministic identifier
    pid: int = 0
    process_name: str = ""
    process_path: str = ""
    executable_path: str = ""  # alias of process_path, "unavailable" fallback
    local_addr: str = ""
    local_port: int = 0
    remote_addr: str = ""
    remote_port: int = 0
    remote_hostname: str = ""  # reverse DNS, "UNRESOLVED" if fails
    protocol: str = ""  # TCP, UDP, TCP6, UDP6
    address_family: str = ""  # IPv4, IPv6
    state: str = ""  # ESTABLISHED, LISTEN, TIME_WAIT, etc.
    status: str = ""  # alias of state (Phase 2 naming)
    local_role: str = ""  # LOCAL, LOOPBACK, PRIVATE, LINK_LOCAL, REMOTE, UNKNOWN
    remote_role: str = ""
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None and v != ""}


@dataclass
class TrafficRate:
    """Traffic rate for an interface."""

    interface: str = ""
    bytes_sent: int = 0
    bytes_recv: int = 0
    bytes_sent_rate: float = 0.0  # bytes/sec
    bytes_recv_rate: float = 0.0  # bytes/sec

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NeighborInfo:
    """A discovered local network neighbor (ARP/NDP entry)."""

    ip: str = ""
    mac: str = ""
    interface: str = ""
    state: str = ""  # REACHABLE, STALE, etc.
    hostname: str = ""  # reverse DNS if available

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None and v != ""}


@dataclass
class ConnectionEvent:
    """A lifecycle event for a connection (new, closed, state change)."""

    event_type: str = ""  # NEW, CLOSED, STATE_CHANGE, ...
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    connection_id: str = ""
    process_name: str = ""
    pid: int = 0
    protocol: str = ""
    address_family: str = ""
    local_addr: str = ""
    local_port: int = 0
    remote_addr: str = ""
    remote_port: int = 0
    state: str = ""
    previous_state: str = ""
    local_role: str = ""
    remote_role: str = ""

    @property
    def status(self) -> str:
        """Phase 2 alias for event state."""
        return self.state

    def to_dict(self) -> dict[str, Any]:
        data = {k: v for k, v in asdict(self).items() if v is not None and v != ""}
        if "state" in data:
            data["status"] = data["state"]
        return data


@dataclass
class NetworkTopologySnapshot:
    """Comprehensive network topology snapshot."""

    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    hostname: str = ""
    interfaces: list[NetworkInterfaceInfo] = field(default_factory=list)
    default_gateway: GatewayInfo = field(default_factory=GatewayInfo)
    dns_servers: list[DnsInfo] = field(default_factory=list)
    connections: list[ProcessConnectionInfo] = field(default_factory=list)
    traffic_rates: list[TrafficRate] = field(default_factory=list)
    neighbors: list[NeighborInfo] = field(default_factory=list)
    connection_events: list[ConnectionEvent] = field(default_factory=list)
    public_ip: str = ""
    udp_endpoints: int = 0
    tcp_listening: int = 0
    total_connections: int = 0
    established_count: int = 0
    listen_count: int = 0
    tcp_count: int = 0
    udp_count: int = 0
    time_wait_count: int = 0
    other_state_count: int = 0
    ipv4_count: int = 0
    ipv6_count: int = 0
    unique_remote_ips: int = 0
    unique_processes: int = 0

    def recompute_stats(self) -> None:
        """Recalculate derived counters from the current connections list."""
        stats = compute_connection_stats(self.connections)
        self.total_connections = stats["total_count"]
        self.established_count = stats["established_count"]
        self.listen_count = stats["listen_count"]
        self.tcp_listening = stats["listen_count"]
        self.udp_endpoints = stats["udp_count"]
        self.tcp_count = stats["tcp_count"]
        self.udp_count = stats["udp_count"]
        self.time_wait_count = stats["time_wait_count"]
        self.other_state_count = stats["other_state_count"]
        self.ipv4_count = stats["ipv4_count"]
        self.ipv6_count = stats["ipv6_count"]
        self.unique_remote_ips = stats["unique_remote_ips"]
        self.unique_processes = stats["unique_processes"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "hostname": self.hostname,
            "interfaces": [i.to_dict() for i in self.interfaces],
            "default_gateway": self.default_gateway.to_dict(),
            "dns_servers": [d.to_dict() for d in self.dns_servers],
            "connections": [c.to_dict() for c in self.connections],
            "traffic_rates": [t.to_dict() for t in self.traffic_rates],
            "neighbors": [n.to_dict() for n in self.neighbors],
            "connection_events": [e.to_dict() for e in self.connection_events],
            "public_ip": self.public_ip,
            "udp_endpoints": self.udp_endpoints,
            "tcp_listening": self.tcp_listening,
            "total_connections": self.total_connections,
            "established_count": self.established_count,
            "listen_count": self.listen_count,
            "tcp_count": self.tcp_count,
            "udp_count": self.udp_count,
            "time_wait_count": self.time_wait_count,
            "other_state_count": self.other_state_count,
            "ipv4_count": self.ipv4_count,
            "ipv6_count": self.ipv6_count,
            "unique_remote_ips": self.unique_remote_ips,
            "unique_processes": self.unique_processes,
        }
