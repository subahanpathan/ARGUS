"""Phase 3 — Port intelligence data models.

Distinguishes between:
  - TCP LISTENING PORT (a socket bound and waiting for connections)
  - ACTIVE TCP CONNECTION (an established TCP session)
  - UDP ENDPOINT (a UDP socket, stateless)
  - EPHEMERAL LOCAL PORT (client-side ephemeral port)
  - LOOPBACK SOCKET (bound to 127.0.0.1 or ::1)

Every port gets a stable, deterministic ID derived from:
  protocol + address_family + local_address + local_port + PID
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


@dataclass
class PortInfo:
    """A single observed listening port or UDP endpoint."""

    port_id: str = ""  # stable deterministic ID
    protocol: str = ""  # TCP, TCP6, UDP, UDP6
    address_family: str = ""  # IPv4, IPv6
    local_addr: str = ""
    local_port: int = 0
    state: str = ""  # LISTENING, NONE (for UDP)
    pid: int = 0
    process_name: str = ""  # "unavailable" if resolution fails
    executable_path: str = ""
    binding_type: str = ""  # LOOPBACK, WILDCARD, INTERFACE
    local_role: str = ""  # LOOPBACK, PRIVATE, LINK_LOCAL, LOCAL, REMOTE, UNKNOWN
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    associated_connection_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = {k: v for k, v in asdict(self).items() if v is not None and v != ""}
        return d


@dataclass
class PortEvent:
    """A lifecycle event for a port (PORT_OPENED, PORT_CLOSED, PORT_CHANGED)."""

    event_type: str = ""  # PORT_OPENED, PORT_CLOSED, PORT_CHANGED
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    port_id: str = ""
    protocol: str = ""
    address_family: str = ""
    local_addr: str = ""
    local_port: int = 0
    state: str = ""
    pid: int = 0
    process_name: str = ""
    executable_path: str = ""
    binding_type: str = ""
    previous_pid: int = 0
    previous_process_name: str = ""
    previous_state: str = ""
    change_details: str = ""  # what changed for PORT_CHANGED events

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None and v != ""}


@dataclass
class PortSummary:
    """Real-time port statistics derived from the current snapshot."""

    tcp_listening_count: int = 0
    udp_endpoint_count: int = 0
    ipv4_listening_count: int = 0
    ipv6_listening_count: int = 0
    loopback_count: int = 0
    wildcard_count: int = 0
    interface_count: int = 0
    active_tcp_connections: int = 0
    unique_processes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PortAssociation:
    """Map a listening port to the active connections that landed on it.

    Populated from actual Phase 2 connection data (a connection whose local
    endpoint and PID match the listening socket). Never inferred from the
    process alone.
    """

    port_id: str = ""
    connection_ids: list[str] = field(default_factory=list)


@dataclass
class PortIntelligenceSnapshot:
    """A point-in-time collection of all observed ports and endpoints."""

    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tcp_listening: list[PortInfo] = field(default_factory=list)
    udp_endpoints: list[PortInfo] = field(default_factory=list)
    port_events: list[PortEvent] = field(default_factory=list)
    summary: PortSummary = field(default_factory=PortSummary)
    active_tcp_connections: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "tcp_listening": [p.to_dict() for p in self.tcp_listening],
            "udp_endpoints": [p.to_dict() for p in self.udp_endpoints],
            "port_events": [e.to_dict() for e in self.port_events],
            "summary": self.summary.to_dict(),
            "active_tcp_connections": self.active_tcp_connections,
        }
