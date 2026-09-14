"""ARGUS Windows Network Monitor — read-only network connection collection."""

from .models import (
    NetworkConnection,
    NetworkSnapshot,
    NetworkInterfaceInfo,
    GatewayInfo,
    DnsInfo,
    ProcessConnectionInfo,
    TrafficRate,
    NeighborInfo,
    ConnectionEvent,
    NetworkTopologySnapshot,
)
from .collector import collect_connections
from .watcher import NetworkMonitorWatcher
from .topology_collector import collect_topology
from .topology_watcher import NetworkTopologyWatcher
from .port_models import PortInfo, PortEvent, PortSummary, PortAssociation, PortIntelligenceSnapshot
from .port_collector import collect_ports, compute_port_summary
from .port_watcher import PortIntelligenceWatcher

__all__ = [
    "NetworkConnection",
    "NetworkSnapshot",
    "collect_connections",
    "NetworkMonitorWatcher",
    "NetworkInterfaceInfo",
    "GatewayInfo",
    "DnsInfo",
    "ProcessConnectionInfo",
    "TrafficRate",
    "NeighborInfo",
    "ConnectionEvent",
    "NetworkTopologySnapshot",
    "collect_topology",
    "NetworkTopologyWatcher",
    "PortInfo",
    "PortEvent",
    "PortSummary",
    "PortAssociation",
    "PortIntelligenceSnapshot",
    "collect_ports",
    "compute_port_summary",
    "PortIntelligenceWatcher",
]
