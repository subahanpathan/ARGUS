"""Phase 3 — Port intelligence collector.

Reads the Windows socket table via psutil and extracts:
  - TCP listening ports (state == LISTEN)
  - UDP endpoints (all UDP sockets)

Each port receives:
  - Stable port_id (protocol + AF + addr + port + PID)
  - Process resolution via the shared ProcessInfoCache
  - Binding classification (LOOPBACK / WILDCARD / INTERFACE)
  - Address role classification

Data sources used:
  - psutil.net_connections(kind="inet") — raw socket table (TCP + UDP)
  - psutil.Process(pid).name() / .exe() — process resolution
  Both are read-only. No PowerShell, no network scanning, no packet capture.
"""

from __future__ import annotations

import hashlib
import logging
import socket

import psutil

from .connections import classify_address, family_name, make_connection_id, process_info_cache
from .port_models import PortInfo, PortSummary

logger = logging.getLogger("argus.network_monitor.port_collector")

_PORT_ID_LENGTH = 16


def make_port_id(
    protocol: str,
    address_family: str,
    local_addr: str,
    local_port: int,
    pid: int,
) -> str:
    """Build a stable, deterministic port identifier.

    The ID is derived from (protocol, address_family, local_addr, local_port, pid)
    and is identical across polling cycles for the same listening socket.
    """
    parts = [
        str(protocol).upper(),
        str(address_family),
        str(local_addr),
        str(local_port),
        str(pid),
    ]
    digest = hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()
    return f"port_{digest[:_PORT_ID_LENGTH]}"


def classify_binding(addr: str) -> str:
    """Classify how a socket is bound: LOOPBACK, WILDCARD, or INTERFACE."""
    if not addr or addr.strip() in ("",):
        return "WILDCARD"
    stripped = addr.strip()
    if stripped in ("0.0.0.0", "::", "*", ":"):
        return "WILDCARD"
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(stripped)
        if ip_obj.is_loopback:
            return "LOOPBACK"
        if ip_obj.is_unspecified:
            return "WILDCARD"
    except ValueError:
        pass
    # Could not parse as IP — treat as INTERFACE if non-empty
    return "INTERFACE"


def _format_addr(addr) -> tuple[str, int]:
    """Format a psutil address tuple into (ip, port)."""
    if not addr:
        return ("", 0)
    ip = addr[0] if len(addr) > 0 else ""
    port = addr[1] if len(addr) > 1 else 0
    return (ip, port)


def collect_ports():
    """Collect all TCP listening ports and UDP endpoints.

    Returns:
        (tcp_listening, udp_endpoints, active_tcp_connections, associations)

    ``associations`` maps a port_id to the connection IDs of active TCP
    connections whose local endpoint + PID match the listening socket
    (derived from the actual Phase 2 connection table).
    """
    tcp_listening: list[PortInfo] = []
    udp_endpoints: list[PortInfo] = []
    active_tcp_connections = 0
    # port_id -> [connection_id, ...]
    associations: dict[str, list[str]] = {}
    # (protocol, local_addr, local_port, pid) -> port_id for established lookups
    listen_index: dict[tuple[str, str, int, int], str] = {}

    try:
        raw_connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError) as e:
        logger.warning("Access denied enumerating connections for port intelligence: %s", e)
        return tcp_listening, udp_endpoints, active_tcp_connections, associations
    except Exception:
        logger.exception("Failed to enumerate connections for port intelligence")
        return tcp_listening, udp_endpoints, active_tcp_connections, associations

    for conn in raw_connections:
        try:
            pid = conn.pid or 0
            process_name, executable_path = process_info_cache.get(pid)

            local_ip, local_port = _format_addr(conn.laddr)

            af_short = family_name(conn.family)
            is_tcp = conn.type == socket.SOCK_STREAM
            is_udp = conn.type == socket.SOCK_DGRAM

            if is_tcp:
                protocol = "TCP" if conn.family == socket.AF_INET else "TCP6"
                state = str(conn.status).strip().upper() if conn.status else "UNKNOWN"

                if state == "LISTEN":
                    binding = classify_binding(local_ip)
                    local_role = classify_address(local_ip)
                    port_id = make_port_id(protocol, af_short, local_ip, local_port, pid)

                    tcp_listening.append(PortInfo(
                        port_id=port_id,
                        protocol=protocol,
                        address_family=af_short,
                        local_addr=local_ip,
                        local_port=local_port,
                        state="LISTENING",
                        pid=pid,
                        process_name=process_name,
                        executable_path=executable_path,
                        binding_type=binding,
                        local_role=local_role,
                    ))
                    listen_index[(protocol, local_ip, local_port, pid)] = port_id
                else:
                    active_tcp_connections += 1

            elif is_udp:
                protocol = "UDP" if conn.family == socket.AF_INET else "UDP6"
                binding = classify_binding(local_ip)
                local_role = classify_address(local_ip)
                port_id = make_port_id(protocol, af_short, local_ip, local_port, pid)

                udp_endpoints.append(PortInfo(
                    port_id=port_id,
                    protocol=protocol,
                    address_family=af_short,
                    local_addr=local_ip,
                    local_port=local_port,
                    state="UDP",
                    pid=pid,
                    process_name=process_name,
                    executable_path=executable_path,
                    binding_type=binding,
                    local_role=local_role,
                ))

        except Exception:
            logger.debug("Error processing connection for port intelligence")
            continue

    # Finalize associations: established connections resolved after all
    # listening sockets are indexed.
    for conn in raw_connections:
        try:
            pid = conn.pid or 0
            if conn.type != socket.SOCK_STREAM:
                continue
            state = str(conn.status).strip().upper() if conn.status else "UNKNOWN"
            if state == "LISTEN" or not conn.laddr:
                continue
            local_ip, local_port = _format_addr(conn.laddr)
            protocol = "TCP" if conn.family == socket.AF_INET else "TCP6"
            matching = listen_index.get((protocol, local_ip, local_port, pid))
            if not matching:
                continue
            remote_ip = ""
            remote_port = 0
            if conn.raddr:
                remote_ip = conn.raddr[0] if len(conn.raddr) > 0 else ""
                remote_port = conn.raddr[1] if len(conn.raddr) > 1 else 0
            connection_id = make_connection_id(
                protocol, family_name(conn.family), local_ip, local_port,
                remote_ip, remote_port, pid,
            )
            associations.setdefault(matching, []).append(connection_id)
        except Exception:
            continue

    return tcp_listening, udp_endpoints, active_tcp_connections, associations


def compute_port_summary(
    tcp_listening: list[PortInfo],
    udp_endpoints: list[PortInfo],
    active_tcp_connections: int,
) -> PortSummary:
    """Compute real-time port statistics."""
    summary = PortSummary()
    summary.tcp_listening_count = len(tcp_listening)
    summary.udp_endpoint_count = len(udp_endpoints)
    summary.active_tcp_connections = active_tcp_connections

    processes: set[int] = set()

    for p in tcp_listening:
        if p.address_family == "IPv4":
            summary.ipv4_listening_count += 1
        elif p.address_family == "IPv6":
            summary.ipv6_listening_count += 1
        if p.binding_type == "LOOPBACK":
            summary.loopback_count += 1
        elif p.binding_type == "WILDCARD":
            summary.wildcard_count += 1
        else:
            summary.interface_count += 1
        if p.pid > 0:
            processes.add(p.pid)

    for p in udp_endpoints:
        if p.pid > 0:
            processes.add(p.pid)

    summary.unique_processes = len(processes)
    return summary
