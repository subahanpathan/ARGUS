"""Collection of read-only network connection data.

Uses psutil to enumerate active TCP/UDP connections and resolve
owning process names. All collection is wrapped so that a single
failing connection does not crash the collector.
"""

from __future__ import annotations

import logging
import socket

import psutil

from .connections import (
    classify_address,
    family_name,
    make_connection_id,
    normalize_connection_state,
    process_info_cache,
)
from .models import NetworkConnection, NetworkSnapshot

logger = logging.getLogger("argus.network_monitor.collector")


def _format_addr(addr: tuple | None) -> tuple[str, int | None]:
    """Format a psutil address tuple into (ip, port)."""
    if not addr:
        return ("", None)
    ip = addr[0] if len(addr) > 0 else ""
    port = addr[1] if len(addr) > 1 else None
    return (ip, port)


def collect_connections() -> NetworkSnapshot:
    """Collect all active network connections with process names.

    Returns a snapshot of all observed connections. Access-denied or
    zombie processes get the placeholder 'unavailable' name.
    """
    connections: list[NetworkConnection] = []

    try:
        raw_connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError) as e:
        logger.warning("Access denied enumerating connections: %s", e)
        return NetworkSnapshot(connections=[])
    except Exception:  # noqa: BLE001
        logger.exception("Failed to enumerate network connections")
        return NetworkSnapshot(connections=[])

    for conn in raw_connections:
        try:
            pid = conn.pid
            process_name, executable_path = process_info_cache.get(pid) if pid else (process_info_cache.UNAVAILABLE, "")

            local_ip, local_port = _format_addr(conn.laddr)
            remote_ip, remote_port = _format_addr(conn.raddr)

            af_short = family_name(conn.family)
            family_name_raw = "AF_INET" if conn.family == socket.AF_INET else (
                "AF_INET6" if conn.family == socket.AF_INET6 else str(conn.family)
            )
            type_name = "SOCK_STREAM" if conn.type == socket.SOCK_STREAM else (
                "SOCK_DGRAM" if conn.type == socket.SOCK_DGRAM else str(conn.type)
            )
            protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"

            status = normalize_connection_state(conn.status, protocol)

            connections.append(NetworkConnection(
                process=process_name,
                pid=pid,
                connection_id=make_connection_id(
                    protocol, af_short, local_ip, local_port, remote_ip, remote_port, pid
                ),
                local_addr=local_ip,
                local_port=local_port,
                remote_addr=remote_ip,
                remote_port=remote_port,
                family=family_name_raw,
                address_family=af_short,
                type=type_name,
                status=status,
                local_role=classify_address(local_ip),
                remote_role=classify_address(remote_ip),
                executable_path=executable_path,
            ))
        except Exception:  # noqa: BLE001
            logger.debug("Error processing connection: %s", conn)
            continue

    return NetworkSnapshot(connections=connections)
