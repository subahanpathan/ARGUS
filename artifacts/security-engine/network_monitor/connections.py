"""Phase 2 — shared network connection utilities.

Central implementation for real socket/connection observability:
- address role classification (derived only from the IP, never ports)
- stable, deterministic connection identifiers
- TCP state normalization
- snapshot connection statistics
- a small TTL process-info cache so repeated enumeration cycles do not
  spin up thousands of ``psutil.Process`` objects.

All functions are read-only and safe to call from any collector thread.
"""

from __future__ import annotations

import hashlib
import ipaddress
import time
from typing import Any, Iterable, Optional

import psutil

# Normalized TCP states we explicitly track (everything else = other_state_count).
TRACKED_TCP_STATES = ("ESTABLISHED", "LISTEN", "TIME_WAIT")

# psutil's numeric state table (used when a platform reports integers).
_PSUTIL_STATES = getattr(psutil, "tcp_states", None)

_CONNECTION_ID_LENGTH = 16


def classify_address(ip: Optional[str]) -> str:
    """Classify an address into LOCAL/LOOPBACK/PRIVATE/LINK_LOCAL/REMOTE/UNKNOWN.

    Classification is based purely on the IP value (or wildcard/missing
    markers); it never inspects port numbers or service names.
    """
    if not ip:
        return "LOCAL"
    stripped = ip.strip()
    if stripped in ("0.0.0.0", "::", "*", ":"):
        return "LOCAL"
    try:
        addr = ipaddress.ip_address(stripped)
    except ValueError:
        return "UNKNOWN"
    if addr.is_loopback:
        return "LOOPBACK"
    if addr.is_link_local:
        return "LINK_LOCAL"
    if addr.is_private:
        return "PRIVATE"
    return "REMOTE"


def family_name(family: int | None) -> str:
    """Human-readable address family for a psutil address family integer."""
    import socket
    if family == socket.AF_INET:
        return "IPv4"
    if family == socket.AF_INET6:
        return "IPv6"
    return "UNKNOWN"


def make_connection_id(
    protocol: Optional[str],
    family: Optional[str],
    local_addr: Optional[str],
    local_port: Any,
    remote_addr: Optional[str],
    remote_port: Any,
    pid: Any,
) -> str:
    """Build a stable, deterministic connection identifier.

    The identifier is derived from the tuple
    (protocol, family, local addr/port, remote addr/port, pid) and is
    identical across polling cycles for the same socket, so lifecycle
    tracking and the 3D universe can rely on a stable identity.
    """
    if local_addr is None:
        local_addr = ""
    if remote_addr is None:
        remote_addr = ""
    parts = [
        str(protocol or "").upper(),
        str(family or ""),
        str(local_addr),
        str(local_port if local_port is not None else ""),
        str(remote_addr),
        str(remote_port if remote_port is not None else ""),
        str(pid if pid is not None else ""),
    ]
    digest = hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()
    return f"conn_{digest[: _CONNECTION_ID_LENGTH]}"


def fallback_connection_key(record: Any) -> str:
    """Derive a stable lookup key for records without a connection_id."""
    return make_connection_id(
        _get(record, "protocol"),
        _get(record, "address_family"),
        _get(record, "local_addr"),
        _get(record, "local_port"),
        _get(record, "remote_addr"),
        _get(record, "remote_port"),
        _get(record, "pid"),
    )


def normalize_connection_state(state: Any, protocol: Optional[str] = None) -> str:
    """Normalize a connection state to a canonical uppercase label.

    - UDP endpoints always report ``NONE`` (they have no TCP state machine).
    - Unknown/empty TCP states normalize to ``UNKNOWN`` so the frontend can
      distinguish "observed with a defined state" from "unknown".
    """
    if state is None:
        state = ""
    is_udp = str(protocol or "").upper().startswith("UDP")
    if is_udp:
        return "NONE" if state not in ("NONE", "") else "NONE"
    if isinstance(state, int) and _PSUTIL_STATES:
        name = _PSUTIL_STATES.get(state)
        return name.upper() if name else "UNKNOWN"
    text = str(state).strip().upper()
    if not text or text in ("NONE", "UNKNOWN"):
        return "UNKNOWN"
    # psutil already returns canonical names; keep anything recognized-ish
    # and reject garbage shorter than 3 chars that can't be a real state.
    if len(text) < 3:
        return "UNKNOWN"
    return text


def _get(record: Any, field: str) -> Any:
    """Read a field from a dataclass or dict-style record."""
    if isinstance(record, dict):
        return record.get(field)
    return getattr(record, field, None)


def compute_connection_stats(connections: Iterable[Any]) -> dict[str, int]:
    """Compute live statistics from an iterable of connection records.

    Works with both dataclass models (ProcessConnectionInfo,
    NetworkConnection) and plain dicts. Counts are derived from the actual
    snapshot contents — never faked or extrapolated.
    """
    total = tcp = udp = established = listen = time_wait = other = 0
    ipv4 = ipv6 = 0
    remote_ips: set[str] = set()
    processes: set[int] = set()

    for c in connections:
        total += 1
        protocol = str(_get(c, "protocol") or "").upper()
        state = str(_get(c, "state") or _get(c, "status") or "").upper()
        family = str(_get(c, "address_family") or "").lower()
        remote = _get(c, "remote_addr") or ""
        pid = _get(c, "pid")

        is_tcp = protocol in ("TCP", "TCP6") or isinstance(_get(c, "type"), str) and _get(c, "type") == "SOCK_STREAM"
        is_udp = protocol in ("UDP", "UDP6") or isinstance(_get(c, "type"), str) and _get(c, "type") == "SOCK_DGRAM"
        if is_udp:
            udp += 1
        if is_tcp:
            tcp += 1
            if state in TRACKED_TCP_STATES:
                if state == "ESTABLISHED":
                    established += 1
                elif state == "LISTEN":
                    listen += 1
                else:
                    time_wait += 1
            else:
                other += 1

        if family == "ipv4":
            ipv4 += 1
        elif family == "ipv6":
            ipv6 += 1

        if remote and remote not in ("0.0.0.0", "::", "*"):
            remote_ips.add(remote)
        try:
            if pid is not None and int(pid) > 0:
                processes.add(int(pid))
        except (TypeError, ValueError):
            pass

    return {
        "total_count": total,
        "tcp_count": tcp,
        "udp_count": udp,
        "established_count": established,
        "listening_count": listen,
        "listen_count": listen,
        "time_wait_count": time_wait,
        "other_state_count": other,
        "ipv4_count": ipv4,
        "ipv6_count": ipv6,
        "unique_remote_ips": len(remote_ips),
        "unique_processes": len(processes),
    }


class ProcessInfoCache:
    """TTL cache mapping PID -> (process name, executable path).

    Prevents every sampling cycle from constructing thousands of
    ``psutil.Process`` objects. Access-denied / zombie / vanished processes
    resolve to the placeholder ``"unavailable"`` per the Phase 2 contract.
    """

    UNAVAILABLE = "unavailable"

    def __init__(self, ttl_s: float = 5.0, max_entries: int = 8192) -> None:
        self._ttl_s = ttl_s
        self._max_entries = max_entries
        self._cache: dict[int, tuple[float, str, str]] = {}

    def get(self, pid: int) -> tuple[str, str]:
        """Resolve (process_name, executable_path) for a PID."""
        pid = int(pid) if pid is not None else 0
        if pid <= 0:
            return (self.UNAVAILABLE, "")
        now = time.monotonic()
        hit = self._cache.get(pid)
        if hit and now - hit[0] < self._ttl_s:
            return (hit[1], hit[2])
        name, exe = self._lookup(pid)
        if len(self._cache) >= self._max_entries:
            self._cache.clear()
        self._cache[pid] = (now, name, exe)
        return (name, exe)

    @staticmethod
    def _lookup(pid: int) -> tuple[str, str]:
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            exe = ""
            try:
                exe = proc.exe() or ""
            except Exception:
                exe = ""
            return (name, exe)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return (ProcessInfoCache.UNAVAILABLE, "")


# Module-level cache shared by all collectors.
process_info_cache = ProcessInfoCache()