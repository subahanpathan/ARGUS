"""Collection of comprehensive network topology data.

Gathers network interfaces, default gateway, DNS servers, TCP connections
with PID→process mapping, and interface traffic rates. All collection is
read-only and wrapped so failures in one area don't crash the collector.

Performance notes:
- Gateway / DNS discovery shells out rarely (cached ~15s) to avoid blocking
  the sampling loop with slow PowerShell startup.
- Reverse-DNS resolution runs on a decoupled background thread so a slow
  (or missing) DNS server never stalls a sampling cycle. The sampler only
  reads whatever hostname is already cached.
"""

from __future__ import annotations

import atexit
import logging
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import psutil

from .connections import (
    classify_address,
    fallback_connection_key,
    family_name,
    make_connection_id,
    normalize_connection_state,
    process_info_cache,
)
from .models import (
    ConnectionEvent,
    DnsInfo,
    GatewayInfo,
    NeighborInfo,
    NetworkInterfaceInfo,
    NetworkTopologySnapshot,
    ProcessConnectionInfo,
)

logger = logging.getLogger("argus.network_monitor.topology_collector")

_INFO_CACHE_TTL_S = 15.0
_adapter_cache: list[dict[str, str]] = []
_adapter_cache_ts = 0.0
_ADAPTER_CACHE_TTL_S = 60.0

# Bound global socket timeouts so stray lookups can't hang indefinitely.
try:
    socket.setdefaulttimeout(5)
except Exception:
    pass


class ReverseDnsCache:
    """Non-blocking reverse-DNS resolver with a background thread.

    The sampling thread calls ``lookup(ip)`` which returns immediately with
    a cached hostname or "". A background worker resolves queued IPs using a
    thread pool and writes results back under a lock.
    """

    def __init__(self, batch_size: int = 8, workers: int = 8) -> None:
        self._batch_size = batch_size
        self._cache: dict[str, str] = {}
        self._queued: set[str] = set()
        self._lock = threading.Lock()
        self._running = False
        self._cv = threading.Condition(self._lock)
        self._thread: threading.Thread | None = None
        self._executor = ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="argus-reverse-dns"
        )

    def start(self) -> None:
        """Start the background resolver thread."""
        with self._lock:
            if self._running:
                return
            self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="argus-reverse-dns-worker"
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the background resolver and release the pool."""
        with self._lock:
            self._running = False
            self._cv.notify_all()
        if self._thread:
            self._thread.join(timeout=2)
        self._executor.shutdown(wait=False, cancel_futures=True)

    def lookup(self, ip: str) -> str:
        """Return a cached hostname, "" if unknown, without blocking."""
        with self._lock:
            cached = self._cache.get(ip)
            if cached is not None:
                return cached
            if ip not in self._queued:
                self._queued.add(ip)
                self._cv.notify()
            return ""

    def cache_size(self) -> int:
        with self._lock:
            return len(self._cache)

    def _loop(self) -> None:
        while True:
            with self._lock:
                while self._running and not self._queued:
                    self._cv.wait(timeout=1.0)
                if not self._running:
                    return
                batch = list(self._queued)[: self._batch_size]
                self._queued.difference_update(batch)

            if not batch:
                continue

            futures = {
                self._executor.submit(self._resolve, ip): ip for ip in batch
            }
            # Cap total wall time per batch; stray hangs only waste a worker.
            try:
                for future in as_completed(futures, timeout=5.0):
                    try:
                        self._resolve_result(future.result(timeout=2.0))
                    except Exception:
                        continue
            except TimeoutError:
                pass

    def _resolve(self, ip: str) -> tuple[str, str]:
        try:
            return (ip, socket.gethostbyaddr(ip)[0])
        except Exception:
            return (ip, "UNRESOLVED")

    def _resolve_result(self, result: tuple[str, str]) -> None:
        ip, hostname = result
        with self._lock:
            self._cache[ip] = hostname


def _safe(callable_, fallback):
    """Invoke a callable, returning a fallback value on any exception."""
    try:
        return callable_()
    except Exception:
        return fallback


def _get_hostname() -> str:
    """Get the local machine hostname."""
    return _safe(socket.gethostname, "UNKNOWN")


def _get_adapter_info() -> list[dict[str, str]]:
    """Get adapter friendly names and types via Get-NetAdapter. Cached for 60s."""
    global _adapter_cache, _adapter_cache_ts
    now = time.monotonic()
    if now - _adapter_cache_ts < _ADAPTER_CACHE_TTL_S and _adapter_cache:
        return _adapter_cache

    try:
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-Command",
                "Get-NetAdapter | Select-Object Name,InterfaceDescription,InterfaceIndex | ConvertTo-Json -Compress",
            ],
            capture_output=True, text=True, timeout=8,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode == 0 and result.stdout.strip():
            import json
            data = json.loads(result.stdout.strip())
            entries = data if isinstance(data, list) else [data]
            adapters = []
            for e in entries:
                adapters.append({
                    "name": e.get("Name", ""),
                    "friendly_name": e.get("InterfaceDescription", ""),
                })
            if adapters:
                _adapter_cache = adapters
                _adapter_cache_ts = now
                return adapters
    except Exception:
        logger.debug("Get-NetAdapter failed")

    return _adapter_cache


def _detect_iface_type(name: str, friendly: str) -> str:
    """Determine adapter type from name and friendly description."""
    combined = (name + " " + friendly).lower()
    if "wi-fi" in combined or "wireless" in combined or "wifi" in combined or "802.11" in combined:
        return "Wi-Fi"
    if "ethernet" in combined or "lan" in combined:
        return "Ethernet"
    if "loopback" in combined or "loop" in combined or name == "lo":
        return "Loopback"
    if "vpn" in combined or "tunnel" in combined or "tap" in combined:
        return "VPN/Tunnel"
    if "bluetooth" in combined:
        return "Bluetooth"
    if "hyper-v" in combined or "virtual" in combined or "vmware" in combined or "vbox" in combined or "hyper-v" in combined:
        return "Virtual"
    if "wan" in combined or "wwan" in combined or "mobile" in combined:
        return "Cellular"
    return ""


def _get_interfaces() -> list[NetworkInterfaceInfo]:
    """Collect detailed network interface information."""
    interfaces: list[NetworkInterfaceInfo] = []
    try:
        if_addrs = psutil.net_if_addrs()
        if_stats = psutil.net_if_stats()
        io_counters = psutil.net_io_counters(pernic=True)
    except Exception:
        logger.exception("Failed to collect interface data")
        return interfaces

    # Get adapter friendly names via PowerShell (cached)
    adapter_info = _get_adapter_info()
    adapter_map: dict[str, str] = {}
    for a in adapter_info:
        if a.get("name"):
            adapter_map[a["name"]] = a.get("friendly_name", "")

    for name in sorted(set(if_addrs.keys()) | set(if_stats.keys())):
        stats = if_stats.get(name)
        addrs = if_addrs.get(name, [])
        io = io_counters.get(name)
        friendly = adapter_map.get(name, "")

        mac = ""
        ip_addresses = []
        for addr in addrs:
            if addr.family == psutil.AF_LINK and addr.address:
                mac = addr.address
            elif addr.family in (socket.AF_INET, socket.AF_INET6) and addr.address:
                ip_addresses.append(addr.address)

        interfaces.append(NetworkInterfaceInfo(
            name=name,
            friendly_name=friendly,
            interface_type=_detect_iface_type(name, friendly),
            is_up=bool(stats and stats.isup),
            is_running=bool(stats and stats.isup),
            mtu=int(stats.mtu) if stats else None,
            speed=int(stats.speed) if stats and stats.speed else None,
            mac_address=mac,
            addresses=ip_addresses,
            bytes_sent=int(io.bytes_sent) if io else 0,
            bytes_recv=int(io.bytes_recv) if io else 0,
        ))

    return interfaces


# ---------------------------------------------------------------------------
# Cached gateway / DNS lookups (refreshed every _INFO_CACHE_TTL_S)
# ---------------------------------------------------------------------------
_gateway_cache: GatewayInfo = GatewayInfo()
_gateway_cache_ts = 0.0
_dns_cache: list[DnsInfo] = []
_dns_cache_ts = 0.0


def _get_gateway_win() -> GatewayInfo:
    """Parse `route print 0.0.0.0` — a fast native command."""
    try:
        result = subprocess.run(
            ["route", "print", "0.0.0.0"],
            capture_output=True, text=True, timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode == 0:
            seen_header = False
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if not seen_header:
                    if stripped.startswith("Network Destination"):
                        seen_header = True
                    continue
                parts = stripped.split()
                if parts and parts[0] == "0.0.0.0" and len(parts) >= 3:
                    return GatewayInfo(
                        next_hop=parts[2],
                        interface=parts[3] if len(parts) > 3 else "",
                    )
    except Exception:
        logger.debug("route print failed")
    return GatewayInfo()


def _get_dns_win() -> list[DnsInfo]:
    """Parse `ipconfig /all` for DNS servers (fast native command)."""
    dns_list: list[DnsInfo] = []
    try:
        result = subprocess.run(
            ["ipconfig", "/all"],
            capture_output=True, text=True, timeout=8,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        logger.debug("ipconfig /all failed")
        return dns_list

    if result.returncode != 0:
        return dns_list

    current_iface = ""
    dns_servers: list[str] = []
    block_started = False

    def flush_block() -> None:
        nonlocal current_iface, dns_servers, block_started
        if current_iface and dns_servers:
            dns_list.append(DnsInfo(interface=current_iface, servers=dns_servers))
        dns_servers = []
        block_started = False

    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("Ethernet adapter") or line.startswith("Wireless LAN adapter") or line.startswith("Unknown adapter") or line.startswith("Tunnel adapter"):
            flush_block()
            current_iface = line.split(":")[0].replace("adapter", "").strip()
        elif line.startswith("DNS Servers"):
            block_started = True
            if ":" in line:
                val = line.split(":", 1)[1].strip()
                if val:
                    dns_servers.append(val)
        elif block_started:
            if line.startswith("DNS"):
                continue
            if line.startswith(" ") is False:
                # A new heading — flush if DNS block populated meaningful values
                if dns_servers:
                    flush_block()
                elif current_iface and not dns_servers:
                    block_started = False
                block_started = False
                current_iface = ""
            elif line.strip():
                dns_servers.append(line.strip())

        # Stop searching after a reasonable amount of output
        if len(dns_list) > 12:
            break
    flush_block()
    return dns_list


def _get_default_gateway() -> GatewayInfo:
    """Get the default gateway, refreshing the native lookup only on TTL expiry."""
    global _gateway_cache, _gateway_cache_ts
    now = time.monotonic()
    if now - _gateway_cache_ts < _INFO_CACHE_TTL_S and _gateway_cache.next_hop:
        return _gateway_cache
    fresh = _get_gateway_win()
    if fresh.next_hop:
        _gateway_cache = fresh
        _gateway_cache_ts = now
    return fresh


def _get_dns_servers() -> list[DnsInfo]:
    """Get DNS server information per interface, cached across cycles."""
    global _dns_cache, _dns_cache_ts
    now = time.monotonic()
    if now - _dns_cache_ts < _INFO_CACHE_TTL_S and _dns_cache:
        return _dns_cache
    fresh = _get_dns_win()
    if fresh:
        _dns_cache = fresh
        _dns_cache_ts = now
    return fresh


# ---------------------------------------------------------------------------
# Connections + process mapping
# ---------------------------------------------------------------------------

def _get_connections_with_processes(
    dns_cache: ReverseDnsCache,
) -> list[ProcessConnectionInfo]:
    """Collect all connections with PID→process mapping and cached hostnames.

    Each connection receives a stable, deterministic connection_id derived
    from (protocol, family, local/remote addresses and ports, pid) so that
    lifecycle tracking and the universe view share one identity across polls.
    """
    connections: list[ProcessConnectionInfo] = []

    try:
        raw_connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        logger.warning("Access denied enumerating connections")
        return connections
    except Exception:
        logger.exception("Failed to enumerate connections")
        return connections

    for conn in raw_connections:
        try:
            pid = conn.pid or 0
            process_name, process_path = process_info_cache.get(pid)

            local_ip = conn.laddr[0] if conn.laddr else ""
            local_port = conn.laddr[1] if conn.laddr else 0
            remote_ip = conn.raddr[0] if conn.raddr else ""
            remote_port = conn.raddr[1] if conn.raddr else 0

            af_short = family_name(conn.family)

            if conn.family == socket.AF_INET:
                protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            elif conn.family == socket.AF_INET6:
                protocol = "TCP6" if conn.type == socket.SOCK_STREAM else "UDP6"
            else:
                protocol = str(conn.family)

            remote_hostname = ""
            if remote_ip and remote_ip not in ("0.0.0.0", "::", "", "127.0.0.1", "::1", "255.255.255.255"):
                remote_hostname = dns_cache.lookup(remote_ip)

            state = normalize_connection_state(conn.status, protocol)
            connection_id = make_connection_id(
                protocol, af_short, local_ip, local_port, remote_ip, remote_port, pid
            )

            connections.append(ProcessConnectionInfo(
                id=connection_id,
                connection_id=connection_id,
                pid=pid,
                process_name=process_name,
                process_path=process_path,
                executable_path=process_path,
                local_addr=local_ip,
                local_port=local_port,
                remote_addr=remote_ip,
                remote_port=remote_port,
                remote_hostname=remote_hostname,
                protocol=protocol,
                address_family=af_short,
                state=state,
                status=state,
                local_role=classify_address(local_ip),
                remote_role=classify_address(remote_ip),
            ))
        except Exception:
            logger.debug("Error processing connection")
            continue

    return connections


# ---------------------------------------------------------------------------
# ARP / Neighbor table discovery
# ---------------------------------------------------------------------------

_neighbor_cache: list[NeighborInfo] = []
_neighbor_cache_ts = 0.0
_NEIGHBOR_CACHE_TTL_S = 30.0


def _get_neighbors_win() -> list[NeighborInfo]:
    """Parse `arp -a` for IPv4 neighbor (ARP) table entries."""
    neighbors: list[NeighborInfo] = []
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True, text=True, timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0:
            return neighbors

        current_iface = ""
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                current_iface = ""
                continue
            if stripped.startswith("Interface:"):
                parts = stripped.split()
                current_iface = parts[1].rstrip(":") if len(parts) > 1 else ""
                continue
            if stripped.startswith("Internet Address") or stripped.startswith("---"):
                continue
            parts = stripped.split()
            if len(parts) >= 3:
                ip = parts[0]
                mac = parts[1]
                state = parts[2] if len(parts) > 2 else ""
                neighbors.append(NeighborInfo(
                    ip=ip,
                    mac=mac,
                    interface=current_iface,
                    state=state,
                ))
    except Exception:
        logger.debug("arp -a failed")

    # Also try Get-NetNeighbor for richer data on PowerShell-capable systems
    try:
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-Command",
                "Get-NetNeighbor -AddressFamily IPv4 | Select-Object IPAddress,LinkLayerAddress,InterfaceAlias,State | ConvertTo-Json -Compress",
            ],
            capture_output=True, text=True, timeout=8,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode == 0 and result.stdout.strip():
            import json
            data = json.loads(result.stdout.strip())
            entries = data if isinstance(data, list) else [data]
            ps_neighbors = []
            for entry in entries:
                ps_neighbors.append(NeighborInfo(
                    ip=entry.get("IPAddress", ""),
                    mac=entry.get("LinkLayerAddress", ""),
                    interface=entry.get("InterfaceAlias", ""),
                    state=entry.get("State", ""),
                ))
            if ps_neighbors:
                return ps_neighbors
    except Exception:
        logger.debug("Get-NetNeighbor failed")

    return neighbors


def _get_neighbors() -> list[NeighborInfo]:
    """Get neighbor table, cached across cycles."""
    global _neighbor_cache, _neighbor_cache_ts
    now = time.monotonic()
    if now - _neighbor_cache_ts < _NEIGHBOR_CACHE_TTL_S and _neighbor_cache:
        return _neighbor_cache
    fresh = _get_neighbors_win()
    if fresh:
        _neighbor_cache = fresh
        _neighbor_cache_ts = now
    return fresh


# ---------------------------------------------------------------------------
# Public IP detection (safe, read-only, single external call)
# ---------------------------------------------------------------------------

_public_ip_cache: str = ""
_public_ip_cache_ts = 0.0
_PUBLIC_IP_CACHE_TTL_S = 120.0


def _get_public_ip() -> str:
    """Retrieve public IP via a safe, read-only external endpoint. Cached for 2 minutes."""
    global _public_ip_cache, _public_ip_cache_ts
    now = time.monotonic()
    if now - _public_ip_cache_ts < _PUBLIC_IP_CACHE_TTL_S and _public_ip_cache:
        return _public_ip_cache

    try:
        import urllib.request
        req = urllib.request.Request(
            "https://api.ipify.org?format=json",
            headers={"User-Agent": "ARGUS-Network-Monitor/1.0"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            import json
            data = json.loads(resp.read().decode())
            ip = data.get("ip", "")
            if ip:
                _public_ip_cache = ip
                _public_ip_cache_ts = now
                return ip
    except Exception:
        logger.debug("Public IP lookup failed")
    return ""


def collect_topology(dns_cache: ReverseDnsCache) -> NetworkTopologySnapshot:
    """Collect a comprehensive network topology snapshot.

    This is the main entry point that aggregates all network data sources
    into a single snapshot. ``dns_cache`` supplies non-blocking reverse-DNS.
    """
    snapshot = NetworkTopologySnapshot()
    snapshot.hostname = _get_hostname()
    snapshot.interfaces = _get_interfaces()
    snapshot.default_gateway = _get_default_gateway()
    snapshot.dns_servers = _get_dns_servers()
    snapshot.connections = _get_connections_with_processes(dns_cache)
    snapshot.neighbors = _get_neighbors()
    snapshot.recompute_stats()

    # Populate neighbor hostnames from DNS cache (non-blocking)
    for neighbor in snapshot.neighbors:
        if neighbor.ip and not neighbor.hostname:
            cached = dns_cache.lookup(neighbor.ip)
            if cached:
                neighbor.hostname = cached

    return snapshot