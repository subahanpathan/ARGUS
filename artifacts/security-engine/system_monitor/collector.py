"""Collection of read-only Windows system telemetry.

Uses psutil to gather CPU, memory, disk, system uptime, and network
interface state. All collection is wrapped so that a single failing
metric produces ``None`` for that block rather than crashing the engine.

Only system-level metadata is collected. No credentials, cookies,
browser data, personal content, or file contents are ever inspected.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable

import psutil

from .models import NetworkInterface, TelemetrySnapshot

logger = logging.getLogger("argus.system_monitor.collector")


def _safe(fn: Callable[[], Any], default: Any = None) -> Any:
    """Run a collector function, returning a default on any failure."""
    try:
        return fn()
    except Exception:  # noqa: BLE001
        logger.exception("System metric collection failed")
        return default


def collect_cpu(interval: float = 0.0) -> dict[str, Any] | None:
    """Collect CPU utilization and core counts."""
    try:
        percent = psutil.cpu_percent(interval=interval)
        count = psutil.cpu_count(logical=True) or 0
        physical = psutil.cpu_count(logical=False)
    except Exception:  # noqa: BLE001
        logger.exception("CPU collection failed")
        return None

    result: dict[str, Any] = {
        "percent": round(float(percent), 1),
        "count": int(count),
    }
    if physical:
        result["physical_count"] = int(physical)
    return result


def collect_memory() -> dict[str, Any] | None:
    """Collect real and available memory in bytes."""
    try:
        vm = psutil.virtual_memory()
    except Exception:  # noqa: BLE001
        logger.exception("Memory collection failed")
        return None

    return {
        "total_bytes": int(vm.total),
        "available_bytes": int(vm.available),
        "used_bytes": int(vm.used),
        "percent": round(float(vm.percent), 1),
    }


def _detect_system_drive() -> str:
    """Dynamically detect the Windows system drive (best effort)."""
    try:
        import os

        system_root = os.environ.get("SystemDrive")
        if system_root:
            return system_root.rstrip("\\") + "\\"
    except Exception:  # noqa: BLE001
        pass
    return "C:\\"


def collect_disk() -> dict[str, Any] | None:
    """Collect filesystem usage for the system drive."""
    mount = _detect_system_drive()
    try:
        usage = psutil.disk_usage(mount)
    except Exception:  # noqa: BLE001
        logger.exception("Disk usage collection failed for %s", mount)
        # Try common fallback locations if the system drive is unavailable
        for fallback in ("C:\\", "D:\\"):
            if fallback != mount:
                try:
                    usage = psutil.disk_usage(fallback)
                    mount = fallback
                    break
                except Exception:  # noqa: BLE001
                    continue
        else:
            return None

    return {
        "mount": mount,
        "total_bytes": int(usage.total),
        "used_bytes": int(usage.used),
        "free_bytes": int(usage.free),
        "percent": round(float(usage.percent), 1),
    }


def collect_process_count() -> dict[str, Any] | None:
    """Count running processes by PID enumeration."""
    try:
        running = len(psutil.pids())
    except Exception:  # noqa: BLE001
        logger.exception("Process count collection failed")
        return None
    return {"running": int(running)}


def collect_system_uptime() -> dict[str, Any] | None:
    """Compute uptime from the real system boot time."""
    try:
        boot_time = psutil.boot_time()  # epoch seconds (UTC)
    except Exception:  # noqa: BLE001
        logger.exception("Uptime collection failed")
        return None

    uptime_seconds = max(0.0, time.time() - boot_time)
    return {
        "uptime_seconds": int(uptime_seconds),
        "boot_time": boot_time,
    }


def _safe_iface_bytes(bu: Any, name: str) -> tuple[int | None, int | None]:
    """Safely extract cumulative bytes sent/received for an interface."""
    try:
        sent = getattr(bu, "bytes_sent", None)
        recv = getattr(bu, "bytes_recv", None)
        return (
            int(sent) if sent is not None else None,
            int(recv) if recv is not None else None,
        )
    except Exception:  # noqa: BLE001
        return None, None


def collect_network() -> dict[str, Any] | None:
    """Collect network interface state (up/down + cumulative bytes).

    Interface state only — no packet payloads, no credentials.
    """
    try:
        if_addrs = psutil.net_if_addrs()
        if_stats = psutil.net_if_stats()
    except Exception:  # noqa: BLE001
        logger.exception("Network interface collection failed")
        return None

    try:
        io_counters = psutil.net_io_counters(pernic=True)
    except Exception:  # noqa: BLE001
        io_counters = None

    interfaces: list[NetworkInterface] = []
    # Also include interfaces with stats but no addresses (e.g. virtio)
    names = set(if_addrs.keys()) | set(if_stats.keys())
    for name in sorted(names):
        stats = if_stats.get(name)
        is_up = bool(stats and stats.isup)

        addresses: list[str] = []
        for addr in if_addrs.get(name, []):
            if addr.family.name in ("AF_INET", "AF_INET6") and addr.address:
                addresses.append(addr.address)

        bytes_sent: int | None = None
        bytes_recv: int | None = None
        if io_counters and name in io_counters:
            bytes_sent, bytes_recv = _safe_iface_bytes(io_counters[name], name)

        interfaces.append(
            NetworkInterface(
                name=name,
                is_up=is_up,
                is_running=bool(stats and stats.isup),
                mtu=int(stats.mtu) if stats else None,
                speed=int(stats.speed) if stats and stats.speed else None,
                addresses=addresses,
                bytes_sent=bytes_sent,
                bytes_recv=bytes_recv,
            )
        )

    active_count = sum(1 for i in interfaces if i.is_up)
    return {
        "interfaces": [i.to_dict() for i in interfaces],
        "active_count": active_count,
        "total_count": len(interfaces),
    }


def collect_snapshot(cpu_interval: float = 0.0) -> TelemetrySnapshot:
    """Collect a full telemetry snapshot. Failing metric -> None block."""
    snapshot = TelemetrySnapshot()
    snapshot.cpu = _safe(lambda: collect_cpu(cpu_interval))
    snapshot.memory = _safe(lambda: collect_memory())
    snapshot.disk = _safe(lambda: collect_disk())
    snapshot.processes = _safe(lambda: collect_process_count())
    snapshot.system = _safe(lambda: collect_system_uptime())
    snapshot.network = _safe(lambda: collect_network())
    return snapshot
