"""Normalized data models for Windows system telemetry.

These models represent a lightweight, read-only snapshot of the host
Windows machine. Every metric is optional so that a single failing
metric (e.g. CPU unavailable) does not invalidate the whole payload.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


@dataclass
class NetworkInterface:
    """Safe state information about a single network interface.

    Only interface state is collected — never packet payloads.
    """

    name: str
    is_up: bool
    is_running: bool = False
    mtu: int | None = None
    speed: int | None = None
    addresses: list[str] = field(default_factory=list)
    bytes_sent: int | None = None
    bytes_recv: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class TelemetrySnapshot:
    """A point-in-time snapshot of system telemetry.

    Every collection block (cpu, memory, disk, processes, system,
    network) is optional so partial failures remain representable.
    """

    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    source: str = "windows_system_monitor"
    observed: bool = True

    cpu: dict[str, Any] | None = None
    memory: dict[str, Any] | None = None
    disk: dict[str, Any] | None = None
    processes: dict[str, Any] | None = None
    system: dict[str, Any] | None = None
    network: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "timestamp": self.timestamp,
            "source": self.source,
            "observed": self.observed,
        }
        if self.cpu is not None:
            d["cpu"] = self.cpu
        if self.memory is not None:
            d["memory"] = self.memory
        if self.disk is not None:
            d["disk"] = self.disk
        if self.processes is not None:
            d["processes"] = self.processes
        if self.system is not None:
            d["system"] = self.system
        if self.network is not None:
            d["network"] = self.network
        return d
