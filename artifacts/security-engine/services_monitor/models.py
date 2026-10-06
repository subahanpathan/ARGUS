"""Normalized models for Windows service observation.

Service state is read-only metadata only: name, display name, status and
startup type. No credentials, configurations or sensitive data are read.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


@dataclass
class ServiceInfo:
    """A single observed Windows service."""

    name: str
    status: str = "unknown"  # running | stopped | paused | starting | stopping | unknown
    startup_type: str = "unknown"  # automatic | manual | disabled | boot | system | unknown
    display_name: str = ""
    pid: int | None = None  # owning process PID when the service is running
    executable_path: str = ""
    access_error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None and v != ""}


@dataclass
class ServicesSnapshot:
    """A point-in-time snapshot of all observed services."""

    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    source: str = "windows_service_monitor"
    observed: bool = True
    services: list[ServiceInfo] = field(default_factory=list)
    total_count: int = 0
    running_count: int = 0
    stopped_count: int = 0
    access_denied_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "source": self.source,
            "observed": self.observed,
            "total_count": self.total_count,
            "running_count": self.running_count,
            "stopped_count": self.stopped_count,
            "access_denied_count": self.access_denied_count,
            "services": [s.to_dict() for s in self.services],
        }