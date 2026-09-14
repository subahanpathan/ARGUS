"""Normalized data models for process monitoring events."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class EventType(str, Enum):
    PROCESS_STARTED = "PROCESS_STARTED"
    PROCESS_TERMINATED = "PROCESS_TERMINATED"
    SNAPSHOT = "SNAPSHOT"


@dataclass
class ProcessInfo:
    """Normalized information about a single running process."""

    pid: int
    name: str
    executable_path: str | None = None
    command_line: str | None = None
    parent_pid: int | None = None
    parent_name: str | None = None
    creation_time: str | None = None
    cpu_percent: float | None = None
    memory_bytes: int | None = None
    memory_percent: float | None = None
    username: str | None = None
    status: str | None = None
    integrity: str | None = None
    access_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class ProcessEvent:
    """A normalized process event (start/terminate/snapshot)."""

    event_type: EventType
    pid: int
    process_name: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    executable_path: str | None = None
    command_line: str | None = None
    parent_pid: int | None = None
    parent_process_name: str | None = None
    source: str = "windows_process_monitor"
    observed: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp,
            "pid": self.pid,
            "process_name": self.process_name,
            "source": self.source,
            "observed": self.observed,
        }
        if self.executable_path is not None:
            d["executable_path"] = self.executable_path
        if self.command_line is not None:
            d["command_line"] = self.command_line
        if self.parent_pid is not None:
            d["parent_pid"] = self.parent_pid
        if self.parent_process_name is not None:
            d["parent_process_name"] = self.parent_process_name
        if self.metadata:
            d["metadata"] = self.metadata
        return d

    @classmethod
    def from_process_info(cls, info: ProcessInfo, event_type: EventType) -> ProcessEvent:
        return cls(
            event_type=event_type,
            pid=info.pid,
            process_name=info.name,
            executable_path=info.executable_path,
            command_line=info.command_line,
            parent_pid=info.parent_pid,
            parent_process_name=info.parent_name,
            metadata={
                k: v
                for k, v in {
                    "cpu_percent": info.cpu_percent,
                    "memory_bytes": info.memory_bytes,
                    "memory_percent": info.memory_percent,
                    "username": info.username,
                    "status": info.status,
                    "integrity": info.integrity,
                    "access_error": info.access_error,
                }.items()
                if v is not None
            },
        )


@dataclass
class ProcessSnapshot:
    """A point-in-time collection of all observed processes."""

    processes: list[ProcessInfo]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_count: int = 0
    access_denied_count: int = 0

    def __post_init__(self) -> None:
        self.total_count = len(self.processes)
        self.access_denied_count = sum(1 for p in self.processes if p.access_error)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "total_count": self.total_count,
            "access_denied_count": self.access_denied_count,
            "processes": [p.to_dict() for p in self.processes],
        }
