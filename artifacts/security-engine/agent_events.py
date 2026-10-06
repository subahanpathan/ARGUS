"""Normalized monitoring events produced by the ARGUS Endpoint Agent.

Every observation the agent makes — a process start, a file write, a port
opening, a service state change, a security-provider alert, a scan transition —
is representable in one shape so the API can order, deduplicate, correlate and
stream them without special-casing each source.

Field discipline:

* ``eventId``     stable, derived from source + native identity + timestamp
* ``timestamp``   always the observation time, never a placeholder
* ``severity``    ``None`` when the observation carries no severity
* ``evidence``    the observed facts (paths, pids, ports, provider fields)
* ``metadata``    bounded, non-sensitive context only
* ``correlationId`` present when the event belongs to a scan or a provider alert
"""

from __future__ import annotations

import hashlib
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Event types
# ---------------------------------------------------------------------------
PROCESS_STARTED = "PROCESS_STARTED"
PROCESS_STOPPED = "PROCESS_STOPPED"
PROCESS_CHANGED = "PROCESS_CHANGED"
NETWORK_CONNECTED = "NETWORK_CONNECTED"
NETWORK_DISCONNECTED = "NETWORK_DISCONNECTED"
PORT_OPENED = "PORT_OPENED"
PORT_CLOSED = "PORT_CLOSED"
PORT_CHANGED = "PORT_CHANGED"
FILE_CREATED = "FILE_CREATED"
FILE_MODIFIED = "FILE_MODIFIED"
FILE_RENAMED = "FILE_RENAMED"
FILE_DELETED = "FILE_DELETED"
FILE_DIRECTORY_CHANGED = "FILE_DIRECTORY_CHANGED"
SCAN_STARTED = "SCAN_STARTED"
SCAN_PROGRESS = "SCAN_PROGRESS"
SCAN_COMPLETED = "SCAN_COMPLETED"
SCAN_FAILED = "SCAN_FAILED"
SERVICE_STARTED = "SERVICE_STARTED"
SERVICE_STOPPED = "SERVICE_STOPPED"
SERVICE_CHANGED = "SERVICE_CHANGED"
SECURITY_PROVIDER_ALERT = "SECURITY_PROVIDER_ALERT"
SECURITY_PROVIDER_STATE_CHANGED = "SECURITY_PROVIDER_STATE_CHANGED"
TELEMETRY_DEGRADED = "TELEMETRY_DEGRADED"
TELEMETRY_RECOVERED = "TELEMETRY_RECOVERED"
CONNECTION_STATE_CHANGED = "CONNECTION_STATE_CHANGED"

#: Scan state -> lifecycle event type.
_SCAN_STATE_EVENTS: dict[str, str] = {
    "STARTING": SCAN_STARTED,
    "INVENTORY": SCAN_STARTED,
    "SCANNING": SCAN_PROGRESS,
    "ANALYZING": SCAN_PROGRESS,
    "COMPLETED": SCAN_COMPLETED,
    "PARTIAL": SCAN_COMPLETED,
    "FAILED": SCAN_FAILED,
    "CANCELLED": SCAN_PROGRESS,
}

_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})

#: Maximum metadata payload carried on a single event (bytes when serialized).
MAX_METADATA_BYTES = 4096


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_event_id(source: str, native_id: str, timestamp: str) -> str:
    """Deterministic id so a redelivered event is recognisably the same one."""
    digest = hashlib.sha256(f"{source}|{native_id}|{timestamp}".encode("utf-8")).hexdigest()
    return f"{source}-{digest[:20]}"


def _bound_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    """Clamp metadata so one noisy field cannot blow up a delivery."""
    if not metadata:
        return {}
    bounded: dict[str, Any] = {}
    size = 0
    for key, value in metadata.items():
        if value is None:
            continue
        try:
            encoded = len(f"{key}={value}".encode("utf-8", "replace"))
        except Exception:  # noqa: BLE001
            continue
        if size + encoded > MAX_METADATA_BYTES:
            break
        bounded[key] = value if isinstance(value, (int, float, bool)) else str(value)[:512]
        size += encoded
    return bounded


@dataclass
class MonitoringEvent:
    """One normalized observation."""

    event_type: str
    source: str
    entity_kind: str
    entity_id: str
    entity_name: str = ""
    timestamp: str = field(default_factory=now_iso)
    severity: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    correlation_id: str | None = None
    event_id: str = ""

    def __post_init__(self) -> None:
        if self.severity is not None and self.severity not in _SEVERITIES:
            self.severity = "info"
        self.evidence = self.evidence or {}
        self.metadata = _bound_metadata(self.metadata)
        if not self.event_id:
            native = f"{self.entity_kind}:{self.entity_id}"
            self.event_id = make_event_id(self.source, native, self.timestamp)

    def to_dict(self) -> dict[str, Any]:
        return {
            "eventId": self.event_id,
            "timestamp": self.timestamp,
            "eventType": self.event_type,
            "source": self.source,
            "entity": {
                "kind": self.entity_kind,
                "id": self.entity_id,
                "name": self.entity_name,
            },
            "severity": self.severity,
            "evidence": self.evidence,
            "metadata": self.metadata,
            "correlationId": self.correlation_id,
        }


class EventBatcher:
    """Bounded, thread-safe buffer that batches events for delivery.

    Keeps the agent's outbound rate predictable: producers never block on the
    network, and a burst is flushed in one request.
    """

    def __init__(self, max_events: int = 250, max_wait_seconds: float = 1.0) -> None:
        self._events: deque[MonitoringEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()
        self._max_wait = max_wait_seconds
        self._first_at: float | None = None
        self._dropped = 0

    def add(self, event: MonitoringEvent) -> None:
        import time

        now = time.monotonic()
        with self._lock:
            if len(self._events) == self._events.maxlen and self._events.maxlen:
                self._dropped += 1
            self._events.append(event)
            if self._first_at is None:
                self._first_at = now

    def extend(self, events: list[MonitoringEvent]) -> None:
        for event in events:
            self.add(event)

    def should_flush(self) -> bool:
        import time

        with self._lock:
            if not self._events:
                return False
            assert self._first_at is not None
            return (time.monotonic() - self._first_at) >= self._max_wait

    def drain(self, limit: int = 250) -> list[MonitoringEvent]:
        with self._lock:
            count = min(limit, len(self._events))
            batch = [self._events.popleft() for _ in range(count)]
            if not self._events:
                self._first_at = None
            return batch

    @property
    def pending(self) -> int:
        with self._lock:
            return len(self._events)

    @property
    def dropped(self) -> int:
        return self._dropped


# ---------------------------------------------------------------------------
# Builders — one per agent subsystem
# ---------------------------------------------------------------------------


def file_change_event(
    kind: str, change: Any, correlation_id: str | None = None
) -> MonitoringEvent:
    payload = change.to_dict() if hasattr(change, "to_dict") else dict(change)
    return MonitoringEvent(
        event_type=kind,
        source="filesystem_watch",
        entity_kind="file",
        entity_id=payload.get("path") or payload.get("name") or "unknown",
        entity_name=payload.get("name") or "",
        timestamp=payload.get("timestamp") or now_iso(),
        severity="medium" if (payload.get("extension") or "") in _EXECUTABLE_EXTENSIONS else "info",
        evidence={
            "path": payload.get("path"),
            "old_path": payload.get("old_path"),
            "root": payload.get("root"),
            "is_directory": payload.get("is_directory"),
            "size_bytes": payload.get("size_bytes"),
            "extension": payload.get("extension"),
            "created_at": payload.get("created_at"),
            "modified_at": payload.get("modified_at"),
        },
        metadata={"contents_read": False, "observation": "filesystem metadata only"},
        correlation_id=correlation_id,
    )


_EXECUTABLE_EXTENSIONS = frozenset(
    {".exe", ".dll", ".sys", ".scr", ".ps1", ".vbs", ".js", ".jse", ".bat", ".cmd", ".hta", ".msi", ".jar"}
)


def scan_state_event(state: Any) -> MonitoringEvent:
    """Translate a scan state transition into a lifecycle event."""
    payload = state.to_dict() if hasattr(state, "to_dict") else dict(state)
    scan_state = str(payload.get("state") or "").upper()
    event_type = _SCAN_STATE_EVENTS.get(scan_state, SCAN_PROGRESS)

    severity: str | None = None
    if event_type == SCAN_FAILED:
        severity = "high"
    elif scan_state in ("COMPLETED", "PARTIAL", "CANCELLED", "FAILED"):
        severity = "info"

    return MonitoringEvent(
        event_type=event_type,
        source="filesystem_scan",
        entity_kind="scan",
        entity_id=str(payload.get("scan_id") or "scan"),
        entity_name=str(payload.get("label") or "filesystem scan"),
        timestamp=str(payload.get("updated_at") or now_iso()),
        severity=severity,
        evidence={
            "scan_state": scan_state,
            "scan_type": payload.get("scan_type"),
            "started_at": payload.get("started_at"),
            "completed_at": payload.get("completed_at"),
            "files_discovered": payload.get("files_discovered"),
            "files_scanned": payload.get("files_scanned"),
            "folders_discovered": payload.get("folders_discovered"),
            "folders_scanned": payload.get("folders_scanned"),
            "bytes_scanned": payload.get("bytes_scanned"),
            "errors": payload.get("errors"),
            "permission_denied": payload.get("permission_denied"),
            "skipped": payload.get("skipped"),
            "total_known": payload.get("total_known"),
            "progress_percent": payload.get("progress_percent"),
            "current_path": payload.get("current_path"),
            "current_operation": payload.get("current_operation"),
            "roots": payload.get("roots"),
        },
        metadata={
            "requested_by": payload.get("requested_by"),
            "message": payload.get("message"),
        },
        correlation_id=str(payload.get("scan_id") or "scan"),
    )


def provider_alert_event(alert: Any) -> MonitoringEvent:
    payload = alert.to_dict() if hasattr(alert, "to_dict") else dict(alert)
    kind = str(payload.get("kind") or "OPERATIONAL").upper()
    is_detection = kind == "DETECTION"
    return MonitoringEvent(
        event_type=(
            SECURITY_PROVIDER_ALERT if is_detection else SECURITY_PROVIDER_STATE_CHANGED
        ),
        source="security_provider",
        entity_kind="security_provider",
        entity_id=str(payload.get("provider_id") or "unknown"),
        entity_name=str(payload.get("provider_name") or ""),
        timestamp=str(payload.get("timestamp") or now_iso()),
        severity=str(payload.get("severity") or "info"),
        evidence={
            "provider_id": payload.get("provider_id"),
            "provider_name": payload.get("provider_name"),
            "kind": kind,
            "title": payload.get("title"),
            "detail": payload.get("detail"),
            "resources": payload.get("resources") or [],
            "process_name": payload.get("process_name"),
        },
        metadata={"provider_raw": payload.get("raw") or {}},
        correlation_id=str(payload.get("alert_id") or payload.get("provider_id") or ""),
    )


__all__ = [
    "CONNECTION_STATE_CHANGED",
    "EventBatcher",
    "FILE_CREATED",
    "FILE_DELETED",
    "FILE_DIRECTORY_CHANGED",
    "FILE_MODIFIED",
    "FILE_RENAMED",
    "MonitoringEvent",
    "NETWORK_CONNECTED",
    "NETWORK_DISCONNECTED",
    "PORT_CHANGED",
    "PORT_CLOSED",
    "PORT_OPENED",
    "PROCESS_CHANGED",
    "PROCESS_STARTED",
    "PROCESS_STOPPED",
    "SCAN_COMPLETED",
    "SCAN_FAILED",
    "SCAN_PROGRESS",
    "SCAN_STARTED",
    "SECURITY_PROVIDER_ALERT",
    "SECURITY_PROVIDER_STATE_CHANGED",
    "SERVICE_CHANGED",
    "SERVICE_STARTED",
    "SERVICE_STOPPED",
    "TELEMETRY_DEGRADED",
    "TELEMETRY_RECOVERED",
    "file_change_event",
    "make_event_id",
    "now_iso",
    "provider_alert_event",
    "scan_state_event",
]
