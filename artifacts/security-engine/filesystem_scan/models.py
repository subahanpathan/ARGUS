"""Filesystem scan models — honest, verifiable scan state.

Two rules shape everything here:

1. **A percentage may only exist when its denominator is measured.** A scan runs
   an inventory phase first which counts the real entries under its roots. Only
   when that count completes within budget does the scan report
   ``total_known = true`` and expose a progress ratio. If the inventory is cut
   short by the entry budget, ``total_known`` stays ``false`` and consumers show
   raw counters with the total marked *unknown*.
2. **Counters are never estimated.** ``files_scanned`` is incremented after a
   real metadata read. ``permission_denied`` is counted separately from generic
   ``errors`` so a restricted tree is never mistaken for a clean one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# Scan state machine.
IDLE = "IDLE"
STARTING = "STARTING"
INVENTORY = "INVENTORY"
SCANNING = "SCANNING"
ANALYZING = "ANALYZING"
COMPLETED = "COMPLETED"
PARTIAL = "PARTIAL"
FAILED = "FAILED"
CANCELLED = "CANCELLED"

VALID_STATES: frozenset[str] = frozenset({
    IDLE, STARTING, INVENTORY, SCANNING, ANALYZING,
    COMPLETED, PARTIAL, FAILED, CANCELLED,
})

TERMINAL_STATES: frozenset[str] = frozenset({COMPLETED, PARTIAL, FAILED, CANCELLED})
ACTIVE_STATES: frozenset[str] = frozenset({STARTING, INVENTORY, SCANNING, ANALYZING})

#: Scan sources. ``filesystem`` walks the tree; ``security_provider`` requests a
#: scan from an integrated product (ARGUS never initiates these itself).
SCAN_FILESYSTEM = "filesystem"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ScanCounters:
    """Mutable counters for one scan."""

    # Inventory phase — the denominator.
    files_discovered: int = 0
    folders_discovered: int = 0
    #: True when the inventory walked every reachable entry (not budget-truncated).
    total_known: bool = False
    inventory_truncated: bool = False

    # Scan phase — the numerator.
    files_scanned: int = 0
    folders_scanned: int = 0
    bytes_scanned: int = 0

    # Honest failure accounting.
    errors: int = 0
    permission_denied: int = 0
    skipped: int = 0

    def progress(self) -> float | None:
        """File progress in ``0..1``, or ``None`` when no denominator exists."""
        if not self.total_known or self.files_discovered <= 0:
            return None
        return min(1.0, self.files_scanned / self.files_discovered)

    def folder_progress(self) -> float | None:
        if not self.total_known or self.folders_discovered <= 0:
            return None
        return min(1.0, self.folders_scanned / self.folders_discovered)

    def to_dict(self) -> dict[str, Any]:
        progress = self.progress()
        folder_progress = self.folder_progress()
        return {
            "files_discovered": self.files_discovered,
            "folders_discovered": self.folders_discovered,
            "files_scanned": self.files_scanned,
            "folders_scanned": self.folders_scanned,
            "bytes_scanned": self.bytes_scanned,
            "errors": self.errors,
            "permission_denied": self.permission_denied,
            "skipped": self.skipped,
            "total_known": self.total_known,
            "inventory_truncated": self.inventory_truncated,
            # ``progress_percent`` is null unless a denominator was measured.
            "progress_percent": None if progress is None else round(progress * 100, 2),
            "folder_progress_percent": (
                None if folder_progress is None else round(folder_progress * 100, 2)
            ),
        }


@dataclass
class ScanRequest:
    """Parameters for one on-demand scan."""

    scan_id: str
    roots: list[str] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)
    entry_budget: int = 250_000
    max_depth: int = 24
    max_workers: int = 4
    follow_symlinks: bool = False
    throttle_seconds: float = 1.0
    scan_type: str = SCAN_FILESYSTEM
    requested_at: str = field(default_factory=now_iso)
    requested_by: str = "api"
    label: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "scan_type": self.scan_type,
            "roots": list(self.roots),
            "exclusions": list(self.exclusions),
            "entry_budget": self.entry_budget,
            "max_depth": self.max_depth,
            "max_workers": self.max_workers,
            "follow_symlinks": self.follow_symlinks,
            "requested_at": self.requested_at,
            "requested_by": self.requested_by,
            "label": self.label,
        }


@dataclass
class FilesystemScanState:
    """Full, serializable state of one scan."""

    scan_id: str
    state: str = IDLE
    scan_type: str = SCAN_FILESYSTEM
    label: str | None = None
    requested_by: str = "api"
    requested_at: str = field(default_factory=now_iso)
    started_at: str | None = None
    updated_at: str | None = None
    completed_at: str | None = None

    counters: ScanCounters = field(default_factory=ScanCounters)

    current_path: str = ""
    current_operation: str = ""
    roots: list[str] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)
    errors_detail: list[str] = field(default_factory=list)
    message: str | None = None

    @property
    def is_active(self) -> bool:
        return self.state in ACTIVE_STATES

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "scan_id": self.scan_id,
            "state": self.state,
            "scan_type": self.scan_type,
            "label": self.label,
            "requested_by": self.requested_by,
            "requested_at": self.requested_at,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
            "completed_at": self.completed_at,
            "current_path": self.current_path,
            "current_operation": self.current_operation,
            "roots": list(self.roots),
            "exclusions": list(self.exclusions),
            "errors_detail": self.errors_detail[:50],
            "message": self.message,
            "is_active": self.is_active,
        }
        payload.update(self.counters.to_dict())
        # Legacy alias so existing consumers keep working.
        payload["permission_denied_count"] = self.counters.permission_denied
        return payload

    def apply(self, payload: dict[str, Any]) -> None:
        """Fold an API-side state update into this record."""
        self.state = str(payload.get("state") or self.state)
        if payload.get("scan_type"):
            self.scan_type = str(payload["scan_type"])
        if payload.get("label") is not None:
            self.label = payload["label"]
        if payload.get("requested_by"):
            self.requested_by = str(payload["requested_by"])
        if payload.get("requested_at"):
            self.requested_at = str(payload["requested_at"])
        if payload.get("started_at") is not None:
            self.started_at = payload["started_at"]
        if payload.get("updated_at") is not None:
            self.updated_at = payload["updated_at"]
        if payload.get("completed_at") is not None:
            self.completed_at = payload["completed_at"]
        if payload.get("current_path") is not None:
            self.current_path = str(payload["current_path"])
        if payload.get("current_operation") is not None:
            self.current_operation = str(payload["current_operation"])
        if isinstance(payload.get("roots"), list):
            self.roots = [str(r) for r in payload["roots"]]
        if isinstance(payload.get("exclusions"), list):
            self.exclusions = [str(r) for r in payload["exclusions"]]
        if isinstance(payload.get("message"), str):
            self.message = payload["message"]

        counters = self.counters
        int_fields = (
            "files_discovered",
            "folders_discovered",
            "files_scanned",
            "folders_scanned",
            "bytes_scanned",
            "errors",
            "skipped",
        )
        for name in int_fields:
            value = payload.get(name)
            if isinstance(value, (int, float)):
                setattr(counters, name, int(value))
        # ``permission_denied`` may arrive under either name depending on producer.
        for name in ("permission_denied", "permission_denied_count"):
            value = payload.get(name)
            if isinstance(value, (int, float)):
                counters.permission_denied = int(value)
                break
        if isinstance(payload.get("total_known"), bool):
            counters.total_known = payload["total_known"]
        if isinstance(payload.get("inventory_truncated"), bool):
            counters.inventory_truncated = payload["inventory_truncated"]


__all__ = [
    "ACTIVE_STATES",
    "ANALYZING",
    "CANCELLED",
    "COMPLETED",
    "FAILED",
    "FilesystemScanState",
    "IDLE",
    "INVENTORY",
    "PARTIAL",
    "SCANNING",
    "SCAN_FILESYSTEM",
    "STARTING",
    "ScanCounters",
    "ScanRequest",
    "TERMINAL_STATES",
    "VALID_STATES",
    "now_iso",
]
