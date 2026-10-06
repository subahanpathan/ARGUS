"""ARGUS Endpoint Agent — filesystem scan subsystem.

Read-only, bounded, cancellable filesystem observation:

* :mod:`.scanner` — the real two-phase walk (inventory → metadata scan)
* :mod:`.scan_coordinator` — single-flight on-demand scan orchestration
* :mod:`.watcher` — the scheduled observation cadence
* :mod:`.models` — the scan state machine and honest counters

Progress percentages are only ever produced from a *measured* denominator.
"""

from __future__ import annotations

from .models import (
    ACTIVE_STATES,
    ANALYZING,
    CANCELLED,
    COMPLETED,
    FAILED,
    FilesystemScanState,
    IDLE,
    INVENTORY,
    PARTIAL,
    SCANNING,
    SCAN_FILESYSTEM,
    STARTING,
    TERMINAL_STATES,
    VALID_STATES,
    ScanCounters,
    ScanRequest,
    now_iso,
)
from .scan_coordinator import ScanCoordinator, new_scan_id
from .scanner import (
    DEFAULT_ENTRY_BUDGET,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_WORKERS,
    resolve_default_scan_roots,
    resolve_scan_roots,
    run_filesystem_scan,
    run_scan,
)
from .watcher import FilesystemScanWatcher

__all__ = [
    "ACTIVE_STATES",
    "ANALYZING",
    "CANCELLED",
    "COMPLETED",
    "DEFAULT_ENTRY_BUDGET",
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_MAX_WORKERS",
    "FAILED",
    "FilesystemScanState",
    "FilesystemScanWatcher",
    "IDLE",
    "INVENTORY",
    "PARTIAL",
    "SCANNING",
    "SCAN_FILESYSTEM",
    "STARTING",
    "ScanCoordinator",
    "ScanCounters",
    "ScanRequest",
    "TERMINAL_STATES",
    "VALID_STATES",
    "new_scan_id",
    "now_iso",
    "resolve_default_scan_roots",
    "resolve_scan_roots",
    "run_filesystem_scan",
    "run_scan",
]
