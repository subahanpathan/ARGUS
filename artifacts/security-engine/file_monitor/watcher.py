"""Continuous filesystem threat monitor — periodic read-only scanning.

Runs in a background daemon thread and invokes a callback with each
completed scan snapshot. Mirrors the other watcher implementations so the
engine lifecycle (start/stop/graceful shutdown) stays uniform.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable

from .models import FileScanSnapshot
from .scanner import scan_files

logger = logging.getLogger("argus.file_monitor.watcher")


class FileMonitorWatcher:
    """Periodically scans user-writable locations for file threats."""

    def __init__(
        self,
        interval_ms: int = 15000,
        on_snapshot: Callable[[FileScanSnapshot], None] | None = None,
        running_paths_provider: Callable[[], set[str]] | None = None,
    ) -> None:
        self._interval = max(interval_ms, 1000) / 1000.0
        self._on_snapshot = on_snapshot
        self._running_paths_provider = running_paths_provider
        self._running = False
        self._thread: threading.Thread | None = None
        self._snapshot_count = 0
        self._callback_errors = 0

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def snapshot_count(self) -> int:
        return self._snapshot_count

    @property
    def callback_errors(self) -> int:
        return self._callback_errors

    def start(self) -> None:
        """Start the filesystem scanner in a background daemon thread."""
        if self._running:
            logger.warning("File monitor already running")
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="argus-file-monitor"
        )
        self._thread.start()
        logger.info("File monitor started (interval: %.1fs)", self._interval)

    def stop(self) -> None:
        """Signal the scanner to stop and wait for the thread to exit."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self._interval * 3)
        logger.info(
            "File monitor stopped (snapshots: %d, callback errors: %d)",
            self._snapshot_count,
            self._callback_errors,
        )

    def _loop(self) -> None:
        """Main scanning loop — runs in a daemon thread."""
        while self._running:
            started = time.monotonic()
            try:
                running = (
                    self._running_paths_provider() if self._running_paths_provider else None
                )
                snapshot = scan_files(running)
                self._snapshot_count += 1
                if self._on_snapshot is not None:
                    try:
                        self._on_snapshot(snapshot)
                    except Exception:  # noqa: BLE001
                        self._callback_errors += 1
                        logger.exception("Error in file scan callback")
            except Exception:  # noqa: BLE001
                logger.exception("Error in file scanning cycle")

            elapsed = time.monotonic() - started
            delay = max(0.0, self._interval - elapsed)
            time.sleep(delay)