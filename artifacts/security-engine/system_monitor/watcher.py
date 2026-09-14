"""Continuous system telemetry collector — periodic read-only sampling.

Runs in a background daemon thread and invokes a callback with each
collected snapshot. Uses a configurable interval; never blocks the
process monitor, never spins a busy loop, and supports clean shutdown.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable

from .models import TelemetrySnapshot
from .collector import collect_snapshot

logger = logging.getLogger("argus.system_monitor.watcher")


class SystemMonitorWatcher:
    """Periodically samples host telemetry on a background thread."""

    def __init__(
        self,
        interval_ms: int = 1000,
        on_snapshot: Callable[[TelemetrySnapshot], None] | None = None,
    ) -> None:
        self._interval = interval_ms / 1000.0
        self._on_snapshot = on_snapshot
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
        """Start the telemetry sampler in a background daemon thread."""
        if self._running:
            logger.warning("System monitor already running")
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="argus-system-monitor"
        )
        self._thread.start()
        logger.info("System monitor started (interval: %.1fs)", self._interval)

    def stop(self) -> None:
        """Signal the sampler to stop and wait for the thread to exit."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self._interval * 3)
        logger.info(
            "System monitor stopped (snapshots: %d, callback errors: %d)",
            self._snapshot_count,
            self._callback_errors,
        )

    def _loop(self) -> None:
        """Main sampling loop — runs in a daemon thread."""
        while self._running:
            try:
                snapshot = collect_snapshot()
                self._snapshot_count += 1
                if self._on_snapshot is not None:
                    try:
                        self._on_snapshot(snapshot)
                    except Exception:  # noqa: BLE001
                        self._callback_errors += 1
                        logger.exception("Error in telemetry callback")
            except Exception:  # noqa: BLE001
                logger.exception("Error in telemetry sampling cycle")
            time.sleep(self._interval)
