"""Continuous network connection monitor — periodic read-only sampling.

Runs in a background daemon thread and invokes a callback with each
collected snapshot. Detects new and terminated connections across
sampling cycles.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable

from .models import NetworkConnection, NetworkSnapshot
from .collector import collect_connections

logger = logging.getLogger("argus.network_monitor.watcher")


class NetworkMonitorWatcher:
    """Periodically samples network connections on a background thread."""

    def __init__(
        self,
        interval_ms: int = 3000,
        on_snapshot: Callable[[NetworkSnapshot], None] | None = None,
    ) -> None:
        self._interval = interval_ms / 1000.0
        self._on_snapshot = on_snapshot
        self._running = False
        self._thread: threading.Thread | None = None
        self._snapshot_count = 0
        self._callback_errors = 0
        self._previous_connections: set[str] = set()
        self._lock = threading.Lock()

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
        """Start the network sampler in a background daemon thread."""
        if self._running:
            logger.warning("Network monitor already running")
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="argus-network-monitor"
        )
        self._thread.start()
        logger.info("Network monitor started (interval: %.1fs)", self._interval)

    def stop(self) -> None:
        """Signal the sampler to stop and wait for the thread to exit."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self._interval * 3)
        logger.info(
            "Network monitor stopped (snapshots: %d, callback errors: %d)",
            self._snapshot_count,
            self._callback_errors,
        )

    def _connection_key(self, conn: NetworkConnection) -> str:
        """Create a unique key for a connection to detect changes."""
        return f"{conn.process}:{conn.local_addr}:{conn.local_port}:{conn.remote_addr}:{conn.remote_port}:{conn.status}"

    def _loop(self) -> None:
        """Main sampling loop — runs in a daemon thread."""
        while self._running:
            try:
                snapshot = collect_connections()
                self._snapshot_count += 1
                if self._on_snapshot is not None:
                    try:
                        self._on_snapshot(snapshot)
                    except Exception:  # noqa: BLE001
                        self._callback_errors += 1
                        logger.exception("Error in network snapshot callback")
            except Exception:  # noqa: BLE001
                logger.exception("Error in network sampling cycle")
            time.sleep(self._interval)
