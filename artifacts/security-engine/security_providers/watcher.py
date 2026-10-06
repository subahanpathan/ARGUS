"""Security provider watcher — periodic, bounded observation.

Runs the (relatively expensive) PowerShell/CIM reads on a dedicated daemon
thread at a configurable interval and hands each snapshot to a callback. The
watcher never runs concurrently with itself, so a slow query cannot pile up.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable

from .collector import collect_security_providers
from .models import UNAVAILABLE, SecurityProviderSnapshot

logger = logging.getLogger("argus.security_providers.watcher")


class SecurityProviderWatcher:
    """Periodically collect security-provider state from the endpoint."""

    def __init__(
        self,
        interval_ms: int = 30_000,
        on_snapshot: Callable[[SecurityProviderSnapshot], None] | None = None,
        defender_events_max: int = 120,
        include_registry_corroboration: bool = True,
    ) -> None:
        self._interval_ms = max(5_000, int(interval_ms))
        self._on_snapshot = on_snapshot
        self._defender_events_max = defender_events_max
        self._include_registry = include_registry_corroboration

        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._snapshot: SecurityProviderSnapshot | None = None

        self.snapshot_count = 0
        self.callback_errors = 0
        self.collection_errors = 0

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="argus-security-providers", daemon=True
        )
        self._thread.start()
        logger.info(
            "Security provider watcher started (interval %dms)", self._interval_ms
        )

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=5)
        self._thread = None
        logger.info("Security provider watcher stopped")

    # -- accessors ---------------------------------------------------------

    @property
    def last_snapshot(self) -> SecurityProviderSnapshot | None:
        with self._lock:
            return self._snapshot

    # -- internals ---------------------------------------------------------

    def collect_once(self) -> SecurityProviderSnapshot:
        """Run one collection cycle synchronously."""
        try:
            snapshot = collect_security_providers(
                defender_events_max=self._defender_events_max,
                include_registry_corroboration=self._include_registry,
            )
        except Exception:  # noqa: BLE001
            logger.exception("Security provider collection failed")
            self.collection_errors += 1
            snapshot = SecurityProviderSnapshot(
                timestamp="",
                providers=[],
                alerts=[],
                discovery_state=UNAVAILABLE,
                errors=["collection raised an exception"],
            )
        with self._lock:
            self._snapshot = snapshot
        return snapshot

    def _emit(self, snapshot: SecurityProviderSnapshot) -> None:
        self.snapshot_count += 1
        if self._on_snapshot is None:
            return
        try:
            self._on_snapshot(snapshot)
        except Exception:  # noqa: BLE001
            self.callback_errors += 1
            logger.exception("Security provider callback failed")

    def _loop(self) -> None:
        # Small startup delay so the engine's other collectors settle first.
        if self._stop.wait(2.0):
            return
        while not self._stop.is_set():
            started = time.monotonic()
            self._emit(self.collect_once())
            elapsed = time.monotonic() - started
            remaining = (self._interval_ms / 1000.0) - elapsed
            if remaining > 0:
                self._stop.wait(remaining)
