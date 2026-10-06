"""Periodic filesystem scan cadence.

The watcher owns *when* a scan should happen; it does not own *how*. Scans are
executed by :class:`scan_coordinator.ScanCoordinator` — the single place where
scans actually run — so a scheduled cycle and an operator-requested scan can
never walk the disk at the same time.

``trigger`` is injected. In the agent it enqueues a coordinator request; when it
is omitted the watcher falls back to running the scan inline, which keeps the
class usable standalone.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable

from .models import IDLE, FilesystemScanState, ScanRequest, now_iso
from .scanner import DEFAULT_ENTRY_BUDGET, run_scan

logger = logging.getLogger("argus.filesystem_scan.watcher")


class FilesystemScanWatcher:
    """Fires a scan request on a fixed cadence and reports what happened."""

    def __init__(
        self,
        interval_ms: int = 600000,
        on_update: Callable[[FilesystemScanState], None] | None = None,
        throttle_ms: int = 1000,
        entry_budget: int = DEFAULT_ENTRY_BUDGET,
        max_workers: int = 4,
        max_depth: int = 24,
        trigger: Callable[[], tuple[FilesystemScanState, bool]] | None = None,
        is_busy: Callable[[], bool] | None = None,
    ) -> None:
        self._interval = max(interval_ms, 30000) / 1000.0
        self._on_update = on_update
        self._throttle = max(throttle_ms, 250) / 1000.0
        self._entry_budget = entry_budget
        self._max_workers = max_workers
        self._max_depth = max_depth
        self._trigger = trigger
        self._is_busy = is_busy
        self._running = False
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._last_state: FilesystemScanState = FilesystemScanState(
            scan_id="scheduled", state=IDLE, current_operation="idle", updated_at=now_iso()
        )
        self.cycles_completed = 0
        self.cycles_skipped = 0

    # -- lifecycle ---------------------------------------------------------

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def is_scanning(self) -> bool:
        return self._last_state.is_active

    @property
    def last_state(self) -> FilesystemScanState:
        return self._last_state

    def start(self) -> None:
        if self._running:
            logger.warning("Filesystem scan cadence already running")
            return

        self._stop.clear()
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="argus-fs-scan-cadence"
        )
        self._thread.start()
        logger.info(
            "Filesystem scan cadence started (every %.1fs, throttle %.1fs, budget %d)",
            self._interval,
            self._throttle,
            self._entry_budget,
        )

    def stop(self) -> None:
        self._running = False
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=15)
        self._thread = None
        logger.info(
            "Filesystem scan cadence stopped (cycles=%d skipped=%d)",
            self.cycles_completed,
            self.cycles_skipped,
        )

    # -- reporting ---------------------------------------------------------

    def describe(self) -> dict[str, Any]:
        return {
            "running": self._running,
            "interval_seconds": self._interval,
            "throttle_seconds": self._throttle,
            "entry_budget": self._entry_budget,
            "max_depth": self._max_depth,
            "max_workers": self._max_workers,
            "executes_scans": self._trigger is None,
            "cycles_completed": self.cycles_completed,
            "cycles_skipped": self.cycles_skipped,
            "last_state": self._last_state.to_dict(),
        }

    def _emit(self, state: FilesystemScanState) -> None:
        self._last_state = state
        if self._on_update is not None:
            try:
                self._on_update(state)
            except Exception:  # noqa: BLE001
                logger.exception("Error in filesystem scan update callback")

    # -- loop --------------------------------------------------------------

    def _idle(self, operation: str) -> None:
        self._emit(
            FilesystemScanState(
                scan_id="scheduled",
                state=IDLE,
                requested_by="scheduler",
                label="scheduled filesystem scan",
                updated_at=now_iso(),
                current_operation=operation,
            )
        )

    def _loop(self) -> None:
        first = True
        while not self._stop.is_set():
            if not first:
                self._idle("waiting_for_next_cycle")
                if self._stop.wait(self._interval):
                    return
            first = False

            if self._is_busy is not None and self._is_busy():
                # Another scan already owns the disk; do not queue a duplicate.
                self.cycles_skipped += 1
                self._idle("skipped_scan_already_running")
                continue

            if self._trigger is not None:
                try:
                    state, started = self._trigger()
                except Exception:  # noqa: BLE001
                    logger.exception("Scheduled scan trigger failed")
                    self.cycles_skipped += 1
                    self._idle("trigger_failed")
                    continue
                self.cycles_completed += 1
                logger.info(
                    "Scheduled scan request %s (scan_id=%s state=%s)",
                    "started" if started else "folded into active scan",
                    state.scan_id,
                    state.state,
                )
                continue

            # Standalone mode: run the scan inline on this thread.
            request = ScanRequest(
                scan_id="scheduled",
                entry_budget=self._entry_budget,
                max_depth=self._max_depth,
                max_workers=self._max_workers,
                throttle_seconds=self._throttle,
                requested_by="scheduler",
                label="scheduled filesystem scan",
                requested_at=now_iso(),
            )
            final = run_scan(
                request=request, cancel=self._stop, on_progress=self._emit
            )
            self.cycles_completed += 1
            logger.info(
                "Scheduled filesystem scan finished (state=%s files_scanned=%d "
                "files_discovered=%d total_known=%s)",
                final.state,
                final.counters.files_scanned,
                final.counters.files_discovered,
                final.counters.total_known,
            )


__all__ = ["FilesystemScanWatcher"]
