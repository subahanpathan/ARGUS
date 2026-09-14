"""Continuous process watcher — detects starts and terminations via polling."""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable

import psutil

from .models import EventType, ProcessEvent, ProcessInfo
from .snapshot import take_snapshot, _collect_one

logger = logging.getLogger("argus.process_monitor.watcher")


class ProcessWatcher:
    """
    Polls running processes at a configurable interval.
    Detects new process creation and termination events.
    Maintains a parent-child relationship map.
    """

    def __init__(
        self,
        poll_interval_ms: int = 2000,
        on_event: Callable[[ProcessEvent], None] | None = None,
    ) -> None:
        self._poll_interval = poll_interval_ms / 1000.0
        self._on_event = on_event
        self._running = False
        self._thread: threading.Thread | None = None
        self._known_pids: dict[int, ProcessInfo] = {}
        self._lock = threading.Lock()
        self._event_count = 0
        self._callback_errors = 0

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def known_pid_count(self) -> int:
        with self._lock:
            return len(self._known_pids)

    @property
    def event_count(self) -> int:
        return self._event_count

    def get_known_pids(self) -> dict[int, ProcessInfo]:
        """Return a copy of the current known process map."""
        with self._lock:
            return dict(self._known_pids)

    def start(self) -> None:
        """Start the watcher in a background daemon thread."""
        if self._running:
            logger.warning("Watcher already running")
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._poll_loop, daemon=True, name="argus-process-watcher"
        )
        self._thread.start()
        logger.info(
            "Process watcher started (poll interval: %.1fs)", self._poll_interval
        )

    def stop(self) -> None:
        """Signal the watcher to stop and wait for the thread to exit."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self._poll_interval * 3)
        logger.info(
            "Process watcher stopped (events emitted: %d, callback errors: %d)",
            self._event_count,
            self._callback_errors,
        )

    def _poll_loop(self) -> None:
        """Main polling loop — runs in a daemon thread."""
        logger.info("Poll loop starting — initial snapshot")
        initial = take_snapshot()
        with self._lock:
            for p in initial.processes:
                self._known_pids[p.pid] = p

        logger.info(
            "Initial snapshot: %d processes tracked (%d access-denied)",
            len(initial.processes),
            initial.access_denied_count,
        )

        while self._running:
            try:
                self._poll_once()
            except Exception:
                logger.exception("Error in poll cycle")
            time.sleep(self._poll_interval)

    def _poll_once(self) -> None:
        """Single poll cycle: detect new and terminated processes."""
        current_pids: set[int] = set()

        try:
            for proc in psutil.process_iter(["pid"]):
                try:
                    pid = proc.pid
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

                current_pids.add(pid)

                with self._lock:
                    if pid in self._known_pids:
                        continue

                try:
                    info = _collect_one(proc)
                except psutil.NoSuchProcess:
                    logger.debug("PID %d disappeared before collection", pid)
                    continue
                except Exception as e:
                    logger.debug("Error collecting PID %d: %s", pid, e)
                    info = ProcessInfo(pid=pid, name=f"<error-{pid}>", access_error=str(e))

                with self._lock:
                    self._known_pids[pid] = info

                event = ProcessEvent.from_process_info(info, EventType.PROCESS_STARTED)
                self._emit(event)

        except Exception:
            logger.exception("Error iterating processes")

        terminated_pids: list[int] = []
        with self._lock:
            known_snapshot = dict(self._known_pids)

        for pid, info in known_snapshot.items():
            if pid not in current_pids:
                terminated_pids.append(pid)

        for pid in terminated_pids:
            with self._lock:
                info = self._known_pids.pop(pid, None)

            if info is None:
                continue

            event = ProcessEvent.from_process_info(info, EventType.PROCESS_TERMINATED)
            self._emit(event)

    def _emit(self, event: ProcessEvent) -> None:
        """Emit an event to the registered callback."""
        self._event_count += 1
        if self._on_event is None:
            return
        try:
            self._on_event(event)
        except Exception:
            self._callback_errors += 1
            logger.exception("Error in event callback")
