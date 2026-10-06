"""On-demand scan coordination for the ARGUS Endpoint Agent.

Responsibilities:

* accept an explicit scan request (roots, exclusions, budget, depth, workers)
* guarantee only one scan runs at a time — a second request returns the active
  scan instead of starting a duplicate walk
* honour cancellation at the next filesystem entry
* publish every state transition so the API can stream real progress
* keep a bounded history so the API can answer "what happened to that scan"

A scan never runs on the API thread: work happens on a dedicated thread so the
HTTP listener and the SSE stream stay responsive while a scan is in flight.
"""

from __future__ import annotations

import logging
import threading
import uuid
from collections import OrderedDict
from typing import Any, Callable

from .models import (
    ACTIVE_STATES,
    CANCELLED,
    COMPLETED,
    FAILED,
    FilesystemScanState,
    IDLE,
    PARTIAL,
    STARTING,
    ScanRequest,
    now_iso,
)
from .scanner import (
    DEFAULT_ENTRY_BUDGET,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_WORKERS,
    run_scan,
)

logger = logging.getLogger("argus.filesystem_scan.coordinator")

MAX_HISTORY = 25


def new_scan_id() -> str:
    return f"scan-{uuid.uuid4().hex[:16]}"


class ScanCoordinator:
    """Single-flight, cancellable scan executor."""

    def __init__(
        self,
        on_state: Callable[[FilesystemScanState], None] | None = None,
        on_event: Callable[[str, FilesystemScanState], None] | None = None,
        entry_budget: int = DEFAULT_ENTRY_BUDGET,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_workers: int = DEFAULT_MAX_WORKERS,
        throttle_seconds: float = 1.0,
        history: int = MAX_HISTORY,
    ) -> None:
        self._on_state = on_state
        self._on_event = on_event
        self._entry_budget = entry_budget
        self._max_depth = max_depth
        self._max_workers = max_workers
        self._throttle = throttle_seconds
        self._history_limit = max(1, history)

        self._lock = threading.RLock()
        self._active: FilesystemScanState | None = None
        self._active_cancel: threading.Event | None = None
        self._active_thread: threading.Thread | None = None
        self._cancel_requested: set[str] = set()
        self._history: "OrderedDict[str, FilesystemScanState]" = OrderedDict()
        self._scans_started = 0
        self._scans_completed = 0
        self._scans_failed = 0
        self._scans_cancelled = 0
        self._duplicate_requests = 0

    # -- introspection -----------------------------------------------------

    @property
    def active_scan(self) -> FilesystemScanState | None:
        with self._lock:
            if self._active is None:
                return None
            # Return a copy so callers cannot mutate coordinator state.
            return self._active

    def describe(self) -> dict[str, Any]:
        with self._lock:
            active = self._active
            return {
                "scans_started": self._scans_started,
                "scans_completed": self._scans_completed,
                "scans_failed": self._scans_failed,
                "scans_cancelled": self._scans_cancelled,
                "duplicate_requests": self._duplicate_requests,
                "active_scan_id": active.scan_id if active else None,
                "history_size": len(self._history),
                "supported_scan_types": ["filesystem"],
                "supported_operations": ["scan", "cancel"],
            }

    def get(self, scan_id: str) -> FilesystemScanState | None:
        with self._lock:
            if self._active is not None and self._active.scan_id == scan_id:
                return self._active
            return self._history.get(scan_id)

    def list_scans(self, limit: int = 25) -> list[FilesystemScanState]:
        with self._lock:
            items = list(self._history.values())
            if self._active is not None:
                items.append(self._active)
            items.sort(key=lambda s: s.requested_at or "", reverse=True)
            return items[: max(1, limit)]

    # -- command surface ---------------------------------------------------

    def request_scan(
        self,
        roots: list[str] | None = None,
        exclusions: list[str] | None = None,
        entry_budget: int | None = None,
        max_depth: int | None = None,
        max_workers: int | None = None,
        label: str | None = None,
        requested_by: str = "api",
    ) -> tuple[FilesystemScanState, bool]:
        """Start a scan, or return the already-running one.

        Returns ``(state, started)``. ``started`` is ``False`` when a scan was
        already active and the duplicate request was folded into it.
        """
        with self._lock:
            if self._active is not None and self._active.is_active:
                self._duplicate_requests += 1
                logger.info(
                    "Scan %s already active; request folded in",
                    self._active.scan_id,
                )
                return self._active, False

            request = ScanRequest(
                scan_id=new_scan_id(),
                roots=list(roots or []),
                exclusions=list(exclusions or []),
                entry_budget=self._clamp(entry_budget or self._entry_budget, 1_000, 5_000_000),
                max_depth=self._clamp(max_depth or self._max_depth, 1, 64),
                max_workers=self._clamp(max_workers or self._max_workers, 1, 16),
                throttle_seconds=self._throttle,
                requested_by=requested_by,
                label=label or "on-demand filesystem scan",
                requested_at=now_iso(),
            )

            cancel = threading.Event()
            state = FilesystemScanState(
                scan_id=request.scan_id,
                state=STARTING,
                scan_type=request.scan_type,
                label=request.label,
                requested_by=requested_by,
                requested_at=request.requested_at,
                started_at=now_iso(),
                updated_at=now_iso(),
                current_operation="queued",
            )
            self._active = state
            self._active_cancel = cancel
            self._scans_started += 1
            self._remember(state)

        thread = threading.Thread(
            target=self._run,
            args=(request, cancel),
            name="argus-scan-coordinator",
            daemon=True,
        )
        with self._lock:
            self._active_thread = thread
        thread.start()
        logger.info("Scan %s started by %s", request.scan_id, requested_by)
        return state, True

    def cancel(self, scan_id: str) -> tuple[FilesystemScanState | None, str]:
        """Request cancellation. Returns ``(state, outcome)``.

        Outcome is one of ``cancelled`` | ``cancel_pending`` | ``already_finished``
        | ``not_found``.
        """
        with self._lock:
            active = self._active
            if active is not None and active.scan_id == scan_id:
                if not active.is_active:
                    return active, "already_finished"
                assert self._active_cancel is not None
                self._active_cancel.set()
                self._cancel_requested.add(scan_id)
                return active, "cancel_pending"
            historical = self._history.get(scan_id)
            if historical is not None:
                if historical.state in ACTIVE_STATES:
                    # State came from an external producer (e.g. a previous agent
                    # run) — record the intent; nothing local to signal.
                    self._cancel_requested.add(scan_id)
                    return historical, "cancel_pending"
                return historical, "already_finished"
            return None, "not_found"

    def cancel_all(self) -> None:
        with self._lock:
            if self._active is not None and self._active.is_active and self._active_cancel is not None:
                self._active_cancel.set()
                self._cancel_requested.add(self._active.scan_id)

    def stop(self, timeout: float = 12.0) -> None:
        """Cancel any active scan and wait for the worker to exit."""
        self.cancel_all()
        thread: threading.Thread | None
        with self._lock:
            thread = self._active_thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _clamp(value: int, low: int, high: int) -> int:
        return max(low, min(high, int(value)))

    def _remember(self, state: FilesystemScanState) -> None:
        self._history[state.scan_id] = state
        self._history.move_to_end(state.scan_id)
        while len(self._history) > self._history_limit:
            self._history.popitem(last=False)

    def _publish(self, state: FilesystemScanState, emit_event: bool = False) -> None:
        with self._lock:
            self._remember(state)
        if self._on_state is not None:
            try:
                self._on_state(state)
            except Exception:  # noqa: BLE001
                logger.exception("scan state callback failed")
        if emit_event and self._on_event is not None:
            try:
                self._on_event("SCAN_STATE", state)
            except Exception:  # noqa: BLE001
                logger.exception("scan event callback failed")

    def _run(self, request: ScanRequest, cancel: threading.Event) -> None:
        previous: dict[str, Any] = {}

        def on_progress(state: FilesystemScanState) -> None:
            # Collapse no-op repeats so the stream is not flooded.
            fingerprint = (state.state, state.current_operation, state.counters.files_scanned)
            changed = fingerprint != previous.get("fingerprint")
            previous["fingerprint"] = fingerprint
            if changed:
                self._publish(state, emit_event=state.state in (COMPLETED, PARTIAL, FAILED, CANCELLED))

        try:
            final = run_scan(request=request, cancel=cancel, on_progress=on_progress)
        except Exception:  # noqa: BLE001 - defensive: a worker must never die silently
            logger.exception("scan worker raised")
            with self._lock:
                active = self._active
            if active is not None and active.scan_id == request.scan_id:
                final = FilesystemScanState(
                    scan_id=request.scan_id,
                    state=FAILED,
                    started_at=active.started_at,
                    updated_at=now_iso(),
                    completed_at=now_iso(),
                    current_operation="failed",
                    message="scan worker raised an exception",
                )
            else:  # pragma: no cover
                return

        with self._lock:
            self._active = None
            self._active_cancel = None
            self._active_thread = None
            if final.state == COMPLETED:
                self._scans_completed += 1
            elif final.state == FAILED:
                self._scans_failed += 1
            elif final.state == CANCELLED:
                self._scans_cancelled += 1
            self._cancel_requested.discard(final.scan_id)

        self._publish(final, emit_event=True)
        logger.info(
            "Scan %s finished: state=%s files_scanned=%d files_discovered=%d "
            "total_known=%s permission_denied=%d errors=%d skipped=%d",
            final.scan_id,
            final.state,
            final.counters.files_scanned,
            final.counters.files_discovered,
            final.counters.total_known,
            final.counters.permission_denied,
            final.counters.errors,
            final.counters.skipped,
        )


__all__ = ["MAX_HISTORY", "ScanCoordinator", "new_scan_id", "IDLE"]
