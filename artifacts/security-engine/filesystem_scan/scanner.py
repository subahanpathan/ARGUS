"""Real, bounded, cancellable filesystem scan.

Two phases, both read-only:

**INVENTORY** — walk the selected roots counting entries with ``os.scandir``.
This produces the *measured denominator* for progress. If the walk is cut short
by the entry budget, ``total_known`` stays ``False`` and no percentage is ever
produced.

**SCANNING** — walk the same roots again and read real file metadata. File
metadata reads are dispatched to a bounded thread pool (``max_workers``) because
``stat`` on a filtered/remote path can block for a long time; the pool size is
capped so the endpoint stays responsive.

Safety properties:

* metadata only — file contents are never opened or read
* ``follow_symlinks=False`` — no reparse-point recursion or cycles
* ``visited`` set keyed on the normalized path — the same directory is never
  scanned twice
* explicit skip-list + caller-supplied exclusions
* ``PermissionError`` is counted separately from generic errors
* a ``threading.Event`` cancels at the next entry
"""

from __future__ import annotations

import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Iterable

from .models import (
    ANALYZING,
    CANCELLED,
    COMPLETED,
    FAILED,
    FilesystemScanState,
    INVENTORY,
    PARTIAL,
    SCANNING,
    STARTING,
    ScanCounters,
    ScanRequest,
    now_iso,
)

logger = logging.getLogger("argus.filesystem_scan.scanner")

# Directories never descended into (system-sensitive or bulk).
DEFAULT_SKIP_DIR_NAMES: frozenset[str] = frozenset({
    "node_modules",
    ".git",
    "__pycache__",
    "$recycle.bin",
    "system volume information",
    "recovery",
    "perflogs",
    "config.msi",
    "$windows.~bt",
    "$windows.~ws",
    "winsxs",
    "installer",
    "msocache",
})

#: Path prefixes pruned outright. Keeps the scan inside the user-writable set.
DEFAULT_SKIP_DIR_PREFIXES: tuple[str, ...] = (
    r"c:\windows",
    r"c:\program files\microsoft visual studio",
    r"c:\programdata\microsoft\windows defender",
)

DEFAULT_ENTRY_BUDGET = 250_000
DEFAULT_MAX_DEPTH = 24
DEFAULT_MAX_WORKERS = 4


@dataclass
class ScanCountersEntry:
    """Metadata captured for one file during the scan phase."""

    path: str
    size: int
    mtime: float
    is_dir: bool = False


def _dedupe_valid_dirs(paths: Iterable[str]) -> list[str]:
    """Keep existing directories only, normalized, order-preserved, no repeats."""
    result: list[str] = []
    seen: set[str] = set()
    for raw in paths:
        if not raw:
            continue
        normalized = os.path.normpath(str(raw))
        key = os.path.normcase(normalized)
        if key in seen:
            continue
        seen.add(key)
        if os.path.isdir(normalized):
            result.append(normalized)
    return result


def resolve_default_scan_roots() -> list[str]:
    """The bounded set of roots walked when a scan request names no roots.

    User-writable locations by default. The user profile itself is deliberately
    *not* added wholesale: the specific high-activity subdirectories are used
    individually so the walk stays bounded and meaningful.
    """
    home = os.path.expanduser("~")
    candidates: list[str] = [
        os.environ.get("TEMP") or "",
        os.environ.get("TMP") or "",
        os.path.join(os.environ["LOCALAPPDATA"], "Temp")
        if os.environ.get("LOCALAPPDATA")
        else "",
        os.path.join(home, "Downloads") if home else "",
        os.path.join(home, "Desktop") if home else "",
        os.path.join(home, "Documents") if home else "",
        os.environ.get("PROGRAMDATA") or "",
    ]
    return _dedupe_valid_dirs(p for p in candidates if p)


def resolve_scan_roots(requested_roots: Iterable[str] | None = None) -> list[str]:
    """Resolve the directories a scan is allowed to walk.

    When a request names roots they are *authoritative*: only those directories
    are walked. The default set is used solely when the request names none, so an
    on-demand scan of one path can never widen itself into unrelated locations.
    """
    if requested_roots:
        return _dedupe_valid_dirs(requested_roots)
    return resolve_default_scan_roots()


def normalize_prefixes(prefixes: Iterable[str]) -> list[str]:
    return [os.path.normcase(os.path.normpath(p)) for p in prefixes if p]


class _Pruner:
    """Skip-list evaluation shared by both phases."""

    def __init__(self, exclusions: Iterable[str] = ()) -> None:
        self.skip_names = set(DEFAULT_SKIP_DIR_NAMES)
        self.skip_prefixes = normalize_prefixes(DEFAULT_SKIP_DIR_PREFIXES)
        for raw in exclusions:
            text = str(raw).strip()
            if not text:
                continue
            candidate = os.path.normcase(os.path.normpath(text))
            # A trailing separator marks the entry as a *name* to skip anywhere.
            if text.endswith(("/", "\\")):
                self.skip_names.add(os.path.basename(candidate))
            else:
                self.skip_prefixes.append(candidate)

    def should_prune(self, dirpath: str, name: str) -> bool:
        if name.lower() in self.skip_names:
            return True
        lowered = os.path.normcase(dirpath)
        for prefix in self.skip_prefixes:
            if lowered.startswith(prefix):
                return True
        return False


def _inventory(
    roots: list[str],
    cancel: threading.Event,
    counters: ScanCounters,
    pruner: _Pruner,
    budget: int,
    max_depth: int,
    on_progress: Callable[[FilesystemScanState], None],
    state: FilesystemScanState,
) -> None:
    """Count every reachable entry under ``roots``. Establishes the denominator."""
    visited: set[str] = set()
    stack: list[tuple[str, int]] = [(root, 0) for root in reversed(roots)]
    entries_seen = 0

    while stack and not cancel.is_set():
        dirpath, depth = stack.pop()
        key = os.path.normcase(os.path.normpath(dirpath))
        if key in visited:
            continue
        visited.add(key)

        if pruner.should_prune(dirpath, os.path.basename(dirpath)):
            counters.skipped += 1
            continue

        try:
            with os.scandir(dirpath) as scan:
                for entry in scan:
                    if cancel.is_set():
                        return
                    entries_seen += 1
                    if entries_seen > budget:
                        # The denominator is not measurable — say so.
                        counters.inventory_truncated = True
                        counters.total_known = False
                        state.current_operation = "inventory_truncated"
                        return
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            counters.folders_discovered += 1
                            name = entry.name
                            if depth + 1 <= max_depth and not pruner.should_prune(entry.path, name):
                                stack.append((entry.path, depth + 1))
                        elif entry.is_file(follow_symlinks=False):
                            counters.files_discovered += 1
                    except OSError:
                        counters.errors += 1
        except PermissionError:
            counters.permission_denied += 1
        except OSError:
            counters.errors += 1

    if not cancel.is_set() and not counters.inventory_truncated:
        counters.total_known = True


def _scan(
    roots: list[str],
    cancel: threading.Event,
    counters: ScanCounters,
    pruner: _Pruner,
    max_depth: int,
    max_workers: int,
    on_progress: Callable[[FilesystemScanState], None],
    state: FilesystemScanState,
    throttle_seconds: float,
) -> None:
    """Read real metadata for every entry and advance the real counters."""
    import time

    visited: set[str] = set()
    stack: list[tuple[str, int]] = [(root, 0) for root in reversed(roots)]
    last_emit = time.monotonic()
    pool = ThreadPoolExecutor(max_workers=max(1, max_workers), thread_name_prefix="argus-scan")
    cancelled = False

    def stat_entry(path: str) -> ScanCountersEntry | None:
        try:
            info = os.stat(path, follow_symlinks=False)
        except PermissionError:
            return None
        except OSError:
            return None
        return ScanCountersEntry(path=path, size=int(info.st_size), mtime=info.st_mtime)

    try:
        while stack:
            if cancel.is_set():
                cancelled = True
                break

            dirpath, depth = stack.pop()
            key = os.path.normcase(os.path.normpath(dirpath))
            if key in visited:
                continue
            visited.add(key)

            if pruner.should_prune(dirpath, os.path.basename(dirpath)):
                counters.skipped += 1
                continue

            state.current_path = dirpath
            state.current_operation = "stat_metadata"

            try:
                with os.scandir(dirpath) as scan:
                    subdirs: list[str] = []
                    file_paths: list[str] = []
                    for entry in scan:
                        if cancel.is_set():
                            cancelled = True
                            break
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                # Counted at discovery, exactly like the inventory
                                # phase, so both denominators stay comparable.
                                counters.folders_scanned += 1
                                name = entry.name
                                if depth + 1 <= max_depth and not pruner.should_prune(entry.path, name):
                                    subdirs.append(entry.path)
                            elif entry.is_file(follow_symlinks=False):
                                file_paths.append(entry.path)
                        except PermissionError:
                            counters.permission_denied += 1
                        except OSError:
                            counters.errors += 1

                    if not cancelled and file_paths:
                        # Bounded-concurrency metadata reads.
                        results = list(pool.map(stat_entry, file_paths))
                        for result in results:
                            if result is None:
                                counters.errors += 1
                                continue
                            counters.files_scanned += 1
                            counters.bytes_scanned += result.size

                if cancelled:
                    break

                stack.extend((subdir, depth + 1) for subdir in reversed(subdirs))
            except PermissionError:
                counters.permission_denied += 1
            except OSError:
                counters.errors += 1

            now = time.monotonic()
            if now - last_emit >= throttle_seconds:
                last_emit = now
                state.updated_at = now_iso()
                on_progress(state)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    state.current_path = ""
    if cancelled:
        state.current_operation = "cancelled"


def run_scan(
    request: ScanRequest,
    cancel: threading.Event,
    on_progress: Callable[[FilesystemScanState], None],
) -> FilesystemScanState:
    """Execute one bounded scan described by ``request``.

    Emits at least one state per phase plus throttled progress updates. The
    returned state is the terminal state.
    """
    counters = ScanCounters()
    roots = resolve_scan_roots(request.roots)
    pruner = _Pruner(request.exclusions)

    state = FilesystemScanState(
        scan_id=request.scan_id,
        state=STARTING,
        scan_type=request.scan_type,
        label=request.label,
        requested_by=request.requested_by,
        requested_at=request.requested_at,
        started_at=now_iso(),
        updated_at=now_iso(),
        roots=roots,
        exclusions=list(request.exclusions),
        counters=counters,
        current_operation="starting",
    )
    on_progress(state)

    if not roots:
        state.state = FAILED
        state.current_operation = "failed"
        state.completed_at = now_iso()
        state.message = "no accessible scan roots"
        state.updated_at = state.completed_at
        on_progress(state)
        return state

    try:
        # -- phase 1: inventory (the denominator) --------------------------
        state.state = INVENTORY
        state.current_operation = "inventory"
        state.current_path = roots[0]
        state.updated_at = now_iso()
        on_progress(state)

        _inventory(
            roots, cancel, counters, pruner, request.entry_budget,
            request.max_depth, on_progress, state,
        )
        state.updated_at = now_iso()
        on_progress(state)

        if cancel.is_set():
            state.state = CANCELLED
            state.current_operation = "cancelled"
        else:
            # -- phase 2: scan (the numerator) ----------------------------
            state.state = SCANNING
            state.current_operation = "stat_metadata"
            state.updated_at = now_iso()
            on_progress(state)

            _scan(
                roots, cancel, counters, pruner, request.max_depth,
                request.max_workers, on_progress, state, request.throttle_seconds,
            )

            if cancel.is_set():
                state.state = CANCELLED
                state.current_operation = "cancelled"
            elif counters.permission_denied or counters.skipped or counters.errors or counters.inventory_truncated:
                state.state = PARTIAL
                state.current_operation = "analyzed"
            else:
                state.state = COMPLETED
                state.current_operation = "analyzed"

        state.completed_at = now_iso()
        state.updated_at = state.completed_at
        state.counters = counters
        on_progress(state)
        return state
    except Exception as exc:  # noqa: BLE001
        logger.exception("Filesystem scan failed")
        state.state = FAILED
        state.current_operation = "failed"
        state.completed_at = now_iso()
        state.updated_at = state.completed_at
        state.message = str(exc)
        state.counters = counters
        on_progress(state)
        return state


def run_filesystem_scan(
    cancel: threading.Event,
    on_progress: Callable[[FilesystemScanState], None],
    throttle_seconds: float = 1.0,
    entry_budget: int = DEFAULT_ENTRY_BUDGET,
) -> FilesystemScanState:
    """Backwards-compatible entry point used by the periodic scan watcher."""
    request = ScanRequest(
        scan_id="scheduled",
        entry_budget=entry_budget,
        throttle_seconds=throttle_seconds,
        requested_by="scheduler",
        label="scheduled filesystem scan",
    )
    return run_scan(request, cancel, on_progress)


__all__ = [
    "DEFAULT_ENTRY_BUDGET",
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_MAX_WORKERS",
    "DEFAULT_SKIP_DIR_NAMES",
    "DEFAULT_SKIP_DIR_PREFIXES",
    "ScanCountersEntry",
    "resolve_default_scan_roots",
    "resolve_scan_roots",
    "run_filesystem_scan",
    "run_scan",
]
