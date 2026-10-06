"""Real filesystem change telemetry for the ARGUS Endpoint Agent.

Primary mechanism is the supported Windows API ``ReadDirectoryChangesW`` with
overlapped I/O — event-driven, no polling, and read-only. Each watched root
gets a daemon thread with a 1-second completion tick so shutdown stays clean
and no thread can be left blocked inside the kernel.

If ``ReadDirectoryChangesW`` is unavailable (non-Windows host, filtered handle,
AV interference) the agent falls back to a bounded polling differ and reports
``backend = "poll"`` so the distinction is never hidden.

What is recorded: path, name, extension, size, timestamps and the change kind.
File *contents* are never read, hashed, or stored.
"""

from __future__ import annotations

import ctypes
import logging
import os
import struct
import sys
import threading
import time
from ctypes import wintypes
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

logger = logging.getLogger("argus.filesystem_events")

IS_WINDOWS = sys.platform == "win32"


class OVERLAPPED(ctypes.Structure):
    """Win32 ``OVERLAPPED``. ``ctypes.wintypes`` does not ship one."""

    _fields_ = [
        ("Internal", ctypes.POINTER(ctypes.c_ulong)),
        ("InternalHigh", ctypes.POINTER(ctypes.c_ulong)),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]

# FILE_NOTIFY_CHANGE_* mask — names, directory names, size and last-write.
FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
FILE_NOTIFY_CHANGE_SIZE = 0x00000008
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
FILE_NOTIFY_CHANGE_CREATION = 0x00000040

WATCH_MASK = (
    FILE_NOTIFY_CHANGE_FILE_NAME
    | FILE_NOTIFY_CHANGE_DIR_NAME
    | FILE_NOTIFY_CHANGE_SIZE
    | FILE_NOTIFY_CHANGE_LAST_WRITE
    | FILE_NOTIFY_CHANGE_CREATION
)

FILE_ACTION_ADDED = 1
FILE_ACTION_REMOVED = 2
FILE_ACTION_MODIFIED = 3
FILE_ACTION_RENAMED_OLD_NAME = 4
FILE_ACTION_RENAMED_NEW_NAME = 5

FILE_CREATED = "FILE_CREATED"
FILE_MODIFIED = "FILE_MODIFIED"
FILE_DELETED = "FILE_DELETED"
FILE_RENAMED = "FILE_RENAMED"
FILE_DIRECTORY_CHANGED = "FILE_DIRECTORY_CHANGED"

EVENT_KINDS = frozenset(
    {FILE_CREATED, FILE_MODIFIED, FILE_DELETED, FILE_RENAMED, FILE_DIRECTORY_CHANGED}
)

#: Per-root buffer for the change journal. Larger buffers mean fewer
#: kernel round-trips; anything unreadable is simply dropped by Windows and the
#: agent reports ``overflow`` rather than pretending it saw everything.
_JOURNAL_BUFFER_BYTES = 64 * 1024


@dataclass
class FileChangeEvent:
    """One observed filesystem change (metadata only)."""

    kind: str
    path: str
    root: str
    name: str
    is_directory: bool
    size_bytes: int | None = None
    extension: str | None = None
    created_at: str | None = None
    modified_at: str | None = None
    accessed_at: str | None = None
    old_path: str | None = None
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "path": self.path,
            "root": self.root,
            "name": self.name,
            "is_directory": self.is_directory,
            "size_bytes": self.size_bytes,
            "extension": self.extension,
            "created_at": self.created_at,
            "modified_at": self.modified_at,
            "accessed_at": self.accessed_at,
            "old_path": self.old_path,
            "timestamp": self.timestamp,
        }


@dataclass
class WatchStats:
    """Bounded, honest counters for the filesystem watcher."""

    events_emitted: int = 0
    events_suppressed: int = 0
    journal_overflows: int = 0
    read_errors: int = 0
    poll_cycles: int = 0
    roots_active: int = 0
    roots_failed: int = 0
    last_error: str = ""
    last_event_at: str | None = None
    backend: str = "unavailable"
    last_tick_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "events_emitted": self.events_emitted,
            "events_suppressed": self.events_suppressed,
            "journal_overflows": self.journal_overflows,
            "read_errors": self.read_errors,
            "poll_cycles": self.poll_cycles,
            "roots_active": self.roots_active,
            "roots_failed": self.roots_failed,
            "last_error": self.last_error,
            "last_event_at": self.last_event_at,
            "backend": self.backend,
            "last_tick_at": self.last_tick_at,
        }


def _iso(timestamp: float | None) -> str | None:
    if not timestamp:
        return None
    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_watch_roots(max_roots: int = 8) -> list[str]:
    """Bounded, user-writable roots where real activity actually happens.

    Deliberately excludes system volumes: ARGUS monitors the endpoint's working
    set, and watching ``C:\\Windows`` recursively would be both expensive and
    uninformative.
    """
    candidates: list[str] = []

    def add(path: str | None) -> None:
        if not path:
            return
        normalized = os.path.normpath(path)
        if os.path.isdir(normalized):
            candidates.append(normalized)

    home = os.path.expanduser("~")
    add(os.environ.get("ARGUS_FS_WATCH_DOWNLOADS") or os.path.join(home, "Downloads"))
    add(os.path.join(home, "Desktop"))
    add(os.path.join(home, "Documents"))
    add(os.environ.get("TEMP") or os.path.join(home, "AppData", "Local", "Temp"))
    add(os.environ.get("TMP"))
    add(os.environ.get("LOCALAPPDATA") and os.path.join(os.environ["LOCALAPPDATA"], "Temp"))

    extra = os.environ.get("ARGUS_FS_WATCH_ROOTS", "")
    for raw in extra.split(";"):
        if raw.strip():
            add(raw.strip())

    unique: list[str] = []
    seen: set[str] = set()
    for path in candidates:
        key = os.path.normcase(path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique[:max_roots]


def parse_journal(buffer: bytes) -> list[tuple[int, str]]:
    """Decode a ``ReadDirectoryChangesW`` completion buffer.

    Returns ``[(action, relative_name), ...]``. Returns an empty list for the
    zero-byte completion that Windows delivers when the buffer overflowed —
    the caller reports that as an explicit gap rather than as "no activity".
    """
    entries: list[tuple[int, str]] = []
    offset = 0
    size = len(buffer)
    while offset + 12 <= size:
        next_offset, action, name_length = struct.unpack_from("<III", buffer, offset)
        name_start = offset + 12
        name_end = name_start + name_length
        if name_end > size:
            break
        raw_name = buffer[name_start:name_end]
        try:
            name = raw_name.decode("utf-16-le", "replace")
        except Exception:  # noqa: BLE001 - defensive
            name = ""
        name = name.rstrip("\x00")
        if name:
            entries.append((action, name))
        if next_offset == 0:
            break
        offset += next_offset
    return entries


class _Win32DirectoryWatcher:
    """One root, one thread, overlapped ``ReadDirectoryChangesW``."""

    def __init__(
        self,
        root: str,
        on_events: Callable[[list[FileChangeEvent]], None],
        on_overflow: Callable[[], None],
        on_error: Callable[[str], None],
        tick_seconds: float = 1.0,
    ) -> None:
        self.root = root
        self._on_events = on_events
        self._on_overflow = on_overflow
        self._on_error = on_error
        self._tick_ms = int(max(0.2, tick_seconds) * 1000)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._loop, name="argus-fswatch", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=4)
        self._thread = None

    # -- internals ---------------------------------------------------------

    def _loop(self) -> None:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        CreateFileW = kernel32.CreateFileW
        CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        CreateFileW.restype = wintypes.HANDLE

        ReadDirectoryChangesW = kernel32.ReadDirectoryChangesW
        ReadDirectoryChangesW.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL,
            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        ReadDirectoryChangesW.restype = wintypes.BOOL

        CreateEventW = kernel32.CreateEventW
        CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
        CreateEventW.restype = wintypes.HANDLE

        kernel32.CreateIoCompletionPort  # referenced for clarity; unused
        GetOverlappedResult = kernel32.GetOverlappedResult
        GetOverlappedResult.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
        ]
        GetOverlappedResult.restype = wintypes.BOOL

        WaitForSingleObject = kernel32.WaitForSingleObject
        WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        WaitForSingleObject.restype = wintypes.DWORD

        ResetEvent = kernel32.ResetEvent
        ResetEvent.argtypes = [wintypes.HANDLE]
        ResetEvent.restype = wintypes.BOOL

        CancelIoEx = kernel32.CancelIoEx
        CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
        CancelIoEx.restype = wintypes.BOOL

        CloseHandle = kernel32.CloseHandle
        CloseHandle.argtypes = [wintypes.HANDLE]
        CloseHandle.restype = wintypes.BOOL

        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        FILE_SHARE_DELETE = 0x00000004
        OPEN_EXISTING = 3
        FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
        FILE_FLAG_OVERLAPPED = 0x40000000
        WAIT_OBJECT_0 = 0x00000000
        WAIT_TIMEOUT = 0x00000102
        INFINITE = 0xFFFFFFFF

        handle = CreateFileW(
            self.root, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, None,
        )
        if handle == INVALID_HANDLE_VALUE or handle is None:
            self._on_error(
                f"CreateFileW({self.root}) failed: winerror "
                f"{ctypes.get_last_error()}"
            )
            return

        event_handle = CreateEventW(None, True, False, None)
        if not event_handle:
            self._on_error("CreateEvent failed")
            CloseHandle(handle)
            return

        buffer = ctypes.create_string_buffer(_JOURNAL_BUFFER_BYTES)
        try:
            while not self._stop.is_set():
                ResetEvent(event_handle)

                overlapped = OVERLAPPED()
                overlapped.hEvent = event_handle
                bytes_returned = wintypes.DWORD(0)

                ok = ReadDirectoryChangesW(
                    handle,
                    ctypes.byref(buffer),
                    _JOURNAL_BUFFER_BYTES,
                    True,  # watch subtree
                    WATCH_MASK,
                    ctypes.byref(bytes_returned),
                    ctypes.byref(overlapped),
                    None,
                )
                if not ok:
                    self._on_error(
                        f"ReadDirectoryChangesW({self.root}) failed: winerror "
                        f"{ctypes.get_last_error()}"
                    )
                    return

                wait_result = WaitForSingleObject(event_handle, self._tick_ms)
                if wait_result == WAIT_TIMEOUT:
                    CancelIoEx(handle, ctypes.byref(overlapped))
                    # Drain the cancelled completion so the kernel does not keep
                    # the buffer pinned.
                    GetOverlappedResult(handle, ctypes.byref(overlapped), ctypes.byref(bytes_returned), True)
                    continue
                if wait_result != WAIT_OBJECT_0:
                    continue

                if not GetOverlappedResult(
                    handle, ctypes.byref(overlapped),
                    ctypes.byref(bytes_returned), False,
                ):
                    error = ctypes.get_last_error()
                    if error == 995:  # ERROR_OPERATION_ABORTED
                        continue
                    self._on_error(f"GetOverlappedResult failed: winerror {error}")
                    return

                moved = int(bytes_returned.value)
                if moved == 0:
                    # Windows signals "the journal overflowed; you missed events".
                    self._on_overflow()
                    continue

                entries = parse_journal(buffer.raw[:moved])
                if not entries:
                    continue
                self._on_events(self._materialize(entries))
        except Exception as exc:  # noqa: BLE001 - thread must never die silently
            self._on_error(f"watcher thread error: {exc}")
        finally:
            CancelIoEx(handle, None)
            CloseHandle(event_handle)
            CloseHandle(handle)

    def _materialize(self, entries: Iterable[tuple[int, str]]) -> list[FileChangeEvent]:
        events: list[FileChangeEvent] = []
        pending_old: str | None = None

        for action, name in entries:
            path = os.path.normpath(os.path.join(self.root, name))
            base = os.path.basename(path)
            extension = os.path.splitext(base)[1].lower() or None

            if action == FILE_ACTION_RENAMED_OLD_NAME:
                pending_old = path
                continue
            if action == FILE_ACTION_RENAMED_NEW_NAME:
                events.append(self._event(FILE_RENAMED, path, base, extension, old_path=pending_old))
                pending_old = None
                continue
            if action == FILE_ACTION_ADDED:
                kind = FILE_DIRECTORY_CHANGED if os.path.isdir(path) else FILE_CREATED
                events.append(self._event(kind, path, base, extension))
            elif action == FILE_ACTION_REMOVED:
                events.append(self._event(FILE_DELETED, path, base, extension))
            elif action == FILE_ACTION_MODIFIED:
                if os.path.isdir(path):
                    continue
                events.append(self._event(FILE_MODIFIED, path, base, extension))

        return events

    def _event(
        self,
        kind: str,
        path: str,
        base: str,
        extension: str | None,
        old_path: str | None = None,
    ) -> FileChangeEvent:
        size: int | None = None
        created = modified = accessed = None
        if kind in (FILE_CREATED, FILE_MODIFIED):
            try:
                info = os.stat(path, follow_symlinks=False)
                size = int(info.st_size)
                created = _iso(info.st_ctime)
                modified = _iso(info.st_mtime)
                accessed = _iso(info.st_atime)
                if os.path.isdir(path):
                    kind = FILE_DIRECTORY_CHANGED
            except OSError:
                # The file may already be gone (or be permission-filtered).
                # Report the change without inventing metadata.
                size = None

        return FileChangeEvent(
            kind=kind,
            path=path,
            root=self.root,
            name=base,
            is_directory=kind == FILE_DIRECTORY_CHANGED,
            size_bytes=size,
            extension=extension,
            created_at=created,
            modified_at=modified,
            accessed_at=accessed,
            old_path=old_path,
            timestamp=_now_iso(),
        )


class _PollDirectoryWatcher:
    """Bounded polling fallback used when ``ReadDirectoryChangesW`` is unusable.

    Compares one level of each root per cycle. It is deliberately shallow: it
    exists so filesystem telemetry degrades to *less* rather than to *nothing*,
    and the backend is reported so the UI can say which one is running.
    """

    def __init__(
        self,
        root: str,
        interval_seconds: float,
        on_events: Callable[[list[FileChangeEvent]], None],
        on_tick: Callable[[], None],
        on_error: Callable[[str], None],
    ) -> None:
        self.root = root
        self._interval = max(1.0, interval_seconds)
        self._on_events = on_events
        self._on_tick = on_tick
        self._on_error = on_error
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._loop, name="argus-fspoll", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=4)
        self._thread = None

    def _snapshot(self) -> dict[str, float]:
        found: dict[str, float] = {}
        try:
            with os.scandir(self.root) as entries:
                for entry in entries:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            continue
                        found[entry.path] = entry.stat(follow_symlinks=False).st_mtime
                    except OSError:
                        continue
        except OSError as exc:
            self._on_error(f"poll scandir({self.root}) failed: {exc}")
        return found

    def _loop(self) -> None:
        previous = self._snapshot()
        while not self._stop.wait(self._interval):
            current = self._snapshot()
            self._on_tick()
            events: list[FileChangeEvent] = []
            for path, mtime in current.items():
                if path not in previous:
                    kind = FILE_CREATED
                elif previous[path] != mtime:
                    kind = FILE_MODIFIED
                else:
                    continue
                base = os.path.basename(path)
                events.append(
                    FileChangeEvent(
                        kind=kind,
                        path=path,
                        root=self.root,
                        name=base,
                        is_directory=False,
                        extension=os.path.splitext(base)[1].lower() or None,
                        modified_at=_iso(mtime),
                        timestamp=_now_iso(),
                    )
                )
            for path in previous:
                if path not in current:
                    base = os.path.basename(path)
                    events.append(
                        FileChangeEvent(
                            kind=FILE_DELETED,
                            path=path,
                            root=self.root,
                            name=base,
                            is_directory=False,
                            extension=os.path.splitext(base)[1].lower() or None,
                            timestamp=_now_iso(),
                        )
                    )
            if events:
                self._on_events(events)
            previous = current


INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value


def probe_directory_watch(root: str) -> tuple[bool, str]:
    """Verify that overlapped ``ReadDirectoryChangesW`` works on ``root``.

    Returns ``(supported, reason)``. The probe opens the directory exactly the
    way the real watcher does and submits one zero-length overlapped read, so a
    host that filters the API (or an AV filter driver that blocks it) is
    detected up front instead of silently producing no events.
    """
    if not IS_WINDOWS:
        return False, "not a Windows host"
    if not root or not os.path.isdir(root):
        return False, f"root not accessible: {root}"

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    CreateFileW = kernel32.CreateFileW
    CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    CreateFileW.restype = wintypes.HANDLE
    ReadDirectoryChangesW = kernel32.ReadDirectoryChangesW
    ReadDirectoryChangesW.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.BOOL,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, ctypes.c_void_p,
    ]
    ReadDirectoryChangesW.restype = wintypes.BOOL
    CancelIoEx = kernel32.CancelIoEx
    CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    CancelIoEx.restype = wintypes.BOOL
    CloseHandle = kernel32.CloseHandle
    CloseHandle.argtypes = [wintypes.HANDLE]
    CloseHandle.restype = wintypes.BOOL

    GENERIC_READ = 0x80000000
    SHARE_ALL = 0x00000001 | 0x00000002 | 0x00000004
    OPEN_EXISTING = 3
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_FLAG_OVERLAPPED = 0x40000000

    handle = CreateFileW(
        root, GENERIC_READ, SHARE_ALL, None, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, None,
    )
    if handle is None or handle == INVALID_HANDLE_VALUE:
        return False, f"CreateFileW failed: winerror {ctypes.get_last_error()}"

    try:
        buffer = ctypes.create_string_buffer(4096)
        overlapped = OVERLAPPED()
        moved = wintypes.DWORD(0)
        ok = ReadDirectoryChangesW(
            handle, ctypes.byref(buffer), 4096, False, WATCH_MASK,
            ctypes.byref(moved), ctypes.byref(overlapped), None,
        )
        if not ok:
            return False, f"ReadDirectoryChangesW failed: winerror {ctypes.get_last_error()}"
        CancelIoEx(handle, ctypes.byref(overlapped))
        return True, "ok"
    finally:
        CloseHandle(handle)


class FilesystemEventWatcher:
    """Watches a bounded set of roots and emits real change events.

    Chooses the event-driven Win32 backend when available and degrades to a
    bounded polling backend otherwise, reporting which one is in use.
    """

    def __init__(
        self,
        roots: list[str] | None = None,
        max_roots: int = 8,
        poll_interval_seconds: float = 5.0,
        max_events_per_second: int = 50,
        on_events: Callable[[list[FileChangeEvent]], None] | None = None,
        on_tick: Callable[[], None] | None = None,
    ) -> None:
        self.roots = roots if roots is not None else default_watch_roots(max_roots)
        self._poll_interval = poll_interval_seconds
        self._max_eps = max(1, max_events_per_second)
        self._on_events = on_events
        self._on_tick = on_tick

        self._watchers: list[Any] = []
        self._stop = threading.Event()
        self._stats = WatchStats()
        self._stats_lock = threading.Lock()
        self._token_bucket = float(max_events_per_second)
        self._last_refill = time.monotonic()
        self.backend = "unavailable"

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> str:
        """Start watching. Returns the backend actually used."""
        self._stop.clear()

        probe_reason = "no roots configured"
        if self.roots:
            supported, probe_reason = probe_directory_watch(self.roots[0])
        else:
            supported = False

        if supported:
            self.backend = "readdirectorychangesw"
            for root in self.roots:
                watcher = _Win32DirectoryWatcher(
                    root,
                    on_events=self._handle_events,
                    on_overflow=self._handle_overflow,
                    on_error=lambda message, r=root: self._handle_error(r, message),
                )
                watcher.start()
                self._watchers.append(watcher)
        else:
            # Degrade to bounded polling rather than to nothing, and say so.
            self.backend = "poll" if self.roots else "unavailable"
            if self.roots:
                logger.info(
                    "ReadDirectoryChangesW unavailable (%s); using bounded polling differ",
                    probe_reason,
                )
            for root in self.roots:
                self._watchers.append(
                    _PollDirectoryWatcher(
                        root,
                        self._poll_interval,
                        on_events=self._handle_events,
                        on_tick=self._handle_tick,
                        on_error=lambda message, r=root: self._handle_error(r, message),
                    )
                )
                self._watchers[-1].start()

        with self._stats_lock:
            self._stats.backend = self.backend
            self._stats.roots_active = len(self._watchers)
            self._stats.roots_failed = 0 if supported else len(self.roots)
        logger.info(
            "Filesystem event watcher started: backend=%s roots=%d",
            self.backend,
            len(self._watchers),
        )
        return self.backend

    def stop(self) -> None:
        self._stop.set()
        for watcher in self._watchers:
            try:
                watcher.stop()
            except Exception:  # noqa: BLE001
                logger.debug("watcher stop failed", exc_info=True)
        self._watchers.clear()
        with self._stats_lock:
            self._stats.roots_active = 0
        logger.info("Filesystem event watcher stopped")

    # -- stats -------------------------------------------------------------

    @property
    def stats(self) -> WatchStats:
        with self._stats_lock:
            snapshot = WatchStats(**self._stats.__dict__)
        return snapshot

    @property
    def available(self) -> bool:
        return self.backend != "unavailable" and bool(self.roots)

    # -- internals ---------------------------------------------------------

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._token_bucket = min(
            float(self._max_eps), self._token_bucket + elapsed * self._max_eps
        )
        self._last_refill = now

    def _handle_events(self, events: list[FileChangeEvent]) -> None:
        if not events or self._stop.is_set():
            return
        self._refill()
        accepted: list[FileChangeEvent] = []
        suppressed = 0
        for event in events:
            if self._token_bucket < 1.0:
                suppressed += 1
                continue
            self._token_bucket -= 1.0
            accepted.append(event)

        with self._stats_lock:
            self._stats.events_emitted += len(accepted)
            self._stats.events_suppressed += suppressed
            self._stats.last_event_at = accepted[-1].timestamp if accepted else self._stats.last_event_at

        if accepted and self._on_events is not None:
            try:
                self._on_events(accepted)
            except Exception:  # noqa: BLE001
                logger.exception("filesystem event callback failed")

    def _handle_overflow(self) -> None:
        with self._stats_lock:
            self._stats.journal_overflows += 1
            self._stats.last_error = "change journal overflow — events were dropped by Windows"

    def _handle_tick(self) -> None:
        with self._stats_lock:
            self._stats.poll_cycles += 1
            self._stats.last_tick_at = _now_iso()
        if self._on_tick is not None:
            try:
                self._on_tick()
            except Exception:  # noqa: BLE001
                logger.exception("filesystem tick callback failed")

    def _handle_error(self, root: str, message: str) -> None:
        logger.info("Filesystem watch error on %s: %s", root, message)
        with self._stats_lock:
            self._stats.read_errors += 1
            self._stats.last_error = message

    def describe(self) -> dict[str, Any]:
        """Backend + roots + stats, for the monitoring snapshot."""
        return {
            "backend": self.backend,
            "available": self.available,
            "roots": list(self.roots),
            "root_count": len(self.roots),
            "stats": self.stats.to_dict(),
        }


__all__ = [
    "EVENT_KINDS",
    "FILE_CREATED",
    "FILE_DELETED",
    "FILE_DIRECTORY_CHANGED",
    "FILE_MODIFIED",
    "FILE_RENAMED",
    "FileChangeEvent",
    "FilesystemEventWatcher",
    "WatchStats",
    "default_watch_roots",
    "parse_journal",
    "probe_directory_watch",
]
