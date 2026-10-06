"""ARGUS Endpoint Agent — real filesystem change telemetry.

Event-driven on Windows via ``ReadDirectoryChangesW`` with a bounded polling
fallback. Metadata only: path, name, extension, size and timestamps. File
contents are never read.
"""

from __future__ import annotations

from .watcher import (
    EVENT_KINDS,
    FILE_CREATED,
    FILE_DELETED,
    FILE_DIRECTORY_CHANGED,
    FILE_MODIFIED,
    FILE_RENAMED,
    FileChangeEvent,
    FilesystemEventWatcher,
    WatchStats,
    default_watch_roots,
    parse_journal,
    probe_directory_watch,
)

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
