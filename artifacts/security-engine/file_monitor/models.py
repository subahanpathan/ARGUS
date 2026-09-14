"""Normalized data models for file-based threat detection."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


def stable_id(*parts: Any) -> str:
    """Deterministic identifier derived from the given parts."""
    raw = "\x1f".join(str(p) for p in parts if p is not None and p != "")
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


@dataclass
class FileFinding:
    """A single threat detection triggered by an analyzed system file.

    Every finding carries the real SHA-256 hash of the file it refers to
    so the UI (and later containment workflows) reference a real artifact.
    """

    id: str
    path: str
    name: str
    extension: str = ""
    size_bytes: int = 0
    modified: str = ""  # ISO timestamp of last file modification
    hash: str = ""  # real SHA-256 of the file contents
    severity: str = "low"  # critical | high | medium | low
    className: str = ""  # MITRE ATT&CK-style tactic
    reason: str = ""
    category: str = ""  # detection rule that fired
    is_running: bool = False  # whether a live process references this path
    source: str = "file_scanner"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            k: v
            for k, v in asdict(self).items()
            if v is not None and v != "" and v != []
        }


@dataclass
class FileScanSnapshot:
    """A point-in-time result of a filesystem threat scan."""

    findings: list[FileFinding]
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    directories_scanned: int = 0
    files_candidates: int = 0
    files_hashed: int = 0
    files_read: int = 0

    @property
    def total_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "directories_scanned": self.directories_scanned,
            "files_candidates": self.files_candidates,
            "files_hashed": self.files_hashed,
            "files_read": self.files_read,
            "total_count": self.total_count,
            "findings": [f.to_dict() for f in self.findings],
        }