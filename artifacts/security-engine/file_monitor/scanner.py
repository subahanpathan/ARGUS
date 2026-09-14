"""Real filesystem threat scanner.

Walks the actual user-writable locations on the host (Temp, Downloads,
AppData, Startup folders, plus any user-supplied roots) and applies a set
of conservative heuristic rules against real file metadata and contents.

Every detection references the real on-disk artifact: path, size, last
modification time and a SHA-256 hash of the file contents. The scanner
never modifies, quarantines or deletes anything — it is read-only.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from config import Config  # type: ignore[import-not-found]

from .models import FileFinding, FileScanSnapshot, stable_id

logger = logging.getLogger("argus.file_monitor.scanner")

# File kinds the scanner will actually read and hash. Anything outside this
# list is ignored even when it sits in a scanned directory.
_TARGET_EXTENSIONS: frozenset[str] = frozenset({
    ".exe", ".scr", ".pif", ".msi", ".cpl", ".com", ".jar",
    ".dll", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".hta", ".sh", ".py", ".zip", ".rar", ".7z",
})

# Extensions whose contents we read to detect script-based payloads.
_SCRIPT_EXTENSIONS: frozenset[str] = frozenset({
    ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".hta", ".sh", ".py",
})

# Filename patterns that are often used to disguise a payload as a document.
_MISLEADING_PATTERNS = [
    re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpg|png|txt|csv|rtf)\.(exe|scr|com|bat|cmd|ps1|js|vbs|jar)$", re.I),
    re.compile(r"^[^.]*invoice[^.]*\.(exe|scr|cmd|bat|js|jar)$", re.I),
    re.compile(r"^[^.]*(invoice|report|document|scan|f0llow|payment|order|tracking)[^.]*\.(exe|scr|msi|jar)$", re.I),
    re.compile(r"\s+.?(exe|scr|msi|js|jar)$", re.I),
]

# Content markers that indicate encoded/obfuscated or downloader payloads.
_SCRIPT_MARKERS: dict[str, tuple[re.Pattern[str], str, str]] = {
    "encoded-powershell": (
        re.compile(r"-enc(oded)?[ \t]+([A-Za-z0-9+/=]{20,})", re.I),
        "Command & Control",
        "Encoded or obfuscated PowerShell payload found in script content.",
    ),
    "download-cradle": (
        re.compile(r"(FromBase64String|DownloadString|DownloadData|Invoke-WebRequest|Net\.WebClient|IEX\s*\(|Invoke-Expression|Start-BitsTransfer|certutil[^\n]*urlcache)", re.I),
        "Command & Control",
        "Download cradle or web fetch primitive present in script content.",
    ),
    "lsass-access": (
        re.compile(r"(mimikatz|sekurlsa|lsass(\.exe)?|mini[-_ ]?dump|procdump|comsvcs)", re.I),
        "Credential Access",
        "Credential-dumping keywords (`lsass`, `mimikatz`, ...) present in script content.",
    ),
    "scheduled-task": (
        re.compile(r"(Register-ScheduledTask|schtasks|New-ScheduledTaskAction|at\s+\d\d:\d\d)", re.I),
        "Persistence",
        "Scheduled task creation primitive found in script content.",
    ),
    "startup-copy": (
        re.compile(r"(Startup[^\n]*Copy-Item|Copy-Item[^\n]*Startup|WScript\.Shell[^\n]*Startup|registry[^\n]*Run)", re.I),
        "Persistence",
        "Persistence copy to startup/registry Run location found in script content.",
    ),
    "archive-stager": (
        re.compile(r"(Compress-Archive|7z\s+a[^\n]*-p|zip|rar\s+a[^\n]*\S+)", re.I),
        "Collection",
        "Archive/staging primitive found in script content.",
    ),
    "recon-commands": (
        re.compile(r"(whoami|net\s+user|net\s+localgroup|query\s+user|systeminfo|ipconfig\s+/all)", re.I),
        "Discovery",
        "System discovery / recon command found in script content.",
    ),
    "obfuscated-string": (
        re.compile(r"([\"'][A-Za-z0-9+/]{40,}==[\"']|char\s*\(\s*\d+)", re.I),
        "Defense Evasion",
        "Obfuscated string (base64 blob or built via char codes) in script content.",
    ),
}

# Startup locations that indicate a persistence attempt when files appear there.
_STARTUP_MARKERS = ("startup", "appdata\\roaming\\microsoft\\windows\\start menu", "start menu\\programs\\startup")


@dataclass
class ScannedFile:
    path: str
    name: str
    extension: str
    size_bytes: int
    modified_iso: str
    is_hidden: bool


def resolve_scan_roots() -> list[str]:
    """Resolve the real directories to scan from the environment."""
    roots: set[str] = set()

    def note(p: str | None) -> None:
        if p:
            normalized = os.path.normpath(p)
            if os.path.isdir(normalized):
                roots.add(normalized)

    note(os.environ.get("TEMP"))
    note(os.environ.get("TMP"))
    note(os.path.join(os.environ.get("LOCALAPPDATA", ""), "Temp"))
    note(os.path.join(os.environ.get("USERPROFILE", ""), "Downloads"))
    if os.environ.get("APPDATA"):
        roots.add(os.path.normpath(os.environ["APPDATA"]))
    if os.environ.get("PROGRAMDATA"):
        roots.add(os.path.normpath(os.environ["PROGRAMDATA"]))

    # Extra user-configured roots (comma separated).
    for raw in Config.FILE_SCAN_ROOTS:
        p = os.path.expandvars(os.path.expanduser(raw.strip()))
        if p and os.path.isdir(p):
            roots.add(os.path.normpath(p))

    return sorted(roots)


def _walk_candidates(roots: list[str], window_hours: float, max_candidates: int) -> list[ScannedFile]:
    """Enumerate candidate files under the scan roots."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
    candidates: list[ScannedFile] = []

    for root in roots:
        try:
            for dirpath, dirnames, filenames in os.walk(root):
                # Skip the bulk of node/npm clutter inside user roots.
                dirnames[:] = [
                    d
                    for d in dirnames
                    if not d.startswith("node_modules")
                    and not d.startswith(".git")
                    and not d.startswith("__pycache__")
                ]
                for filename in filenames:
                    if len(candidates) >= max_candidates:
                        return candidates
                    path = os.path.join(dirpath, filename)
                    ext = os.path.splitext(filename)[1].lower()
                    if ext not in _TARGET_EXTENSIONS:
                        continue
                    try:
                        stat = os.stat(path)
                        mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                        if mtime < cutoff:
                            continue
                        candidates.append(
                            ScannedFile(
                                path=path,
                                name=filename,
                                extension=ext,
                                size_bytes=stat.st_size,
                                modified_iso=mtime.isoformat(),
                                is_hidden=bool(getattr(stat, "st_file_attributes", 0) & 0x2),
                            )
                        )
                    except OSError:
                        continue
        except OSError:
            logger.debug("Skipping unreadable scan root: %s", root)

    return candidates


def _sha256_of(path: str, max_bytes: int) -> tuple[str, int]:
    """SHA-256 of a file, reading at most ``max_bytes`` from its head."""
    h = hashlib.sha256()
    read = 0
    try:
        with open(path, "rb") as fh:
            while read < max_bytes:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                read += len(chunk)
                h.update(chunk)
    except OSError:
        return "", 0
    return h.hexdigest(), read


def _sample_text(path: str, max_bytes: int) -> str:
    """Read a text preview of a script-like file (best effort)."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(min(max_bytes, 256 * 1024))
    except OSError:
        return ""
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return raw.decode("latin-1", errors="replace")


def _misleading_name(name: str) -> tuple[bool, str]:
    for pattern in _MISLEADING_PATTERNS:
        if pattern.search(name):
            return True, f"Filename `{name}` is designed to appear as a document or well-known file while actually being an executable/script."
    return False, ""


def _content_hits(text: str) -> list[tuple[str, str, str]]:
    """Return (category, className, reasonBase) for every rule that fires."""
    hits: list[tuple[str, str, str]] = []
    for category, (pattern, className, reason) in _SCRIPT_MARKERS.items():
        if pattern.search(text):
            hits.append((category, className, reason))
    return hits


def _severity_for(categories: list[str], misleading: bool, in_temp: bool, in_startup: bool, extension: str) -> tuple[str, str]:
    """Map detections to a severity and final reason text."""
    combined: set[str] = set(categories)
    if misleading:
        combined.add("misleading-name")
    if in_startup:
        combined.add("startup-file")

    base = " / ".join(sorted(combined))
    if in_startup and {"lsass-access", "encoded-powershell", "download-cradle"} & combined:
        return "critical", f"Persistence-capable payload found in a Startup folder ({base})."
    if "lsass-access" in combined or "encoded-powershell" in combined:
        return "critical", f"High-confidence credential/obfuscation indicators ({base})."
    if "download-cradle" in combined:
        return "high", f"Download/download-execute primitive ({base})."
    if "startup-file" in combined and misleading:
        return "high", f"Disguised executable in a Startup folder ({base})."
    if "startup-file" in combined:
        return "medium", f"Executable/script placed in a Startup folder ({base})."
    if misleading and in_temp:
        return "medium", f"Disguised executable in a user-writable directory ({base})."
    if misleading:
        return "medium", f"Filename disguised to look like a document or known file ({base})."
    if "archive-stager" in combined:
        return "medium", f"Archive/staging primitive ({base})."
    if "recon-commands" in combined:
        return "medium", f"Reconnaissance commands ({base})."
    if "scheduled-task" in combined:
        return "medium", f"Persistence via scheduled task ({base})."
    if "obfuscated-string" in combined:
        return "high", f"Obfuscated content ({base})."
    if combined:
        return "low", f"Scripted activity observed ({base})."
    return "low", "No heuristic rule fired."


def _path_context(path: str) -> tuple[bool, bool]:
    lower = path.lower()
    in_temp = any(t in lower for t in ("\\temp\\", "\\downloads\\", "\\appdata\\local\\temp"))
    in_startup = any(m in lower for m in _STARTUP_MARKERS)
    return in_temp, in_startup


def analyze_file(candidate: ScannedFile, max_hash_bytes: int, is_running: bool) -> list[FileFinding]:
    """Analyze a single candidate file and return all detections for it."""
    findings: list[FileFinding] = []
    hash_hex, _ = _sha256_of(candidate.path, max_hash_bytes)
    in_temp, in_startup = _path_context(candidate.path)

    misleading, misleading_reason = _misleading_name(candidate.name)

    categories: list[str] = []
    reasons: list[str] = []
    class_names: list[str] = []

    if candidate.extension in _SCRIPT_EXTENSIONS and candidate.size_bytes <= Config.FILE_MAX_READ_BYTES:
        text = _sample_text(candidate.path, Config.FILE_MAX_READ_BYTES)
        for category, className, reason in _content_hits(text):
            if category not in categories:
                categories.append(category)
                class_names.append(className)
                reasons.append(reason)

    if misleading:
        categories.append("misleading-name")
        class_names.append("Execution")
        if misleading_reason not in reasons:
            reasons.append(misleading_reason)

    if in_startup and candidate.extension in (".exe", ".scr", ".com", ".js", ".vbs", ".bat", ".cmd", ".ps1"):
        categories.append("startup-file")
        class_names.append("Persistence")
        reasons.append("Executable/script resident in a Windows Startup folder — persistence indicator.")

    if not categories:
        return findings

    severity, reason_text = _severity_for(
        categories,
        misleading=misleading,
        in_temp=in_temp,
        in_startup=in_startup,
        extension=candidate.extension,
    )

    reason_join = " ".join(reasons)
    findings.append(
        FileFinding(
            id=stable_id("file", candidate.path),
            path=candidate.path,
            name=candidate.name,
            extension=candidate.extension,
            size_bytes=candidate.size_bytes,
            modified=candidate.modified_iso,
            hash=hash_hex,
            severity=severity,
            className=" / ".join(dict.fromkeys(class_names)) or "Execution",
            reason=f"{reason_text} {reason_join}".strip(),
            category=" / ".join(sorted(set(categories))),
            is_running=is_running,
        )
    )
    return findings


def scan_files(running_paths: set[str] | None = None) -> FileScanSnapshot:
    """Scan the real filesystem and return all file threat findings."""
    paths = running_paths or set()
    roots = resolve_scan_roots()
    window_hours = float(Config.FILE_SCAN_RECENT_WINDOW_HOURS)
    max_candidates = int(Config.FILE_MAX_CANDIDATES)
    max_hash_bytes = int(Config.FILE_MAX_HASH_BYTES)

    candidates = _walk_candidates(roots, window_hours, max_candidates)

    findings: list[FileFinding] = []
    files_hashed = 0
    files_read = 0
    for candidate in candidates:
        is_running = os.path.normpath(candidate.path).lower() in paths
        hits = analyze_file(candidate, max_hash_bytes, is_running)
        if hits:
            findings.extend(hits)
        # Count hashing/read attempts for reporting.
        if candidate.size_bytes <= max_hash_bytes:
            files_hashed += 1
        if candidate.extension in _SCRIPT_EXTENSIONS and candidate.size_bytes <= Config.FILE_MAX_READ_BYTES:
            files_read += 1

    findings.sort(key=lambda f: (f.timestamp, f.path))

    logger.info(
        "File scan: %d roots, %d candidates, %d findings",
        len(roots),
        len(candidates),
        len(findings),
    )
    return FileScanSnapshot(
        findings=findings,
        directories_scanned=len(roots),
        files_candidates=len(candidates),
        files_hashed=files_hashed,
        files_read=files_read,
    )


def running_process_paths(processes: Iterable[object]) -> set[str]:
    """Normalize executable paths from a process snapshot for running-file linkage."""
    normalized: set[str] = set()
    for p in processes:
        path = getattr(p, "executable_path", None)
        if path:
            normalized.add(os.path.normpath(path).lower())
    return normalized