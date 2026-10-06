import os
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from ..config import Config
from ..detection.file_rules import (
    ArchiveStagingRule,
    BulkFileAccessExfiltrationRule,
    CanaryFileTripwireRule,
)
from ..detection.rules_base import DetectionAlert
from ..response.canary_manager import CanaryManager


class _WatchdogHandler(FileSystemEventHandler):
    def __init__(self, callback: Callable[[str, str], None]):
        super().__init__()
        self.callback = callback

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.callback(event.src_path, "created")

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.callback(event.src_path, "modified")

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self.callback(event.src_path, "deleted")

    def on_moved(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            dest = getattr(event, "dest_path", event.src_path)
            self.callback(dest, "moved")


class FileMonitor:
    """Monitors protected directories in real-time using watchdog and flags exfiltration & canary access."""

    def __init__(self, config: Config, on_alert: Callable[[DetectionAlert], None],
                 on_event: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.config = config
        self.on_alert = on_alert
        self.on_event = on_event
        self.canary_manager = CanaryManager(config)

        self.rules = [
            CanaryFileTripwireRule(config, self.canary_manager),
            BulkFileAccessExfiltrationRule(config),
            ArchiveStagingRule(config),
        ]

        self.observer: Optional[Observer] = None
        self._lock = threading.Lock()

    def _resolve_watch_paths(self) -> List[Path]:
        user_profile = os.environ.get("USERPROFILE", "C:\\Users\\Default")
        watch_dirs = []
        for name in self.config.get("files", "protected_directories", ["Documents", "Desktop"]):
            p = Path(user_profile) / name
            if p.exists():
                watch_dirs.append(p)
        return watch_dirs

    def handle_file_event(self, file_path: str, action: str) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        context = {
            "file_events": [
                {
                    "file_path": file_path,
                    "action": action,
                }
            ]
        }

        for rule in self.rules:
            try:
                rule_alerts = rule.evaluate(context)
                for alert in rule_alerts:
                    alerts.append(alert)
                    self.on_alert(alert)
            except Exception as e:
                print(f"[FileMonitor] Error evaluating {rule.name}: {e}")

        if self.on_event:
            self.on_event({
                "event_type": "file_touch",
                "source_module": "file",
                "severity": "Low",
                "file_path": file_path,
                "details": {"action": action}
            })

        return alerts

    def start(self) -> None:
        with self._lock:
            if self.observer is not None:
                return
            self.observer = Observer()
            handler = _WatchdogHandler(self.handle_file_event)
            watch_paths = self._resolve_watch_paths()
            for path in watch_paths:
                try:
                    self.observer.schedule(handler, str(path), recursive=True)
                except Exception as e:
                    print(f"[FileMonitor] Could not watch {path}: {e}")
            try:
                self.observer.start()
            except Exception as e:
                print(f"[FileMonitor] Failed to start observer: {e}")

    def stop(self) -> None:
        with self._lock:
            if self.observer:
                try:
                    self.observer.stop()
                    self.observer.join(timeout=2.0)
                except Exception:
                    pass
                self.observer = None
