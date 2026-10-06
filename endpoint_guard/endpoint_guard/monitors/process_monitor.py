import hashlib
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set

import psutil

from ..config import Config
from ..detection.process_rules import (
    EncodedPowerShellRule,
    LolbinAbuseRule,
    SuspiciousParentChildRule,
    UntrustedPathExecutionRule,
)
from ..detection.rules_base import DetectionAlert


def compute_file_sha256(file_path: str) -> Optional[str]:
    """Calculates SHA-256 hash of a file on disk."""
    if not file_path or not os.path.exists(file_path):
        return None
    try:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception:
        return None


class ProcessMonitor:
    """Monitors process spawning, parent-child trees, and command-line arguments."""

    def __init__(self, config: Config, on_alert: Callable[[DetectionAlert], None],
                 on_event: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.config = config
        self.on_alert = on_alert
        self.on_event = on_event
        self.running = False
        self._thread: Optional[threading.Thread] = None

        self.rules = [
            SuspiciousParentChildRule(config),
            EncodedPowerShellRule(config),
            LolbinAbuseRule(config),
            UntrustedPathExecutionRule(config),
        ]

        self._known_pids: Set[int] = set()
        self._seed_pids()

    def _seed_pids(self) -> None:
        try:
            self._known_pids = set(psutil.pids())
        except Exception:
            self._known_pids = set()

    def scan_new_processes(self) -> List[Dict[str, Any]]:
        new_procs: List[Dict[str, Any]] = []
        try:
            current_pids = set(psutil.pids())
            spawned_pids = current_pids - self._known_pids
            self._known_pids = current_pids
        except Exception:
            return []

        for pid in spawned_pids:
            try:
                proc = psutil.Process(pid)
                name = proc.name()
                try:
                    cmdline = " ".join(proc.cmdline())
                except Exception:
                    cmdline = ""
                try:
                    exe = proc.exe()
                except Exception:
                    exe = ""
                try:
                    parent = proc.parent()
                    parent_pid = parent.pid if parent else None
                    parent_name = parent.name() if parent else None
                except Exception:
                    parent_pid = None
                    parent_name = None
                try:
                    username = proc.username()
                except Exception:
                    username = ""

                file_hash = compute_file_sha256(exe) if exe else None

                entry = {
                    "pid": pid,
                    "process_name": name,
                    "command_line": cmdline,
                    "exe_path": exe,
                    "parent_pid": parent_pid,
                    "parent_process_name": parent_name,
                    "user_account": username,
                    "file_hash_sha256": file_hash,
                }
                new_procs.append(entry)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return new_procs

    def evaluate_snapshot(self, processes: Optional[List[Dict[str, Any]]] = None) -> List[DetectionAlert]:
        procs = processes if processes is not None else self.scan_new_processes()
        if not procs:
            return []

        context = {"processes": procs}
        all_alerts: List[DetectionAlert] = []

        for rule in self.rules:
            try:
                alerts = rule.evaluate(context)
                for alert in alerts:
                    all_alerts.append(alert)
                    self.on_alert(alert)
            except Exception as e:
                print(f"[ProcessMonitor] Error evaluating {rule.name}: {e}")

        if self.on_event:
            for p in procs:
                self.on_event({
                    "event_type": "process_spawn",
                    "source_module": "process",
                    "severity": "Low",
                    "pid": p["pid"],
                    "process_name": p["process_name"],
                    "command_line": p["command_line"],
                    "parent_pid": p["parent_pid"],
                    "parent_process_name": p["parent_process_name"],
                    "user_account": p["user_account"],
                    "file_path": p["exe_path"],
                    "file_hash_sha256": p["file_hash_sha256"],
                })

        return all_alerts

    def _loop(self) -> None:
        interval = float(self.config.get("process", "poll_interval_seconds", 1.0))
        while self.running:
            try:
                self.evaluate_snapshot()
            except Exception as e:
                print(f"[ProcessMonitor] Loop error: {e}")
            time.sleep(interval)

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._loop, name="ProcessMonitorThread", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
