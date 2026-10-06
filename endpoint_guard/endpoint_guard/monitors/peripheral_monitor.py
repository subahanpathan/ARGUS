import os
import threading
import time
import winreg
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import psutil

from ..config import Config
from ..detection.peripheral_rules import MicrophoneAccessRule, WebcamAccessRule
from ..detection.rules_base import DetectionAlert


REG_PERIPHERAL_PATHS = [
    ("webcam", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged"),
    ("webcam", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged"),
    ("microphone", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged"),
    ("microphone", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged"),
]


class PeripheralMonitor:
    """
    Monitors Windows CapabilityAccessManager ConsentStore for webcam and microphone usage.
    Detects unauthorized or hostile processes attempting to record video or audio.
    """

    def __init__(self, config: Config, on_alert: Callable[[DetectionAlert], None],
                 on_event: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.config = config
        self.on_alert = on_alert
        self.on_event = on_event
        self.running = False
        self._thread: Optional[threading.Thread] = None

        self.rules = [
            WebcamAccessRule(config),
            MicrophoneAccessRule(config),
        ]

        # Cache of (device_type, exe_key) -> LastUsedTimeStart
        self._last_access_times: Dict[Tuple[str, str], int] = {}
        self._seed_baseline()

    def _seed_baseline(self) -> None:
        """Seeds existing access timestamps so historical accesses do not cause false alarms on boot."""
        for dev_type, hive, subpath in REG_PERIPHERAL_PATHS:
            try:
                with winreg.OpenKey(hive, subpath, 0, winreg.KEY_READ) as key:
                    count, _, _ = winreg.QueryInfoKey(key)
                    for i in range(count):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ) as subkey:
                                try:
                                    t_start, _ = winreg.QueryValueEx(subkey, "LastUsedTimeStart")
                                    self._last_access_times[(dev_type, subkey_name.lower())] = int(t_start)
                                except OSError:
                                    pass
                        except OSError:
                            continue
            except Exception:
                pass

    def _find_pid_for_binary(self, binary_path: str) -> Tuple[Optional[int], Optional[str], Optional[str]]:
        exe_name = Path(binary_path).name.lower()
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                info = proc.info
                p_name = (info.get("name") or "").lower()
                p_exe = (info.get("exe") or "").lower()
                if p_name == exe_name or (p_exe and p_exe == binary_path.lower()):
                    cmdline = " ".join(info.get("cmdline") or [])
                    return info["pid"], info.get("name"), cmdline
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return None, Path(binary_path).name, None

    def scan_device_access(self) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        raw_events: List[Dict[str, Any]] = []

        for dev_type, hive, subpath in REG_PERIPHERAL_PATHS:
            try:
                with winreg.OpenKey(hive, subpath, 0, winreg.KEY_READ) as key:
                    count, _, _ = winreg.QueryInfoKey(key)
                    for i in range(count):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ) as subkey:
                                try:
                                    t_start, _ = winreg.QueryValueEx(subkey, "LastUsedTimeStart")
                                    t_stop, _ = winreg.QueryValueEx(subkey, "LastUsedTimeStop")
                                    t_start = int(t_start)
                                    t_stop = int(t_stop)
                                except OSError:
                                    continue

                                key_id = (dev_type, subkey_name.lower())
                                prev_start = self._last_access_times.get(key_id, 0)

                                # Device is actively capturing (stop == 0 or start > stop)
                                is_active = (t_stop == 0 or t_start > t_stop) and t_start > 0
                                # Or new access since last scan
                                is_new_access = t_start > prev_start and t_start > 0

                                if is_active or is_new_access:
                                    self._last_access_times[key_id] = t_start
                                    # Convert subkey_name back to file path (Windows converts '\' to '#')
                                    real_exe_path = subkey_name.replace("#", "\\")
                                    pid, proc_name, cmdline = self._find_pid_for_binary(real_exe_path)

                                    raw_events.append({
                                        "device_type": dev_type,
                                        "is_active": is_active,
                                        "registry_key": subkey_name,
                                        "exe_path": real_exe_path,
                                        "process_name": proc_name or Path(real_exe_path).name,
                                        "pid": pid,
                                        "command_line": cmdline,
                                        "start_time": t_start,
                                    })
                        except OSError:
                            continue
            except Exception:
                pass

        if raw_events:
            context = {"peripheral_events": raw_events}
            for rule in self.rules:
                try:
                    rule_alerts = rule.evaluate(context)
                    for alert in rule_alerts:
                        alerts.append(alert)
                        self.on_alert(alert)
                except Exception as e:
                    print(f"[PeripheralMonitor] Error evaluating {rule.name}: {e}")

            if self.on_event:
                for ev in raw_events:
                    self.on_event({
                        "event_type": "peripheral_access",
                        "source_module": "peripheral",
                        "severity": "Medium",
                        "pid": ev.get("pid"),
                        "process_name": ev.get("process_name"),
                        "details": {
                            "device": ev.get("device_type"),
                            "is_active": ev.get("is_active"),
                            "exe_path": ev.get("exe_path")
                        }
                    })

        return alerts

    def _loop(self) -> None:
        interval = float(self.config.get("peripherals", "poll_interval_seconds", 1.0))
        while self.running:
            try:
                self.scan_device_access()
            except Exception as e:
                print(f"[PeripheralMonitor] Loop error: {e}")
            time.sleep(interval)

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._loop, name="PeripheralMonitorThread", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
