import os
import threading
import time
import winreg
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import psutil

REG_PERIPHERAL_PATHS = [
    ("webcam", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged"),
    ("webcam", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged"),
    ("microphone", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged"),
    ("microphone", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\NonPackaged"),
]

APPROVED_CONFERENCING_APPS = {
    "zoom.exe", "teams.exe", "chrome.exe", "msedge.exe", "firefox.exe",
    "obs64.exe", "skype.exe", "discord.exe", "audacity.exe", "slack.exe"
}


class PeripheralWatcher:
    """
    Watches Windows CapabilityAccessManager ConsentStore for webcam and microphone usage.
    Detects unauthorized or hostile processes attempting to record video or audio.
    """

    def __init__(self, on_event: Callable[[Dict[str, Any]], None], poll_interval_ms: int = 1000):
        self.on_event = on_event
        self.poll_interval = poll_interval_ms / 1000.0
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._last_access_times: Dict[Tuple[str, str], int] = {}
        self._seed_baseline()

    def _seed_baseline(self) -> None:
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

    def _find_process_for_binary(self, binary_path: str) -> Tuple[Optional[int], Optional[str], Optional[str]]:
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

    def scan_access(self) -> None:
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

                                is_active = (t_stop == 0 or t_start > t_stop) and t_start > 0
                                is_new = t_start > prev_start and t_start > 0

                                if is_active or is_new:
                                    self._last_access_times[key_id] = t_start
                                    real_exe_path = subkey_name.replace("#", "\\")
                                    exe_name = Path(real_exe_path).name.lower()

                                    # Skip approved conferencing tools
                                    if exe_name in APPROVED_CONFERENCING_APPS:
                                        continue

                                    pid, proc_name, cmdline = self._find_process_for_binary(real_exe_path)

                                    event = {
                                        "event_type": "DEVICE_ACCESS",
                                        "source": "windows_peripheral_monitor",
                                        "device": dev_type,
                                        "is_active": is_active,
                                        "pid": pid,
                                        "process_name": proc_name or exe_name,
                                        "executable_path": real_exe_path,
                                        "command_line": cmdline or "",
                                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                        "severity": "critical",
                                        "observed": True,
                                    }
                                    self.on_event(event)

                                    # Active defense: auto-kill unauthorized camera/mic accessing process
                                    if pid and pid > 4:
                                        try:
                                            os.system(f"taskkill /F /T /PID {pid} >nul 2>&1")
                                        except Exception:
                                            pass
                        except OSError:
                            continue
            except Exception:
                pass

    def _loop(self) -> None:
        while self.running:
            try:
                self.scan_access()
            except Exception:
                pass
            time.sleep(self.poll_interval)

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._loop, name="ArgusPeripheralWatcher", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
