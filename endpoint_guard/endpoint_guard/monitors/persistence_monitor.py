import os
import threading
import time
import winreg
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from ..config import Config
from ..detection.rules_base import DetectionAlert


REG_LOCATIONS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU_Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU_RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM_Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM_RunOnce"),
]


class PersistenceMonitor:
    """Monitors Windows persistence keys (Run/RunOnce) and Startup folders for unauthorized autoruns."""

    def __init__(self, config: Config, on_alert: Callable[[DetectionAlert], None],
                 on_event: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.config = config
        self.on_alert = on_alert
        self.on_event = on_event
        self.running = False
        self._thread: Optional[threading.Thread] = None

        # Baseline snapshots: (hive_name, value_name) -> value_data
        self._known_reg_entries: Dict[Tuple[str, str], str] = {}
        self._known_startup_files: Set[str] = set()

        self._snapshot_baseline()

    def _get_startup_folders(self) -> List[str]:
        folders = []
        appdata = os.environ.get("APPDATA")
        if appdata:
            folders.append(os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\Startup"))
        programdata = os.environ.get("PROGRAMDATA")
        if programdata:
            folders.append(os.path.join(programdata, r"Microsoft\Windows\Start Menu\Programs\Startup"))
        return [f for f in folders if os.path.exists(f)]

    def _snapshot_baseline(self) -> None:
        # 1. Registry
        for root_hive, subkey, label in REG_LOCATIONS:
            try:
                with winreg.OpenKey(root_hive, subkey, 0, winreg.KEY_READ) as key:
                    index = 0
                    while True:
                        try:
                            val_name, val_data, _ = winreg.EnumValue(key, index)
                            self._known_reg_entries[(label, val_name)] = str(val_data)
                            index += 1
                        except OSError:
                            break
            except Exception:
                pass

        # 2. Startup folders
        for folder in self._get_startup_folders():
            try:
                for fname in os.listdir(folder):
                    self._known_startup_files.add(os.path.join(folder, fname).lower())
            except Exception:
                pass

    def scan_for_changes(self) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []

        # 1. Registry Check
        for root_hive, subkey, label in REG_LOCATIONS:
            try:
                with winreg.OpenKey(root_hive, subkey, 0, winreg.KEY_READ) as key:
                    index = 0
                    while True:
                        try:
                            val_name, val_data, _ = winreg.EnumValue(key, index)
                            key_pair = (label, val_name)
                            if key_pair not in self._known_reg_entries:
                                # New entry discovered!
                                self._known_reg_entries[key_pair] = str(val_data)
                                alert = DetectionAlert(
                                    rule_id="PERSIST-001",
                                    name="Unauthorized Registry Persistence Detected",
                                    severity="High",
                                    description=(
                                        f"New autorun entry '{val_name}' pointing to '{val_data}' "
                                        f"was added in {label} ({subkey})."
                                    ),
                                    mitre_technique="T1547.001",
                                    details={
                                        "hive": label,
                                        "subkey": subkey,
                                        "entry_name": val_name,
                                        "entry_value": str(val_data)
                                    }
                                )
                                alerts.append(alert)
                                self.on_alert(alert)
                            index += 1
                        except OSError:
                            break
            except Exception:
                pass

        # 2. Startup Folder Check
        for folder in self._get_startup_folders():
            try:
                for fname in os.listdir(folder):
                    full_path = os.path.join(folder, fname).lower()
                    if full_path not in self._known_startup_files:
                        self._known_startup_files.add(full_path)
                        alert = DetectionAlert(
                            rule_id="PERSIST-002",
                            name="Unauthorized Startup Folder File Dropped",
                            severity="High",
                            description=f"New executable/shortcut dropped in Startup folder: {full_path}",
                            mitre_technique="T1547.001",
                            file_path=full_path,
                            details={"startup_file": full_path}
                        )
                        alerts.append(alert)
                        self.on_alert(alert)
            except Exception:
                pass

        return alerts

    def remove_registry_persistence(self, label: str, entry_name: str) -> bool:
        """Removes a malicious autorun key from registry."""
        for root_hive, subkey, lab in REG_LOCATIONS:
            if lab == label:
                try:
                    with winreg.OpenKey(root_hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
                        winreg.DeleteValue(key, entry_name)
                        self._known_reg_entries.pop((label, entry_name), None)
                        return True
                except Exception as e:
                    print(f"[PersistenceMonitor] Failed to delete {label}\\{entry_name}: {e}")
                    return False
        return False

    def _loop(self) -> None:
        while self.running:
            try:
                self.scan_for_changes()
            except Exception as e:
                print(f"[PersistenceMonitor] Loop error: {e}")
            time.sleep(5.0)

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._loop, name="PersistenceMonitorThread", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
