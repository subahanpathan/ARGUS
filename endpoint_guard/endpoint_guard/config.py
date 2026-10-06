import os
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_CONFIG: Dict[str, Any] = {
    "general": {
        "app_name": "Endpoint Guard",
        "log_level": "INFO",
        "data_dir": "C:\\ProgramData\\EndpointGuard",
        "db_path": "C:\\ProgramData\\EndpointGuard\\endpoint_guard.db",
        "quarantine_dir": "C:\\ProgramData\\EndpointGuard\\quarantine",
        "incident_dir": "C:\\ProgramData\\EndpointGuard\\incidents",
        "canary_dir": "C:\\ProgramData\\EndpointGuard\\canaries",
        "dry_run": False,
    },
    "dashboard": {
        "host": "127.0.0.1",
        "port": 8443,
        "secret_key": "endpoint-guard-local-secure-key",
    },
    "self_protection": {
        "heartbeat_interval_seconds": 5,
        "protected_processes": ["endpoint_guard", "python.exe"],
        "critical_system_processes": [
            "system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
            "lsass.exe", "svchost.exe", "explorer.exe", "winlogon.exe", "spoolsv.exe"
        ],
    },
    "network": {
        "scan_interval_seconds": 1.0,
        "port_scan_threshold": 15,
        "port_scan_window_seconds": 10,
        "brute_force_threshold": 5,
        "brute_force_window_seconds": 60,
        "suspicious_ports": [4444, 4445, 1337, 8888, 9001, 5555, 6666, 31337],
        "trusted_ips": ["127.0.0.1", "::1", "0.0.0.0"],
        "trusted_subnets": ["127.0.0.0/8"],
    },
    "process": {
        "poll_interval_seconds": 1.0,
        "suspicious_lolbins": [
            "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe",
            "wmic.exe", "rundll32.exe", "cscript.exe", "wscript.exe"
        ],
        "suspicious_parents": [
            "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrobat.exe"
        ],
        "suspicious_children": [
            "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "bash.exe", "sh.exe"
        ],
        "untrusted_execution_paths": [
            "AppData\\Local\\Temp", "Windows\\Temp", "Downloads"
        ],
    },
    "files": {
        "protected_directories": ["Documents", "Desktop", "Downloads"],
        "bulk_read_threshold": 20,
        "bulk_read_window_seconds": 10,
        "sensitive_extensions": [
            ".docx", ".xlsx", ".pdf", ".txt", ".key", ".kdbx", ".env", ".pem", ".id_rsa", ".sql", ".db"
        ],
    },
    "canary": {
        "enabled": True,
        "files": [
            {"name": "passwords.xlsx", "rel_path": "Documents\\passwords.xlsx"},
            {"name": "corporate_secrets.docx", "rel_path": "Desktop\\corporate_secrets.docx"},
            {"name": "vpn_credentials.txt", "rel_path": "Documents\\vpn_credentials.txt"},
        ],
    },
    "peripherals": {
        "poll_interval_seconds": 1.0,
        "approved_camera_apps": [
            "zoom.exe", "teams.exe", "chrome.exe", "msedge.exe", "firefox.exe", "obs64.exe", "skype.exe"
        ],
        "approved_microphone_apps": [
            "zoom.exe", "teams.exe", "chrome.exe", "msedge.exe", "firefox.exe", "obs64.exe", "discord.exe", "audacity.exe"
        ],
    },
    "response_playbook": {
        "low": {"action": "log"},
        "medium": {"action": "alert_and_capture"},
        "high": {"action": "kill_and_block"},
        "critical": {"action": "isolate_host_and_quarantine"},
    },
}


class Config:
    """Manages application configuration, path resolution, and runtime flags."""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._find_default_config()
        self.raw_data: Dict[str, Any] = self._load()
        self._ensure_directories()

    def _find_default_config(self) -> str:
        candidates = [
            Path("config.yaml").resolve(),
            Path(__file__).parent.parent / "config.yaml",
            Path("C:/ProgramData/EndpointGuard/config.yaml"),
        ]
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
        return str(candidates[0])

    def _load(self) -> Dict[str, Any]:
        data = DEFAULT_CONFIG.copy()
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f)
                    if isinstance(loaded, dict):
                        # Merge top-level dictionaries
                        for key, val in loaded.items():
                            if isinstance(val, dict) and key in data and isinstance(data[key], dict):
                                data[key] = {**data[key], **val}
                            else:
                                data[key] = val
            except Exception as e:
                print(f"[Config] Warning: Failed to parse {self.config_path}: {e}. Using defaults.")
        return data

    def _ensure_directories(self) -> None:
        try:
            for path_key in ["data_dir", "quarantine_dir", "incident_dir", "canary_dir"]:
                dir_path = self.get("general", path_key)
                if dir_path:
                    os.makedirs(dir_path, exist_ok=True)
        except Exception as e:
            print(f"[Config] Note: Could not pre-create directory: {e}")

    def get(self, section: str, key: Optional[str] = None, default: Any = None) -> Any:
        sec = self.raw_data.get(section, {})
        if key is None:
            return sec
        if isinstance(sec, dict):
            return sec.get(key, default)
        return default

    @property
    def dry_run(self) -> bool:
        return bool(self.get("general", "dry_run", False))

    @property
    def data_dir(self) -> str:
        return str(self.get("general", "data_dir", "C:\\ProgramData\\EndpointGuard"))

    @property
    def db_path(self) -> str:
        return str(self.get("general", "db_path", os.path.join(self.data_dir, "endpoint_guard.db")))

    @property
    def quarantine_dir(self) -> str:
        return str(self.get("general", "quarantine_dir", os.path.join(self.data_dir, "quarantine")))

    @property
    def incident_dir(self) -> str:
        return str(self.get("general", "incident_dir", os.path.join(self.data_dir, "incidents")))

    @property
    def canary_dir(self) -> str:
        return str(self.get("general", "canary_dir", os.path.join(self.data_dir, "canaries")))

    def is_ip_trusted(self, ip: str) -> bool:
        if not ip:
            return True
        trusted = self.get("network", "trusted_ips", ["127.0.0.1", "::1", "0.0.0.0"])
        return ip in trusted or ip.startswith("127.")

    def is_critical_process(self, proc_name: str) -> bool:
        if not proc_name:
            return False
        proc_lower = proc_name.lower().strip()
        critical_list = [p.lower() for p in self.get("self_protection", "critical_system_processes", [])]
        return proc_lower in critical_list

    def is_camera_app_approved(self, proc_name: str) -> bool:
        if not proc_name:
            return False
        proc_lower = proc_name.lower().strip()
        approved = [p.lower() for p in self.get("peripherals", "approved_camera_apps", [])]
        return proc_lower in approved

    def is_microphone_app_approved(self, proc_name: str) -> bool:
        if not proc_name:
            return False
        proc_lower = proc_name.lower().strip()
        approved = [p.lower() for p in self.get("peripherals", "approved_microphone_apps", [])]
        return proc_lower in approved
