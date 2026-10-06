import re
import socket
import subprocess
import threading
import time
from typing import Any, Callable, Dict, List, Optional

import psutil

from ..config import Config
from ..detection.network_rules import (
    BruteForceDetectionRule,
    PortScanDetectionRule,
    ReverseShellRule,
    SuspiciousInterpreterSocketRule,
)
from ..detection.rules_base import DetectionAlert


def resolve_mac_address(ip: str) -> Optional[str]:
    """Resolves MAC address of an IP on the local subnet via the Windows ARP cache."""
    try:
        output = subprocess.check_output(f"arp -a {ip}", shell=True, text=True, stderr=subprocess.DEVNULL)
        match = re.search(r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", output)
        if match:
            return match.group(1).replace("-", ":").upper()
    except Exception:
        pass
    return None


def resolve_hostname(ip: str) -> Optional[str]:
    """Resolves hostname via reverse DNS or NetBIOS."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None


class NetworkMonitor:
    """Continuously monitors active sockets, identifies attacker IPs, and applies detection rules."""

    def __init__(self, config: Config, on_alert: Callable[[DetectionAlert], None],
                 on_event: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.config = config
        self.on_alert = on_alert
        self.on_event = on_event
        self.running = False
        self._thread: Optional[threading.Thread] = None

        # Initialize network rules
        self.rules = [
            ReverseShellRule(config),
            SuspiciousInterpreterSocketRule(config),
            PortScanDetectionRule(config),
            BruteForceDetectionRule(config),
        ]

        # Cache process metadata to minimize overhead
        self._proc_cache: Dict[int, Dict[str, Any]] = {}
        self._last_cache_clean = time.time()

    def _get_process_info(self, pid: Optional[int]) -> Dict[str, Any]:
        if not pid or pid == 0:
            return {
                "name": "System", "cmdline": "", "parent_pid": None,
                "parent_name": None, "username": "SYSTEM"
            }

        now = time.time()
        if now - self._last_cache_clean > 30:
            self._proc_cache.clear()
            self._last_cache_clean = now

        if pid in self._proc_cache:
            return self._proc_cache[pid]

        try:
            proc = psutil.Process(pid)
            name = proc.name()
            cmdline = " ".join(proc.cmdline()) if proc.cmdline() else ""
            parent = proc.parent()
            parent_pid = parent.pid if parent else None
            parent_name = parent.name() if parent else None
            username = proc.username() if hasattr(proc, "username") else ""

            info = {
                "name": name,
                "cmdline": cmdline,
                "parent_pid": parent_pid,
                "parent_name": parent_name,
                "username": username
            }
            self._proc_cache[pid] = info
            return info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {
                "name": "unknown", "cmdline": "", "parent_pid": None,
                "parent_name": None, "username": ""
            }

    def scan_connections(self) -> List[Dict[str, Any]]:
        """Scans current network connections and enriches them with process context."""
        enriched: List[Dict[str, Any]] = []
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            conns = []

        for conn in conns:
            if not conn.raddr:
                continue

            r_ip = conn.raddr.ip
            r_port = conn.raddr.port
            l_ip = conn.laddr.ip if conn.laddr else ""
            l_port = conn.laddr.port if conn.laddr else 0
            pid = conn.pid

            proc_info = self._get_process_info(pid)

            entry = {
                "pid": pid,
                "process_name": proc_info["name"],
                "command_line": proc_info["cmdline"],
                "parent_pid": proc_info["parent_pid"],
                "parent_process_name": proc_info["parent_name"],
                "user_account": proc_info["username"],
                "local_ip": l_ip,
                "local_port": l_port,
                "remote_ip": r_ip,
                "remote_port": r_port,
                "status": conn.status,
                "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
            }
            enriched.append(entry)

        return enriched

    def evaluate_snapshot(self, connections: Optional[List[Dict[str, Any]]] = None) -> List[DetectionAlert]:
        """Evaluates detection rules against current or provided connection snapshot."""
        conns = connections if connections is not None else self.scan_connections()
        context = {"connections": conns}

        all_alerts: List[DetectionAlert] = []
        for rule in self.rules:
            try:
                alerts = rule.evaluate(context)
                for alert in alerts:
                    all_alerts.append(alert)
                    self.on_alert(alert)
            except Exception as e:
                print(f"[NetworkMonitor] Error evaluating {rule.name}: {e}")

        # Dispatch connection events if callback set
        if self.on_event:
            for conn in conns:
                if not self.config.is_ip_trusted(conn["remote_ip"]):
                    self.on_event({
                        "event_type": "network_connection",
                        "source_module": "network",
                        "severity": "Low",
                        "attacker_ip": conn["remote_ip"],
                        "pid": conn["pid"],
                        "process_name": conn["process_name"],
                        "command_line": conn["command_line"],
                        "remote_port": conn["remote_port"],
                        "local_port": conn["local_port"],
                        "protocol": conn["protocol"],
                        "details": {"status": conn["status"]}
                    })

        return all_alerts

    def _loop(self) -> None:
        interval = float(self.config.get("network", "scan_interval_seconds", 1.0))
        while self.running:
            try:
                self.evaluate_snapshot()
            except Exception as e:
                print(f"[NetworkMonitor] Scan error: {e}")
            time.sleep(interval)

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._loop, name="NetworkMonitorThread", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
