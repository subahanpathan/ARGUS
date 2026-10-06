import time
from collections import defaultdict
from typing import Any, Dict, List, Set, Tuple

from .rules_base import BaseDetectionRule, DetectionAlert
from ..config import Config


SHELL_BINARIES: Set[str] = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "nc.exe", "ncat.exe", "netcat.exe",
    "socat.exe", "bash.exe", "sh.exe"
}

SCRIPT_INTERPRETERS: Set[str] = {
    "python.exe", "pythonw.exe", "cscript.exe", "wscript.exe", "mshta.exe", "certutil.exe"
}


class ReverseShellRule(BaseDetectionRule):
    """
    Detects interactive command shells maintaining established TCP sockets
    to non-whitelisted remote endpoints (classic Kali reverse shell).
    """

    def __init__(self, config: Config):
        super().__init__(
            rule_id="NET-001",
            name="Interactive Shell Reverse Connection Detected",
            severity="Critical",
            mitre_technique="T1059.001 / T1071"
        )
        self.config = config

    def evaluate(self, context: Dict[str, Any]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        connections = context.get("connections", [])

        for conn in connections:
            remote_ip = conn.get("remote_ip")
            if not remote_ip or self.config.is_ip_trusted(remote_ip):
                continue

            status = conn.get("status", "").upper()
            if status not in ("ESTABLISHED", "SYN_SENT"):
                continue

            proc_name = (conn.get("process_name") or "").lower()
            cmdline = conn.get("command_line") or ""

            is_shell = proc_name in SHELL_BINARIES
            # Also catch python one-liner reverse shells e.g. socket.connect
            is_py_rev = "python" in proc_name and ("socket" in cmdline.lower() or "connect" in cmdline.lower())

            if is_shell or is_py_rev:
                alerts.append(DetectionAlert(
                    rule_id=self.rule_id,
                    name=self.name,
                    severity=self.severity,
                    description=(
                        f"Active reverse shell detected: Process '{proc_name}' (PID {conn.get('pid')}) "
                        f"connected to remote host {remote_ip}:{conn.get('remote_port')}."
                    ),
                    mitre_technique=self.mitre_technique,
                    attacker_ip=remote_ip,
                    pid=conn.get("pid"),
                    process_name=conn.get("process_name"),
                    command_line=conn.get("command_line"),
                    parent_pid=conn.get("parent_pid"),
                    parent_process_name=conn.get("parent_process_name"),
                    details={
                        "remote_ip": remote_ip,
                        "remote_port": conn.get("remote_port"),
                        "local_port": conn.get("local_port"),
                        "status": status,
                        "protocol": conn.get("protocol", "TCP")
                    }
                ))

        return alerts


class SuspiciousInterpreterSocketRule(BaseDetectionRule):
    """
    Detects script engines or LOLBins communicating over common Kali / Metasploit
    payload ports (e.g. 4444, 1337, 8888) or non-standard remote ports.
    """

    def __init__(self, config: Config):
        super().__init__(
            rule_id="NET-002",
            name="Script Engine Suspicious Network Activity",
            severity="High",
            mitre_technique="T1059.006"
        )
        self.config = config

    def evaluate(self, context: Dict[str, Any]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        connections = context.get("connections", [])
        suspicious_ports = set(self.config.get("network", "suspicious_ports", [4444, 4445, 1337, 8888, 9001]))

        for conn in connections:
            remote_ip = conn.get("remote_ip")
            if not remote_ip or self.config.is_ip_trusted(remote_ip):
                continue

            proc_name = (conn.get("process_name") or "").lower()
            remote_port = conn.get("remote_port")

            if proc_name in SCRIPT_INTERPRETERS:
                if remote_port in suspicious_ports:
                    alerts.append(DetectionAlert(
                        rule_id=self.rule_id,
                        name=f"Interpreter Connected to Known C2 Port ({remote_port})",
                        severity="High",
                        description=(
                            f"Interpreter '{proc_name}' (PID {conn.get('pid')}) connected to "
                            f"{remote_ip}:{remote_port} on a known exploit handler port."
                        ),
                        mitre_technique=self.mitre_technique,
                        attacker_ip=remote_ip,
                        pid=conn.get("pid"),
                        process_name=conn.get("process_name"),
                        command_line=conn.get("command_line"),
                        details={
                            "remote_ip": remote_ip,
                            "remote_port": remote_port,
                            "protocol": conn.get("protocol", "TCP")
                        }
                    ))

        return alerts


class PortScanDetectionRule(BaseDetectionRule):
    """
    Detects rapid horizontal or vertical port scans (e.g., nmap, masscan)
    originating from an external IP targeting local ports.
    """

    def __init__(self, config: Config):
        super().__init__(
            rule_id="NET-003",
            name="Network Port Scan Detected",
            severity="Medium",
            mitre_technique="T1046"
        )
        self.config = config
        # Store: ip -> list of (timestamp, local_port)
        self.history: Dict[str, List[Tuple[float, int]]] = defaultdict(list)

    def evaluate(self, context: Dict[str, Any]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        connections = context.get("connections", [])
        now = time.time()
        window = float(self.config.get("network", "port_scan_window_seconds", 10))
        threshold = int(self.config.get("network", "port_scan_threshold", 15))

        for conn in connections:
            remote_ip = conn.get("remote_ip")
            local_port = conn.get("local_port")
            if not remote_ip or not local_port or self.config.is_ip_trusted(remote_ip):
                continue

            self.history[remote_ip].append((now, local_port))

        # Check thresholds
        for ip, attempts in list(self.history.items()):
            # Prune out-of-window
            recent = [item for item in attempts if (now - item[0]) <= window]
            self.history[ip] = recent

            unique_ports = {item[1] for item in recent}
            if len(unique_ports) >= threshold:
                alerts.append(DetectionAlert(
                    rule_id=self.rule_id,
                    name=self.name,
                    severity=self.severity,
                    description=(
                        f"Port scan detected from {ip}: probed {len(unique_ports)} distinct ports "
                        f"within {window:.1f} seconds."
                    ),
                    mitre_technique=self.mitre_technique,
                    attacker_ip=ip,
                    details={
                        "probed_ports_count": len(unique_ports),
                        "ports_sample": list(unique_ports)[:20],
                        "window_seconds": window
                    }
                ))
                # Reset history for this IP to prevent duplicate spam
                self.history[ip] = []

        return alerts


class BruteForceDetectionRule(BaseDetectionRule):
    """
    Detects repeated incoming connections to SMB (445), RDP (3389),
    or WinRM (5985/5986) indicating brute force authentication attempts.
    """

    BRUTE_PORTS = {445, 3389, 5985, 5986, 22}

    def __init__(self, config: Config):
        super().__init__(
            rule_id="NET-004",
            name="Remote Authentication Brute Force Attempt",
            severity="High",
            mitre_technique="T1110"
        )
        self.config = config
        self.history: Dict[str, List[Tuple[float, int]]] = defaultdict(list)

    def evaluate(self, context: Dict[str, Any]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        connections = context.get("connections", [])
        now = time.time()
        window = float(self.config.get("network", "brute_force_window_seconds", 60))
        threshold = int(self.config.get("network", "brute_force_threshold", 5))

        for conn in connections:
            remote_ip = conn.get("remote_ip")
            local_port = conn.get("local_port")
            if not remote_ip or not local_port or self.config.is_ip_trusted(remote_ip):
                continue

            if local_port in self.BRUTE_PORTS:
                self.history[remote_ip].append((now, local_port))

        for ip, attempts in list(self.history.items()):
            recent = [item for item in attempts if (now - item[0]) <= window]
            self.history[ip] = recent

            if len(recent) >= threshold:
                target_ports = list({item[1] for item in recent})
                alerts.append(DetectionAlert(
                    rule_id=self.rule_id,
                    name=self.name,
                    severity=self.severity,
                    description=(
                        f"Brute force attempt detected from {ip}: {len(recent)} connection bursts "
                        f"targeting management ports {target_ports} in {window:.1f}s."
                    ),
                    mitre_technique=self.mitre_technique,
                    attacker_ip=ip,
                    details={
                        "attempts_count": len(recent),
                        "ports": target_ports,
                        "window_seconds": window
                    }
                ))
                self.history[ip] = []

        return alerts
