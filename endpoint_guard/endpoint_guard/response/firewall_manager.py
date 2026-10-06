import subprocess
from typing import List, Optional

from ..config import Config


class FirewallManager:
    """Manages Windows Firewall rules for blocking attacker IPs and host isolation."""

    def __init__(self, config: Config):
        self.config = config

    def _run_powershell(self, cmd: str) -> bool:
        if self.config.dry_run:
            print(f"[FirewallManager] [DRY RUN] Would execute PowerShell: {cmd}")
            return True
        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=10
            )
            return res.returncode == 0
        except Exception as e:
            print(f"[FirewallManager] Error executing PowerShell: {e}")
            return False

    def block_ip(self, ip: str, rule_name: Optional[str] = None) -> str:
        """Blocks all inbound and outbound traffic to/from the attacker IP."""
        if not ip or self.config.is_ip_trusted(ip):
            return ""

        clean_ip = ip.replace("/", "_").replace(":", "_")
        r_name = rule_name or f"EndpointGuard_Block_{clean_ip}"

        cmd_in = (
            f"New-NetFirewallRule -DisplayName '{r_name}_IN' -Direction Inbound "
            f"-Action Block -RemoteAddress '{ip}' -Profile Any"
        )
        cmd_out = (
            f"New-NetFirewallRule -DisplayName '{r_name}_OUT' -Direction Outbound "
            f"-Action Block -RemoteAddress '{ip}' -Profile Any"
        )

        self._run_powershell(cmd_in)
        self._run_powershell(cmd_out)
        return r_name

    def unblock_ip(self, rule_name: str) -> bool:
        """Removes the block firewall rules."""
        if not rule_name:
            return False
        cmd_in = f"Remove-NetFirewallRule -DisplayName '{rule_name}_IN' -ErrorAction SilentlyContinue"
        cmd_out = f"Remove-NetFirewallRule -DisplayName '{rule_name}_OUT' -ErrorAction SilentlyContinue"
        s1 = self._run_powershell(cmd_in)
        s2 = self._run_powershell(cmd_out)
        return s1 or s2

    def isolate_host(self, allowlist_ips: Optional[List[str]] = None) -> bool:
        """
        Emergency Host Isolation: Blocks all outbound and inbound traffic
        except localhost and explicitly allowed IPs.
        """
        rule_name = "EndpointGuard_EMERGENCY_ISOLATION"
        allowed = ["127.0.0.1", "::1"] + (allowlist_ips or [])
        allowed_str = ",".join(f"'{ip}'" for ip in allowed)

        cmd = (
            f"New-NetFirewallRule -DisplayName '{rule_name}_IN' -Direction Inbound -Action Block -Profile Any; "
            f"New-NetFirewallRule -DisplayName '{rule_name}_OUT' -Direction Outbound -Action Block -Profile Any; "
            f"New-NetFirewallRule -DisplayName '{rule_name}_ALLOW_LOOP' -Direction Inbound -Action Allow "
            f"-RemoteAddress @({allowed_str}) -Profile Any"
        )
        return self._run_powershell(cmd)

    def restore_host_isolation(self) -> bool:
        """Removes the emergency host isolation rules."""
        rule_name = "EndpointGuard_EMERGENCY_ISOLATION"
        cmd = (
            f"Remove-NetFirewallRule -DisplayName '{rule_name}_IN' -ErrorAction SilentlyContinue; "
            f"Remove-NetFirewallRule -DisplayName '{rule_name}_OUT' -ErrorAction SilentlyContinue; "
            f"Remove-NetFirewallRule -DisplayName '{rule_name}_ALLOW_LOOP' -ErrorAction SilentlyContinue"
        )
        return self._run_powershell(cmd)
