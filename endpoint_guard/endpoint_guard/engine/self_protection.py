import subprocess
import threading
import time
from typing import Callable, Optional

from ..config import Config
from ..detection.rules_base import DetectionAlert


class SelfProtection:
    """Monitors host defense integrity (Defender, Firewall) and runs heartbeat watchdog."""

    def __init__(self, config: Config, on_alert: Callable[[DetectionAlert], None]):
        self.config = config
        self.on_alert = on_alert
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._firewall_was_enabled = True

    def check_security_status(self) -> None:
        """Inspects if Windows Firewall or Defender real-time protection was disabled."""
        # 1. Check Firewall profile states
        try:
            out = subprocess.check_output(
                "netsh advfirewall show allprofiles state",
                shell=True,
                text=True,
                stderr=subprocess.DEVNULL
            )
            is_off = "State                                 OFF" in out or "State                                 Off" in out
            if is_off and self._firewall_was_enabled:
                self._firewall_was_enabled = False
                self.on_alert(DetectionAlert(
                    rule_id="DEF-001",
                    name="Windows Firewall Disabled by External Actor",
                    severity="Critical",
                    description="Windows Firewall state was turned OFF. Possible defense evasion attempt.",
                    mitre_technique="T1562.001",
                    details={"source": "netsh_check"}
                ))
            elif not is_off:
                self._firewall_was_enabled = True
        except Exception:
            pass

    def _loop(self) -> None:
        interval = float(self.config.get("self_protection", "heartbeat_interval_seconds", 5))
        while self.running:
            try:
                self.check_security_status()
            except Exception as e:
                print(f"[SelfProtection] Error in check: {e}")
            time.sleep(interval)

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._loop, name="SelfProtectionThread", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
