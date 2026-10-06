import threading
from typing import Any, Callable, Dict, List, Optional

from .firewall_manager import FirewallManager
from .process_killer import ProcessKiller
from .quarantine_manager import QuarantineManager
from ..config import Config
from ..database.manager import DatabaseManager
from ..detection.rules_base import DetectionAlert


class ResponseEngine:
    """Orchestrates automated containment, logging, evidence capture, and playbooks."""

    def __init__(self, config: Config, db: DatabaseManager,
                 on_notification: Optional[Callable[[str, str], None]] = None):
        self.config = config
        self.db = db
        self.on_notification = on_notification
        self.firewall = FirewallManager(config)
        self.killer = ProcessKiller(config)
        self.quarantine = QuarantineManager(config, db)
        self._lock = threading.Lock()

        # Cache of active incident per attacker IP
        self._active_incidents: Dict[str, str] = {}

    def _notify(self, title: str, message: str) -> None:
        if self.on_notification:
            try:
                self.on_notification(title, message)
            except Exception as e:
                print(f"[ResponseEngine] Notification error: {e}")

    def handle_alert(self, alert: DetectionAlert) -> str:
        with self._lock:
            attacker_ip = alert.attacker_ip
            # 1. Upsert attacker profile if IP present
            if attacker_ip:
                self.db.upsert_attacker({
                    "source_ip": attacker_ip,
                    "ports": [alert.details.get("remote_port")] if alert.details.get("remote_port") else [],
                    "attack_tags": [alert.rule_id],
                    "connection_direction": "inbound" if alert.details.get("local_port") else "outbound",
                    "risk_score": 90 if alert.severity in ("High", "Critical") else 50
                })

            # 2. Get or create incident
            incident_key = attacker_ip or f"HOST_{alert.rule_id}"
            incident_id = self._active_incidents.get(incident_key)

            if not incident_id:
                incident_id = self.db.create_incident({
                    "attacker_ip": attacker_ip,
                    "title": f"Incident: {alert.name}",
                    "description": alert.description,
                    "severity": alert.severity,
                    "risk_score": 95 if alert.severity == "Critical" else (80 if alert.severity == "High" else 40),
                    "mitre_techniques": [alert.mitre_technique],
                })
                self._active_incidents[incident_key] = incident_id

            # 3. Record detection event in hash-chained ledger
            self.db.record_event({
                "incident_id": incident_id,
                "event_type": "detection",
                "source_module": "detection_engine",
                "severity": alert.severity,
                "attacker_ip": attacker_ip,
                "pid": alert.pid,
                "process_name": alert.process_name,
                "command_line": alert.command_line,
                "file_path": alert.file_path,
                "details": {
                    "rule_id": alert.rule_id,
                    "name": alert.name,
                    "description": alert.description,
                    "mitre": alert.mitre_technique,
                    "extra": alert.details,
                }
            })

            # 4. Execute playbook
            actions_taken: List[str] = []

            # Process Termination
            if alert.severity in ("High", "Critical") and alert.pid:
                killed, kill_msg = self.killer.kill_process_tree(alert.pid, alert.process_name)
                if killed:
                    actions_taken.append(kill_msg)
                    self.db.record_event({
                        "incident_id": incident_id,
                        "event_type": "response_action",
                        "source_module": "orchestrator",
                        "severity": "High",
                        "pid": alert.pid,
                        "process_name": alert.process_name,
                        "details": {"action": "process_kill", "status": "success", "message": kill_msg}
                    })

            # Firewall IP Block
            if alert.severity in ("High", "Critical") and attacker_ip and not self.config.is_ip_trusted(attacker_ip):
                rule_name = self.firewall.block_ip(attacker_ip)
                if rule_name:
                    actions_taken.append(f"Blocked IP {attacker_ip} in Windows Firewall")
                    self.db.record_blocked_ip(attacker_ip, rule_name, alert.name, incident_id)
                    self.db.set_attacker_blocked(attacker_ip, True, rule_name)
                    self.db.record_event({
                        "incident_id": incident_id,
                        "event_type": "response_action",
                        "source_module": "orchestrator",
                        "severity": "High",
                        "attacker_ip": attacker_ip,
                        "details": {"action": "firewall_block", "rule": rule_name}
                    })

            # Quarantine payload if file specified
            if alert.file_path:
                q_meta = self.quarantine.quarantine_file(alert.file_path, alert.name, incident_id)
                if q_meta:
                    actions_taken.append(f"Quarantined {alert.file_path}")
                    self.db.record_event({
                        "incident_id": incident_id,
                        "event_type": "response_action",
                        "source_module": "orchestrator",
                        "severity": "High",
                        "file_path": alert.file_path,
                        "file_hash_sha256": q_meta.get("sha256"),
                        "details": {"action": "quarantine", "meta": q_meta}
                    })

            # Update incident containment state
            if actions_taken:
                containment_summary = "; ".join(actions_taken)
                self.db.update_incident_containment(incident_id, "Fully Contained", containment_summary)
                self._notify(
                    f"Endpoint Guard: Attack Contained ({alert.severity})",
                    f"{alert.name}\nActions: {containment_summary}"
                )
            else:
                self._notify(
                    f"Endpoint Guard: Alert ({alert.severity})",
                    alert.description
                )

            return incident_id

    def panic_isolate(self) -> bool:
        """User-triggered emergency host isolation."""
        with self._lock:
            success = self.firewall.isolate_host()
            self._notify("Endpoint Guard: PANIC ISOLATION ACTIVE", "All external network traffic severed.")
            return success

    def panic_restore(self) -> bool:
        """Restores network from panic isolation."""
        with self._lock:
            success = self.firewall.restore_host_isolation()
            self._notify("Endpoint Guard: Isolation Lifted", "Network traffic restored.")
            return success
