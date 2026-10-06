from typing import Any, Dict, List

from .rules_base import BaseDetectionRule, DetectionAlert
from ..config import Config


class WebcamAccessRule(BaseDetectionRule):
    """
    Detects unauthorized or suspicious processes accessing the laptop webcam.
    """

    def __init__(self, config: Config):
        super().__init__(
            rule_id="PERIPH-001",
            name="Unauthorized Webcam Access Attempt",
            severity="Critical",
            mitre_technique="T1125"  # Video Capture
        )
        self.config = config

    def evaluate(self, context: Dict[str, Any]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        events = context.get("peripheral_events", [])

        for ev in events:
            if ev.get("device_type") == "webcam":
                proc_name = ev.get("process_name", "")
                if not self.config.is_camera_app_approved(proc_name):
                    alerts.append(DetectionAlert(
                        rule_id=self.rule_id,
                        name=self.name,
                        severity=self.severity,
                        description=(
                            f"UNAUTHORIZED WEBCAM ACCESS: Process '{proc_name}' (PID {ev.get('pid')}) "
                            f"attempted to activate the webcam! Potential remote surveillance."
                        ),
                        mitre_technique=self.mitre_technique,
                        pid=ev.get("pid"),
                        process_name=proc_name,
                        command_line=ev.get("command_line"),
                        file_path=ev.get("exe_path"),
                        attacker_ip=ev.get("attacker_ip"),
                        details={
                            "device": "webcam",
                            "is_active": ev.get("is_active", True),
                            "registry_key": ev.get("registry_key", ""),
                            "start_time": ev.get("start_time"),
                        }
                    ))

        return alerts


class MicrophoneAccessRule(BaseDetectionRule):
    """
    Detects unauthorized or suspicious processes accessing the laptop microphone.
    """

    def __init__(self, config: Config):
        super().__init__(
            rule_id="PERIPH-002",
            name="Unauthorized Microphone Access Attempt",
            severity="Critical",
            mitre_technique="T1123"  # Audio Capture
        )
        self.config = config

    def evaluate(self, context: Dict[str, Any]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        events = context.get("peripheral_events", [])

        for ev in events:
            if ev.get("device_type") == "microphone":
                proc_name = ev.get("process_name", "")
                if not self.config.is_microphone_app_approved(proc_name):
                    alerts.append(DetectionAlert(
                        rule_id=self.rule_id,
                        name=self.name,
                        severity=self.severity,
                        description=(
                            f"UNAUTHORIZED MICROPHONE ACCESS: Process '{proc_name}' (PID {ev.get('pid')}) "
                            f"attempted to activate audio recording! Potential eavesdropping."
                        ),
                        mitre_technique=self.mitre_technique,
                        pid=ev.get("pid"),
                        process_name=proc_name,
                        command_line=ev.get("command_line"),
                        file_path=ev.get("exe_path"),
                        attacker_ip=ev.get("attacker_ip"),
                        details={
                            "device": "microphone",
                            "is_active": ev.get("is_active", True),
                            "registry_key": ev.get("registry_key", ""),
                            "start_time": ev.get("start_time"),
                        }
                    ))

        return alerts
