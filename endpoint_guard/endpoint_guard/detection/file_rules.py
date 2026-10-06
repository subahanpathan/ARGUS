import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .rules_base import BaseDetectionRule, DetectionAlert
from ..config import Config
from ..response.canary_manager import CanaryManager


class CanaryFileTripwireRule(BaseDetectionRule):
    """
    Detects any access, copy, modification, or movement of deployed honeypot decoy files.
    High-fidelity signal of active unauthorized file theft.
    """

    def __init__(self, config: Config, canary_manager: Optional[CanaryManager] = None):
        super().__init__(
            rule_id="FILE-001",
            name="Honeypot Canary File Tripwire Triggered",
            severity="Critical",
            mitre_technique="T1083 / T1567"
        )
        self.config = config
        self.canary_manager = canary_manager or CanaryManager(config)

    def evaluate(self, context: Dict[str, Any]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        file_events = context.get("file_events", [])

        for ev in file_events:
            target_path = ev.get("file_path", "")
            if self.canary_manager.is_canary_file(target_path):
                alerts.append(DetectionAlert(
                    rule_id=self.rule_id,
                    name=self.name,
                    severity=self.severity,
                    description=(
                        f"CRITICAL TRIPWIRE: Honeypot decoy file '{Path(target_path).name}' was accessed/modified "
                        f"(action: {ev.get('action')})! Immediate exfiltration containment required."
                    ),
                    mitre_technique=self.mitre_technique,
                    attacker_ip=ev.get("attacker_ip"),
                    pid=ev.get("pid"),
                    process_name=ev.get("process_name"),
                    command_line=ev.get("command_line"),
                    file_path=target_path,
                    details={
                        "action": ev.get("action"),
                        "file_path": target_path,
                        "tripwire": "canary_decoy"
                    }
                ))

        return alerts


class BulkFileAccessExfiltrationRule(BaseDetectionRule):
    """
    Detects rapid harvesting of sensitive user documents (.docx, .xlsx, .pdf, .txt, .key).
    """

    def __init__(self, config: Config):
        super().__init__(
            rule_id="FILE-002",
            name="Bulk Sensitive File Harvesting Pattern",
            severity="High",
            mitre_technique="T1005 / T1560"
        )
        self.config = config
        self.sensitive_exts: Set[str] = {
            ext.lower() for ext in config.get("files", "sensitive_extensions", [".docx", ".xlsx", ".pdf", ".txt"])
        }
        # pid/actor -> list of (timestamp, file_path)
        self.history: Dict[str, List[Tuple[float, str]]] = defaultdict(list)

    def evaluate(self, context: Dict[str, Any]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        file_events = context.get("file_events", [])
        now = time.time()
        window = float(self.config.get("files", "bulk_read_window_seconds", 10))
        threshold = int(self.config.get("files", "bulk_read_threshold", 20))

        for ev in file_events:
            path = ev.get("file_path", "")
            ext = Path(path).suffix.lower()
            if ext in self.sensitive_exts:
                actor_key = str(ev.get("pid") or ev.get("attacker_ip") or "global")
                self.history[actor_key].append((now, path))

        for actor, records in list(self.history.items()):
            recent = [r for r in records if (now - r[0]) <= window]
            self.history[actor] = recent

            unique_files = {r[1] for r in recent}
            if len(unique_files) >= threshold:
                alerts.append(DetectionAlert(
                    rule_id=self.rule_id,
                    name=self.name,
                    severity=self.severity,
                    description=(
                        f"Bulk file harvesting detected: {len(unique_files)} sensitive documents touched "
                        f"within {window:.1f} seconds."
                    ),
                    mitre_technique=self.mitre_technique,
                    attacker_ip=context.get("attacker_ip"),
                    pid=int(actor) if actor.isdigit() else None,
                    details={
                        "files_touched_count": len(unique_files),
                        "sample_files": list(unique_files)[:10],
                        "window_seconds": window
                    }
                ))
                self.history[actor] = []

        return alerts


class ArchiveStagingRule(BaseDetectionRule):
    """
    Detects creation of archive containers (.zip, .7z, .rar, .tar.gz) in temp or protected folders.
    """

    ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".tar", ".gz"}

    def __init__(self, config: Config):
        super().__init__(
            rule_id="FILE-003",
            name="Exfiltration Archive Staging Detected",
            severity="High",
            mitre_technique="T1560.001"
        )
        self.config = config

    def evaluate(self, context: Dict[str, Any]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        file_events = context.get("file_events", [])

        for ev in file_events:
            path = ev.get("file_path", "")
            action = ev.get("action", "")
            if action in ("created", "modified"):
                ext = Path(path).suffix.lower()
                if ext in self.ARCHIVE_EXTS:
                    alerts.append(DetectionAlert(
                        rule_id=self.rule_id,
                        name=self.name,
                        severity=self.severity,
                        description=f"Archive staging file created: '{path}' (potential data bundling).",
                        mitre_technique=self.mitre_technique,
                        pid=ev.get("pid"),
                        process_name=ev.get("process_name"),
                        file_path=path,
                        details={"archive_path": path, "action": action}
                    ))

        return alerts
