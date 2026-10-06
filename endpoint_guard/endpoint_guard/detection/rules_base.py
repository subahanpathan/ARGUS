from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class DetectionAlert:
    rule_id: str
    name: str
    severity: str  # Low, Medium, High, Critical
    description: str
    mitre_technique: str
    attacker_ip: Optional[str] = None
    pid: Optional[int] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    parent_pid: Optional[int] = None
    parent_process_name: Optional[str] = None
    file_path: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity,
            "description": self.description,
            "mitre_technique": self.mitre_technique,
            "attacker_ip": self.attacker_ip,
            "pid": self.pid,
            "process_name": self.process_name,
            "command_line": self.command_line,
            "parent_pid": self.parent_pid,
            "parent_process_name": self.parent_process_name,
            "file_path": self.file_path,
            "details": self.details,
            "timestamp": self.timestamp,
        }


class BaseDetectionRule(ABC):
    """Abstract base class for all Endpoint Guard detection rules."""

    def __init__(self, rule_id: str, name: str, severity: str, mitre_technique: str):
        self.rule_id = rule_id
        self.name = name
        self.severity = severity
        self.mitre_technique = mitre_technique

    @abstractmethod
    def evaluate(self, context: Dict[str, Any]) -> List[DetectionAlert]:
        """Evaluates telemetry context and returns a list of zero or more DetectionAlerts."""
        pass
