import logging
import threading
from typing import Any, Callable, Dict, Optional

from ..config import Config
from ..database.manager import DatabaseManager
from ..detection.rules_base import DetectionAlert
from ..engine.event_bus import EventBus
from ..engine.self_protection import SelfProtection
from ..forensics.evidence_collector import EvidenceCollector
from ..forensics.report_generator import ReportGenerator
from ..monitors.file_monitor import FileMonitor
from ..monitors.network_monitor import NetworkMonitor
from ..monitors.peripheral_monitor import PeripheralMonitor
from ..monitors.persistence_monitor import PersistenceMonitor
from ..monitors.process_monitor import ProcessMonitor
from ..response.canary_manager import CanaryManager
from ..response.response_engine import ResponseEngine

logger = logging.getLogger("EndpointGuard.Orchestrator")


class EndpointGuardOrchestrator:
    """Master orchestrator managing all telemetry collectors, detection rules, and response playbooks."""

    def __init__(self, config: Optional[Config] = None,
                 on_notification: Optional[Callable[[str, str], None]] = None):
        self.config = config or Config()
        self.on_notification = on_notification
        self.db = DatabaseManager(self.config.db_path)
        self.event_bus = EventBus()

        # Core subsystems
        self.canary_manager = CanaryManager(self.config)
        self.response_engine = ResponseEngine(self.config, self.db, on_notification=self.on_notification)
        self.evidence_collector = EvidenceCollector(self.config, self.db)
        self.report_generator = ReportGenerator(self.config, self.db)

        # Telemetry monitors
        self.network_monitor = NetworkMonitor(
            self.config, on_alert=self.handle_alert, on_event=self.handle_event
        )
        self.process_monitor = ProcessMonitor(
            self.config, on_alert=self.handle_alert, on_event=self.handle_event
        )
        self.persistence_monitor = PersistenceMonitor(
            self.config, on_alert=self.handle_alert, on_event=self.handle_event
        )
        self.file_monitor = FileMonitor(
            self.config, on_alert=self.handle_alert, on_event=self.handle_event
        )
        self.peripheral_monitor = PeripheralMonitor(
            self.config, on_alert=self.handle_alert, on_event=self.handle_event
        )
        self.self_protection = SelfProtection(
            self.config, on_alert=self.handle_alert
        )

        self._running = False
        self._lock = threading.Lock()

    def handle_alert(self, alert: DetectionAlert) -> None:
        """Central alert dispatcher."""
        logger.warning(f"[ALERT] [{alert.severity}] {alert.name} - {alert.description}")
        incident_id = self.response_engine.handle_alert(alert)

        # Capture evidence artifacts in background
        threading.Thread(
            target=self._capture_and_report,
            args=(incident_id, alert),
            name="EvidenceWorker",
            daemon=True
        ).start()

    def _capture_and_report(self, incident_id: str, alert: DetectionAlert) -> None:
        try:
            self.evidence_collector.capture_incident_package(incident_id, alert)
            self.report_generator.generate_html_report(incident_id)
        except Exception as e:
            logger.error(f"Error capturing evidence: {e}")

    def handle_event(self, event: Dict[str, Any]) -> None:
        """Records general telemetry events into hash-chained audit database."""
        try:
            self.db.record_event(event)
        except Exception as e:
            logger.error(f"Error recording event: {e}")

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._running = True
            logger.info("Starting Endpoint Guard master orchestrator...")
            self.event_bus.start()
            self.network_monitor.start()
            self.process_monitor.start()
            self.persistence_monitor.start()
            self.file_monitor.start()
            self.peripheral_monitor.start()
            self.self_protection.start()
            logger.info("All Endpoint Guard defensive monitors active and running.")

    def stop(self) -> None:
        with self._lock:
            if not self._running:
                return
            self._running = False
            logger.info("Stopping Endpoint Guard...")
            self.self_protection.stop()
            self.peripheral_monitor.stop()
            self.file_monitor.stop()
            self.persistence_monitor.stop()
            self.process_monitor.stop()
            self.network_monitor.stop()
            self.event_bus.stop()
            logger.info("Endpoint Guard stopped.")
