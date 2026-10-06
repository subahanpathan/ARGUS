import os
import sys
import time
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from endpoint_guard.config import Config
from endpoint_guard.engine.orchestrator import EndpointGuardOrchestrator
from endpoint_guard.ui.dashboard import DashboardServer


def run_service():
    """Runs Endpoint Guard in headless background mode (ideal for Windows Service / Scheduled Task)."""
    config = Config()
    orchestrator = EndpointGuardOrchestrator(config)
    dashboard = DashboardServer(orchestrator)

    orchestrator.start()
    dashboard.start()

    print("[*] Endpoint Guard Service running in background.")
    try:
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        orchestrator.stop()


if __name__ == "__main__":
    run_service()
