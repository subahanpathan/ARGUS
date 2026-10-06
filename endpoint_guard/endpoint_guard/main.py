import argparse
import logging
import os
import signal
import sys
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from endpoint_guard.config import Config
from endpoint_guard.engine.orchestrator import EndpointGuardOrchestrator
from endpoint_guard.ui.dashboard import DashboardServer
from endpoint_guard.ui.tray_icon import TrayIcon

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("EndpointGuard")


def main():
    parser = argparse.ArgumentParser(description="Endpoint Guard - Host Detection and Response")
    parser.add_argument("--config", default=None, help="Path to config.yaml")
    parser.add_argument("--dry-run", action="store_true", help="Monitor and log only; do not kill or block")
    parser.add_argument("--headless", action="store_true", help="Run without system tray icon")
    args = parser.parse_args()

    config = Config(args.config)
    if args.dry_run:
        config.raw_data["general"]["dry_run"] = True

    print("=" * 65)
    print("      ENDPOINT GUARD // HOST-BASED DETECTION & RESPONSE      ")
    print("=" * 65)
    print(f"[*] Data Directory:       {config.data_dir}")
    print(f"[*] SQLite Database:      {config.db_path}")
    print(f"[*] Quarantine Vault:     {config.quarantine_dir}")
    print(f"[*] Incidents Directory:  {config.incident_dir}")
    print(f"[*] Dry-Run Mode:         {'ENABLED (Observation only)' if config.dry_run else 'DISABLED (Active Containment Active)'}")
    print("=" * 65)

    tray: Optional[TrayIcon] = None

    def on_notification(title: str, msg: str) -> None:
        if tray:
            tray.show_notification(title, msg)

    orchestrator = EndpointGuardOrchestrator(config, on_notification=on_notification)
    dashboard = DashboardServer(orchestrator)

    # Handle graceful exit
    def signal_handler(sig, frame):
        print("\n[*] Shutting down Endpoint Guard gracefully...")
        orchestrator.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        orchestrator.start()
        dashboard.start()

        if not args.headless:
            try:
                tray = TrayIcon(orchestrator)
                print("[+] System tray icon initialized. Running main loop...")
                tray.run()
            except Exception as e:
                print(f"[!] Note: System tray could not start in current console context ({e}). Running in background mode.")
                while True:
                    time.sleep(1)
        else:
            print("[+] Running in headless service mode.")
            while True:
                time.sleep(1)

    except KeyboardInterrupt:
        orchestrator.stop()
    except Exception as e:
        logger.error(f"Fatal error in Endpoint Guard: {e}", exc_info=True)
        orchestrator.stop()


if __name__ == "__main__":
    main()
