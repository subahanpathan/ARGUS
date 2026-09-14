"""
ARGUS Security Engine — Main entry point.

Starts the Windows process monitor and optionally delivers events
to the ARGUS API server.

Usage:
    python main.py                    # Monitor only (stdout events)
    python main.py --api              # Monitor + send to API
    python main.py --api --snapshot   # Send initial snapshot + continuous events
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import time
from typing import Any

from config import Config
from process_monitor import ProcessWatcher, take_snapshot
from process_monitor.models import EventType, ProcessEvent
from system_monitor import SystemMonitorWatcher
from network_monitor import NetworkMonitorWatcher, NetworkSnapshot
from network_monitor import NetworkTopologyWatcher, NetworkTopologySnapshot
from network_monitor import PortIntelligenceWatcher, PortIntelligenceSnapshot
from file_monitor import FileMonitorWatcher, FileScanSnapshot
from file_monitor.scanner import running_process_paths
from api_client import ArgusApiClient

logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL),
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("argus.main")


class ArgusEngine:
    """
    Top-level orchestrator for the ARGUS security engine.
    Coordinates the process watcher, event delivery, and graceful shutdown.
    """

    def __init__(self, use_api: bool = False, send_snapshot: bool = False) -> None:
        self._use_api = use_api
        self._send_snapshot = send_snapshot
        self._api_client: ArgusApiClient | None = None
        self._watcher: ProcessWatcher | None = None
        self._system_monitor: SystemMonitorWatcher | None = None
        self._network_monitor: NetworkMonitorWatcher | None = None
        self._topology_monitor: NetworkTopologyWatcher | None = None
        self._port_monitor: PortIntelligenceWatcher | None = None
        self._file_monitor: FileMonitorWatcher | None = None
        self._last_running_paths: set[str] = set()
        self._event_buffer: list[dict[str, Any]] = []
        self._flush_interval = 2.0  # seconds
        self._running = False

    def start(self) -> None:
        """Initialize and start all engine components."""
        logger.info("=" * 60)
        logger.info("ARGUS Security Engine — Phase 1/2/3: Process, System & Network Monitoring")
        logger.info("=" * 60)

        if self._use_api:
            self._api_client = ArgusApiClient()
            if self._api_client.health_check():
                logger.info("API server is reachable at %s", Config.API_BASE_URL)
            else:
                logger.warning(
                    "API server not reachable at %s — events will be buffered locally",
                    Config.API_BASE_URL,
                )

        if self._send_snapshot and self._api_client:
            logger.info("Taking initial process snapshot...")
            snapshot = take_snapshot()
            logger.info(
                "Snapshot: %d processes (%d access-denied)",
                snapshot.total_count,
                snapshot.access_denied_count,
            )
            self._last_running_paths = running_process_paths(snapshot.processes)
            self._api_client.send_snapshot(snapshot.to_dict())

        self._watcher = ProcessWatcher(
            poll_interval_ms=Config.PROCESS_POLL_INTERVAL_MS,
            on_event=self._on_process_event,
        )
        self._watcher.start()

        if self._use_api:
            self._system_monitor = SystemMonitorWatcher(
                interval_ms=Config.TELEMETRY_INTERVAL_MS,
                on_snapshot=self._on_telemetry_snapshot,
            )
            self._system_monitor.start()

            self._network_monitor = NetworkMonitorWatcher(
                interval_ms=Config.CONNECTION_POLL_INTERVAL_MS,
                on_snapshot=self._on_network_snapshot,
            )
            self._network_monitor.start()

            self._topology_monitor = NetworkTopologyWatcher(
                interval_ms=Config.CONNECTION_POLL_INTERVAL_MS,
                on_snapshot=self._on_topology_snapshot,
                event_history_limit=Config.CONNECTION_EVENT_HISTORY_LIMIT,
            )
            self._topology_monitor.start()

            self._port_monitor = PortIntelligenceWatcher(
                interval_ms=Config.PORT_POLL_INTERVAL_MS,
                on_snapshot=self._on_port_snapshot,
                event_history_limit=Config.PORT_EVENT_HISTORY_LIMIT,
            )
            self._port_monitor.start()

            self._file_monitor = FileMonitorWatcher(
                interval_ms=Config.FILE_POLL_INTERVAL_MS,
                on_snapshot=self._on_file_scan,
                running_paths_provider=lambda: self._last_running_paths,
            )
            self._file_monitor.start()

        self._running = True

        logger.info(
            "Engine running — process polling every %dms, telemetry every %dms, network/topology every %dms, ports every %dms, files every %dms",
            Config.PROCESS_POLL_INTERVAL_MS,
            Config.TELEMETRY_INTERVAL_MS,
            Config.CONNECTION_POLL_INTERVAL_MS,
            Config.PORT_POLL_INTERVAL_MS,
            Config.FILE_POLL_INTERVAL_MS,
        )
        logger.info("Press Ctrl+C to stop")

    def _on_telemetry_snapshot(self, snapshot: Any) -> None:
        """Callback invoked by the system monitor each sampling cycle."""
        if not self._api_client:
            return
        try:
            self._api_client.send_telemetry(snapshot.to_dict())
        except Exception:  # noqa: BLE001
            logger.exception("Error delivering telemetry snapshot")

    def _on_network_snapshot(self, snapshot: NetworkSnapshot) -> None:
        """Callback invoked by the network monitor each sampling cycle."""
        if not self._api_client:
            return
        try:
            self._api_client.send_network_snapshot(snapshot.to_dict())
        except Exception:  # noqa: BLE001
            logger.exception("Error delivering network snapshot")

    def _on_topology_snapshot(self, snapshot: NetworkTopologySnapshot) -> None:
        """Callback invoked by the topology watcher each sampling cycle."""
        if not self._api_client:
            return
        try:
            self._api_client.send_topology_snapshot(snapshot.to_dict())
        except Exception:  # noqa: BLE001
            logger.exception("Error delivering topology snapshot")

    def _on_port_snapshot(self, snapshot: PortIntelligenceSnapshot) -> None:
        """Callback invoked by the port intelligence watcher each sampling cycle."""
        if not self._api_client:
            return
        try:
            self._api_client.send_port_intelligence(snapshot.to_dict())
        except Exception:  # noqa: BLE001
            logger.exception("Error delivering port intelligence snapshot")

    def _on_file_scan(self, snapshot: FileScanSnapshot) -> None:
        """Callback invoked by the file monitor each scan cycle."""
        if not self._api_client:
            return
        try:
            self._api_client.send_file_scan(snapshot.to_dict())
        except Exception:  # noqa: BLE001
            logger.exception("Error delivering file scan snapshot")

    def _on_process_event(self, event: ProcessEvent) -> None:
        """Callback invoked by the watcher for each detected event."""
        event_dict = event.to_dict()

        # Always log to stdout for local consumption
        event_type = event.event_type.value
        if event.event_type == EventType.PROCESS_STARTED:
            logger.info(
                "EVENT: %s — PID %d (%s) parent=%s",
                event_type,
                event.pid,
                event.process_name,
                event.parent_pid or "none",
            )
        elif event.event_type == EventType.PROCESS_TERMINATED:
            logger.info(
                "EVENT: %s — PID %d (%s)",
                event_type,
                event.pid,
                event.process_name,
            )

        # Send to API if configured
        if self._api_client:
            success = self._api_client.send_event(event_dict)
            if not success:
                self._event_buffer.append(event_dict)

    def run(self) -> None:
        """Run the engine until interrupted."""
        self.start()
        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self) -> None:
        """Gracefully shut down the engine."""
        logger.info("Shutting down ARGUS Security Engine...")
        self._running = False

        if self._system_monitor:
            self._system_monitor.stop()
            logger.info(
                "System monitor stats: %d snapshots, %d callback errors",
                self._system_monitor.snapshot_count,
                self._system_monitor.callback_errors,
            )

        if self._network_monitor:
            self._network_monitor.stop()
            logger.info(
                "Network monitor stats: %d snapshots, %d callback errors",
                self._network_monitor.snapshot_count,
                self._network_monitor.callback_errors,
            )

        if self._topology_monitor:
            self._topology_monitor.stop()
            logger.info(
                "Topology watcher stats: %d snapshots, %d callback errors",
                self._topology_monitor.snapshot_count,
                self._topology_monitor.callback_errors,
            )

        if self._port_monitor:
            self._port_monitor.stop()
            logger.info(
                "Port intelligence watcher stats: %d snapshots, %d callback errors",
                self._port_monitor.snapshot_count,
                self._port_monitor.callback_errors,
            )

        if self._file_monitor:
            self._file_monitor.stop()
            logger.info(
                "File monitor stats: %d scans, %d callback errors",
                self._file_monitor.snapshot_count,
                self._file_monitor.callback_errors,
            )

        if self._watcher:
            self._watcher.stop()
            logger.info(
                "Watcher stats: %d events emitted",
                self._watcher.event_count,
            )

        if self._api_client:
            logger.info(
                "API client stats: %d sent, %d errors, %d buffered",
                self._api_client.send_successes,
                self._api_client.send_errors,
                len(self._event_buffer),
            )

        if self._event_buffer:
            logger.info(
                "Buffered %d events (API was unreachable during delivery)",
                len(self._event_buffer),
            )

        logger.info("ARGUS Security Engine stopped.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ARGUS Security Engine — Phase 1: Process Monitoring"
    )
    parser.add_argument(
        "--api",
        action="store_true",
        help="Send events to the ARGUS API server",
    )
    parser.add_argument(
        "--snapshot",
        action="store_true",
        help="Send initial full process snapshot to the API",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Take a single snapshot and exit (no continuous monitoring)",
    )
    args = parser.parse_args()

    engine = ArgusEngine(use_api=args.api, send_snapshot=args.snapshot)

    # Graceful shutdown on signals
    def handle_signal(sig: int, frame: Any) -> None:
        logger.info("Received signal %d", sig)
        engine.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    if args.once:
        engine.start()
        time.sleep(3)  # Allow one poll cycle
        engine.stop()
    else:
        engine.run()


if __name__ == "__main__":
    main()
