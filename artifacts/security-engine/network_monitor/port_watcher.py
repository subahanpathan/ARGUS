"""Phase 3 — Port intelligence watcher.

Periodically polls the Windows socket table and tracks port lifecycle:
  - PORT_OPENED: a new listening port or UDP endpoint appeared
  - PORT_CLOSED: a previously observed port disappeared
  - PORT_CHANGED: an existing port's metadata changed (PID, state, etc.)

Stable port IDs ensure no duplicate OPEN events across polling cycles.
First-seen / last-seen timestamps persist while a port remains observed.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable

from .port_models import PortEvent, PortInfo, PortIntelligenceSnapshot, PortSummary
from .port_collector import collect_ports, compute_port_summary

logger = logging.getLogger("argus.network_monitor.port_watcher")


class PortIntelligenceWatcher:
    """Periodically samples port data on a background thread."""

    def __init__(
        self,
        interval_ms: int = 3000,
        on_snapshot: Callable[[PortIntelligenceSnapshot], None] | None = None,
        event_history_limit: int = 200,
    ) -> None:
        self._interval = interval_ms / 1000.0
        self._on_snapshot = on_snapshot
        self._running = False
        self._thread: threading.Thread | None = None
        self._snapshot_count = 0
        self._callback_errors = 0
        self._lock = threading.Lock()
        # Previous state keyed by stable port_id
        self._prev_ports: dict[str, PortInfo] = {}
        # Stable first_seen timestamps: port_id -> ISO timestamp
        self._first_seen: dict[str, str] = {}
        # Bounded event history
        self._port_events: list[PortEvent] = []
        self._max_events = max(1, event_history_limit)

    def _append_events(self, events: list[PortEvent]) -> None:
        """Append events to the bounded history."""
        if not events:
            return
        self._port_events.extend(events)
        if len(self._port_events) > self._max_events:
            self._port_events = self._port_events[-self._max_events:]

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def snapshot_count(self) -> int:
        return self._snapshot_count

    @property
    def callback_errors(self) -> int:
        return self._callback_errors

    @property
    def event_history(self) -> list[PortEvent]:
        """Bounded, chronological history of all observed port events."""
        return list(self._port_events)

    def start(self) -> None:
        """Start the port intelligence sampler in a background daemon thread."""
        if self._running:
            logger.warning("Port intelligence watcher already running")
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="argus-port-intelligence"
        )
        self._thread.start()
        logger.info("Port intelligence watcher started (interval: %.1fs)", self._interval)

    def stop(self) -> None:
        """Signal the sampler to stop and wait for the thread to exit."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self._interval * 3)
        logger.info(
            "Port intelligence watcher stopped (snapshots: %d, callback errors: %d)",
            self._snapshot_count,
            self._callback_errors,
        )

    def _track_port_lifecycle(
        self,
        snapshot: PortIntelligenceSnapshot,
    ) -> None:
        """Detect PORT_OPENED, PORT_CLOSED, PORT_CHANGED events.

        Lifecycle identity is the stable port_id (derived from protocol + AF + addr + port + pid).
        """
        now_iso = snapshot.timestamp
        current_ports: dict[str, PortInfo] = {}

        # Build current port map from both TCP listening and UDP endpoints
        for p in snapshot.tcp_listening:
            current_ports[p.port_id] = p
        for p in snapshot.udp_endpoints:
            current_ports[p.port_id] = p

        new_events: list[PortEvent] = []

        # Detect new ports and state changes
        for port_id, port in current_ports.items():
            prev = self._prev_ports.get(port_id)
            if prev is None:
                # New port
                self._first_seen[port_id] = now_iso
                new_events.append(PortEvent(
                    event_type="PORT_OPENED",
                    timestamp=now_iso,
                    port_id=port_id,
                    protocol=port.protocol,
                    address_family=port.address_family,
                    local_addr=port.local_addr,
                    local_port=port.local_port,
                    state=port.state,
                    pid=port.pid,
                    process_name=port.process_name,
                    executable_path=port.executable_path,
                    binding_type=port.binding_type,
                ))
            else:
                # Check for metadata changes
                changes: list[str] = []
                if prev.pid != port.pid:
                    changes.append("PID")
                if prev.process_name != port.process_name:
                    changes.append("PROCESS")
                if prev.state != port.state:
                    changes.append("STATE")
                if prev.local_addr != port.local_addr:
                    changes.append("ADDRESS")

                if changes:
                    new_events.append(PortEvent(
                        event_type="PORT_CHANGED",
                        timestamp=now_iso,
                        port_id=port_id,
                        protocol=port.protocol,
                        address_family=port.address_family,
                        local_addr=port.local_addr,
                        local_port=port.local_port,
                        state=port.state,
                        pid=port.pid,
                        process_name=port.process_name,
                        executable_path=port.executable_path,
                        binding_type=port.binding_type,
                        previous_pid=prev.pid,
                        previous_process_name=prev.process_name,
                        previous_state=prev.state,
                        change_details=", ".join(changes),
                    ))

        # Detect closed ports
        for port_id, prev in self._prev_ports.items():
            if port_id not in current_ports:
                new_events.append(PortEvent(
                    event_type="PORT_CLOSED",
                    timestamp=now_iso,
                    port_id=port_id,
                    protocol=prev.protocol,
                    address_family=prev.address_family,
                    local_addr=prev.local_addr,
                    local_port=prev.local_port,
                    state=prev.state,
                    pid=prev.pid,
                    process_name=prev.process_name,
                    executable_path=prev.executable_path,
                    binding_type=prev.binding_type,
                ))
                self._first_seen.pop(port_id, None)

        self._prev_ports = current_ports

        # Apply stable first_seen / last_seen
        for port in snapshot.tcp_listening + snapshot.udp_endpoints:
            seen = self._first_seen.get(port.port_id)
            if seen:
                port.first_seen = seen
            else:
                seen = port.first_seen or now_iso
                self._first_seen[port.port_id] = seen
                port.first_seen = seen
            port.last_seen = now_iso

        # Clean up first_seen for ports that no longer exist
        stale_keys = [k for k in self._first_seen if k not in current_ports]
        for k in stale_keys:
            self._first_seen.pop(k, None)

        self._append_events(new_events)
        snapshot.port_events = new_events

    def _loop(self) -> None:
        """Main sampling loop — runs in a daemon thread."""
        while self._running:
            try:
                tcp_listening, udp_endpoints, active_tcp, associations = collect_ports()
                summary = compute_port_summary(tcp_listening, udp_endpoints, active_tcp)

                # Attach associated connection IDs (actual observed connections
                # landing on each listening socket).
                for port in tcp_listening:
                    conn_ids = associations.get(port.port_id)
                    if conn_ids:
                        port.associated_connection_ids = conn_ids

                snapshot = PortIntelligenceSnapshot(
                    tcp_listening=tcp_listening,
                    udp_endpoints=udp_endpoints,
                    summary=summary,
                    active_tcp_connections=active_tcp,
                )

                self._track_port_lifecycle(snapshot)

                self._snapshot_count += 1
                if self._on_snapshot is not None:
                    try:
                        self._on_snapshot(snapshot)
                    except Exception:
                        self._callback_errors += 1
                        logger.exception("Error in port intelligence snapshot callback")
            except Exception:
                logger.exception("Error in port intelligence sampling cycle")
            time.sleep(self._interval)
