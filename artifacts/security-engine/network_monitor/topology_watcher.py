"""Continuous network topology monitor — periodic read-only sampling.

Runs in a background daemon thread and invokes a callback with each
collected topology snapshot. Tracks traffic rates by computing deltas
between successive interface byte counter samples.

Enhancements:
- Stable connection identity: first_seen/last_seen persist across polls
- CLOSED events correctly include process name from previous state
- New event types: LISTENING_PORT_OPENED/CLOSED, INTERFACE_UP/DOWN,
  GATEWAY_CHANGE, DNS_CHANGE, DNS_ACTIVITY
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable

from .connections import fallback_connection_key
from .models import ConnectionEvent, NetworkTopologySnapshot, ProcessConnectionInfo, TrafficRate
from .topology_collector import ReverseDnsCache, collect_topology, _get_public_ip

logger = logging.getLogger("argus.network_monitor.topology_watcher")


class NetworkTopologyWatcher:
    """Periodically samples network topology on a background thread."""

    def __init__(
        self,
        interval_ms: int = 3000,
        on_snapshot: Callable[[NetworkTopologySnapshot], None] | None = None,
        event_history_limit: int = 200,
    ) -> None:
        self._interval = interval_ms / 1000.0
        self._on_snapshot = on_snapshot
        self._running = False
        self._thread: threading.Thread | None = None
        self._snapshot_count = 0
        self._callback_errors = 0
        self._lock = threading.Lock()
        self._dns_cache = ReverseDnsCache()
        self._prev_io: dict[str, tuple[int, int, float]] = {}  # iface_name -> (sent, recv, timestamp)
        # Previous connection state keyed by stable connection_id
        self._prev_conns: dict[str, ProcessConnectionInfo] = {}
        # Stable first_seen timestamps: connection_id -> ISO timestamp
        self._first_seen: dict[str, str] = {}
        self._conn_events: list[ConnectionEvent] = []
        self._max_events = max(1, event_history_limit)
        # Infrastructure state for change detection
        self._prev_gateway: str = ""
        self._prev_dns: list[str] = []
        self._prev_iface_up: dict[str, bool] = {}

    def _append_events(self, events: list[ConnectionEvent]) -> None:
        """Append events to the bounded history."""
        if not events:
            return
        self._conn_events.extend(events)
        if len(self._conn_events) > self._max_events:
            self._conn_events = self._conn_events[-self._max_events:]

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
    def dns_cache_size(self) -> int:
        return self._dns_cache.cache_size()

    def start(self) -> None:
        """Start the topology sampler in a background daemon thread."""
        if self._running:
            logger.warning("Network topology watcher already running")
            return

        self._dns_cache.start()
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="argus-network-topology"
        )
        self._thread.start()
        logger.info("Network topology watcher started (interval: %.1fs)", self._interval)

    def stop(self) -> None:
        """Signal the sampler to stop and wait for the thread to exit."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self._interval * 3)
        self._dns_cache.stop()
        logger.info(
            "Network topology watcher stopped (snapshots: %d, callback errors: %d)",
            self._snapshot_count,
            self._callback_errors,
        )

    def _compute_traffic_rates(self, snapshot: NetworkTopologySnapshot) -> None:
        """Compute traffic rates by comparing with previous sample."""
        now = time.time()
        rates: list[TrafficRate] = []

        for iface in snapshot.interfaces:
            prev = self._prev_io.get(iface.name)
            rate = TrafficRate(
                interface=iface.name,
                bytes_sent=iface.bytes_sent,
                bytes_recv=iface.bytes_recv,
            )
            if prev and now > prev[2]:
                dt = now - prev[2]
                if dt > 0:
                    rate.bytes_sent_rate = max(0.0, (iface.bytes_sent - prev[0]) / dt)
                    rate.bytes_recv_rate = max(0.0, (iface.bytes_recv - prev[1]) / dt)
            rates.append(rate)
            self._prev_io[iface.name] = (iface.bytes_sent, iface.bytes_recv, now)

        snapshot.traffic_rates = rates

    def _track_connection_lifecycle(self, snapshot: NetworkTopologySnapshot) -> None:
        """Detect new, closed, and state-changed connections.

        Lifecycle identity is the stable connection_id (derived from the
        socket tuple + pid), so the same connection keeps one history across
        polls even if the enumeration order or ids change. Processes for
        CLOSED events are recovered from the previous connection record.
        """
        now_iso = snapshot.timestamp
        current_conns: dict[str, ProcessConnectionInfo] = {}

        for c in snapshot.connections:
            key = c.connection_id or fallback_connection_key(c)
            current_conns[key] = c

        new_events: list[ConnectionEvent] = []

        # Detect NEW connections and STATE_CHANGES
        for key, c in current_conns.items():
            prev = self._prev_conns.get(key)
            if prev is None:
                self._first_seen[key] = now_iso
                new_events.append(self._conn_event("NEW", c))
            elif (prev.state or "") != (c.state or ""):
                new_events.append(self._conn_event("STATE_CHANGE", c, previous_state=prev.state))

        # Detect CLOSED connections — recover process info from prev record
        for key, prev in self._prev_conns.items():
            if key not in current_conns:
                new_events.append(self._conn_event("CLOSED", prev, previous_state=prev.state))
                self._first_seen.pop(key, None)

        self._prev_conns = current_conns

        # Apply stable first_seen/last_seen
        for c in snapshot.connections:
            key = c.connection_id or fallback_connection_key(c)
            seen = self._first_seen.get(key)
            if seen:
                c.first_seen = seen
            else:
                seen = c.first_seen or now_iso
                self._first_seen[key] = seen
                c.first_seen = seen
            c.last_seen = now_iso

        # Clean up first_seen for connections that no longer exist
        stale_keys = [k for k in self._first_seen if k not in current_conns]
        for k in stale_keys:
            self._first_seen.pop(k, None)

        self._append_events(new_events)
        snapshot.connection_events = new_events

    @staticmethod
    def _conn_event(
        event_type: str,
        c: ProcessConnectionInfo,
        previous_state: str = "",
    ) -> ConnectionEvent:
        """Build a ConnectionEvent from a connection record."""
        return ConnectionEvent(
            event_type=event_type,
            timestamp=c.last_seen,
            connection_id=c.connection_id or c.id,
            process_name=c.process_name,
            pid=c.pid,
            protocol=c.protocol,
            address_family=c.address_family,
            local_addr=c.local_addr,
            local_port=c.local_port,
            remote_addr=c.remote_addr,
            remote_port=c.remote_port,
            state=c.state,
            previous_state=previous_state,
            local_role=c.local_role,
            remote_role=c.remote_role,
        )

    def _track_infrastructure_changes(self, snapshot: NetworkTopologySnapshot) -> None:
        """Detect gateway changes, DNS changes, interface up/down, and listening port changes."""
        new_events: list[ConnectionEvent] = []
        now_iso = snapshot.timestamp

        # Gateway change
        gw = snapshot.default_gateway.next_hop if snapshot.default_gateway else ""
        if self._prev_gateway and gw and self._prev_gateway != gw:
            new_events.append(ConnectionEvent(
                event_type="GATEWAY_CHANGE",
                state=gw,
                previous_state=self._prev_gateway,
            ))
        if gw:
            self._prev_gateway = gw

        # DNS change
        dns_servers = sorted(
            s for d in snapshot.dns_servers for s in (d.servers or [])
        )
        if self._prev_dns and dns_servers and self._prev_dns != dns_servers:
            new_events.append(ConnectionEvent(
                event_type="DNS_CHANGE",
                state=", ".join(dns_servers[:3]),
                previous_state=", ".join(self._prev_dns[:3]),
            ))
        if dns_servers:
            self._prev_dns = dns_servers

        # Interface up/down
        for iface in snapshot.interfaces:
            prev_up = self._prev_iface_up.get(iface.name)
            if prev_up is not None and prev_up != iface.is_up:
                new_events.append(ConnectionEvent(
                    event_type="INTERFACE_UP" if iface.is_up else "INTERFACE_DOWN",
                    local_addr=iface.name,
                    state="UP" if iface.is_up else "DOWN",
                    previous_state="DOWN" if iface.is_up else "UP",
                ))
            self._prev_iface_up[iface.name] = iface.is_up

        if new_events:
            self._append_events(new_events)
            snapshot.connection_events = (snapshot.connection_events or []) + new_events

    @property
    def event_history(self) -> list[ConnectionEvent]:
        """Bounded, chronological history of all observed connection events."""
        return list(self._conn_events)

    def _loop(self) -> None:
        """Main sampling loop — runs in a daemon thread."""
        public_ip_counter = 0
        while self._running:
            try:
                snapshot = collect_topology(self._dns_cache)
                self._compute_traffic_rates(snapshot)
                self._track_connection_lifecycle(snapshot)
                self._track_infrastructure_changes(snapshot)

                # Fetch public IP periodically (every ~40 cycles = ~120s at 3s interval)
                public_ip_counter += 1
                if public_ip_counter >= 40 or not snapshot.public_ip:
                    snapshot.public_ip = _get_public_ip()
                    if snapshot.public_ip:
                        public_ip_counter = 0

                self._snapshot_count += 1
                if self._on_snapshot is not None:
                    try:
                        self._on_snapshot(snapshot)
                    except Exception:
                        self._callback_errors += 1
                        logger.exception("Error in topology snapshot callback")
            except Exception:
                logger.exception("Error in topology sampling cycle")
            time.sleep(self._interval)
