"""Continuous Windows services watcher — read-only observation of services.

Background daemon thread that periodically enumerates installed services
(name, status, startup type). Service metadata is combined from the SCM
(psutil) and the local service configuration registry hive (read-only).

Nothing is ever modified: no service starts/stops, no registry writes.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable

import psutil

from .models import ServiceInfo, ServicesSnapshot

logger = logging.getLogger("argus.services_monitor.watcher")

# Status values reported by the Windows Service Control Manager.
_SCM_MAP = {
    "running": "running",
    "stopped": "stopped",
    "paused": "paused",
    "start_pending": "starting",
    "stop_pending": "stopping",
    "continue_pending": "starting",
    "pause_pending": "pausing",
}

# Registry Start values → startup type.
_START_TYPE_MAP = {
    0: "boot",
    1: "system",
    2: "automatic",
    3: "manual",
    4: "disabled",
}


def _read_startup_types() -> dict[str, str]:
    """Read service startup types from the configuration registry (read-only)."""
    result: dict[str, str] = {}
    import winreg  # type: ignore[import-not-found]

    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services",
        )
    except OSError:
        return result
    try:
        index = 0
        while True:
            try:
                name = winreg.EnumKey(key, index)
            except OSError:
                break
            index += 1
            try:
                with winreg.OpenKey(key, name) as subkey:
                    try:
                        value, _ = winreg.QueryValueEx(subkey, "Start")
                        display = "DisplayName"
                        try:
                            display_name, _ = winreg.QueryValueEx(subkey, display)
                        except OSError:
                            display_name = name
                        result[name] = _START_TYPE_MAP.get(
                            int(value), "unknown"
                        )
                        if display_name and isinstance(display_name, str):
                            result[f"{name}\x1fdisplay"] = display_name
                    except OSError:
                        continue
            except OSError:
                continue
    finally:
        winreg.CloseKey(key)
    return result


def collect_services() -> ServicesSnapshot:
    """Collect a read-only snapshot of installed Windows services."""
    services: list[ServiceInfo] = []
    running = stopped = denied = 0
    startup_map: dict[str, str] = {}
    display_map: dict[str, str] = {}

    try:
        startup_map = _read_startup_types()
    except Exception:  # noqa: BLE001
        logger.debug("Could not read service startup types from registry")

    try:
        seen: set[str] = set()
        for svc in psutil.win_service_iter():  # type: ignore[attr-defined,union-attr]
            name = svc.name()
            seen.add(name)
            status_raw = "unknown"
            pid: int | None = None
            try:
                status_raw = svc.status()
            except Exception:  # noqa: BLE001
                pass
            try:
                pid = svc.pid()
            except Exception:  # noqa: BLE001
                pid = None

            status = _SCM_MAP.get(str(status_raw).lower(), "unknown")
            if status == "running":
                running += 1
            elif status == "stopped":
                stopped += 1

            startup = startup_map.get(name, "unknown")
            display = display_map.get(name) or startup_map.get(f"{name}\x1fdisplay") or name

            services.append(
                ServiceInfo(
                    name=name,
                    status=status,
                    startup_type=startup,
                    display_name=display,
                    pid=pid,
                )
            )
    except Exception:  # noqa: BLE001
        logger.exception("Error enumerating services via SCM")
        denied += 1

    # Fallback: when psutil SCM enumeration is unavailable (non-Windows or
    # restricted), fall back to the registry names only with unknown status.
    if not services and startup_map:
        for name in sorted(startup_map):
            if "\x1f" in name:
                continue
            display = startup_map.get(f"{name}\x1fdisplay") or name
            services.append(
                ServiceInfo(
                    name=name,
                    status="unknown",
                    startup_type=startup_map.get(name, "unknown"),
                    display_name=display,
                )
            )
        denied = len(seen) - len(services) if seen else 0

    services.sort(key=lambda s: s.name.lower())
    snapshot = ServicesSnapshot(
        services=services,
        total_count=len(services),
        running_count=running,
        stopped_count=stopped,
        access_denied_count=denied,
    )
    logger.info(
        "Services snapshot: %d total, %d running, %d stopped",
        snapshot.total_count,
        snapshot.running_count,
        snapshot.stopped_count,
    )
    return snapshot


class ServicesWatcher:
    """Periodically collects Windows service state on a background thread."""

    def __init__(
        self,
        interval_ms: int = 15000,
        on_snapshot: Callable[[ServicesSnapshot], None] | None = None,
    ) -> None:
        self._interval = max(interval_ms, 1000) / 1000.0
        self._on_snapshot = on_snapshot
        self._running = False
        self._thread: threading.Thread | None = None
        self._snapshot_count = 0
        self._callback_errors = 0

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def snapshot_count(self) -> int:
        return self._snapshot_count

    @property
    def callback_errors(self) -> int:
        return self._callback_errors

    def start(self) -> None:
        if self._running:
            logger.warning("Services watcher already running")
            return

        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="argus-services-watcher"
        )
        self._thread.start()
        logger.info("Services watcher started (interval: %.1fs)", self._interval)

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self._interval * 3)
        logger.info(
            "Services watcher stopped (snapshots: %d, callback errors: %d)",
            self._snapshot_count,
            self._callback_errors,
        )

    def _loop(self) -> None:
        while self._running:
            started = time.monotonic()
            try:
                snapshot = collect_services()
                self._snapshot_count += 1
                if self._on_snapshot is not None:
                    try:
                        self._on_snapshot(snapshot)
                    except Exception:  # noqa: BLE001
                        self._callback_errors += 1
                        logger.exception("Error in services callback")
            except Exception:  # noqa: BLE001
                logger.exception("Error in services collection cycle")

            elapsed = time.monotonic() - started
            delay = max(0.0, self._interval - elapsed)
            time.sleep(delay)