"""HTTP client for delivering process events to the ARGUS API server."""

from __future__ import annotations

import json
import logging
from typing import Any

import urllib.request
import urllib.error

from config import Config

logger = logging.getLogger("argus.api_client")


class ArgusApiClient:
    """
    Sends process events and snapshots to the ARGUS API server.
    Uses only stdlib (urllib) — no third-party HTTP dependencies required.
    """

    def __init__(self, base_url: str | None = None) -> None:
        self._base_url = (base_url or Config.API_BASE_URL).rstrip("/")
        self._events_path = Config.API_EVENTS_ENDPOINT
        self._snapshot_path = Config.API_SNAPSHOT_ENDPOINT
        self._telemetry_path = Config.API_TELEMETRY_ENDPOINT
        self._network_path = Config.API_NETWORK_ENDPOINT
        self._topology_path = Config.API_NETWORK_TOPOLOGY_ENDPOINT
        self._ports_path = "/api/network/ports"
        self._file_scan_path = Config.API_FILE_SCAN_ENDPOINT
        self._send_errors = 0
        self._send_successes = 0

    @property
    def send_errors(self) -> int:
        return self._send_errors

    @property
    def send_successes(self) -> int:
        return self._send_successes

    def send_event(self, event_data: dict[str, Any]) -> bool:
        """
        POST a single process event to the API.

        Returns True on success, False on failure.
        Does not raise on network errors — logs and continues.
        """
        url = f"{self._base_url}{self._events_path}"
        return self._post_json(url, event_data)

    def send_events_batch(self, events: list[dict[str, Any]]) -> bool:
        """
        POST a batch of process events to the API.

        The API endpoint accepts both single events and arrays.
        """
        url = f"{self._base_url}{self._events_path}"
        return self._post_json(url, events)

    def send_snapshot(self, snapshot_data: dict[str, Any]) -> bool:
        """
        POST a full process snapshot to the API.
        """
        url = f"{self._base_url}{self._snapshot_path}"
        return self._post_json(url, snapshot_data)

    def send_telemetry(self, telemetry_data: dict[str, Any]) -> bool:
        """
        POST a system telemetry snapshot to the API.

        Returns True on success, False on failure.
        Does not raise on network errors — logs and continues.
        """
        url = f"{self._base_url}{self._telemetry_path}"
        return self._post_json(url, telemetry_data)

    def send_network_snapshot(self, snapshot_data: dict[str, Any]) -> bool:
        """
        POST a network connection snapshot to the API.

        Returns True on success, False on failure.
        Does not raise on network errors — logs and continues.
        """
        url = f"{self._base_url}{self._network_path}"
        return self._post_json(url, snapshot_data)

    def send_topology_snapshot(self, snapshot_data: dict[str, Any]) -> bool:
        """
        POST a network topology snapshot to the API.

        Returns True on success, False on failure.
        Does not raise on network errors — logs and continues.
        """
        url = f"{self._base_url}{self._topology_path}"
        return self._post_json(url, snapshot_data)

    def send_port_intelligence(self, snapshot_data: dict[str, Any]) -> bool:
        """
        POST a port intelligence snapshot to the API.

        Returns True on success, False on failure.
        Does not raise on network errors — logs and continues.
        """
        url = f"{self._base_url}{self._ports_path}"
        return self._post_json(url, snapshot_data)

    def send_file_scan(self, snapshot_data: dict[str, Any]) -> bool:
        """
        POST a filesystem threat scan snapshot to the API.

        Returns True on success, False on failure.
        Does not raise on network errors — logs and continues.
        """
        url = f"{self._base_url}{self._file_scan_path}"
        return self._post_json(url, snapshot_data)

    def health_check(self) -> bool:
        """Check if the API server is reachable."""
        url = f"{self._base_url}/api/healthz"
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception:
            return False

    def _post_json(self, url: str, payload: Any) -> bool:
        """POST JSON payload to a URL. Returns True on 2xx."""
        try:
            data = json.dumps(payload, default=str).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
                if 200 <= status < 300:
                    self._send_successes += 1
                    return True
                self._send_errors += 1
                logger.warning("API returned status %d for %s", status, url)
                return False
        except urllib.error.URLError as e:
            self._send_errors += 1
            logger.debug("API not reachable at %s: %s", url, e)
            return False
        except Exception:
            self._send_errors += 1
            logger.exception("Error posting to %s", url)
            return False
