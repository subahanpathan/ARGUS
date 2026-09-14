"""ARGUS Security Engine — Configuration."""

import os


class Config:
    """Central configuration for the ARGUS security engine."""

    # Process monitoring
    PROCESS_POLL_INTERVAL_MS: int = int(
        os.getenv("PROCESS_POLL_INTERVAL_MS", "2000")
    )
    PROCESS_SNAPSHOT_ON_START: bool = True
    MAX_EVENTS_PER_SECOND: int = 50

    # System telemetry monitoring (Phase 1.5)
    TELEMETRY_INTERVAL_MS: int = int(
        os.getenv("TELEMETRY_INTERVAL_MS", "1000")
    )
    TELEMETRY_CPU_INTERVAL: float = float(
        os.getenv("TELEMETRY_CPU_INTERVAL", "0.0")
    )

    # Network monitoring (Phase 1.5)
    NETWORK_POLL_INTERVAL_MS: int = int(
        os.getenv("NETWORK_POLL_INTERVAL_MS", "3000")
    )

    # Network connection monitoring (Phase 2)
    # Connection enumeration is the most expensive sampling operation, so it
    # gets its own configurable interval (defaults to the network interval).
    CONNECTION_POLL_INTERVAL_MS: int = int(
        os.getenv("CONNECTION_POLL_INTERVAL_MS", os.getenv("NETWORK_POLL_INTERVAL_MS", "3000"))
    )
    # Bounded per-process connection event history delivered to the API.
    CONNECTION_EVENT_HISTORY_LIMIT: int = int(
        os.getenv("CONNECTION_EVENT_HISTORY_LIMIT", "200")
    )

    # Port intelligence (Phase 3)
    PORT_POLL_INTERVAL_MS: int = int(
        os.getenv("PORT_POLL_INTERVAL_MS", os.getenv("CONNECTION_POLL_INTERVAL_MS", "3000"))
    )
    PORT_EVENT_HISTORY_LIMIT: int = int(
        os.getenv("PORT_EVENT_HISTORY_LIMIT", "200")
    )

    # Filesystem threat scanning (Phase 4)
    FILE_POLL_INTERVAL_MS: int = int(
        os.getenv("FILE_POLL_INTERVAL_MS", "15000")
    )
    # Only files modified within this window are considered.
    FILE_SCAN_RECENT_WINDOW_HOURS: float = float(
        os.getenv("FILE_SCAN_RECENT_WINDOW_HOURS", "48")
    )
    # Upper bound for hashing a file (bytes). Larger files are skipped.
    FILE_MAX_HASH_BYTES: int = int(
        os.getenv("FILE_MAX_HASH_BYTES", str(8 * 1024 * 1024))
    )
    # Upper bound for reading a script file's content (bytes).
    FILE_MAX_READ_BYTES: int = int(
        os.getenv("FILE_MAX_READ_BYTES", str(512 * 1024))
    )
    # Cap on candidate files walked per scan cycle.
    FILE_MAX_CANDIDATES: int = int(
        os.getenv("FILE_MAX_CANDIDATES", "2000")
    )
    # Extra user-supplied scan roots (semicolon separated).
    FILE_SCAN_ROOTS: list[str] = [
        p for p in os.getenv("FILE_SCAN_ROOTS", "").split(";") if p.strip()
    ]

    # API connection
    API_BASE_URL: str = os.getenv("ARGUS_API_BASE_URL", "http://localhost:5000")
    API_EVENTS_ENDPOINT: str = "/api/events/process"
    API_SNAPSHOT_ENDPOINT: str = "/api/processes"
    API_TELEMETRY_ENDPOINT: str = "/api/system/telemetry"
    API_NETWORK_ENDPOINT: str = "/api/network/connections"
    API_NETWORK_TOPOLOGY_ENDPOINT: str = "/api/network/topology"
    API_FILE_SCAN_ENDPOINT: str = "/api/files/scan"

    # Logging
    LOG_LEVEL: str = os.getenv("ARGUS_LOG_LEVEL", "INFO")

    # Safety
    DENY_LIST: frozenset[str] = frozenset()  # Processes to never inspect deeply
    MAX_METADATA_BYTES: int = 4096
