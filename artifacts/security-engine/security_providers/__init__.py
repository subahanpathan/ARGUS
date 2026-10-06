"""ARGUS Endpoint Agent — security provider observation.

Read-only discovery and status collection for endpoint security products.

Integration policy
------------------
* Microsoft Defender: read through ``Get-MpComputerStatus``,
  ``Get-MpThreat``, ``Get-MpThreatDetection`` and the
  ``Microsoft-Windows-Windows Defender/Operational`` event log.
* Third-party antivirus/EDR: read through Windows Security registration
  (``root\\SecurityCenter2``) and corroborate with installed-software metadata.
* Anything without a supported read interface is reported as
  ``integration_status = NOT_SUPPORTED``. No data is invented for it.

This package contains no code that disables, reconfigures, tampers with,
injects into, or evades any security product.
"""

from __future__ import annotations

from .collector import collect_security_providers, summarize
from .models import (
    AVAILABLE,
    CAN_READ_DETECTIONS,
    CAN_READ_EVENTS,
    CAN_READ_SCAN_STATUS,
    CAN_READ_STATUS,
    DEGRADED,
    INTEGRATED,
    NOT_SUPPORTED,
    NOT_SCANNED,
    PARTIAL,
    PERMISSION_DENIED,
    ProviderAlert,
    ProviderDetection,
    ProviderScanState,
    SecurityProvider,
    SecurityProviderSnapshot,
    STALE,
    UNAVAILABLE,
    now_iso,
)
from .watcher import SecurityProviderWatcher

__all__ = [
    "AVAILABLE",
    "CAN_READ_DETECTIONS",
    "CAN_READ_EVENTS",
    "CAN_READ_SCAN_STATUS",
    "CAN_READ_STATUS",
    "DEGRADED",
    "INTEGRATED",
    "NOT_SCANNED",
    "NOT_SUPPORTED",
    "PARTIAL",
    "PERMISSION_DENIED",
    "ProviderAlert",
    "ProviderDetection",
    "ProviderScanState",
    "STALE",
    "SecurityProvider",
    "SecurityProviderSnapshot",
    "SecurityProviderWatcher",
    "UNAVAILABLE",
    "collect_security_providers",
    "now_iso",
    "summarize",
]
