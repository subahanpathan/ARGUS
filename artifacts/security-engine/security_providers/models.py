"""Security provider models — read-only abstraction over endpoint security products.

A :class:`SecurityProvider` is an explicit, honest record of one security
product observed on the endpoint (Microsoft Defender, a third-party
antivirus/EDR registered with Windows Security, ...).

Design rules enforced here:

* Every field is either a *measured* value or an explicit availability state.
  Nothing is defaulted to a plausible-looking number.
* When a product has no supported read interface on this host the record
  still exists, but its ``integration_status`` is ``NOT_SUPPORTED`` and every
  capability is reported as unsupported. That is a valid observation.
* This module never expresses an intent to change provider state. ARGUS
  observes; it does not reconfigure security software.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Availability states — used for every measured field group.
# ---------------------------------------------------------------------------
AVAILABLE = "AVAILABLE"
DEGRADED = "DEGRADED"
UNAVAILABLE = "UNAVAILABLE"
PERMISSION_DENIED = "PERMISSION_DENIED"
NOT_SUPPORTED = "NOT_SUPPORTED"
STALE = "STALE"
NOT_SCANNED = "NOT_SCANNED"

AVAILABILITY_STATES: frozenset[str] = frozenset({
    AVAILABLE, DEGRADED, UNAVAILABLE, PERMISSION_DENIED, NOT_SUPPORTED, STALE, NOT_SCANNED,
})

# ---------------------------------------------------------------------------
# Integration status — how well ARGUS can read this provider.
# ---------------------------------------------------------------------------
INTEGRATED = "INTEGRATED"
PARTIAL = "PARTIAL"

# ---------------------------------------------------------------------------
# Capabilities. Only capabilities whose read path is actually implemented and
# exercised may be advertised.
# ---------------------------------------------------------------------------
CAN_READ_STATUS = "CAN_READ_STATUS"
CAN_READ_EVENTS = "CAN_READ_EVENTS"
CAN_READ_DETECTIONS = "CAN_READ_DETECTIONS"
CAN_REQUEST_SCAN = "CAN_REQUEST_SCAN"
CAN_READ_SCAN_STATUS = "CAN_READ_SCAN_STATUS"

ALL_CAPABILITIES: tuple[str, ...] = (
    CAN_READ_STATUS,
    CAN_READ_EVENTS,
    CAN_READ_DETECTIONS,
    CAN_REQUEST_SCAN,
    CAN_READ_SCAN_STATUS,
)

# ARGUS never initiates a scan on a third-party security product. Requesting
# one would change the provider's runtime behaviour, which is out of scope for
# a read-only monitoring agent, so the capability is never advertised even when
# a product would technically expose it.
UNSUPPORTED_BY_ARGUS: frozenset[str] = frozenset({CAN_REQUEST_SCAN})


def all_capabilities() -> list[str]:
    """Every capability name ARGUS knows about, sorted."""
    return sorted(ALL_CAPABILITIES)


@dataclass
class ProviderScanState:
    """Last scan information a provider is willing to report (read-only)."""

    state: str = NOT_SCANNED
    availability: str = NOT_SCANNED
    quick_scan_started_at: str | None = None
    quick_scan_ended_at: str | None = None
    full_scan_started_at: str | None = None
    full_scan_ended_at: str | None = None
    signature_version: str | None = None
    signature_updated_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "availability": self.availability,
            "quick_scan_started_at": self.quick_scan_started_at,
            "quick_scan_ended_at": self.quick_scan_ended_at,
            "full_scan_started_at": self.full_scan_started_at,
            "full_scan_ended_at": self.full_scan_ended_at,
            "signature_version": self.signature_version,
            "signature_updated_at": self.signature_updated_at,
        }


@dataclass
class ProviderDetection:
    """A single detection reported by a security provider (read-only)."""

    detection_id: str
    threat_name: str | None = None
    severity: str | None = None
    resources: list[str] = field(default_factory=list)
    process_name: str | None = None
    initial_detection_at: str | None = None
    last_status_change_at: str | None = None
    threat_status_id: int | None = None
    action_success: bool | None = None
    current_execution_status_id: int | None = None
    availability: str = AVAILABLE

    def to_dict(self) -> dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "threat_name": self.threat_name,
            "severity": self.severity,
            "resources": self.resources,
            "process_name": self.process_name,
            "initial_detection_at": self.initial_detection_at,
            "last_status_change_at": self.last_status_change_at,
            "threat_status_id": self.threat_status_id,
            "action_success": self.action_success,
            "current_execution_status_id": self.current_execution_status_id,
            "availability": self.availability,
        }


@dataclass
class SecurityProvider:
    """One security product observed on the endpoint."""

    provider_id: str
    provider_name: str
    product: str
    vendor: str | None = None

    status: str = UNAVAILABLE
    status_availability: str = UNAVAILABLE

    realtime_protection: bool | None = None
    realtime_protection_availability: str = UNAVAILABLE

    last_known_scan: ProviderScanState = field(default_factory=ProviderScanState)

    detection_count: int = 0
    detections_availability: str = NOT_SUPPORTED
    detections: list[ProviderDetection] = field(default_factory=list)

    integration_status: str = NOT_SUPPORTED
    supported_capabilities: list[str] = field(default_factory=list)
    unsupported_capabilities: list[str] = field(default_factory=list)

    #: Raw, non-interpreted evidence (e.g. SecurityCenter2 productState hex).
    raw_state: dict[str, Any] = field(default_factory=dict)
    #: Human-readable reason a capability or field is unavailable.
    notes: list[str] = field(default_factory=list)

    last_updated: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "provider_name": self.provider_name,
            "product": self.product,
            "vendor": self.vendor,
            "status": self.status,
            "status_availability": self.status_availability,
            "realtime_protection": self.realtime_protection,
            "realtime_protection_availability": self.realtime_protection_availability,
            "last_known_scan": self.last_known_scan.to_dict(),
            "detection_count": self.detection_count,
            "detections_availability": self.detections_availability,
            "detections": [d.to_dict() for d in self.detections],
            "integration_status": self.integration_status,
            "supported_capabilities": list(self.supported_capabilities),
            "unsupported_capabilities": list(self.unsupported_capabilities),
            "raw_state": self.raw_state,
            "notes": list(self.notes),
            "last_updated": self.last_updated,
        }


@dataclass
class ProviderAlert:
    """A security-provider-originated observation worth correlating."""

    alert_id: str
    provider_id: str
    provider_name: str
    kind: str  # DETECTION | STATE_CHANGED | OPERATIONAL
    timestamp: str
    title: str
    severity: str = "info"  # info | low | medium | high | critical
    resources: list[str] = field(default_factory=list)
    process_name: str | None = None
    detail: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "provider_id": self.provider_id,
            "provider_name": self.provider_name,
            "kind": self.kind,
            "timestamp": self.timestamp,
            "title": self.title,
            "severity": self.severity,
            "resources": self.resources,
            "process_name": self.process_name,
            "detail": self.detail,
            "raw": self.raw,
        }


@dataclass
class SecurityProviderSnapshot:
    """Collection result for one sampling cycle."""

    timestamp: str
    providers: list[SecurityProvider] = field(default_factory=list)
    alerts: list[ProviderAlert] = field(default_factory=list)
    discovery_state: str = AVAILABLE
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "source": "windows_security_provider_collector",
            "observed": True,
            "discovery_state": self.discovery_state,
            "providers": [p.to_dict() for p in self.providers],
            "alerts": [a.to_dict() for a in self.alerts],
            "errors": list(self.errors),
            "provider_count": len(self.providers),
        }


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def coerce_iso(value: Any) -> str | None:
    """Normalize a provider-supplied timestamp to an ISO-8601 UTC string.

    Returns ``None`` when the value is absent or unparseable — ARGUS never
    substitutes its own clock for a value the provider did not report.
    """
    if value in (None, "", "null"):
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        if not text:
            return None
        # PowerShell serializes DateTime as ISO 8601; tolerate trailing Z.
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()
