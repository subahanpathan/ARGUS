"""Security provider collection — assembles the endpoint's security posture.

Combines:

* ``security_providers.defender``  — Microsoft Defender, full read integration
* ``security_providers.registry_providers`` — Windows Security registration of
  third-party antivirus/EDR products and installed-software corroboration

Every provider that cannot be read is still reported, with an explicit
integration status. Nothing is fabricated and no product is ever created that
Windows did not report.
"""

from __future__ import annotations

import logging
from typing import Any

from .defender import collect_defender
from .models import (
    INTEGRATED,
    NOT_SUPPORTED,
    PARTIAL,
    ProviderAlert,
    SecurityProvider,
    SecurityProviderSnapshot,
    UNAVAILABLE,
    now_iso,
)
from .registry_providers import collect_third_party_products

logger = logging.getLogger("argus.security_providers.collector")


def collect_security_providers(
    defender_events_max: int = 120,
    include_registry_corroboration: bool = True,
) -> SecurityProviderSnapshot:
    """Collect every security provider ARGUS can observe on this endpoint."""
    providers: list[SecurityProvider] = []
    alerts: list[ProviderAlert] = []
    errors: list[str] = []
    discovery_state = "AVAILABLE"

    defender, defender_alerts, defender_errors = collect_defender(
        defender_events_max=defender_events_max
    )
    providers.append(defender)
    alerts.extend(defender_alerts)
    errors.extend(defender_errors)

    if include_registry_corroboration:
        third_party, state, tp_errors = collect_third_party_products()
        providers.extend(third_party)
        errors.extend(tp_errors)
        if state != "AVAILABLE" and third_party:
            discovery_state = state
        elif state != "AVAILABLE" and not third_party:
            # Discovery itself failed — say so instead of implying "no AV".
            discovery_state = state if state in ("NOT_SUPPORTED", "PERMISSION_DENIED") else UNAVAILABLE
    else:
        discovery_state = NOT_SUPPORTED

    if defender.status_availability in ("PERMISSION_DENIED", "UNAVAILABLE") and len(providers) == 1:
        discovery_state = defender.status_availability

    providers.sort(key=lambda p: (0 if p.integration_status == INTEGRATED else 1, p.provider_name.lower()))

    snapshot = SecurityProviderSnapshot(
        timestamp=now_iso(),
        providers=providers,
        alerts=alerts,
        discovery_state=discovery_state,
        errors=errors,
    )
    logger.info(
        "Security providers: %d observed (%d integrated), %d provider events",
        len(providers),
        sum(1 for p in providers if p.integration_status == INTEGRATED),
        len(alerts),
    )
    return snapshot


def summarize(snapshot: SecurityProviderSnapshot) -> dict[str, Any]:
    """Compact summary used for the monitoring snapshot header."""
    integrated = [p for p in snapshot.providers if p.integration_status == INTEGRATED]
    partial = [p for p in snapshot.providers if p.integration_status == PARTIAL]
    unsupported = [p for p in snapshot.providers if p.integration_status == NOT_SUPPORTED]
    detections = sum(p.detection_count for p in snapshot.providers)
    realtime_on = [p for p in snapshot.providers if p.realtime_protection is True]
    return {
        "provider_count": len(snapshot.providers),
        "integrated_count": len(integrated),
        "partial_count": len(partial),
        "not_supported_count": len(unsupported),
        "detection_count": detections,
        "realtime_protection_providers": [p.provider_name for p in realtime_on],
        "discovery_state": snapshot.discovery_state,
    }
