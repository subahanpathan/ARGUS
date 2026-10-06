"""Third-party security product discovery — read-only.

Windows exposes registered antivirus / endpoint-security products through the
WMI namespace ``root\\SecurityCenter2`` (class ``AntiVirusProduct``) and, for
history, ``root\\SecurityCenter``. This module performs a *read* of that
namespace plus a read-only scan of the installed-software registry keys to
corroborate what is present.

If neither surface is reachable — which is common on Windows 11 builds where
``SecurityCenter2`` has been retired for some classes — the discovery result is
reported as ``NOT_SUPPORTED``/``UNAVAILABLE`` and no product is invented.

ARGUS never asks a third-party product for anything beyond status. Products
that expose no supported read interface are listed with
``integration_status = NOT_SUPPORTED`` and an empty capability set.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from .models import (
    AVAILABLE,
    INTEGRATED,
    NOT_SUPPORTED,
    PARTIAL,
    SecurityProvider,
    UNAVAILABLE,
    all_capabilities,
    now_iso,
)
from .psbridge import NOT_SUPPORTED as PS_NOT_SUPPORTED
from .psbridge import as_list, decode_product_state, ps_script, run_readonly

logger = logging.getLogger("argus.security_providers.registry")

# Products registered through Windows Security that are not Defender itself.
_DEFENDER_NAME_HINTS = ("defender", "windows defender", "microsoft defender")

#: Words that mark an installed-software entry as a security product. Used only
#: to corroborate Windows Security registration — never as the sole authority.
#: Short acronyms are matched on word boundaries so unrelated names
#: (e.g. "FedRamp", "Extrados") are not misclassified.
_SECURITY_KEYWORDS = (
    "antivirus",
    "anti-virus",
    "antimalware",
    "endpoint protection",
    "endpoint security",
    "internet security",
    "total security",
    "cloud security",
    "security suite",
    "cyber security",
    "edr",
    "xdr",
)

_SECURITY_KEYWORD_PATTERN = re.compile(
    r"(?<![a-z0-9])(?:" + "|".join(re.escape(k) for k in _SECURITY_KEYWORDS) + r")(?![a-z0-9])",
    re.IGNORECASE,
)

_MAX_PRODUCTS = 40


def _sanitize_id(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")
    return f"wsc-{slug or 'unknown'}"


def _securitycenter2_script() -> str:
    body = (
        "$p = @(Get-CimInstance -Namespace 'root\\SecurityCenter2' "
        "-ClassName AntiVirusProduct -ErrorAction Stop)\n"
        "$out = @()\n"
        "foreach ($x in $p) {\n"
        "  $out += [pscustomobject]@{\n"
        "    displayName = [string]$x.displayName\n"
        "    productState = [int]$x.productState\n"
        "    pathToSignedProductExe = [string]$x.pathToSignedProductExe\n"
        "    pathToSignedReportingExe = [string]$x.pathToSignedReportingExe\n"
        "    timestamp = $x.timestamp\n"
        "  }\n"
        "}\n"
        "$out | ConvertTo-Json -Compress -Depth 4\n"
    )
    return ps_script(f"try {{ {body} }} catch {{ __argus_fail $_.Exception.Message }}")


def _uninstall_script() -> str:
    body = (
        "$paths = @(\n"
        "  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',\n"
        "  'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'\n"
        ")\n"
        "$out = @()\n"
        "foreach ($p in $paths) {\n"
        "  foreach ($k in @(Get-ItemProperty -Path $p -ErrorAction SilentlyContinue)) {\n"
        "    if ($k.DisplayName) {\n"
        "      $out += [pscustomobject]@{\n"
        "        displayName = [string]$k.DisplayName\n"
        "        displayVersion = [string]$k.DisplayVersion\n"
        "        publisher = [string]$k.Publisher\n"
        "        installLocation = [string]$k.InstallLocation\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n"
        "$out | ConvertTo-Json -Compress -Depth 3\n"
    )
    return ps_script(f"try {{ {body} }} catch {{ __argus_fail $_.Exception.Message }}")


def _is_defender(name: str) -> bool:
    lowered = (name or "").lower()
    return any(hint in lowered for hint in _DEFENDER_NAME_HINTS)


def _looks_security(name: str) -> bool:
    lowered = (name or "").lower()
    return bool(_SECURITY_KEYWORD_PATTERN.search(lowered))


def collect_registered_products() -> tuple[list[SecurityProvider], str, list[str]]:
    """Discover security products registered with Windows Security.

    Returns ``(providers, discovery_state, errors)``.
    """
    errors: list[str] = []
    result = run_readonly(_securitycenter2_script(), timeout_seconds=25)

    if not result.ok:
        errors.append(f"root\\SecurityCenter2: {result.error or result.kind}")
        logger.info("SecurityCenter2 unavailable: %s", result.error or result.kind)
        return [], result.kind if result.kind in ("NOT_SUPPORTED", "PERMISSION_DENIED") else UNAVAILABLE, errors

    providers: list[SecurityProvider] = []
    for item in as_list(result.data):
        if not isinstance(item, dict):
            continue
        name = str(item.get("displayName") or "").strip()
        if not name or _is_defender(name):
            # Defender is reported through its own supported interface with
            # authoritative real-time state; do not duplicate it here.
            continue

        decoded = decode_product_state(item.get("productState"))
        provider_state = decoded.get("provider_state", "unknown")
        notes = [
            "Status derived from Windows Security registration only.",
            "Windows Security does not publish real-time protection state for "
            "registered products, so realtime_protection is NOT_SUPPORTED here.",
            "This product exposes no supported ARGUS read interface, so "
            "detections and events are NOT_SUPPORTED for it.",
        ]
        provider = SecurityProvider(
            provider_id=_sanitize_id(name),
            provider_name=name,
            product="antivirus",
            vendor=None,
            status="REGISTERED",
            status_availability=AVAILABLE,
            realtime_protection=None,
            realtime_protection_availability=NOT_SUPPORTED,
            integration_status=NOT_SUPPORTED,
            supported_capabilities=[],
            unsupported_capabilities=sorted(all_capabilities()),
            notes=notes,
            last_updated=now_iso(),
        )
        provider.detections_availability = NOT_SUPPORTED
        provider.last_known_scan.availability = NOT_SUPPORTED
        provider.last_known_scan.state = "NOT_SUPPORTED"
        provider.raw_state = {
            "wmi_namespace": "root\\SecurityCenter2",
            "wmi_class": "AntiVirusProduct",
            "productState": decoded,
            "registered_provider_state": provider_state,
            "product_executable": item.get("pathToSignedProductExe") or None,
            "reporting_executable": item.get("pathToSignedReportingExe") or None,
            "registered_at": str(item.get("timestamp") or "") or None,
        }
        providers.append(provider)

    providers.sort(key=lambda p: p.provider_name.lower())
    return providers[:_MAX_PRODUCTS], AVAILABLE, errors


def collect_installed_security_products() -> tuple[list[SecurityProvider], list[str]]:
    """Corroborate registered products against installed-software metadata.

    This is a supporting signal only: the registry does not report real-time
    state, so anything discovered only here is reported ``NOT_SUPPORTED``.
    """
    errors: list[str] = []
    result = run_readonly(_uninstall_script(), timeout_seconds=25)
    if not result.ok:
        errors.append(f"installed-software registry: {result.error or result.kind}")
        return [], errors

    providers: list[SecurityProvider] = []
    seen: set[str] = set()
    for item in as_list(result.data):
        if not isinstance(item, dict):
            continue
        name = str(item.get("displayName") or "").strip()
        if not name or _is_defender(name) or not _looks_security(name):
            continue
        provider_id = _sanitize_id(name)
        if provider_id in seen:
            # The 32-bit and 64-bit Uninstall keys both list the same product.
            continue
        seen.add(provider_id)
        provider = SecurityProvider(
            provider_id=provider_id,
            provider_name=name,
            product="antivirus",
            vendor=str(item.get("publisher") or "").strip() or None,
            status="INSTALLED",
            status_availability=AVAILABLE,
            integration_status=NOT_SUPPORTED,
            supported_capabilities=[],
            unsupported_capabilities=sorted(all_capabilities()),
            notes=[
                "Discovered from installed-software metadata only. No supported "
                "read interface is available for this product."
            ],
            last_updated=now_iso(),
        )
        provider.raw_state = {
            "source": "HKLM Uninstall registry (read-only)",
            "display_version": item.get("displayVersion") or None,
            "install_location": item.get("installLocation") or None,
        }
        providers.append(provider)

    providers.sort(key=lambda p: p.provider_name.lower())
    return providers[:_MAX_PRODUCTS], errors


def collect_third_party_products() -> tuple[list[SecurityProvider], str, list[str]]:
    """Full third-party discovery: Windows Security registration + registry."""
    providers, state, errors = collect_registered_products()
    registered_ids = {p.provider_id for p in providers}

    registry_products, registry_errors = collect_installed_security_products()
    errors.extend(registry_errors)
    for product in registry_products:
        if product.provider_id not in registered_ids:
            providers.append(product)

    providers.sort(key=lambda p: p.provider_name.lower())
    if providers and state == UNAVAILABLE:
        state = AVAILABLE
    return providers[:_MAX_PRODUCTS], state, errors


__all__ = [
    "collect_registered_products",
    "collect_installed_security_products",
    "collect_third_party_products",
    "PS_NOT_SUPPORTED",
    "INTEGRATED",
    "PARTIAL",
]
