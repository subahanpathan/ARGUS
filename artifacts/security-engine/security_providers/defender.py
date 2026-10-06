"""Microsoft Defender observation — supported, read-only interfaces only.

ARGUS reads Defender through the documented Microsoft management surface:

* ``Get-MpComputerStatus``     — engine/realtime/signature/scan state
* ``Get-MpThreat``             — currently known threats
* ``Get-MpThreatDetection``    — detection history with affected resources
* ``Microsoft-Windows-Windows Defender/Operational`` event log — state
  changes and tamper-relevant signals (read with ``Get-WinEvent``)

Nothing here writes to Defender. ``Set-MpPreference``, ``Remove-MpThreat`` and
``Start-MpScan`` are refused by :mod:`.psbridge` and are not used.

If Defender is present but inactive (for example because a third-party
antivirus product owns real-time protection) that is reported verbatim:
``AMRunningMode`` is passed through untouched.
"""

from __future__ import annotations

import logging
from typing import Any

from .models import (
    AVAILABLE,
    CAN_READ_DETECTIONS,
    CAN_READ_EVENTS,
    CAN_READ_SCAN_STATUS,
    CAN_READ_STATUS,
    INTEGRATED,
    NOT_SUPPORTED,
    PARTIAL,
    ProviderAlert,
    ProviderDetection,
    ProviderScanState,
    SecurityProvider,
    UNSUPPORTED_BY_ARGUS,
    all_capabilities,
    coerce_iso,
    now_iso,
)
from .psbridge import OK, PsResult, as_list, parse_bool, ps_script, run_readonly

logger = logging.getLogger("argus.security_providers.defender")

DEFENDER_PROVIDER_ID = "windows-defender"

#: Bounded so a long history cannot exhaust memory or the API body limit.
MAX_DETECTIONS = 50
MAX_LOG_EVENTS = 120
MAX_LOG_MESSAGE = 400

# Defender Operational event IDs relevant to monitoring. Only IDs with a
# documented, stable meaning are listed; anything else is surfaced verbatim as
# an operational event without an invented interpretation.
_DEFENDER_EVENT_MAP: dict[int, tuple[str, str]] = {
    1116: ("detection", "high"),      # Antimalware detected a threat
    1117: ("state_changed", "info"),  # Antimalware action taken
    1118: ("state_changed", "medium"),  # Antimalware action failed
    1119: ("detection", "high"),      # Antimalware restored a quarantined item
    1006: ("detection", "high"),      # legacy: malware detected
    1007: ("state_changed", "info"),  # legacy: action taken
    5001: ("state_changed", "critical"),  # Real-time protection disabled
    5004: ("state_changed", "info"),      # Real-time protection enabled
    5010: ("state_changed", "critical"),  # Scanning disabled
    5012: ("state_changed", "critical"),  # Antimalware engine disabled
    5007: ("operational", "info"),        # Configuration changed
}


def _status_script() -> str:
    body = (
        "$c = Get-MpComputerStatus -ErrorAction Stop\n"
        "[pscustomobject]@{\n"
        "  AMServiceEnabled = $c.AMServiceEnabled\n"
        "  AMRunningMode = [string]$c.AMRunningMode\n"
        "  AntivirusEnabled = $c.AntivirusEnabled\n"
        "  AntispywareEnabled = $c.AntispywareEnabled\n"
        "  RealTimeProtectionEnabled = $c.RealTimeProtectionEnabled\n"
        "  BehaviorMonitorEnabled = $c.BehaviorMonitorEnabled\n"
        "  IoavProtectionEnabled = $c.IoavProtectionEnabled\n"
        "  NISEnabled = $c.NISEnabled\n"
        "  IsTamperProtected = $c.IsTamperProtected\n"
        "  AntivirusSignatureVersion = [string]$c.AntivirusSignatureVersion\n"
        "  AntivirusSignatureLastUpdated = $c.AntivirusSignatureLastUpdated\n"
        "  AntispywareSignatureVersion = [string]$c.AntispywareSignatureVersion\n"
        "  AntivirusProductVersion = [string]$c.AntivirusProductVersion\n"
        "  QuickScanStartTime = $c.QuickScanStartTime\n"
        "  QuickScanEndTime = $c.QuickScanEndTime\n"
        "  FullScanStartTime = $c.FullScanStartTime\n"
        "  FullScanEndTime = $c.FullScanEndTime\n"
        "  QuickScanAge = $c.QuickScanAge\n"
        "  FullScanAge = $c.FullScanAge\n"
        "} | ConvertTo-Json -Compress -Depth 3\n"
    )
    return ps_script(f"try {{ {body} }} catch {{ __argus_fail $_.Exception.Message }}")


def _detection_script() -> str:
    body = (
        "$d = @(Get-MpThreatDetection -ErrorAction Stop)\n"
        "$t = @(Get-MpThreat -ErrorAction Stop)\n"
        "$threats = @{}\n"
        "foreach ($x in $t) { $threats[[string]$x.ThreatID] = $x }\n"
        "$out = @()\n"
        "foreach ($x in $d) {\n"
        "  $tk = $null\n"
        "  if ($threats.ContainsKey([string]$x.ThreatID)) { $tk = $threats[[string]$x.ThreatID] }\n"
        "  $out += [pscustomobject]@{\n"
        "    ThreatID = $x.ThreatID\n"
        "    ThreatName = $(if ($tk) { [string]$tk.ThreatName } else { $null })\n"
        "    SeverityID = $(if ($tk) { $tk.SeverityID } else { $null })\n"
        "    CategoryID = $(if ($tk) { $tk.CategoryID } else { $null })\n"
        "    ThreatStatusID = $x.ThreatStatusID\n"
        "    ActionSuccess = $x.ActionSuccess\n"
        "    CurrentThreatExecutionStatusID = $x.CurrentThreatExecutionStatusID\n"
        "    InitialDetectionTime = $x.InitialDetectionTime\n"
        "    LastThreatStatusChangeTime = $x.LastThreatStatusChangeTime\n"
        "    Resources = @($x.Resources)\n"
        "  }\n"
        "}\n"
        "[pscustomobject]@{\n"
        "  detections = $out\n"
        "  active_threats = $t.Count\n"
        "} | ConvertTo-Json -Compress -Depth 5\n"
    )
    return ps_script(f"try {{ {body} }} catch {{ __argus_fail $_.Exception.Message }}")


def _event_script(max_events: int) -> str:
    body = (
        f"$e = @(Get-WinEvent -FilterHashtable @{{ LogName = "
        f"'Microsoft-Windows-Windows Defender/Operational'; Id = @({','.join(str(i) for i in sorted(_DEFENDER_EVENT_MAP))}) }} "
        f"-MaxEvents {int(max_events)} -ErrorAction Stop)\n"
        "$out = @()\n"
        "foreach ($x in $e) {\n"
        "  $m = [string]$x.Message\n"
        "  if ($m.Length -gt 400) { $m = $m.Substring(0, 400) }\n"
        "  $out += [pscustomobject]@{\n"
        "    RecordId = $x.RecordId\n"
        "    Id = $x.Id\n"
        "    TimeCreated = $x.TimeCreated\n"
        "    Level = [string]$x.LevelDisplayName\n"
        "    Message = $m\n"
        "  }\n"
        "}\n"
        "$out | ConvertTo-Json -Compress -Depth 4\n"
    )
    return ps_script(f"try {{ {body} }} catch {{ __argus_fail $_.Exception.Message }}")


def _scan_state_from_status(payload: dict[str, Any]) -> ProviderScanState:
    """Derive last-known-scan facts from Get-MpComputerStatus fields."""
    signature_version = payload.get("AntivirusSignatureVersion") or None
    signature_updated = coerce_iso(payload.get("AntivirusSignatureLastUpdated"))
    quick_start = coerce_iso(payload.get("QuickScanStartTime"))
    quick_end = coerce_iso(payload.get("QuickScanEndTime"))
    full_start = coerce_iso(payload.get("FullScanStartTime"))
    full_end = coerce_iso(payload.get("FullScanEndTime"))

    if quick_end or full_end:
        state = "COMPLETED"
    elif quick_start or full_start:
        state = "IN_PROGRESS"
    else:
        state = "NOT_SCANNED"

    return ProviderScanState(
        state=state,
        availability=AVAILABLE,
        quick_scan_started_at=quick_start,
        quick_scan_ended_at=quick_end,
        full_scan_started_at=full_start,
        full_scan_ended_at=full_end,
        signature_version=signature_version,
        signature_updated_at=signature_updated,
    )


def _provider_from_status(payload: dict[str, Any]) -> SecurityProvider:
    running_mode = str(payload.get("AMRunningMode") or "unknown")
    engine_enabled = parse_bool(payload.get("AMServiceEnabled"))
    realtime = parse_bool(payload.get("RealTimeProtectionEnabled"))

    # Report exactly what Windows reported. "Not running" is a real, common and
    # useful observation — it usually means another AV product owns real-time
    # protection — so it is never normalized into "enabled".
    notes: list[str] = []
    if running_mode.lower() not in ("normal",):
        notes.append(f"AMRunningMode={running_mode}")
    if engine_enabled is False:
        notes.append("Antimalware engine reports AMServiceEnabled=false")
    if realtime is False:
        notes.append("Real-time protection reports disabled (possibly owned by another registered product)")

    provider = SecurityProvider(
        provider_id=DEFENDER_PROVIDER_ID,
        provider_name="Microsoft Defender Antivirus",
        product="antivirus",
        vendor="Microsoft Corporation",
        status=running_mode,
        status_availability=AVAILABLE,
        realtime_protection=realtime,
        realtime_protection_availability=AVAILABLE,
        last_known_scan=_scan_state_from_status(payload),
        integration_status=INTEGRATED,
        supported_capabilities=[
            CAN_READ_STATUS,
            CAN_READ_EVENTS,
            CAN_READ_DETECTIONS,
            CAN_READ_SCAN_STATUS,
        ],
        unsupported_capabilities=sorted(UNSUPPORTED_BY_ARGUS),
        notes=notes,
        last_updated=now_iso(),
    )
    provider.raw_state = {
        "AMServiceEnabled": payload.get("AMServiceEnabled"),
        "AntivirusEnabled": payload.get("AntivirusEnabled"),
        "AntispywareEnabled": payload.get("AntispywareEnabled"),
        "BehaviorMonitorEnabled": payload.get("BehaviorMonitorEnabled"),
        "IoavProtectionEnabled": payload.get("IoavProtectionEnabled"),
        "NISEnabled": payload.get("NISEnabled"),
        "IsTamperProtected": payload.get("IsTamperProtected"),
        "AntivirusProductVersion": payload.get("AntivirusProductVersion"),
        "AMRunningMode": running_mode,
    }
    return provider


_SEVERITY_BY_ID = {1: "severe", 2: "high"}


def _detections_from_payload(payload: Any) -> list[ProviderDetection]:
    detections: list[ProviderDetection] = []
    for index, item in enumerate(as_list(payload if isinstance(payload, dict) else payload)):
        if not isinstance(item, dict):
            continue
        resources = [str(r) for r in as_list(item.get("Resources")) if r]
        threat_id = item.get("ThreatID")
        severity_id = item.get("SeverityID")
        process_name = next(
            (name for name in (exe_name_from_resource(r) for r in resources) if name),
            None,
        )
        detections.append(
            ProviderDetection(
                detection_id=f"defender-{threat_id}-{coerce_iso(item.get('InitialDetectionTime')) or index}",
                threat_name=item.get("ThreatName") or None,
                severity=_SEVERITY_BY_ID.get(severity_id, None) if severity_id else None,
                resources=resources[:MAX_DETECTIONS],
                process_name=process_name,
                initial_detection_at=coerce_iso(item.get("InitialDetectionTime")),
                last_status_change_at=coerce_iso(item.get("LastThreatStatusChangeTime")),
                threat_status_id=item.get("ThreatStatusID"),
                action_success=parse_bool(item.get("ActionSuccess")),
                current_execution_status_id=item.get("CurrentThreatExecutionStatusID"),
                availability=AVAILABLE,
            )
        )
    detections.sort(key=lambda d: (d.initial_detection_at or ""), reverse=True)
    return detections[:MAX_DETECTIONS]


def exe_name_from_resource(resource: str) -> str | None:
    """Best-effort executable name from a Defender detection resource.

    Defender reports resources as file paths (or ``process:pid=NNN`` markers).
    Only the file *name* is derived — ARGUS never opens the file to read its
    contents.
    """
    if not resource:
        return None
    text = resource.strip().strip('"')
    if not text:
        return None
    if text.lower().startswith("process:") or text.lower().startswith("domain:") or text.lower().startswith("regkey:"):
        return None
    tail = text.replace("/", "\\").rsplit("\\", 1)[-1]
    if tail and "." in tail:
        return tail
    return None


def _alerts_from_log(events: Any) -> list[ProviderAlert]:
    alerts: list[ProviderAlert] = []
    for item in as_list(events):
        if not isinstance(item, dict):
            continue
        event_id = item.get("Id")
        try:
            event_id_int = int(event_id)
        except (TypeError, ValueError):
            continue
        kind, severity = _DEFENDER_EVENT_MAP.get(event_id_int, ("operational", "info"))
        record_id = item.get("RecordId")
        timestamp = coerce_iso(item.get("TimeCreated")) or now_iso()
        message = str(item.get("Message") or "")
        if len(message) > MAX_LOG_MESSAGE:
            message = message[:MAX_LOG_MESSAGE]
        alerts.append(
            ProviderAlert(
                alert_id=f"defender-log-{record_id}" if record_id is not None else f"defender-log-{timestamp}-{event_id_int}",
                provider_id=DEFENDER_PROVIDER_ID,
                provider_name="Microsoft Defender Antivirus",
                kind=kind.upper(),
                timestamp=timestamp,
                title=f"Defender event {event_id_int} ({kind.replace('_', ' ')})",
                severity=severity,
                detail=message.replace("\r\n", " ").replace("\n", " ").strip(),
                raw={
                    "event_id": event_id_int,
                    "record_id": record_id,
                    "level": item.get("Level"),
                    "log": "Microsoft-Windows-Windows Defender/Operational",
                },
            )
        )
    return alerts


def collect_defender(defender_events_max: int = MAX_LOG_EVENTS) -> tuple[SecurityProvider, list[ProviderAlert], list[str]]:
    """Read Defender status, detections and operational log events.

    Returns ``(provider, alerts, errors)``. The provider record always exists so
    downstream consumers can distinguish "Defender present but unreadable" from
    "Defender not present".
    """
    errors: list[str] = []

    status_result: PsResult = run_readonly(_status_script(), timeout_seconds=25)
    provider: SecurityProvider

    if not status_result.ok:
        detail = status_result.error or status_result.kind
        errors.append(f"Get-MpComputerStatus: {detail}")
        provider = SecurityProvider(
            provider_id=DEFENDER_PROVIDER_ID,
            provider_name="Microsoft Defender Antivirus",
            product="antivirus",
            vendor="Microsoft Corporation",
            status="UNAVAILABLE",
            status_availability=status_result.availability,
            integration_status=(
                NOT_SUPPORTED if status_result.kind == NOT_SUPPORTED else "UNAVAILABLE"
            ),
            supported_capabilities=[],
            unsupported_capabilities=sorted(all_capabilities()),
            notes=[f"status query unavailable: {detail}"],
            last_updated=now_iso(),
        )
        provider.last_known_scan = ProviderScanState(
            state="UNAVAILABLE",
            availability=status_result.availability,
        )
        return provider, [], errors

    payload = status_result.data if isinstance(status_result.data, dict) else {}
    provider = _provider_from_status(payload)

    # --- detections -------------------------------------------------------
    detection_result = run_readonly(_detection_script(), timeout_seconds=30)
    if detection_result.ok:
        data = detection_result.data if isinstance(detection_result.data, dict) else {}
        provider.detections = _detections_from_payload(data.get("detections"))
        provider.detection_count = len(provider.detections)
        provider.detections_availability = AVAILABLE
    else:
        provider.detection_count = 0
        provider.detections_availability = detection_result.availability
        provider.unsupported_capabilities = sorted(
            set(provider.unsupported_capabilities) | {CAN_READ_DETECTIONS}
        )
        provider.supported_capabilities = [
            c for c in provider.supported_capabilities if c != CAN_READ_DETECTIONS
        ]
        if provider.supported_capabilities and CAN_READ_STATUS not in provider.supported_capabilities:
            provider.supported_capabilities.append(CAN_READ_STATUS)
        if provider.integration_status == INTEGRATED:
            provider.integration_status = PARTIAL
        errors.append(f"Get-MpThreatDetection: {detection_result.error or detection_result.kind}")
        provider.notes.append(f"detection history unavailable: {detection_result.error or detection_result.kind}")

    # --- operational log --------------------------------------------------
    alerts: list[ProviderAlert] = []
    event_result = run_readonly(_event_script(defender_events_max), timeout_seconds=25)
    if event_result.ok:
        alerts = _alerts_from_log(event_result.data)
    else:
        provider.unsupported_capabilities = sorted(
            set(provider.unsupported_capabilities) | {CAN_READ_EVENTS}
        )
        provider.supported_capabilities = [
            c for c in provider.supported_capabilities if c != CAN_READ_EVENTS
        ]
        if provider.integration_status == INTEGRATED:
            provider.integration_status = PARTIAL
        errors.append(f"Defender Operational log: {event_result.error or event_result.kind}")
        provider.notes.append(
            f"operational log unavailable: {event_result.error or event_result.kind}"
        )

    # Correct integration status after any capability was dropped.
    if provider.integration_status == INTEGRATED and (
        len(provider.supported_capabilities) < 4
    ):
        provider.integration_status = PARTIAL
    if not provider.supported_capabilities and provider.integration_status == INTEGRATED:
        provider.integration_status = NOT_SUPPORTED

    return provider, alerts, errors


__all__ = [
    "DEFENDER_PROVIDER_ID",
    "collect_defender",
    "OK",
]
