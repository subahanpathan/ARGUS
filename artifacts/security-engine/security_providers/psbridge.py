"""Read-only PowerShell bridge for security-provider queries.

Every helper here is a *reader*. The bridge enforces that at runtime: a script
is rejected before execution if it contains any command that could mutate
security-product state.

Explicitly refused (and never sent to Windows):

    Set-MpPreference        Start-MpScan         Start-MpWDOScan
    Remove-MpThreat         Add-MpPreference     Set-MpPreference
    Set-NetFirewallProfile  netsh advfirewall    sc stop / sc config
    Remove-Item/Set-ItemProperty/Set-Service/Stop-Service/Start-Service
                            taskkill / Stop-Process
    reg add / reg delete    bcdedit              wmic process call create

The intent is simple: ARGUS reads the security posture of the endpoint so it
can correlate with its own telemetry. It never reconfigures, disables, evades
or tampers with any security product.
"""

from __future__ import annotations

import base64
import logging
import re
import subprocess
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("argus.security_providers.psbridge")

# Result kinds for a provider query.
OK = "OK"
NOT_SUPPORTED = "NOT_SUPPORTED"
PERMISSION_DENIED = "PERMISSION_DENIED"
UNAVAILABLE = "UNAVAILABLE"
TIMEOUT = "TIMEOUT"

#: Substrings that indicate the requested surface does not exist on this host.
_NOT_SUPPORTED_HINTS = (
    "is not recognized",
    "not recognized as",
    "no such command",
    "was not found",
    "cannot find the path",
    "cannot find path",
    "invalid class",
    "invalid namespace",
    "not supported",
    "unsupported",
    "provider not found",
    "root/securitycenter2",
    "root\\securitycenter2",
)

_PERMISSION_HINTS = (
    "access is denied",
    "access denied",
    "unauthorizedaccess",
    "unauthorized access",
    "privilege",
    "requires elevation",
    "request is not supported",
    "not permitted",
    "hresult: 0x80070005",
    "error accessdenied",
)

_UNAVAILABLE_HINTS = (
    "the rpc server is unavailable",
    "the service is unavailable",
    "could not start",
    "cannot connect",
    "timed out",
    "the object cannot be found",
    "nullreferenceexception",
)


@dataclass
class PsResult:
    """Outcome of one read-only PowerShell query."""

    ok: bool
    kind: str
    data: Any = None
    error: str = ""
    elapsed_ms: int = 0

    @property
    def availability(self) -> str:
        """Map a result kind onto the shared availability vocabulary."""
        return {
            OK: "AVAILABLE",
            NOT_SUPPORTED: "NOT_SUPPORTED",
            PERMISSION_DENIED: "PERMISSION_DENIED",
            TIMEOUT: "UNAVAILABLE",
            UNAVAILABLE: "UNAVAILABLE",
        }.get(self.kind, "UNAVAILABLE")


_FORBIDDEN = (
    "set-mppreference",
    "add-mppreference",
    "removemppreference",
    "set-mppreference",
    "removempthreat",
    "start-mpscan",
    "start-mpwdoscan",
    "start-mpcmdletscan",
    "set-firewallprofile",
    "set-netfirewallprofile",
    "new-netfirewallrule",
    "netsh advfirewall",
    "remove-itemproperty",
    "set-itemproperty",
    "new-itemproperty",
    "remove-item",
    "stop-service",
    "start-service",
    "set-service",
    "sc stop",
    "sc config",
    "sc delete",
    "taskkill",
    "stop-process",
    "reg add",
    "reg delete",
    "bcdedit",
    "invoke-expression",
    "downloadstring",
    "start-bitstransfer",
    "invoke-webrequest",
    "certutil",
    "bitsadmin",
)


class ReadOnlyViolation(RuntimeError):
    """Raised when a caller attempts to submit a mutating script."""


def assert_read_only(script: str) -> None:
    """Reject any script that contains a known state-mutating command."""
    lowered = script.lower()
    for needle in _FORBIDDEN:
        if needle in lowered:
            raise ReadOnlyViolation(
                f"ARGUS endpoint agent refuses to execute a mutating command: {needle!r}"
            )


def classify_error(message: str) -> str:
    """Map a raw PowerShell/CIM error message onto a result kind."""
    lowered = (message or "").lower()
    if any(hint in lowered for hint in _PERMISSION_HINTS):
        return PERMISSION_DENIED
    if any(hint in lowered for hint in _NOT_SUPPORTED_HINTS):
        return NOT_SUPPORTED
    if any(hint in lowered for hint in _UNAVAILABLE_HINTS):
        return UNAVAILABLE
    return UNAVAILABLE


def run_readonly(script: str, timeout_seconds: int = 25) -> PsResult:
    """Execute a read-only PowerShell script and return structured output.

    The script is expected to emit a single JSON document. ``-EncodedCommand``
    is used so quoting is never ambiguous, and ``-NoProfile
    -NonInteractive`` keeps the call hermetic.
    """
    try:
        assert_read_only(script)
    except ReadOnlyViolation as exc:
        logger.error("Refusing script: %s", exc)
        return PsResult(ok=False, kind=UNAVAILABLE, error=str(exc))

    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        encoded,
    ]

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return PsResult(ok=False, kind=TIMEOUT, error=f"timeout after {timeout_seconds}s")
    except FileNotFoundError:
        # No PowerShell on this host — treat the interface as unsupported
        # rather than inventing data.
        return PsResult(ok=False, kind=NOT_SUPPORTED, error="powershell.exe not found")
    except OSError as exc:  # pragma: no cover - defensive
        return PsResult(ok=False, kind=UNAVAILABLE, error=str(exc))

    stdout = (completed.stdout or b"").decode("utf-8", "replace").strip()
    stderr = (completed.stderr or b"").decode("utf-8", "replace").strip()

    if completed.returncode != 0 and not stdout:
        kind = classify_error(stderr)
        return PsResult(ok=False, kind=kind, error=stderr[:800] or f"exit {completed.returncode}")

    payload = _extract_json(stdout)
    if payload is None:
        detail = stderr[:800] or stdout[:800] or f"exit {completed.returncode}"
        return PsResult(ok=False, kind=classify_error(detail), error=detail)

    if isinstance(payload, dict) and payload.get("__error"):
        message = str(payload.get("__error"))
        return PsResult(ok=False, kind=classify_error(message), error=message[:800])

    return PsResult(ok=True, kind=OK, data=payload)


def _extract_json(stdout: str):
    """Pull the first JSON document out of PowerShell stdout.

    PowerShell may prepend informational text. The outermost JSON document is
    found by locating whichever of ``{`` / ``[`` appears *first* and scanning to
    its balanced partner (tracking string literals and escapes). Scanning for
    ``{`` alone would truncate a top-level array at its first element.
    """
    if not stdout:
        return None
    import json

    starts = [(stdout.find(opener), opener, closer) for opener, closer in (("[", "]"), ("{", "}"))]
    candidates = [(idx, opener, closer) for idx, opener, closer in starts if idx != -1]
    if not candidates:
        return None
    start, opener, closer = min(candidates, key=lambda item: item[0])

    depth = 0
    in_string = False
    escape = False
    for index in range(start, len(stdout)):
        ch = stdout[index]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(stdout[start : index + 1])
                except ValueError:
                    return None
    return None


#: A PS script preamble that converts any terminating error into a JSON marker so
#: the caller can classify it instead of guessing from an exit code.
ERROR_PRELUDE = (
    '$ErrorActionPreference = "Stop"\n'
    'function __argus_fail($m) { [pscustomobject]@{ __error = $m } | ConvertTo-Json -Compress }\n'
)


def ps_script(body: str) -> str:
    """Wrap a PowerShell body with the JSON error prelude."""
    return ERROR_PRELUDE + body


def as_list(value: Any) -> list[Any]:
    """PowerShell collapses single-element arrays; normalize to a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


_TRUTHY = {"true", "1", "yes", "enabled", "on"}
_FALSY = {"false", "0", "no", "disabled", "off"}


def parse_bool(value: Any) -> bool | None:
    """Parse a provider boolean. Unknown values return ``None`` (not False)."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in _TRUTHY:
        return True
    if text in _FALSY:
        return False
    return None


_PRODUCT_STATE_HEX = re.compile(r"^[0-9a-fA-F]{6}$")


def _product_state_int(raw: Any) -> int | None:
    """Normalize a WMI ``uint32`` productState into an integer.

    The WMI class exposes ``productState`` as ``uint32``, so PowerShell hands us
    a *decimal* integer. Some tooling renders the same field as a hex string, so
    both forms are accepted: a value containing ``a``-``f`` is read as hex,
    anything else as decimal.
    """
    if raw is None:
        return None
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    text = str(raw).strip()
    if not text:
        return None
    try:
        if re.fullmatch(r"[0-9]+", text):
            return int(text, 10)
        if re.fullmatch(r"0[xX][0-9a-fA-F]+", text):
            return int(text, 16)
        if re.fullmatch(r"[0-9a-fA-F]{6}", text):
            return int(text, 16)
    except ValueError:
        return None
    return None


def decode_product_state(raw: Any) -> dict[str, Any]:
    """Decode a SecurityCenter2 ``productState`` value.

    Windows Security publishes this as a ``uint32`` whose six-hex-digit byte
    layout is documented as provider flags / definition status / scan status,
    where ``0x10`` means "on / up to date" and ``0x00`` means "off". The raw
    value is always preserved next to the interpretation so no claim is made
    without its source, and unrecognised values return ``decoded: false``
    rather than a guess.
    """
    numeric = _product_state_int(raw)
    if numeric is None:
        return {"raw": None if raw is None else str(raw), "decoded": False}

    hexed = f"{numeric:06X}"
    if not _PRODUCT_STATE_HEX.match(hexed):
        return {"raw": str(raw), "hex": hexed, "decoded": False}

    provider_flags = int(hexed[0:2], 16)
    definition_status = int(hexed[2:4], 16)
    scan_status = int(hexed[4:6], 16)

    def _byte_meaning(value_: int, on_word: str, off_word: str) -> str:
        if value_ == 0x10:
            return on_word
        if value_ == 0x00:
            return off_word
        return f"other(0x{value_:02X})"

    return {
        "raw": str(raw),
        "hex": hexed,
        "decoded": True,
        "bytes": {
            "provider": provider_flags,
            "definition": definition_status,
            "scan": scan_status,
        },
        "provider_state": "on" if provider_flags & 0x10 else "off",
        "definition_status": _byte_meaning(definition_status, "up_to_date", "out_of_date"),
        "scan_status": _byte_meaning(scan_status, "enabled", "disabled"),
        "source": "root\\SecurityCenter2 AntiVirusProduct.productState",
        "interpretation": (
            "Byte layout is the widely documented SecurityCenter2 convention "
            "(provider / definitions / real-time scan, 0x10 = on, 0x00 = off). "
            "Microsoft does not publish per-byte semantics for every value, so "
            "the raw hex above is authoritative and this interpretation is "
            "presented as derived, not verified."
        ),
        "authoritative_for_realtime_protection": False,
    }
