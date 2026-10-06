"""Temporary probe: validate ScanCoordinator against the real filesystem."""

from __future__ import annotations

import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from filesystem_scan import (  # noqa: E402
    ScanCoordinator,
    new_scan_id,
    resolve_default_scan_roots,
    resolve_scan_roots,
)

TERMINAL = {"COMPLETED", "PARTIAL", "FAILED", "CANCELLED"}


def wait_terminal(coordinator: ScanCoordinator, scan_id: str, timeout: float = 180.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        state = coordinator.get(scan_id)
        if state is not None and not state.is_active:
            return state
        time.sleep(0.1)
    raise AssertionError(f"TIMEOUT waiting for {scan_id}")


def main() -> int:
    workdir = tempfile.mkdtemp(prefix="argus-scan-probe-")
    for index in range(60):
        sub = os.path.join(workdir, f"d{index % 4}")
        os.makedirs(sub, exist_ok=True)
        with open(os.path.join(sub, f"f{index}.txt"), "w", encoding="utf-8") as fh:
            fh.write("x" * 128)

    # -- root resolution: explicit roots are authoritative ------------------
    explicit = resolve_scan_roots([workdir])
    print("explicit roots:", explicit)
    assert explicit == [os.path.normpath(workdir)], explicit

    deduped = resolve_scan_roots([workdir, workdir.upper(), workdir + "\\"])
    print("deduped explicit roots:", deduped)
    assert len(deduped) == 1, deduped

    defaults = resolve_default_scan_roots()
    print("default roots:", defaults)

    # -- a clean, bounded scan on an explicit root --------------------------
    coordinator = ScanCoordinator(throttle_seconds=0.05)
    print("describe before:", coordinator.describe())

    state, started = coordinator.request_scan(roots=[workdir], label="probe scan")
    assert started is True, "first request should start a scan"
    assert state.scan_id.startswith("scan-"), state.scan_id
    print("started:", state.scan_id)

    # Single-flight: a second request folds into the running scan.
    dup, dup_started = coordinator.request_scan(roots=[workdir], label="duplicate")
    print("duplicate folded:", dup_started, "same scan:", dup.scan_id == state.scan_id)
    assert dup_started is False, "duplicate request must not start a second scan"
    assert dup.scan_id == state.scan_id
    assert coordinator.describe()["duplicate_requests"] == 1, coordinator.describe()

    final = wait_terminal(coordinator, state.scan_id).to_dict()
    print(
        "clean scan:",
        final["state"],
        "discovered:", final["files_discovered"],
        "scanned:", final["files_scanned"],
        "folders:", final["folders_scanned"],
        "total_known:", final["total_known"],
        "progress:", final["progress_percent"],
        "errors:", final["errors"],
        "perm_denied:", final["permission_denied"],
        "roots:", final["roots"],
    )
    assert final["state"] == "COMPLETED", final["state"]
    assert final["files_discovered"] == 60, final
    assert final["files_scanned"] == 60, final
    assert final["total_known"] is True, final
    assert final["progress_percent"] == 100.0, final
    assert final["roots"] == [os.path.normpath(workdir)], final

    # -- unknown scan id must be reported, never invented -------------------
    missing, outcome = coordinator.cancel("scan-does-not-exist")
    print("missing cancel:", missing, outcome)
    assert missing is None and outcome == "not_found"

    # -- cancel a real, in-flight scan (default roots: large enough to catch)
    cancel_state, cancel_started = coordinator.request_scan(label="cancel probe")
    assert cancel_started is True, cancel_state.scan_id
    time.sleep(0.2)
    _, outcome = coordinator.cancel(cancel_state.scan_id)
    print("cancel outcome:", outcome)
    assert outcome == "cancel_pending", outcome

    cancelled = wait_terminal(coordinator, cancel_state.scan_id).to_dict()
    print(
        "cancelled scan:",
        cancelled["state"],
        "scanned:", cancelled["files_scanned"],
        "discovered:", cancelled["files_discovered"],
        "progress:", cancelled["progress_percent"],
    )
    assert cancelled["state"] == "CANCELLED", cancelled["state"]
    assert cancelled["files_scanned"] < cancelled["files_discovered"] or not cancelled["total_known"], cancelled

    _, outcome = coordinator.cancel(cancel_state.scan_id)
    print("cancel after finish:", outcome)
    assert outcome == "already_finished", outcome

    print("list_scans:", [s.scan_id for s in coordinator.list_scans()])
    print("describe after:", coordinator.describe())
    assert coordinator.active_scan is None, "active scan must be cleared"
    assert coordinator.describe()["scans_completed"] == 1, coordinator.describe()
    assert coordinator.describe()["scans_cancelled"] == 1, coordinator.describe()
    coordinator.stop()

    # -- a root that does not exist must fail honestly ----------------------
    coordinator2 = ScanCoordinator()
    bad, bad_started = coordinator2.request_scan(
        roots=[os.path.join(workdir, "nope-not-here")], label="missing root"
    )
    assert bad_started is True, bad.scan_id
    payload2 = wait_terminal(coordinator2, bad.scan_id, timeout=30).to_dict()
    print("missing-root scan:", payload2["state"], "message:", payload2["message"])
    assert payload2["state"] == "FAILED", payload2["state"]
    assert payload2["message"] == "no accessible scan roots", payload2["message"]

    # -- a budget-truncated inventory must not report a percentage ----------
    # The coordinator clamps budgets to >= 1000, so the tree must exceed that.
    big = tempfile.mkdtemp(prefix="argus-scan-budget-")
    for bucket in range(3):
        sub = os.path.join(big, f"b{bucket}")
        os.makedirs(sub, exist_ok=True)
        for index in range(900):
            with open(os.path.join(sub, f"f{index}.txt"), "w", encoding="utf-8") as fh:
                fh.write("x")

    coordinator3 = ScanCoordinator(throttle_seconds=0.05)
    truncated, _ = coordinator3.request_scan(
        roots=[big], entry_budget=1000, label="tiny budget"
    )
    payload3 = wait_terminal(coordinator3, truncated.scan_id, timeout=120).to_dict()
    print(
        "tiny-budget scan:",
        payload3["state"],
        "discovered:", payload3["files_discovered"],
        "inventory_truncated:", payload3["inventory_truncated"],
        "total_known:", payload3["total_known"],
        "progress:", payload3["progress_percent"],
    )
    assert payload3["inventory_truncated"] is True, payload3
    assert payload3["total_known"] is False, payload3
    assert payload3["progress_percent"] is None, payload3
    assert payload3["state"] in TERMINAL, payload3
    coordinator3.stop()

    print("new_scan_id():", new_scan_id())
    print("PROBE OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
