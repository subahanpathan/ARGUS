"""
Tests for the ARGUS lab simulation infrastructure.

Covers:
- SyntheticFileManager file creation, baseline recording, integrity checking
- GroundTruthLog record/save/load round-trip
- LabAttackSimulator dry_run mode
"""

import json
import os
import tempfile

import pytest

from lab.synthetic_files import SyntheticFileManager
from lab.ground_truth import GroundTruthLog, GroundTruthEvent
from lab.simulate_attack import LabAttackSimulator


# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def lab_dir(tmp_path):
    """A temporary directory that is automatically removed after each test."""
    return str(tmp_path / "argus_lab")


# ---------------------------------------------------------------------------
# SyntheticFileManager
# ---------------------------------------------------------------------------


class TestSyntheticFileManager:
    def test_create_returns_hashes(self, lab_dir):
        """create_synthetic_files() creates files and returns non-empty hashes."""
        mgr = SyntheticFileManager(lab_dir)
        hashes = mgr.create_synthetic_files()

        assert len(hashes) == 4, "Expected 4 synthetic files"
        for filename, digest in hashes.items():
            assert len(digest) == 64, f"SHA-256 should be 64 hex chars; got {digest!r}"
            full_path = os.path.join(lab_dir, filename)
            assert os.path.exists(full_path), f"File not created: {full_path}"

    def test_record_baseline_matches_create_hashes(self, lab_dir):
        """record_baseline() returns the same digests as create_synthetic_files()."""
        mgr = SyntheticFileManager(lab_dir)
        create_hashes = mgr.create_synthetic_files()
        baseline = mgr.record_baseline()

        # Baseline keys are absolute paths; create keys are filenames.
        assert len(baseline) == len(create_hashes)
        for abs_path, digest in baseline.items():
            filename = os.path.basename(abs_path)
            assert filename in create_hashes
            assert create_hashes[filename] == digest

    def test_integrity_reports_modified_file(self, lab_dir):
        """A file modified after baseline is reported as MODIFIED."""
        mgr = SyntheticFileManager(lab_dir)
        mgr.create_synthetic_files()
        mgr.record_baseline()

        # Mutate one file.
        target = os.path.join(lab_dir, "lab_credentials.txt")
        with open(target, "a", encoding="utf-8") as fh:
            fh.write("\n# ARGUS_LAB_SYNTHETIC tamper marker\n")

        changes = mgr.check_integrity()
        statuses = {os.path.basename(c["path"]): c["status"] for c in changes}
        assert statuses["lab_credentials.txt"] == "modified"
        # The other files should be unchanged.
        for name in ("lab_pii_records.csv", "lab_financial_data.xlsx", "lab_corporate_docs.docx"):
            assert statuses[name] == "unchanged"

    def test_integrity_reports_deleted_file(self, lab_dir):
        """A file removed after baseline is reported as DELETED."""
        mgr = SyntheticFileManager(lab_dir)
        mgr.create_synthetic_files()
        mgr.record_baseline()

        # Delete one file.
        target = os.path.join(lab_dir, "lab_pii_records.csv")
        os.remove(target)

        changes = mgr.check_integrity()
        statuses = {os.path.basename(c["path"]): c["status"] for c in changes}
        assert statuses["lab_pii_records.csv"] == "deleted"

    def test_get_file_paths_returns_existing(self, lab_dir):
        """get_file_paths() returns only files that exist on disk."""
        mgr = SyntheticFileManager(lab_dir)
        # Before creation: no files.
        assert mgr.get_file_paths() == []

        mgr.create_synthetic_files()
        paths = mgr.get_file_paths()
        assert len(paths) == 4
        for p in paths:
            assert os.path.isabs(p)
            assert os.path.exists(p)

    def test_cleanup_removes_files(self, lab_dir):
        """cleanup() removes all synthetic files."""
        mgr = SyntheticFileManager(lab_dir)
        mgr.create_synthetic_files()
        assert len(mgr.get_file_paths()) == 4

        mgr.cleanup()
        assert mgr.get_file_paths() == []


# ---------------------------------------------------------------------------
# GroundTruthLog
# ---------------------------------------------------------------------------


class TestGroundTruthLog:
    def test_record_appends_event(self):
        """record() appends an event with correct fields."""
        log = GroundTruthLog("test_scenario")
        log.record("EXECUTION", "ping launched", expected_rule="PROC-001", pid=1234, process_name="ping.exe")

        events = log.events
        assert len(events) == 1
        evt = events[0]
        assert isinstance(evt, GroundTruthEvent)
        assert evt.event_type == "EXECUTION"
        assert evt.detail == "ping launched"
        assert evt.expected_detection_rule == "PROC-001"
        assert evt.pid == 1234
        assert evt.process_name == "ping.exe"
        assert evt.timestamp  # non-empty ISO string

    def test_save_load_roundtrip(self, tmp_path):
        """save() and load() reproduce the same events."""
        log = GroundTruthLog("roundtrip_scenario")
        log.record("PRE_ATTACK", "baseline recorded")
        log.record("INITIAL_ACCESS", "socket attempt", expected_rule="NET-001", pid=999)

        save_path = str(tmp_path / "gt.json")
        log.save(save_path)

        loaded = GroundTruthLog.load(save_path)
        assert len(loaded.events) == 2
        assert loaded.events[0].event_type == "PRE_ATTACK"
        assert loaded.events[1].event_type == "INITIAL_ACCESS"
        assert loaded.events[1].expected_detection_rule == "NET-001"
        assert loaded.events[1].pid == 999

    def test_to_dict_structure(self):
        """to_dict() includes scenario_name, event_count, and events list."""
        log = GroundTruthLog("dict_scenario")
        log.record("NORMAL_ACTIVITY", "no-op")
        d = log.to_dict()

        assert d["scenario_name"] == "dict_scenario"
        assert d["event_count"] == 1
        assert isinstance(d["events"], list)
        assert d["events"][0]["detail"] == "no-op"

    def test_save_produces_valid_json(self, tmp_path):
        """The saved file is valid JSON."""
        log = GroundTruthLog("json_check")
        log.record("FILE_MODIFICATION", "file tampered")
        path = str(tmp_path / "out.json")
        log.save(path)

        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        assert data["scenario_name"] == "json_check"


# ---------------------------------------------------------------------------
# LabAttackSimulator (dry_run=True — no real processes spawned)
# ---------------------------------------------------------------------------


class TestLabAttackSimulatorDryRun:
    def test_dry_run_completes_and_returns_log(self, lab_dir):
        """dry_run=True returns a GroundTruthLog without spawning real processes."""
        sim = LabAttackSimulator(lab_dir=lab_dir, scenario_name="dry_test", dry_run=True)
        log = sim.run()

        assert isinstance(log, GroundTruthLog)
        events = log.events
        # Should have at least one event per phase (6 phases).
        assert len(events) >= 6

    def test_dry_run_event_types_present(self, lab_dir):
        """All major phase event types appear in the dry-run log."""
        sim = LabAttackSimulator(lab_dir=lab_dir, dry_run=True)
        log = sim.run()

        event_types = {e.event_type for e in log.events}
        expected = {"PRE_ATTACK", "INITIAL_ACCESS", "EXECUTION", "FILE_MODIFICATION", "NORMAL_ACTIVITY", "POST_ATTACK"}
        assert expected.issubset(event_types), f"Missing event types: {expected - event_types}"

    def test_dry_run_no_files_created(self, lab_dir):
        """dry_run=True must not create synthetic files on disk."""
        sim = LabAttackSimulator(lab_dir=lab_dir, dry_run=True)
        sim.run()

        # lab_dir may be created as a side effect of SyntheticFileManager init,
        # but no synthetic files should exist inside it.
        mgr = SyntheticFileManager(lab_dir)
        assert mgr.get_file_paths() == []
