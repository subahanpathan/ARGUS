import os
import tempfile
import pytest

from endpoint_guard.config import Config
from endpoint_guard.database.manager import DatabaseManager
from endpoint_guard.detection.rules_base import DetectionAlert
from endpoint_guard.response.quarantine_manager import QuarantineManager
from endpoint_guard.response.response_engine import ResponseEngine


def test_quarantine_and_restore():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        quarantine_dir = os.path.join(tmpdir, "vault")
        db = DatabaseManager(db_path)

        cfg = Config()
        cfg.raw_data["general"]["dry_run"] = False
        cfg.raw_data["general"]["quarantine_dir"] = quarantine_dir

        qm = QuarantineManager(cfg, db)

        # Create dummy malicious payload
        bad_file = os.path.join(tmpdir, "payload.exe")
        with open(bad_file, "wb") as f:
            f.write(b"MALICIOUS_PAYLOAD_BYTES_XYZ")

        meta = qm.quarantine_file(bad_file, "Backdoor Dropper", "INC-001")
        assert meta is not None
        assert not os.path.exists(bad_file)
        assert os.path.exists(meta["quarantine_path"])

        # Check DB
        items = db.list_quarantined_items()
        assert len(items) == 1
        assert items[0]["sha256"] == meta["sha256"]

        # Restore file
        restored = qm.restore_file(items[0]["id"])
        assert restored is True
        assert os.path.exists(bad_file)


def test_response_engine_containment():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        db = DatabaseManager(db_path)

        cfg = Config()
        cfg.raw_data["general"]["dry_run"] = True  # Dry run for unit test

        engine = ResponseEngine(cfg, db)

        alert = DetectionAlert(
            rule_id="NET-001",
            name="Interactive Shell Reverse Connection",
            severity="Critical",
            description="PowerShell connected to Kali",
            mitre_technique="T1059.001",
            attacker_ip="192.168.1.150",
            pid=99999,
            process_name="powershell.exe",
            command_line="powershell.exe -w hidden",
            details={"remote_port": 4444}
        )

        incident_id = engine.handle_alert(alert)
        assert incident_id is not None

        # Check incident in DB
        inc = db.get_incident(incident_id)
        assert inc is not None
        assert inc["severity"] == "Critical"
        assert inc["status"] == "Contained"

        # Check attacker profile in DB
        atk = db.get_attacker("192.168.1.150")
        assert atk is not None
        assert atk["is_blocked"] == 1

        # Check hash-chained events
        events = db.get_incident_events(incident_id)
        assert len(events) >= 2  # Detection + response actions
        valid, _, _ = db.verify_hash_chain()
        assert valid is True
