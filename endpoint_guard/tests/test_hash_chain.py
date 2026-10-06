import os
import sqlite3
import tempfile
import pytest

from endpoint_guard.database.manager import DatabaseManager


def test_hash_chain_integrity():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        db = DatabaseManager(db_path)

        # Record 5 sequential events
        for i in range(5):
            db.record_event({
                "incident_id": "INC-TEST-001",
                "timestamp": f"2026-10-06T12:00:0{i}Z",
                "event_type": "network_connection",
                "source_module": "network",
                "severity": "High" if i == 4 else "Low",
                "attacker_ip": "192.168.1.100",
                "pid": 1000 + i,
                "details": {"action": f"test_step_{i}", "counter": i}
            })

        # Verify initial valid chain
        is_valid, broken_id, total = db.verify_hash_chain()
        assert is_valid is True
        assert broken_id is None
        assert total == 5

        # Tamper with event 3 directly via raw SQLite connection
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE events SET details = '{\"tampered\": true}' WHERE id = 3")
        conn.commit()
        conn.close()

        # Re-verify: must fail on row 3!
        is_valid, broken_id, total = db.verify_hash_chain()
        assert is_valid is False
        assert broken_id == 3
