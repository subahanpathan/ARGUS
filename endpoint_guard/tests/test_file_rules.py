import tempfile
from pathlib import Path
import pytest

from endpoint_guard.config import Config
from endpoint_guard.detection.file_rules import (
    ArchiveStagingRule,
    BulkFileAccessExfiltrationRule,
    CanaryFileTripwireRule,
)
from endpoint_guard.response.canary_manager import CanaryManager


@pytest.fixture
def test_config():
    return Config()


def test_canary_tripwire_rule(test_config):
    canary_mgr = CanaryManager(test_config)
    canary_mgr.canary_paths.add("c:\\users\\victim\\documents\\passwords.xlsx")

    rule = CanaryFileTripwireRule(test_config, canary_mgr)
    context = {
        "file_events": [
            {
                "file_path": "C:\\Users\\Victim\\Documents\\passwords.xlsx",
                "action": "modified",
                "attacker_ip": "192.168.1.150",
                "pid": 2048,
                "process_name": "cmd.exe"
            }
        ]
    }
    alerts = rule.evaluate(context)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "FILE-001"
    assert alerts[0].severity == "Critical"
    assert alerts[0].attacker_ip == "192.168.1.150"
    assert alerts[0].file_path == "C:\\Users\\Victim\\Documents\\passwords.xlsx"


def test_bulk_file_harvesting_rule(test_config):
    rule = BulkFileAccessExfiltrationRule(test_config)
    # Generate 22 sensitive file events
    events = []
    for i in range(22):
        events.append({
            "file_path": f"C:\\Users\\Victim\\Documents\\doc_{i}.docx",
            "action": "read",
            "pid": 4096
        })

    alerts = rule.evaluate({"file_events": events, "attacker_ip": "192.168.56.101"})
    assert len(alerts) == 1
    assert alerts[0].rule_id == "FILE-002"
    assert alerts[0].severity == "High"
    assert alerts[0].details["files_touched_count"] >= 20


def test_archive_staging_rule(test_config):
    rule = ArchiveStagingRule(test_config)
    context = {
        "file_events": [
            {
                "file_path": "C:\\Users\\Victim\\AppData\\Local\\Temp\\exfil_bundle.zip",
                "action": "created",
                "pid": 5000,
                "process_name": "powershell.exe"
            }
        ]
    }
    alerts = rule.evaluate(context)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "FILE-003"
    assert alerts[0].severity == "High"
