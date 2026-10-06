import pytest
from endpoint_guard.config import Config
from endpoint_guard.detection.network_rules import (
    BruteForceDetectionRule,
    PortScanDetectionRule,
    ReverseShellRule,
    SuspiciousInterpreterSocketRule,
)


@pytest.fixture
def test_config():
    return Config()


def test_reverse_shell_rule_detection(test_config):
    rule = ReverseShellRule(test_config)

    # 1. Reverse shell connection from powershell to Kali VM
    context = {
        "connections": [
            {
                "pid": 4321,
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass",
                "parent_pid": 1200,
                "parent_process_name": "explorer.exe",
                "remote_ip": "192.168.56.101",
                "remote_port": 4444,
                "local_ip": "192.168.56.1",
                "local_port": 50123,
                "status": "ESTABLISHED",
                "protocol": "TCP"
            }
        ]
    }
    alerts = rule.evaluate(context)
    assert len(alerts) == 1
    assert alerts[0].severity == "Critical"
    assert alerts[0].rule_id == "NET-001"
    assert alerts[0].attacker_ip == "192.168.56.101"
    assert alerts[0].pid == 4321


def test_reverse_shell_rule_ignores_localhost(test_config):
    rule = ReverseShellRule(test_config)
    context = {
        "connections": [
            {
                "pid": 4321,
                "process_name": "cmd.exe",
                "command_line": "cmd.exe",
                "remote_ip": "127.0.0.1",
                "remote_port": 8000,
                "status": "ESTABLISHED",
            }
        ]
    }
    alerts = rule.evaluate(context)
    assert len(alerts) == 0


def test_interpreter_c2_port_detection(test_config):
    rule = SuspiciousInterpreterSocketRule(test_config)
    context = {
        "connections": [
            {
                "pid": 5555,
                "process_name": "python.exe",
                "command_line": "python.exe payload.py",
                "remote_ip": "192.168.1.150",
                "remote_port": 4444,
                "status": "ESTABLISHED",
            }
        ]
    }
    alerts = rule.evaluate(context)
    assert len(alerts) == 1
    assert alerts[0].severity == "High"
    assert alerts[0].rule_id == "NET-002"
    assert alerts[0].attacker_ip == "192.168.1.150"


def test_port_scan_detection(test_config):
    rule = PortScanDetectionRule(test_config)
    # Feed 16 distinct probed ports
    connections = []
    for port in range(1000, 1016):
        connections.append({
            "pid": 0,
            "remote_ip": "192.168.56.101",
            "local_port": port,
            "remote_port": 54321,
            "status": "SYN_SENT"
        })

    alerts = rule.evaluate({"connections": connections})
    assert len(alerts) == 1
    assert alerts[0].rule_id == "NET-003"
    assert alerts[0].attacker_ip == "192.168.56.101"


def test_brute_force_detection(test_config):
    rule = BruteForceDetectionRule(test_config)
    # Feed 6 connections to port 445 (SMB)
    connections = []
    for _ in range(6):
        connections.append({
            "pid": 4,
            "remote_ip": "192.168.56.101",
            "local_port": 445,
            "remote_port": 50000,
            "status": "ESTABLISHED"
        })

    alerts = rule.evaluate({"connections": connections})
    assert len(alerts) == 1
    assert alerts[0].rule_id == "NET-004"
    assert alerts[0].attacker_ip == "192.168.56.101"
