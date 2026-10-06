import pytest
from endpoint_guard.config import Config
from endpoint_guard.detection.peripheral_rules import MicrophoneAccessRule, WebcamAccessRule


@pytest.fixture
def test_config():
    return Config()


def test_webcam_unauthorized_access(test_config):
    rule = WebcamAccessRule(test_config)
    context = {
        "peripheral_events": [
            {
                "device_type": "webcam",
                "process_name": "meterpreter.exe",
                "pid": 8899,
                "command_line": "meterpreter.exe",
                "exe_path": "C:\\Temp\\meterpreter.exe",
                "is_active": True,
            }
        ]
    }
    alerts = rule.evaluate(context)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "PERIPH-001"
    assert alerts[0].severity == "Critical"
    assert alerts[0].pid == 8899


def test_webcam_authorized_app_ignored(test_config):
    rule = WebcamAccessRule(test_config)
    context = {
        "peripheral_events": [
            {
                "device_type": "webcam",
                "process_name": "zoom.exe",
                "pid": 1111,
                "command_line": "zoom.exe",
                "is_active": True,
            }
        ]
    }
    alerts = rule.evaluate(context)
    assert len(alerts) == 0


def test_microphone_unauthorized_access(test_config):
    rule = MicrophoneAccessRule(test_config)
    context = {
        "peripheral_events": [
            {
                "device_type": "microphone",
                "process_name": "audio_recorder.exe",
                "pid": 4455,
                "exe_path": "C:\\Users\\Victim\\Downloads\\audio_recorder.exe",
                "is_active": True,
            }
        ]
    }
    alerts = rule.evaluate(context)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "PERIPH-002"
    assert alerts[0].severity == "Critical"
    assert alerts[0].pid == 4455


def test_microphone_authorized_app_ignored(test_config):
    rule = MicrophoneAccessRule(test_config)
    context = {
        "peripheral_events": [
            {
                "device_type": "microphone",
                "process_name": "discord.exe",
                "pid": 3322,
                "is_active": True,
            }
        ]
    }
    alerts = rule.evaluate(context)
    assert len(alerts) == 0
