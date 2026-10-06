import os
import re
from typing import Any, Dict, List, Set

from .rules_base import BaseDetectionRule, DetectionAlert
from ..config import Config


class SuspiciousParentChildRule(BaseDetectionRule):
    """
    Detects documents, browsers, or non-terminal applications spawning command shells.
    Classic phishing / document exploit behavior.
    """

    def __init__(self, config: Config):
        super().__init__(
            rule_id="PROC-001",
            name="Suspicious Parent Spawning Command Shell",
            severity="High",
            mitre_technique="T1059 / T1204"
        )
        self.config = config
        self.suspicious_parents = {p.lower() for p in config.get("process", "suspicious_parents", [])}
        self.suspicious_children = {c.lower() for c in config.get("process", "suspicious_children", [])}

    def evaluate(self, context: Dict[str, Any]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        processes = context.get("processes", [])

        for proc in processes:
            proc_name = (proc.get("process_name") or "").lower()
            parent_name = (proc.get("parent_process_name") or "").lower()

            if proc_name in self.suspicious_children and parent_name in self.suspicious_parents:
                alerts.append(DetectionAlert(
                    rule_id=self.rule_id,
                    name=self.name,
                    severity=self.severity,
                    description=(
                        f"Application '{parent_name}' (PID {proc.get('parent_pid')}) spawned "
                        f"command shell '{proc_name}' (PID {proc.get('pid')})."
                    ),
                    mitre_technique=self.mitre_technique,
                    pid=proc.get("pid"),
                    process_name=proc.get("process_name"),
                    command_line=proc.get("command_line"),
                    parent_pid=proc.get("parent_pid"),
                    parent_process_name=proc.get("parent_process_name"),
                    details={
                        "parent": parent_name,
                        "child": proc_name,
                        "cmdline": proc.get("command_line")
                    }
                ))

        return alerts


class EncodedPowerShellRule(BaseDetectionRule):
    """
    Detects obfuscated or encoded PowerShell command line executions commonly used by
    Metasploit, Empire, and malware downloaders.
    """

    ENCODED_FLAGS = [
        "-enc", "-encodedcommand", "-ec", "-e "
    ]
    BYPASS_FLAGS = [
        "-executionpolicy bypass", "-ep bypass", "-exec bypass",
        "-windowstyle hidden", "-w hidden", "-noninteractive", "-noni"
    ]

    def __init__(self, config: Config):
        super().__init__(
            rule_id="PROC-002",
            name="Encoded or Obfuscated PowerShell Execution",
            severity="High",
            mitre_technique="T1059.001"
        )
        self.config = config

    def evaluate(self, context: Dict[str, Any]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        processes = context.get("processes", [])

        for proc in processes:
            proc_name = (proc.get("process_name") or "").lower()
            cmdline = (proc.get("command_line") or "").lower()

            if "powershell" in proc_name or "pwsh" in proc_name:
                is_encoded = any(flag in cmdline for flag in self.ENCODED_FLAGS)
                bypass_matches = sum(1 for flag in self.BYPASS_FLAGS if flag in cmdline)

                if is_encoded or bypass_matches >= 2:
                    alerts.append(DetectionAlert(
                        rule_id=self.rule_id,
                        name=self.name,
                        severity=self.severity,
                        description=(
                            f"Suspicious PowerShell invocation detected: PID {proc.get('pid')} "
                            f"used encoded/stealth flags: '{proc.get('command_line')}'."
                        ),
                        mitre_technique=self.mitre_technique,
                        pid=proc.get("pid"),
                        process_name=proc.get("process_name"),
                        command_line=proc.get("command_line"),
                        parent_pid=proc.get("parent_pid"),
                        parent_process_name=proc.get("parent_process_name"),
                        details={
                            "is_encoded": is_encoded,
                            "bypass_count": bypass_matches,
                            "cmdline": proc.get("command_line")
                        }
                    ))

        return alerts


class LolbinAbuseRule(BaseDetectionRule):
    """
    Detects abuse of native Windows Living-off-the-Land Binaries (LOLBins)
    to download files, execute remote scripts, or bypass defenses.
    """

    def __init__(self, config: Config):
        super().__init__(
            rule_id="PROC-003",
            name="Living-off-the-Land Binary (LOLBin) Abuse",
            severity="High",
            mitre_technique="T1218"
        )
        self.config = config

    def evaluate(self, context: Dict[str, Any]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        processes = context.get("processes", [])

        for proc in processes:
            proc_name = (proc.get("process_name") or "").lower()
            cmdline = (proc.get("command_line") or "").lower()

            suspicious = False
            reason = ""

            if "certutil" in proc_name and any(x in cmdline for x in ["-urlcache", "-split", "-f"]):
                suspicious = True
                reason = "Certutil used to download remote payload."
            elif "bitsadmin" in proc_name and any(x in cmdline for x in ["/transfer", "/download", "/addfile"]):
                suspicious = True
                reason = "Bitsadmin used for payload staging / transfer."
            elif "mshta" in proc_name and any(x in cmdline for x in ["http://", "https://", "javascript:", "vbscript:"]):
                suspicious = True
                reason = "Mshta executing remote or inline script."
            elif "regsvr32" in proc_name and any(x in cmdline for x in ["/i:http", "/i:https", "scrobj.dll"]):
                suspicious = True
                reason = "Regsvr32 Squiblydoo remote scriptlet execution."

            if suspicious:
                alerts.append(DetectionAlert(
                    rule_id=self.rule_id,
                    name=self.name,
                    severity=self.severity,
                    description=f"{reason} (PID {proc.get('pid')})",
                    mitre_technique=self.mitre_technique,
                    pid=proc.get("pid"),
                    process_name=proc.get("process_name"),
                    command_line=proc.get("command_line"),
                    parent_pid=proc.get("parent_pid"),
                    parent_process_name=proc.get("parent_process_name"),
                    details={
                        "binary": proc_name,
                        "cmdline": proc.get("command_line"),
                        "reason": reason
                    }
                ))

        return alerts


class UntrustedPathExecutionRule(BaseDetectionRule):
    """
    Detects binaries executing out of Temporary, Downloads, or AppData folders.
    """

    def __init__(self, config: Config):
        super().__init__(
            rule_id="PROC-004",
            name="Binary Executed From Untrusted Directory",
            severity="Medium",
            mitre_technique="T1036"
        )
        self.config = config
        self.untrusted_substrings = [
            s.lower() for s in config.get("process", "untrusted_execution_paths", ["temp", "downloads"])
        ]

    def evaluate(self, context: Dict[str, Any]) -> List[DetectionAlert]:
        alerts: List[DetectionAlert] = []
        processes = context.get("processes", [])

        for proc in processes:
            exe_path = (proc.get("exe_path") or "").lower()
            if not exe_path:
                continue

            # Check if path contains untrusted directories
            if any(sub in exe_path for sub in self.untrusted_substrings):
                proc_name = proc.get("process_name", "")
                if not self.config.is_critical_process(proc_name):
                    alerts.append(DetectionAlert(
                        rule_id=self.rule_id,
                        name=self.name,
                        severity=self.severity,
                        description=(
                            f"Process '{proc_name}' executed from suspicious directory: {proc.get('exe_path')} "
                            f"(PID {proc.get('pid')})."
                        ),
                        mitre_technique=self.mitre_technique,
                        pid=proc.get("pid"),
                        process_name=proc.get("process_name"),
                        command_line=proc.get("command_line"),
                        file_path=proc.get("exe_path"),
                        details={"exe_path": proc.get("exe_path")}
                    ))

        return alerts
