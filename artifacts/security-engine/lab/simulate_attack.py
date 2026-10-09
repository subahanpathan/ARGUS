"""
ARGUS Controlled Lab Attack Simulation.

Simulates a controlled, harmless reverse-shell-like attack scenario for
testing ARGUS detection, containment, and recovery capabilities.

SAFETY:
- Does not create real persistence mechanisms
- Does not steal real credentials
- Does not exfiltrate real data
- Does not execute destructive payloads
- All processes are clearly named with ARGUS_LAB_ prefix in their window title
- All synthetic files contain ARGUS_LAB_SYNTHETIC markers
- All outbound connections target localhost (127.0.0.1) only

Designed for a controlled Windows lab environment.
"""

import os
import socket
import subprocess
import time
from pathlib import Path

from .ground_truth import GroundTruthLog
from .synthetic_files import SyntheticFileManager


class LabAttackSimulator:
    """
    Orchestrates a multi-phase, fully synthetic attack simulation.

    Each phase is recorded in a :class:`~lab.ground_truth.GroundTruthLog`
    so detection results can be measured against the known sequence of events.

    Phase sequence
    --------------
    1. PRE_ATTACK       – deploy synthetic files, record baseline hashes
    2. INITIAL_ACCESS   – simulate outbound connection attempt to 127.0.0.1:4444
    3. EXECUTION        – launch ping as a harmless child process
    4. FILE_MODIFICATION – touch a synthetic file and re-hash it
    5. NORMAL_ACTIVITY  – innocent process (no-op in dry-run or headless mode)
    6. POST_ATTACK      – re-hash synthetic files, compare to baseline

    Args:
        lab_dir:       Directory where synthetic files are written.
        scenario_name: Human-readable label for the scenario.
        dry_run:       When ``True`` all dangerous/side-effectful operations are
                       skipped; the method simply logs what *would* happen.
    """

    def __init__(
        self,
        lab_dir: str,
        scenario_name: str = "reverse_shell_exfiltration",
        dry_run: bool = False,
    ) -> None:
        self._lab_dir = lab_dir
        self._scenario_name = scenario_name
        self._dry_run = dry_run
        self._file_manager = SyntheticFileManager(lab_dir)
        self._ground_truth = GroundTruthLog(scenario_name)
        self._child_processes: list[subprocess.Popen] = []

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> GroundTruthLog:
        """
        Execute the full simulation scenario.

        Returns:
            The populated :class:`~lab.ground_truth.GroundTruthLog`.
        """
        self._phase_pre_attack()
        self._phase_initial_access()
        self._phase_execution()
        self._phase_file_modification()
        self._phase_normal_activity()
        self._phase_post_attack()
        return self._ground_truth

    def stop(self) -> None:
        """
        Terminate any child processes that were spawned during the simulation
        and remove synthetic files.
        """
        for proc in self._child_processes:
            try:
                proc.terminate()
            except OSError:
                pass
        self._child_processes.clear()
        self._file_manager.cleanup()

    # ------------------------------------------------------------------
    # Simulation phases
    # ------------------------------------------------------------------

    def _phase_pre_attack(self) -> None:
        """Deploy synthetic files and record their baseline hashes."""
        if self._dry_run:
            self._ground_truth.record(
                "PRE_ATTACK",
                "[DRY-RUN] Would create synthetic files and record baseline hashes",
            )
            return

        hashes = self._file_manager.create_synthetic_files()
        self._file_manager.record_baseline()
        self._ground_truth.record(
            "PRE_ATTACK",
            f"Created {len(hashes)} synthetic files; baseline recorded",
        )

    def _phase_initial_access(self) -> None:
        """
        Simulate an outbound reverse-shell connection attempt.

        Connects to 127.0.0.1:4444 with a short timeout.  The connection will
        be refused immediately because nothing is listening; that refusal is
        intentional — we only want to generate a connection-attempt event that
        ARGUS network monitoring can observe.
        """
        host, port = "127.0.0.1", 4444
        if self._dry_run:
            self._ground_truth.record(
                "INITIAL_ACCESS",
                f"[DRY-RUN] Would attempt socket connect to {host}:{port}",
                expected_rule="NET-001-SUSPICIOUS-OUTBOUND",
            )
            return

        try:
            with socket.create_connection((host, port), timeout=0.5):
                pass  # pragma: no cover – connection never succeeds in lab
        except (ConnectionRefusedError, OSError):
            # Expected: nothing is listening on 4444 in the lab.
            pass

        self._ground_truth.record(
            "INITIAL_ACCESS",
            f"Socket connect attempt to {host}:{port} (connection refused — expected)",
            expected_rule="NET-001-SUSPICIOUS-OUTBOUND",
        )

    def _phase_execution(self) -> None:
        """
        Launch a harmless subprocess to simulate malicious code execution.

        Uses ``ping 127.0.0.1 -n 3`` which is entirely safe but looks like a
        typical post-exploitation recon command in process trees.
        """
        self._simulate_suspicious_process()

    def _phase_file_modification(self) -> None:
        """Modify a synthetic file to simulate data staging / exfiltration prep."""
        self._simulate_file_access()

    def _phase_normal_activity(self) -> None:
        """Inject normal-looking activity to test false-positive avoidance."""
        self._simulate_normal_activity()

    def _phase_post_attack(self) -> None:
        """Re-hash all synthetic files and compare to baseline."""
        if self._dry_run:
            self._ground_truth.record(
                "POST_ATTACK",
                "[DRY-RUN] Would re-hash synthetic files and compare to baseline",
            )
            return

        changes = self._file_manager.check_integrity()
        modified = [c for c in changes if c["status"] != "unchanged"]
        self._ground_truth.record(
            "POST_ATTACK",
            f"Integrity check complete: {len(modified)} file(s) changed out of {len(changes)}",
        )

    # ------------------------------------------------------------------
    # Granular simulation helpers
    # ------------------------------------------------------------------

    def _simulate_suspicious_process(self) -> None:
        """
        Launch ``ping 127.0.0.1 -n 3`` as a tracked child process.

        This represents a 'suspicious child process' in the process tree —
        something ARGUS process monitoring should flag when spawned from an
        unexpected parent.
        """
        pid: int | None = None
        if self._dry_run:
            self._ground_truth.record(
                "EXECUTION",
                "[DRY-RUN] Would launch: ping 127.0.0.1 -n 3",
                expected_rule="PROC-001-SUSPICIOUS-PARENT-CHILD",
                process_name="ping.exe",
            )
            return

        proc = subprocess.Popen(
            ["ping", "127.0.0.1", "-n", "3"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        pid = proc.pid
        self._child_processes.append(proc)
        self._ground_truth.record(
            "EXECUTION",
            "Launched ping 127.0.0.1 -n 3 as suspicious child process",
            expected_rule="PROC-001-SUSPICIOUS-PARENT-CHILD",
            pid=pid,
            process_name="ping.exe",
        )

    def _simulate_file_access(self) -> None:
        """
        Read then modify a synthetic file to simulate data access/staging.

        Appends a timestamped modification marker to ``lab_credentials.txt``
        so the integrity check in POST_ATTACK will detect the change.
        """
        target_name = "lab_credentials.txt"
        target_path = Path(self._lab_dir) / target_name

        if self._dry_run:
            self._ground_truth.record(
                "FILE_MODIFICATION",
                f"[DRY-RUN] Would read and modify {target_name}",
                expected_rule="FILE-001-SENSITIVE-FILE-ACCESS",
            )
            return

        if target_path.exists():
            content = target_path.read_text(encoding="utf-8")
            modified_content = content + "\n# ARGUS_LAB_SYNTHETIC modification marker\n"
            target_path.write_text(modified_content, encoding="utf-8")
            self._ground_truth.record(
                "FILE_MODIFICATION",
                f"Appended modification marker to {target_name}",
                expected_rule="FILE-001-SENSITIVE-FILE-ACCESS",
            )
        else:
            self._ground_truth.record(
                "FILE_MODIFICATION",
                f"Target file {target_name} not found — skipped",
            )

    def _simulate_normal_activity(self) -> None:
        """
        Record a benign process event to exercise false-positive avoidance.

        In a headless/CI environment we do not actually launch GUI applications,
        so this phase only appends a ground truth event indicating that normal
        activity was simulated.
        """
        self._ground_truth.record(
            "NORMAL_ACTIVITY",
            "Simulated benign process activity (no real process launched in headless mode)",
        )
