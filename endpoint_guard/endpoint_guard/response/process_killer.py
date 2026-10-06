import os
import subprocess
from typing import Optional, Tuple

import psutil

from ..config import Config


class ProcessKiller:
    """Terminates malicious process trees safely with critical system safeguards."""

    def __init__(self, config: Config):
        self.config = config

    def kill_process_tree(self, pid: Optional[int], proc_name: Optional[str] = None) -> Tuple[bool, str]:
        if not pid or pid <= 4:
            return False, f"Invalid PID {pid}"

        if pid == os.getpid():
            return False, "Cannot terminate Endpoint Guard process itself"

        # Safety check against critical Windows processes
        if proc_name and self.config.is_critical_process(proc_name):
            return False, f"Aborted: Process '{proc_name}' is a protected Windows critical system process"

        try:
            proc = psutil.Process(pid)
            name = proc.name()
            if self.config.is_critical_process(name):
                return False, f"Aborted: Detected critical system process '{name}'"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        if self.config.dry_run:
            msg = f"[DRY RUN] Would terminate PID {pid} ({proc_name})"
            print(f"[ProcessKiller] {msg}")
            return True, msg

        # Forceful tree termination via taskkill
        try:
            res = subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True,
                text=True,
                timeout=5
            )
            if res.returncode == 0:
                return True, f"Successfully terminated process tree for PID {pid} via taskkill"
        except Exception as e:
            print(f"[ProcessKiller] taskkill failed: {e}")

        # Fallback to psutil tree termination
        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            parent.kill()
            return True, f"Terminated PID {pid} and {len(children)} child processes via psutil"
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            return False, f"Process termination error: {e}"
