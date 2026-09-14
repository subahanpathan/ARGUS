"""Take a point-in-time snapshot of all running Windows processes."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import psutil

from .models import ProcessInfo, ProcessSnapshot

logger = logging.getLogger("argus.process_monitor.snapshot")


def _safe_creation_time(proc: psutil.Process) -> str | None:
    """Safely extract creation time from a process."""
    try:
        ct = proc.create_time()
        return datetime.fromtimestamp(ct, tz=timezone.utc).isoformat()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def _safe_cpu_percent(proc: psutil.Process) -> float | None:
    """Safely get CPU percent (may return 0.0 on first call)."""
    try:
        return proc.cpu_percent(interval=0)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def _safe_memory_info(proc: psutil.Process) -> tuple[int | None, float | None]:
    """Safely get memory bytes and percent."""
    mem_bytes: int | None = None
    mem_pct: float | None = None
    try:
        mi = proc.memory_info()
        mem_bytes = mi.rss
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
    try:
        mem_pct = proc.memory_percent()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass
    return mem_bytes, mem_pct


def _safe_command_line(proc: psutil.Process) -> str | None:
    """Safely extract the command line as a single string."""
    try:
        cmd = proc.cmdline()
        if not cmd:
            return None
        return " ".join(cmd)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None
    except OSError:
        return None


def _safe_username(proc: psutil.Process) -> str | None:
    """Safely get the process owner username."""
    try:
        return proc.username()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def _safe_status(proc: psutil.Process) -> str | None:
    """Safely get the process status string."""
    try:
        return proc.status()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def _collect_one(proc: psutil.Process) -> ProcessInfo:
    """Collect information for a single process, handling all access errors."""
    try:
        ppid = proc.ppid()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        ppid = None

    try:
        name = proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        name = f"<unknown-pid-{proc.pid}>"

    exe_path: str | None = None
    access_error: str | None = None
    try:
        exe_path = proc.exe()
    except psutil.AccessDenied:
        access_error = "AccessDenied"
    except psutil.NoSuchProcess:
        access_error = "NoSuchProcess"
    except psutil.ZombieProcess:
        access_error = "ZombieProcess"
    except OSError as e:
        access_error = f"OSerror:{e.errno}"

    parent_name: str | None = None
    if ppid is not None:
        try:
            parent = psutil.Process(ppid)
            parent_name = parent.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            parent_name = None

    creation_time = _safe_creation_time(proc)
    cpu_pct = _safe_cpu_percent(proc)
    mem_bytes, mem_pct = _safe_memory_info(proc)
    username = _safe_username(proc)
    status = _safe_status(proc)

    return ProcessInfo(
        pid=proc.pid,
        name=name,
        executable_path=exe_path,
        command_line=_safe_command_line(proc),
        parent_pid=ppid,
        parent_name=parent_name,
        creation_time=creation_time,
        cpu_percent=cpu_pct,
        memory_bytes=mem_bytes,
        memory_percent=mem_pct,
        username=username,
        status=status,
        access_error=access_error,
    )


def take_snapshot() -> ProcessSnapshot:
    """
    Enumerate all currently running Windows processes.

    Returns a ProcessSnapshot containing normalized process information.
    Handles AccessDenied, zombie processes, and race conditions gracefully.
    """
    processes: list[ProcessInfo] = []
    seen_pids: set[int] = set()

    for proc in psutil.process_iter(["pid"]):
        try:
            pid = proc.pid
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        if pid in seen_pids:
            continue
        seen_pids.add(pid)

        try:
            info = _collect_one(proc)
            processes.append(info)
        except psutil.NoSuchProcess:
            logger.debug("Process %d disappeared during collection", pid)
        except Exception as e:
            logger.warning("Unexpected error collecting PID %d: %s", pid, e)
            processes.append(ProcessInfo(
                pid=pid,
                name="<error-collecting>",
                access_error=str(e),
            ))

    logger.info("Snapshot collected: %d processes", len(processes))
    return ProcessSnapshot(processes=processes)
