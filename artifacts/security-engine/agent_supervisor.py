"""
ARGUS Endpoint Agent — Production Process Supervisor.

Manages the background execution, lifecycle, health monitoring, and recovery
of the ARGUS Endpoint Agent.

Commands:
    start       Start the agent as a background process
    stop        Gracefully stop the running agent process
    restart     Stop and restart the agent
    status      Report agent process and subsystem health
    run         Run supervisor in foreground (service mode with auto-restart)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import psutil

# Ensure imports from current directory work
ENGINE_DIR = Path(__file__).resolve().parent
if str(ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ENGINE_DIR))

from config import Config

# Determine runtime directory for PID and logs
def get_runtime_dir() -> Path:
    env_dir = os.getenv("ARGUS_DATA_DIR")
    if env_dir:
        p = Path(env_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p

    # Standard Windows ProgramData if available
    program_data = os.getenv("ProgramData", "C:\\ProgramData")
    candidate = Path(program_data) / "ARGUS"
    try:
        candidate.mkdir(parents=True, exist_ok=True)
        test_file = candidate / ".perm_check"
        test_file.write_text("ok", encoding="utf-8")
        test_file.unlink()
        return candidate
    except Exception:
        pass

    # Fallback to local workspace var/run directory
    workspace_dir = ENGINE_DIR.parent.parent / "var" / "argus"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    return workspace_dir


DATA_DIR = get_runtime_dir()
PID_FILE = DATA_DIR / "agent.pid"
LOG_DIR = DATA_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "argus-agent.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [supervisor] %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, encoding="utf-8", mode="a"),
    ],
)
logger = logging.getLogger("argus.supervisor")


def read_pid() -> int | None:
    if not PID_FILE.exists():
        return None
    try:
        raw = PID_FILE.read_text(encoding="utf-8").strip()
        if not raw:
            return None
        pid = int(raw)
        if psutil.pid_exists(pid):
            p = psutil.Process(pid)
            if p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
                return pid
        # Process not alive: clean stale pid file
        PID_FILE.unlink(missing_ok=True)
        return None
    except Exception:
        PID_FILE.unlink(missing_ok=True)
        return None


def write_pid(pid: int) -> None:
    PID_FILE.write_text(str(pid), encoding="utf-8")


def start_agent(foreground: bool = False) -> bool:
    existing_pid = read_pid()
    if existing_pid:
        logger.info("ARGUS Agent is already running (PID: %d)", existing_pid)
        return True

    python_exe = sys.executable
    main_script = ENGINE_DIR / "main.py"
    cmd = [python_exe, str(main_script), "--api", "--snapshot"]

    logger.info("Starting ARGUS Endpoint Agent...")
    logger.info("Command: %s", " ".join(cmd))
    logger.info("Log output: %s", LOG_FILE)

    if foreground:
        write_pid(os.getpid())
        try:
            import main
            main.main()
        finally:
            PID_FILE.unlink(missing_ok=True)
        return True

    creationflags = 0
    if sys.platform == "win32":
        # DETACHED_PROCESS = 0x00000008, CREATE_NEW_PROCESS_GROUP = 0x00000200
        creationflags = 0x00000008 | 0x00000200

    env = os.environ.copy()
    with open(LOG_FILE, "a", encoding="utf-8") as out:
        proc = subprocess.Popen(
            cmd,
            stdout=out,
            stderr=out,
            stdin=subprocess.DEVNULL,
            creationflags=creationflags,
            close_fds=True,
            cwd=str(ENGINE_DIR),
            env=env,
        )

    write_pid(proc.pid)
    logger.info("ARGUS Agent started with PID %d", proc.pid)

    # Verify startup liveness
    time.sleep(1.5)
    if proc.poll() is not None:
        logger.error("ARGUS Agent exited immediately with code %d. See %s", proc.returncode, LOG_FILE)
        PID_FILE.unlink(missing_ok=True)
        return False

    logger.info("ARGUS Agent background process running healthy (PID: %d)", proc.pid)
    return True


def stop_agent(timeout_sec: float = 10.0) -> bool:
    pid = read_pid()
    if not pid:
        logger.info("ARGUS Agent is not running.")
        PID_FILE.unlink(missing_ok=True)
        return True

    logger.info("Stopping ARGUS Agent (PID: %d)...", pid)
    try:
        proc = psutil.Process(pid)
        # Attempt graceful termination
        proc.terminate()
        gone, alive = psutil.wait_procs([proc], timeout=timeout_sec)
        if alive:
            logger.warning("Agent did not terminate within %s seconds; forcing kill...", timeout_sec)
            for p in alive:
                p.kill()
        logger.info("ARGUS Agent stopped cleanly.")
    except psutil.NoSuchProcess:
        logger.info("Process %d had already exited.", pid)
    except Exception as exc:
        logger.error("Error stopping agent PID %d: %s", pid, exc)
        return False
    finally:
        PID_FILE.unlink(missing_ok=True)
    return True


def restart_agent() -> bool:
    logger.info("Restarting ARGUS Agent...")
    stop_agent()
    time.sleep(1.0)
    return start_agent()


def status_agent() -> dict[str, Any]:
    pid = read_pid()
    is_running = pid is not None
    info: dict[str, Any] = {
        "running": is_running,
        "pid": pid,
        "pid_file": str(PID_FILE),
        "log_file": str(LOG_FILE),
        "api_base_url": Config.API_BASE_URL,
    }

    if is_running and pid:
        try:
            p = psutil.Process(pid)
            info["cpu_percent"] = p.cpu_percent(interval=0.1)
            info["memory_mb"] = round(p.memory_info().rss / (1024 * 1024), 2)
            info["uptime_seconds"] = round(time.time() - p.create_time(), 1)
            info["threads"] = p.num_threads()
            info["status"] = p.status()
        except Exception as exc:
            info["process_error"] = str(exc)

    # Query API server health if reachable
    try:
        import urllib.request
        url = f"{Config.API_BASE_URL}/api/agent/health"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            info["api_health"] = data
            info["agent_state"] = data.get("state", "UNKNOWN")
            info["protected"] = data.get("protected", False)
    except Exception as exc:
        info["api_reachable"] = False
        info["api_error"] = str(exc)
        info["agent_state"] = "RUNNING" if is_running else "STOPPED"

    return info


def run_supervisor() -> None:
    """Run supervisor in foreground with auto-restart supervision."""
    logger.info("Running ARGUS Agent Supervisor in service mode...")
    max_restarts = 5
    restart_window = 60.0
    restart_times: list[float] = []

    def handle_shutdown(sig: int, _frame: Any) -> None:
        logger.info("Supervisor received shutdown signal %d", sig)
        stop_agent()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_shutdown)
    signal.signal(signal.SIGTERM, handle_shutdown)

    while True:
        pid = read_pid()
        if not pid:
            now = time.time()
            restart_times = [t for t in restart_times if now - t < restart_window]
            if len(restart_times) >= max_restarts:
                logger.error(
                    "Agent restarted %d times within %ds. Halting supervisor to prevent spin.",
                    max_restarts,
                    int(restart_window),
                )
                sys.exit(1)

            restart_times.append(now)
            logger.info("Starting child agent process...")
            start_agent(foreground=False)

        time.sleep(3.0)


def main() -> None:
    parser = argparse.ArgumentParser(description="ARGUS Endpoint Agent Supervisor")
    parser.add_argument(
        "action",
        choices=["start", "stop", "restart", "status", "run"],
        default="status",
        nargs="?",
        help="Lifecycle action",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output status as JSON",
    )
    args = parser.parse_args()

    if args.action == "start":
        ok = start_agent()
        sys.exit(0 if ok else 1)
    elif args.action == "stop":
        ok = stop_agent()
        sys.exit(0 if ok else 1)
    elif args.action == "restart":
        ok = restart_agent()
        sys.exit(0 if ok else 1)
    elif args.action == "status":
        stat = status_agent()
        if args.json:
            print(json.dumps(stat, indent=2))
        else:
            state = stat.get("agent_state", "RUNNING" if stat["running"] else "STOPPED")
            print("=" * 60)
            print(f"ARGUS Endpoint Agent Status: [{state}]")
            print("=" * 60)
            print(f" Running:    {stat['running']}")
            if stat["running"]:
                print(f" Process ID: {stat.get('pid')}")
                print(f" Memory:     {stat.get('memory_mb', '—')} MB")
                print(f" Uptime:     {stat.get('uptime_seconds', '—')}s")
                print(f" Threads:    {stat.get('threads', '—')}")
            print(f" PID File:   {stat['pid_file']}")
            print(f" Log File:   {stat['log_file']}")
            print(f" API URL:    {stat['api_base_url']}")
            api_h = stat.get("api_health")
            if api_h:
                print(f" Protection: {'ACTIVE' if api_h.get('protected') else 'INACTIVE'}")
                print("\nSubsystems:")
                for sub, data in api_h.get("subsystems", {}).items():
                    s_state = data.get("state", "unknown").upper()
                    print(f"  • {sub:<20}: [{s_state}]")
            elif "api_error" in stat:
                print(f" API Server: Unavailable ({stat['api_error']})")
            print("=" * 60)
        sys.exit(0)
    elif args.action == "run":
        run_supervisor()


if __name__ == "__main__":
    main()
