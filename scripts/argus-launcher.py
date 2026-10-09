"""
ARGUS Launcher — Native Desktop Application Shell.

Bundles the Node.js API server + React dashboard + Python Security Engine
into a native Windows desktop experience (via pywebview / WebView2).

Controlled startup sequence:
  1. Validate installed files and dependencies.
  2. Single-instance enforcement (bring existing window to front).
  3. Start local API server on a dedicated loopback port.
  4. Wait for API server readiness via health check.
  5. Start Security Engine (passing exact API URL and data directory).
  6. Open native desktop window (pywebview with ARGUS icon).
  7. On window close, cleanly terminate all child processes.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

APP_NAME = "ARGUS Security Intelligence"
DEFAULT_PORT = int(os.getenv("ARGUS_PORT", "5000"))
PORT = DEFAULT_PORT
API_URL = f"http://127.0.0.1:{PORT}"

_server_proc: subprocess.Popen | None = None
_agent_proc: subprocess.Popen | None = None
_shutting_down = False
_mutex = None


def data_dir() -> Path:
    """Persistent application data directory for logs, local database, and state."""
    root = Path(os.getenv("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "ARGUS"
    root.mkdir(parents=True, exist_ok=True)
    return root


def show_error(title: str, message: str) -> None:
    """Display a native Windows error dialog."""
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, message, title, 0x10)  # MB_ICONERROR
    except Exception:
        print(f"[{title}] {message}", file=sys.stderr)


def check_single_instance() -> bool:
    """Ensure only one instance runs. If another exists, bring its window to front."""
    global _mutex
    try:
        import ctypes

        MUTEX_NAME = "Local\\ARGUS_Security_Intelligence_App_Mutex"
        _mutex = ctypes.windll.kernel32.CreateMutexW(None, True, MUTEX_NAME)
        if ctypes.windll.kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
            user32 = ctypes.windll.user32
            hwnd = user32.FindWindowW(None, APP_NAME)
            if hwnd:
                user32.ShowWindow(hwnd, 9)  # SW_RESTORE
                user32.SetForegroundWindow(hwnd)
            return False
        return True
    except Exception:
        return True


def base_dir() -> Path:
    """Locate the root directory containing runtime payload."""
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        # 1. Next to exe in installed location ({app}\api-server)
        if (exe_dir / "api-server" / "index.mjs").exists():
            return exe_dir
        # 2. PyInstaller _MEIPASS extraction directory
        meipass = Path(getattr(sys, "_MEIPASS", exe_dir))
        if (meipass / "api-server" / "index.mjs").exists():
            return meipass
        return exe_dir

    # Source or script mode
    here = Path(__file__).resolve().parent
    repo_root = here.parent
    dist_app = repo_root / "dist" / "app"
    if (dist_app / "api-server" / "index.mjs").exists():
        return dist_app
    return here


def resolve_components() -> tuple[Path | None, Path | None, Path | None]:
    """Resolve paths to node.exe, index.mjs, and argus-agent.exe."""
    payload = base_dir()

    # 1. Node runtime
    node_exe: Path | None = payload / "runtime" / "node.exe"
    if not node_exe.exists():
        import shutil
        system_node = shutil.which("node")
        if system_node:
            node_exe = Path(system_node)
        elif Path("D:/node.exe").exists():
            node_exe = Path("D:/node.exe")
        else:
            node_exe = None

    # 2. API Server bundle
    server_js: Path | None = payload / "api-server" / "index.mjs"
    if not server_js.exists():
        repo_root = Path(__file__).resolve().parent.parent if not getattr(sys, "frozen", False) else None
        if repo_root:
            dev_server = repo_root / "artifacts" / "api-server" / "dist" / "index.mjs"
            if dev_server.exists():
                server_js = dev_server
            else:
                server_js = None
        else:
            server_js = None

    # 3. Security Engine executable
    agent_exe: Path | None = payload / "engine" / "argus-agent.exe"
    if not agent_exe.exists():
        repo_root = Path(__file__).resolve().parent.parent if not getattr(sys, "frozen", False) else None
        if repo_root:
            dev_agent = repo_root / "artifacts" / "security-engine" / "dist" / "argus-agent.exe"
            if dev_agent.exists():
                agent_exe = dev_agent
            else:
                agent_exe = None
        else:
            agent_exe = None

    return node_exe, server_js, agent_exe


def find_free_port(preferred: int) -> int:
    """Find a free TCP port starting from the preferred port on 127.0.0.1."""
    import socket

    for port in range(preferred, preferred + 25):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return preferred


def wait_until_healthy(timeout: float = 30.0) -> bool:
    """Poll backend health check until it responds 200 OK."""
    import urllib.request

    deadline = time.time() + timeout
    while time.time() < deadline:
        if _server_proc and _server_proc.poll() is not None:
            return False
        for url in (f"http://127.0.0.1:{PORT}/api/healthz", f"http://localhost:{PORT}/api/healthz"):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "ARGUS-Launcher"})
                with urllib.request.urlopen(req, timeout=1.5) as resp:
                    if resp.status == 200:
                        return True
            except Exception:
                pass
        time.sleep(0.3)
    return False


def icon_path() -> Path | None:
    """Locate argus.ico icon."""
    p = base_dir() / "argus.ico"
    if p.exists():
        return p
    here = Path(__file__).resolve().parent
    candidates = [
        here / "icon" / "argus.ico",
        here.parent / "scripts" / "icon" / "argus.ico",
        base_dir() / "icon" / "argus.ico",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def start_services() -> bool:
    """Validate files, start API server, wait for readiness, and launch Security Engine."""
    global _server_proc, _agent_proc

    node_exe, server_js, agent_exe = resolve_components()
    log_path = data_dir() / "argus-launcher.log"

    # Step 1: Validate installed files
    if not node_exe or not node_exe.exists():
        show_error(
            "ARGUS Runtime Missing",
            f"Could not locate the Node.js runtime executable.\n\n"
            f"Expected at:\n{base_dir() / 'runtime' / 'node.exe'}\n\n"
            "Please reinstall the ARGUS desktop application."
        )
        return False

    if not server_js or not server_js.exists():
        show_error(
            "ARGUS Application Bundle Missing",
            f"Could not locate the ARGUS API server bundle.\n\n"
            f"Expected at:\n{base_dir() / 'api-server' / 'index.mjs'}\n\n"
            "Please reinstall the ARGUS desktop application."
        )
        return False

    with open(log_path, "a", encoding="utf-8") as log:
        log.write(f"\n=======================================================\n")
        log.write(f"  ARGUS Desktop Session: {time.ctime()}\n")
        log.write(f"  Port: {PORT}\n")
        log.write(f"  Node: {node_exe}\n")
        log.write(f"  Server: {server_js}\n")
        log.write(f"  Engine: {agent_exe}\n")
        log.write(f"=======================================================\n")

    # Step 2: Start API Server
    env = os.environ.copy()
    env["PORT"] = str(PORT)
    env["NODE_ENV"] = "production"
    env["ARGUS_DATA_DIR"] = str(data_dir())

    log_file = open(log_path, "a", encoding="utf-8")
    _server_proc = subprocess.Popen(
        [str(node_exe), "--enable-source-maps", str(server_js)],
        stdout=log_file,
        stderr=log_file,
        stdin=subprocess.DEVNULL,
        cwd=str(server_js.parent),
        env=env,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )

    # Step 3: Wait for backend readiness
    if not wait_until_healthy(timeout=25.0):
        show_error(
            "ARGUS Backend Initialization Failed",
            f"The local ARGUS API server failed to become ready on port {PORT}.\n\n"
            f"Diagnostic log:\n{log_path}"
        )
        stop_services()
        return False

    # Step 4 & 5: Start Security Engine
    if agent_exe and agent_exe.exists():
        try:
            agent_env = os.environ.copy()
            agent_env["ARGUS_API_BASE_URL"] = f"http://127.0.0.1:{PORT}"
            agent_env["ARGUS_DATA_DIR"] = str(data_dir())
            agent_env["PROCESS_POLL_INTERVAL_MS"] = "2000"
            agent_env["TELEMETRY_INTERVAL_MS"] = "1000"
            _agent_proc = subprocess.Popen(
                [str(agent_exe), "--api", "--snapshot"],
                stdout=log_file,
                stderr=log_file,
                stdin=subprocess.DEVNULL,
                cwd=str(agent_exe.parent),
                env=agent_env,
                creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP,
            )
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"[ARGUS] Security Engine started successfully (PID: {_agent_proc.pid})\n")
        except Exception as exc:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"[ARGUS] Security Engine failed to start: {exc}\n")
    else:
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"[ARGUS] Security Engine binary not found. Running with engine OFFLINE.\n")

    return True


def stop_services() -> None:
    """Cleanly shut down all child processes (engine and server)."""
    global _shutting_down
    if _shutting_down:
        return
    _shutting_down = True

    for proc in (_agent_proc, _server_proc):
        if proc and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass

    deadline = time.time() + 4.0
    while time.time() < deadline:
        alive = [p for p in (_agent_proc, _server_proc) if p and p.poll() is None]
        if not alive:
            break
        time.sleep(0.2)

    for proc in (_agent_proc, _server_proc):
        if proc and proc.poll() is None:
            try:
                proc.kill()
            except Exception:
                pass


def on_closed() -> None:
    """Callback triggered when the native window is closed."""
    stop_services()


def get_screen_size() -> tuple[int, int]:
    """Retrieve screen dimensions with DPI awareness for laptop compatibility."""
    try:
        import ctypes
        user32 = ctypes.windll.user32
        user32.SetProcessDPIAware()
        w = user32.GetSystemMetrics(0)
        h = user32.GetSystemMetrics(1)
        if w > 0 and h > 0:
            return w, h
    except Exception:
        pass
    return 1366, 768


def run_window() -> None:
    """Open the native WebView2 desktop window with adaptive laptop sizing."""
    import webview

    url = f"http://127.0.0.1:{PORT}"
    ico = icon_path()

    screen_w, screen_h = get_screen_size()
    # Choose dimensions that fit within standard laptop displays (1366x768 up to 4K)
    win_w = min(1366, max(960, int(screen_w * 0.88)))
    win_h = min(840, max(560, int(screen_h * 0.85)))
    min_w = min(960, int(screen_w * 0.70))
    min_h = min(540, int(screen_h * 0.70))

    window = webview.create_window(
        APP_NAME,
        url,
        width=win_w,
        height=win_h,
        min_size=(min_w, min_h),
        background_color="#05080e",
    )
    window.events.closed += on_closed
    webview.start(icon=str(ico) if ico else None)


def main() -> int:
    global PORT, API_URL

    # Prevent duplicate instances
    if not check_single_instance():
        return 0

    PORT = find_free_port(DEFAULT_PORT)
    API_URL = f"http://127.0.0.1:{PORT}"

    if not start_services():
        return 1

    try:
        run_window()
    except Exception as exc:
        log_path = data_dir() / "argus-launcher.log"
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"[ARGUS] Window error: {exc}\n")
        # Fallback to default browser if WebView2 window fails
        try:
            import webbrowser
            webbrowser.open(API_URL)
            # Keep process alive so background services keep running
            while _server_proc and _server_proc.poll() is None:
                time.sleep(1)
        except Exception:
            pass
        finally:
            stop_services()
        return 1
    finally:
        stop_services()

    return 0


if __name__ == "__main__":
    sys.exit(main())
