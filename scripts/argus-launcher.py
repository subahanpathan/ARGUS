"""
ARGUS Launcher - native desktop app.

Bundles the Node.js API server + React dashboard + Python endpoint agent
into one .exe and shows the dashboard in a NATIVE WINDOWS APP WINDOW
(via pywebview / WebView2), not in the browser.

Flow:
  1. start the bundled API server on a free local port,
  2. start the bundled ARGUS endpoint agent (best effort),
  3. show the dashboard inside a desktop window with the ARGUS icon,
  4. when the window closes, shut the server and agent down.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

APP_NAME = "ARGUS Security Intelligence"
PORT = int(os.getenv("ARGUS_PORT", "5000"))
API_URL = f"http://localhost:{PORT}"

_server_proc = None
_agent_proc = None
_shutting_down = False


def base_dir() -> Path:
    """Directory containing runtime payload (one-dir bundle: next to exe)."""
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        if (exe_dir / "runtime" / "node.exe").exists():
            return exe_dir
        meipass = Path(getattr(sys, "_MEIPASS", exe_dir))
        return meipass
    return Path(__file__).resolve().parent


def data_dir() -> Path:
    root = Path(os.getenv("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "ARGUS"
    root.mkdir(parents=True, exist_ok=True)
    return root


def wait_until_healthy(timeout: float = 30.0) -> bool:
    import urllib.request

    deadline = time.time() + timeout
    while time.time() < deadline:
        if _server_proc and _server_proc.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(f"{API_URL}/api/healthz", timeout=2) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.4)
    return False


def find_free_port(preferred: int) -> int:
    import socket

    for port in range(preferred, preferred + 25):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return preferred


def icon_path():
    p = base_dir() / "argus.ico"
    if not p.exists():
        p = Path(__file__).resolve().parent / "icon" / "argus.ico"
    return p if p.exists() else None


def start_services():
    global _server_proc, _agent_proc

    payload = base_dir()
    node_exe = payload / "runtime" / "node.exe"
    server_js = payload / "api-server" / "index.mjs"
    agent_exe = payload / "engine" / "argus-agent.exe"

    if not node_exe.exists() or not server_js.exists():
        # Fallback for source runs
        node_exe = Path(os.getenv("ARGUS_NODE", "node.exe"))
        server_js = Path(os.getenv("ARGUS_SERVER_JS", "index.mjs"))
        if not node_exe.exists() or not server_js.exists():
            print(f"[ARGUS] Missing runtime payload. Expected {node_exe} and {server_js}")
            return False

    log_path = data_dir() / "argus-launcher.log"

    env = os.environ.copy()
    env["PORT"] = str(PORT)
    env["NODE_ENV"] = "production"
    env["ARGUS_DATA_DIR"] = str(data_dir())

    print(f"[ARGUS] Starting API server on port {PORT}...")
    log = open(log_path, "a", encoding="utf-8")
    _server_proc = subprocess.Popen(
        [str(node_exe), "--enable-source-maps", str(server_js)],
        stdout=log,
        stderr=log,
        stdin=subprocess.DEVNULL,
        cwd=str(server_js.parent),
        env=env,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )

    if not wait_until_healthy():
        print(f"[ARGUS] API server failed to start on port {PORT}. See {log_path}")
        return False

    print(f"[ARGUS] Server ready at {API_URL}")

    # Start endpoint agent (best effort). The frozen agent bundles main.py:
    # --api --snapshot runs the full telemetry agent in-process.
    if agent_exe.exists():
        try:
            _agent_proc = subprocess.Popen(
                [str(agent_exe), "--api", "--snapshot"],
                stdout=log,
                stderr=log,
                stdin=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP,
            )
            print("[ARGUS] Endpoint agent started.")
        except Exception as exc:  # non-fatal
            print(f"[ARGUS] Endpoint agent failed to start: {exc}")
    return True


def stop_services():
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
    deadline = time.time() + 5
    while time.time() < deadline:
        alive = [p for p in (_agent_proc, _server_proc) if p and p.poll() is None]
        if not alive:
            break
        time.sleep(0.3)
    for proc in (_agent_proc, _server_proc):
        if proc and proc.poll() is None:
            try:
                proc.kill()
            except Exception:
                pass


def on_closed():
    """pywebview close handler - clean shutdown of background services."""
    stop_services()


def run_window():
    import webview  # pywebview

    window = webview.create_window(
        APP_NAME,
        API_URL,
        width=1440,
        height=900,
        min_size=(1100, 700),
        background_color="#05080e",
    )
    window.events.closed += on_closed
    # Blocks until the window is closed; services are shut down afterwards.
    webview.start(icon=str(icon_path()) if icon_path() else None)


def main() -> int:
    global PORT, API_URL

    PORT = find_free_port(PORT)
    API_URL = f"http://localhost:{PORT}"

    if not start_services():
        # Headless fallback so the user still sees something actionable.
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(
                0,
                "ARGUS failed to start its background service.\n\n"
                f"Check the log at:\n{data_dir() / 'argus-launcher.log'}",
                APP_NAME,
                0x10,  # MB_ICONERROR
            )
        except Exception:
            pass
        return 1

    try:
        run_window()
    except Exception as exc:
        print(f"[ARGUS] Window error: {exc}")
        stop_services()
        return 1
    finally:
        stop_services()
    return 0


if __name__ == "__main__":
    sys.exit(main())
