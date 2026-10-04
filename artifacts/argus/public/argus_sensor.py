#!/usr/bin/env python3
"""
ARGUS Lightweight Endpoint Sensor
=================================
Self-contained Python sensor that streams live Windows (or macOS/Linux)
hardware vitals, resource utilization, and running process snapshots
to any ARGUS Security Intelligence dashboard (local or remote/Vercel).
"""

import sys
import time
import os
import platform
import subprocess
import json
import traceback

# Ensure dependencies are available
def ensure_packages():
    missing = []
    for pkg in ["psutil", "requests"]:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"[*] Installing required libraries ({', '.join(missing)})...")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "-q", *missing],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            print("[+] Libraries installed successfully.")
        except Exception as e:
            print(f"[!] Warning: pip install failed: {e}. Trying to proceed...")

ensure_packages()

import psutil
import requests

def get_sensor_dir() -> str:
    if platform.system() == "Windows":
        app_data = os.environ.get("APPDATA") or os.path.expanduser("~\\AppData\\Roaming")
        d = os.path.join(app_data, "Argus")
    else:
        d = os.path.expanduser("~/.argus")
    os.makedirs(d, exist_ok=True)
    return d

def get_pid_file() -> str:
    return os.path.join(get_sensor_dir(), "sensor.pid")

def get_log_file() -> str:
    return os.path.join(get_sensor_dir(), "sensor.log")

def log_uncaught_exception(exctype, value, tb):
    try:
        with open(get_log_file(), "a", encoding="utf-8") as f:
            f.write("\n" + "=" * 50 + "\nCRITICAL UNCAUGHT EXCEPTION:\n")
            traceback.print_exception(exctype, value, tb, file=f)
            f.write("=" * 50 + "\n")
            f.flush()
    except Exception:
        pass

sys.excepthook = log_uncaught_exception

def stop_sensor():
    pid_file = get_pid_file()
    if not os.path.exists(pid_file):
        print("[!] No active ARGUS sensor PID found.")
        return
    try:
        with open(pid_file, "r") as f:
            pid = int(f.read().strip())
        if psutil.pid_exists(pid):
            p = psutil.Process(pid)
            p.terminate()
            try:
                p.wait(timeout=3)
            except Exception:
                p.kill()
            print(f"[+] ARGUS sensor (PID {pid}) stopped successfully.")
        else:
            print(f"[*] Sensor process (PID {pid}) is already stopped.")
    except Exception as e:
        print(f"[!] Error stopping sensor: {e}")
    finally:
        if os.path.exists(pid_file):
            try:
                os.remove(pid_file)
            except Exception:
                pass

def check_sensor_status():
    pid_file = get_pid_file()
    if not os.path.exists(pid_file):
        print("[-] ARGUS sensor is NOT running (no PID file).")
        return
    try:
        with open(pid_file, "r") as f:
            pid = int(f.read().strip())
        if psutil.pid_exists(pid):
            p = psutil.Process(pid)
            print("[+] ARGUS sensor is RUNNING silently in background.")
            print(f"    PID        : {pid}")
            try:
                print(f"    CPU %      : {p.cpu_percent(interval=0.1):.1f}%")
                print(f"    Memory RSS : {p.memory_info().rss / (1024*1024):.1f} MB")
            except Exception:
                pass
            print(f"    Log File   : {get_log_file()}")
        else:
            print(f"[-] Stale PID file found (PID {pid} is no longer running).")
            os.remove(pid_file)
    except Exception as e:
        print(f"[!] Error checking sensor status: {e}")

def get_target_url() -> str:
    for arg in sys.argv[1:]:
        arg_clean = arg.strip()
        if arg_clean.startswith("-"):
            continue
        if arg_clean.startswith("http://") or arg_clean.startswith("https://") or ":" in arg_clean or "vercel.app" in arg_clean or "localhost" in arg_clean:
            url = arg_clean.rstrip("/")
            if not url.startswith("http://") and not url.startswith("https://"):
                url = f"http://{url}"
            return url
    env_url = os.environ.get("ARGUS_API_BASE_URL", "").strip().rstrip("/")
    if env_url:
        return env_url
    return "http://localhost:5000"

TARGET_URL = get_target_url()
BOOT_TIME = psutil.boot_time()

def sample_system_telemetry():
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    
    # CPU
    cpu_percent = psutil.cpu_percent(interval=None)
    cpu_count = psutil.cpu_count(logical=True)
    cpu_phys = psutil.cpu_count(logical=False) or cpu_count

    # Memory
    mem = psutil.virtual_memory()

    # Disk
    disk_path = "C:\\" if platform.system() == "Windows" else "/"
    try:
        disk = psutil.disk_usage(disk_path)
    except Exception:
        disk = None

    # Network interfaces
    ifaces = []
    try:
        net_io = psutil.net_io_counters(pernic=True)
        net_addrs = psutil.net_if_addrs()
        for name, io in net_io.items():
            addrs = [a.address for a in net_addrs.get(name, []) if a.family.name in ("AF_INET", "AF_INET6")]
            ifaces.append({
                "name": name,
                "is_up": True,
                "bytes_sent": io.bytes_sent,
                "bytes_recv": io.bytes_recv,
                "addresses": addrs,
            })
    except Exception:
        pass

    telemetry = {
        "timestamp": now_iso,
        "source": "windows_system_monitor",
        "observed": True,
        "cpu": {
            "percent": cpu_percent,
            "count": cpu_count,
            "physical_count": cpu_phys,
        },
        "memory": {
            "total_bytes": mem.total,
            "available_bytes": mem.available,
            "used_bytes": mem.used,
            "percent": mem.percent,
        },
        "disk": {
            "mount": disk_path,
            "total_bytes": disk.total if disk else 0,
            "used_bytes": disk.used if disk else 0,
            "free_bytes": disk.free if disk else 0,
            "percent": disk.percent if disk else 0,
        },
        "processes": {
            "running": len(psutil.pids()),
        },
        "system": {
            "uptime_seconds": int(time.time() - BOOT_TIME),
            "boot_time": BOOT_TIME,
        },
        "network": {
            "interfaces": ifaces,
            "active_count": len([i for i in ifaces if (i.get("bytes_sent", 0) + i.get("bytes_recv", 0)) > 0]),
            "total_count": len(ifaces),
        },
    }
    return telemetry

def sample_process_snapshot():
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    processes = []
    access_denied = 0

    attrs = ["pid", "name", "ppid", "username", "cpu_percent", "memory_info", "status", "create_time", "exe"]
    for p in psutil.process_iter(attrs, ad_value=None):
        try:
            info = p.info
            mem_bytes = info["memory_info"].rss if info.get("memory_info") else 0
            processes.append({
                "pid": info["pid"],
                "name": info["name"] or "unknown",
                "executable_path": info["exe"] or None,
                "parent_pid": info["ppid"] or None,
                "creation_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(info["create_time"])) if info.get("create_time") else None,
                "cpu_percent": info.get("cpu_percent") or 0.0,
                "memory_bytes": mem_bytes,
                "username": info.get("username") or None,
                "status": info.get("status") or "running",
            })
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
        except psutil.AccessDenied:
            access_denied += 1
            processes.append({
                "pid": p.pid,
                "name": "protected_process",
                "access_error": "AccessDenied",
            })

    return {
        "timestamp": now_iso,
        "total_count": len(processes),
        "access_denied_count": access_denied,
        "processes": processes,
    }

def main():
    if "--stop" in sys.argv:
        stop_sensor()
        return

    if "--status" in sys.argv:
        check_sensor_status()
        return

    is_daemon = "--daemon" in sys.argv or "--background" in sys.argv or "pythonw" in os.path.basename(sys.executable).lower()

    if is_daemon:
        try:
            log_fp = open(get_log_file(), "a", encoding="utf-8", buffering=1)
            sys.stdout = log_fp
            sys.stderr = log_fp
        except Exception as e:
            pass

    # Save active PID
    pid_file = get_pid_file()
    try:
        with open(pid_file, "w") as f:
            f.write(str(os.getpid()))
    except Exception:
        pass

    print("=" * 65)
    print("       ARGUS Real-Time Windows Endpoint Sensor")
    print("=" * 65)
    print(f"[*] PID              : {os.getpid()}")
    print(f"[*] Mode             : {'Silent Background Daemon' if is_daemon else 'Interactive Console'}")
    print(f"[*] Dashboard Target : {TARGET_URL}")
    print(f"[*] Host OS          : {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"[*] Hostname         : {platform.node()}")
    print("[*] Sampling cadence : every 2.0 seconds")
    print("-" * 65)
    print("[*] Testing connection to ARGUS server...")

    session = requests.Session()
    # Initial ping
    try:
        r = session.get(f"{TARGET_URL}/healthz", timeout=4)
        print(f"[+] Server acknowledged connection (HTTP {r.status_code})")
    except Exception as e:
        print(f"[!] Note: Server ping responded with: {e}")
        print(f"[!] Will continue streaming directly to {TARGET_URL}/api/system/telemetry")

    print("[+] Sensor operational! Streaming live host vitals and processes...")
    if not is_daemon:
        print("    Press Ctrl+C to terminate sensor.")
    print("-" * 65)

    # First CPU sample prime
    psutil.cpu_percent(interval=None)
    time.sleep(0.5)

    cycle = 0
    try:
        while True:
            cycle += 1
            try:
                # 1. System telemetry
                telem = sample_system_telemetry()
                res_telem = session.post(
                    f"{TARGET_URL}/api/system/telemetry",
                    json=telem,
                    timeout=4,
                    headers={"Content-Type": "application/json"}
                )

                # 2. Process snapshot every 3 cycles (6s) or initial cycle
                if cycle == 1 or cycle % 3 == 0:
                    snap = sample_process_snapshot()
                    session.post(
                        f"{TARGET_URL}/api/processes",
                        json=snap,
                        timeout=6,
                        headers={"Content-Type": "application/json"}
                    )

                cpu_val = telem["cpu"]["percent"]
                mem_val = telem["memory"]["percent"]
                mem_gb = telem["memory"]["used_bytes"] / (1024 ** 3)
                proc_cnt = telem["processes"]["running"]

                status_code = res_telem.status_code
                status_text = "STREAMING OK" if status_code in (200, 201) else f"HTTP {status_code}"

                print(
                    f"[{time.strftime('%H:%M:%S')}] CPU: {cpu_val:4.1f}% | "
                    f"RAM: {mem_val:4.1f}% ({mem_gb:4.1f} GB) | "
                    f"{proc_cnt:3d} Processes -> {status_text}",
                    flush=True
                )
            except Exception as e:
                print(f"[{time.strftime('%H:%M:%S')}] [!] Connection retry: {e}", flush=True)

            time.sleep(2.0)
    except KeyboardInterrupt:
        print("\n[*] ARGUS sensor safely stopped.", flush=True)
    finally:
        if os.path.exists(pid_file):
            try:
                with open(pid_file, "r") as f:
                    saved_pid = int(f.read().strip())
                if saved_pid == os.getpid():
                    os.remove(pid_file)
            except Exception:
                pass

if __name__ == "__main__":
    main()
