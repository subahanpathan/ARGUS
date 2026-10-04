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

def get_target_url() -> str:
    if len(sys.argv) > 1 and sys.argv[1].strip():
        url = sys.argv[1].strip().rstrip("/")
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
    print("=" * 65)
    print("       ARGUS Real-Time Windows Endpoint Sensor")
    print("=" * 65)
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
    print("    Press Ctrl+C to terminate sensor.")
    print("-" * 65)

    # First CPU sample prime
    psutil.cpu_percent(interval=None)
    time.sleep(0.5)

    cycle = 0
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
                f"{proc_cnt:3d} Processes -> {status_text}"
            )
        except KeyboardInterrupt:
            print("\n[*] ARGUS sensor safely stopped.")
            break
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] [!] Connection retry: {e}")

        time.sleep(2.0)

if __name__ == "__main__":
    main()
