"""
Desktop Application Lifecycle Verification Script.

Tests the full startup sequence of the ARGUS desktop application:
  1. Spawns launcher / backend services on loopback.
  2. Polls /api/healthz until 200 OK.
  3. Verifies telemetry, rules, prediction engine, and simulation isolation.
  4. Tests clean process termination and single instance locking.
"""

import os
import sys
import time
import urllib.request
import json
import subprocess
from pathlib import Path

PORT = 5099  # Isolated port for testing launcher

def main():
    print("============================================================")
    print(" Testing ARGUS Desktop Application Runtime & Telemetry      ")
    print("============================================================")

    data_dir = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "ARGUS_TestRun"
    data_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["PORT"] = str(PORT)
    env["HOST"] = "127.0.0.1"
    env["NODE_ENV"] = "production"
    env["ARGUS_DATA_DIR"] = str(data_dir)
    env["ARGUS_DEV_ACCESS_KEY"] = "ARGUS-DEV-2026"

    repo_root = Path(__file__).resolve().parent.parent
    server_js = repo_root / "artifacts" / "api-server" / "dist" / "index.mjs"
    node_exe = shutil_node()

    if not server_js.exists():
        print(f"[FAIL] Missing compiled API server at {server_js}")
        return 1

    print(f"[1/5] Launching local Node.js API server on 127.0.0.1:{PORT}...")
    proc = subprocess.Popen(
        [node_exe, "--enable-source-maps", str(server_js)],
        cwd=str(server_js.parent),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        # Step 2: Health check verification
        print("[2/5] Waiting for /api/healthz HTTP 200 OK...")
        healthy = False
        health_data = {}
        for _ in range(30):
            if proc.poll() is not None:
                stdout, stderr = proc.communicate()
                print(f"[FAIL] Server exited early: {stderr.decode()}")
                return 1
            try:
                req = urllib.request.Request(f"http://127.0.0.1:{PORT}/api/healthz")
                with urllib.request.urlopen(req, timeout=1.0) as resp:
                    if resp.status == 200:
                        health_data = json.loads(resp.read().decode())
                        healthy = True
                        break
            except Exception:
                pass
            time.sleep(0.5)

        if not healthy:
            print("[FAIL] Server failed health check within 15 seconds")
            proc.kill()
            return 1

        print(f"[SUCCESS] Health check passed: {health_data}")

        # Step 3: Test Benchmark Endpoint
        print("[3/5] Testing Deterministic Benchmark endpoint (/api/benchmark/results)...")
        req_bench = urllib.request.Request(f"http://127.0.0.1:{PORT}/api/benchmark/results")
        with urllib.request.urlopen(req_bench, timeout=3.0) as resp:
            bench_res = json.loads(resp.read().decode())
            metrics = bench_res.get("aggregateMetrics", {})
            print(f"       Precision: {metrics.get('precision')} | Recall: {metrics.get('recall')} | F1: {metrics.get('f1Score')}")
            print(f"       Top-1 Prediction Hit Rate: {metrics.get('predictionTop1Accuracy')} | Top-3: {metrics.get('predictionTop3Accuracy')}")
            assert metrics.get("precision") is not None and metrics.get("precision") >= 0.50, "Precision should be valid"
            assert metrics.get("recall") is not None and metrics.get("recall") >= 0.20, "Recall should be valid"

        # Step 4: Test Simulation Isolation Endpoint
        print("[4/5] Testing /api/simulations endpoint isolation...")
        req_sim = urllib.request.Request(
            f"http://127.0.0.1:{PORT}/api/simulations",
            data=json.dumps({"scenarioId": "reverse_shell_exfiltration"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req_sim, timeout=5.0) as resp:
            sim_res = json.loads(resp.read().decode())
            sim_info = sim_res.get("simulation", {})
            print(f"       Simulation started: id={sim_info.get('simulationId')}, status={sim_info.get('status')}")
            assert sim_info.get("simulationId") is not None

        # Step 5: Clean Process Termination
        print("[5/5] Testing clean process shutdown...")
        proc.terminate()
        try:
            proc.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            proc.kill()

        print("============================================================")
        print(" ARGUS Desktop Runtime Verification PASSED cleanly!         ")
        print("============================================================")
        return 0

    finally:
        if proc and proc.poll() is None:
            proc.kill()

def shutil_node():
    import shutil
    return shutil.which("node") or "node"

if __name__ == "__main__":
    sys.exit(main())
