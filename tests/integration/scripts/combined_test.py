#!/usr/bin/env python3
"""
Combined test script that exercises filesystem, network, and process operations.
This simulates a realistic agent workload.
"""
import os
import sys
import json
import subprocess
import tempfile
import time

# Try to use requests
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    import urllib.request

def main():
    print("=== Combined Agent Simulation ===")
    print(f"PID: {os.getpid()}")
    start_time = time.time()

    # Phase 1: Set up working directory
    print("\n[Phase 1] Setting up workspace...")
    workspace = tempfile.mkdtemp(prefix="agent_workspace_")
    print(f"  Workspace: {workspace}")

    # Phase 2: Download some data (network)
    print("\n[Phase 2] Fetching external data...")
    try:
        if HAS_REQUESTS:
            resp = requests.get("https://httpbin.org/json", timeout=10)
            data = resp.json()
        else:
            with urllib.request.urlopen("https://httpbin.org/json", timeout=10) as resp:
                data = json.loads(resp.read().decode())
        print(f"  Fetched JSON with {len(data)} keys")
    except Exception as e:
        print(f"  Network fetch failed: {e}")
        data = {"fallback": True, "reason": str(e)}

    # Phase 3: Write data to file (filesystem)
    print("\n[Phase 3] Saving data to disk...")
    data_file = os.path.join(workspace, "fetched_data.json")
    with open(data_file, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"  Saved to: {data_file}")

    # Phase 4: Process data with subprocess (process)
    print("\n[Phase 4] Processing data...")
    result = subprocess.run(
        ["wc", "-c", data_file],
        capture_output=True,
        text=True
    )
    byte_count = result.stdout.split()[0]
    print(f"  File size: {byte_count} bytes")

    # Phase 5: Create analysis output
    print("\n[Phase 5] Generating analysis...")
    analysis = {
        "timestamp": time.time(),
        "workspace": workspace,
        "data_file": data_file,
        "file_size_bytes": int(byte_count),
        "network_success": "fallback" not in data,
        "duration_ms": (time.time() - start_time) * 1000
    }
    analysis_file = os.path.join(workspace, "analysis.json")
    with open(analysis_file, 'w') as f:
        json.dump(analysis, f, indent=2)
    print(f"  Analysis saved to: {analysis_file}")

    # Phase 6: Run a subprocess that does its own file I/O
    print("\n[Phase 6] Running nested subprocess...")
    script = f'''
import json
with open("{analysis_file}") as f:
    data = json.load(f)
print(f"Nested process read {{len(data)}} analysis fields")
with open("{os.path.join(workspace, 'nested_output.txt')}", 'w') as f:
    f.write("Output from nested process\\n")
'''
    result = subprocess.run(
        ["python3", "-c", script],
        capture_output=True,
        text=True
    )
    print(f"  {result.stdout.strip()}")

    # Verify nested output exists
    nested_output = os.path.join(workspace, "nested_output.txt")
    if os.path.exists(nested_output):
        print(f"  Nested output file created: {nested_output}")

    # Phase 7: Cleanup
    print("\n[Phase 7] Cleanup...")
    for f in os.listdir(workspace):
        os.remove(os.path.join(workspace, f))
    os.rmdir(workspace)
    print(f"  Removed workspace: {workspace}")

    total_time = (time.time() - start_time) * 1000
    print(f"\n=== Combined Test Complete ({total_time:.0f}ms) ===")
    return 0

if __name__ == "__main__":
    sys.exit(main())
