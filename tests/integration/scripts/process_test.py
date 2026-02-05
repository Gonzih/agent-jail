#!/usr/bin/env python3
"""
Process operations test script for agent-jail integration testing.
Spawns subprocesses to verify process tree event capture.
"""
import os
import sys
import subprocess
import time

def main():
    print("=== Python Process Test ===")
    print(f"Main PID: {os.getpid()}")
    print(f"Parent PID: {os.getppid()}")

    # Spawn a simple subprocess
    print("\n--- Subprocess: echo ---")
    result = subprocess.run(
        ["echo", "Hello from subprocess"],
        capture_output=True,
        text=True
    )
    print(f"  stdout: {result.stdout.strip()}")
    print(f"  returncode: {result.returncode}")

    # Spawn subprocess with shell
    print("\n--- Subprocess: shell command ---")
    result = subprocess.run(
        "echo $SHELL && pwd",
        shell=True,
        capture_output=True,
        text=True
    )
    print(f"  stdout: {result.stdout.strip()}")

    # Spawn multiple concurrent subprocesses
    print("\n--- Concurrent subprocesses ---")
    procs = []
    for i in range(3):
        p = subprocess.Popen(
            ["sleep", "0.1"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        procs.append(p)
        print(f"  Started sleep process {i}: PID={p.pid}")

    # Wait for all to complete
    for i, p in enumerate(procs):
        p.wait()
        print(f"  Process {i} (PID={p.pid}) exited with code {p.returncode}")

    # Environment variable passing
    print("\n--- Environment passing ---")
    result = subprocess.run(
        ["sh", "-c", "echo TEST_VAR=$TEST_VAR"],
        env={**os.environ, "TEST_VAR": "hello_world"},
        capture_output=True,
        text=True
    )
    print(f"  {result.stdout.strip()}")

    # Working directory change
    print("\n--- Working directory ---")
    result = subprocess.run(
        ["pwd"],
        cwd="/tmp",
        capture_output=True,
        text=True
    )
    print(f"  pwd in /tmp: {result.stdout.strip()}")

    # Chain of processes (pipeline simulation)
    print("\n--- Process chain ---")
    p1 = subprocess.Popen(
        ["echo", "line1\nline2\nline3"],
        stdout=subprocess.PIPE
    )
    p2 = subprocess.Popen(
        ["wc", "-l"],
        stdin=p1.stdout,
        stdout=subprocess.PIPE
    )
    p1.stdout.close()
    output = p2.communicate()[0]
    print(f"  wc -l output: {output.decode().strip()}")

    print("\n=== Process Test Complete ===")
    return 0

if __name__ == "__main__":
    sys.exit(main())
