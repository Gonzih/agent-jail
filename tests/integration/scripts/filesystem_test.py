#!/usr/bin/env python3
"""
Filesystem operations test script for agent-jail integration testing.
Creates, reads, modifies, and deletes files to verify filesystem event capture.
"""
import os
import sys
import tempfile
import json

def main():
    print("=== Python Filesystem Test ===")

    # Create a temp directory
    test_dir = tempfile.mkdtemp(prefix="jail_test_")
    print(f"Created temp dir: {test_dir}")

    # Create a file
    test_file = os.path.join(test_dir, "test_file.txt")
    with open(test_file, 'w') as f:
        f.write("Hello from Python!\n")
    print(f"Created file: {test_file}")

    # Read the file
    with open(test_file, 'r') as f:
        content = f.read()
    print(f"Read content: {content.strip()}")

    # Append to file
    with open(test_file, 'a') as f:
        f.write("Second line\n")
    print("Appended to file")

    # Create a subdirectory
    sub_dir = os.path.join(test_dir, "subdir")
    os.makedirs(sub_dir)
    print(f"Created subdir: {sub_dir}")

    # Create file in subdirectory
    nested_file = os.path.join(sub_dir, "nested.json")
    with open(nested_file, 'w') as f:
        json.dump({"status": "success", "nested": True}, f)
    print(f"Created nested file: {nested_file}")

    # List directory
    files = os.listdir(test_dir)
    print(f"Directory contents: {files}")

    # Delete files
    os.remove(nested_file)
    print(f"Deleted: {nested_file}")

    os.rmdir(sub_dir)
    print(f"Deleted dir: {sub_dir}")

    os.remove(test_file)
    print(f"Deleted: {test_file}")

    os.rmdir(test_dir)
    print(f"Deleted temp dir: {test_dir}")

    print("=== Filesystem Test Complete ===")
    return 0

if __name__ == "__main__":
    sys.exit(main())
