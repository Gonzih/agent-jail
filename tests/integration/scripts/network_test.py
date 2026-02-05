#!/usr/bin/env python3
"""
Network operations test script for agent-jail integration testing.
Makes HTTP requests to verify network event capture.
"""
import sys
import json

# Try to use requests, fall back to urllib
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    import urllib.request
    import urllib.error

def fetch_with_requests(url):
    """Fetch URL using requests library."""
    resp = requests.get(url, timeout=10)
    return resp.status_code, resp.text[:200]

def fetch_with_urllib(url):
    """Fetch URL using urllib (fallback)."""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'agent-jail-test/1.0'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read()[:200].decode('utf-8', errors='replace')
    except urllib.error.HTTPError as e:
        return e.code, str(e)

def main():
    print("=== Python Network Test ===")

    # Test URLs
    urls = [
        "https://httpbin.org/ip",
        "https://httpbin.org/headers",
        "https://api.github.com/zen",
    ]

    fetch = fetch_with_requests if HAS_REQUESTS else fetch_with_urllib
    print(f"Using: {'requests' if HAS_REQUESTS else 'urllib'}")

    for url in urls:
        print(f"\nFetching: {url}")
        try:
            status, body = fetch(url)
            print(f"  Status: {status}")
            print(f"  Body preview: {body[:100]}...")
        except Exception as e:
            print(f"  Error: {e}")

    # DNS resolution test
    import socket
    hosts = ["google.com", "github.com", "api.anthropic.com"]
    print("\n--- DNS Resolution ---")
    for host in hosts:
        try:
            ip = socket.gethostbyname(host)
            print(f"  {host} -> {ip}")
        except socket.gaierror as e:
            print(f"  {host} -> ERROR: {e}")

    print("\n=== Network Test Complete ===")
    return 0

if __name__ == "__main__":
    sys.exit(main())
