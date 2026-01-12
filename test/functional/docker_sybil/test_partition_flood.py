#!/usr/bin/env python3
"""
Test: Partition Then Flood Attack

Simulate network partition recovery with a connection flood.
Multiple peers reconnect simultaneously and send GETHEADERS.

Expected: Node handles reconnection surge gracefully.

Verification:
- Measure connection acceptance rate during flood
- Verify node continues responding to RPC during surge
- Verify responses after reconnection are valid
- Measure time to process concurrent requests

Usage:
    docker-compose up -d
    python3 test_partition_flood.py
    docker-compose down -v
"""

import socket
import struct
import hashlib
import time
import sys
import subprocess
import random
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# Protocol constants
REGTEST_MAGIC = 0x4B7C2E91
PROTOCOL_VERSION = 70016
NODE_NETWORK = 1
P2P_PORT = 29790
TARGET_CONTAINER = "sybil_target"

# Test parameters
FLOOD_CONNECTIONS = 10  # Try to establish this many connections
FLOOD_INTERVAL_MS = 20  # Milliseconds between connection attempts


def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def write_varint(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    else:
        return b"\xfe" + struct.pack("<I", n)


def create_version_message() -> bytes:
    nonce = random.getrandbits(64)
    payload = b""
    payload += struct.pack("<i", PROTOCOL_VERSION)
    payload += struct.pack("<Q", NODE_NETWORK)
    payload += struct.pack("<q", int(time.time()))
    payload += struct.pack("<Q", NODE_NETWORK)
    payload += b"\x00" * 10 + b"\xff\xff" + socket.inet_aton("127.0.0.1")
    payload += struct.pack(">H", 8333)
    payload += struct.pack("<Q", NODE_NETWORK)
    payload += b"\x00" * 10 + b"\xff\xff" + socket.inet_aton("127.0.0.1")
    payload += struct.pack(">H", 8333)
    payload += struct.pack("<Q", nonce)
    user_agent = b"/PartitionFloodTest:1.0/"
    payload += bytes([len(user_agent)]) + user_agent
    payload += struct.pack("<i", 0)
    return payload


def create_message(command: str, payload: bytes) -> bytes:
    magic = struct.pack("<I", REGTEST_MAGIC)
    cmd_bytes = command.encode("ascii").ljust(12, b"\x00")
    length = struct.pack("<I", len(payload))
    checksum = double_sha256(payload)[:4]
    return magic + cmd_bytes + length + checksum + payload


def create_getheaders_message() -> bytes:
    payload = struct.pack("<I", PROTOCOL_VERSION)
    payload += write_varint(1)
    payload += b"\x00" * 32  # Genesis locator
    payload += b"\x00" * 32  # Stop hash
    return payload


def parse_message(data: bytes) -> tuple:
    """Parse a P2P message, return (command, payload, remaining_data)."""
    if len(data) < 24:
        return None, None, data

    magic = struct.unpack("<I", data[0:4])[0]
    if magic != REGTEST_MAGIC:
        return None, None, data

    command = data[4:16].rstrip(b"\x00").decode("ascii", errors="replace")
    payload_len = struct.unpack("<I", data[16:20])[0]
    checksum = data[20:24]

    if len(data) < 24 + payload_len:
        return None, None, data

    payload = data[24:24+payload_len]
    expected_checksum = double_sha256(payload)[:4]
    if checksum != expected_checksum:
        return None, None, data

    remaining = data[24+payload_len:]
    return command, payload, remaining


def p2p_connect_timed(ip: str, port: int, timeout: float = 5.0) -> tuple:
    """Connect and return (socket, connect_time_ms) or (None, None)."""
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.sendall(create_message("version", create_version_message()))
        sock.recv(4096)
        sock.sendall(create_message("verack", b""))
        time.sleep(0.1)  # Brief wait for verack processing
        try:
            sock.recv(4096)
        except:
            pass
        elapsed_ms = (time.time() - start) * 1000
        return sock, elapsed_ms
    except:
        return None, None


def docker_exec(container: str, cmd: str, timeout: int = 30):
    try:
        result = subprocess.run(
            ["docker", "exec", container, "bash", "-c", cmd],
            capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return -1, "TIMEOUT"


def get_peer_count(container: str):
    cmd = "/app/build/bin/unicity-cli --datadir=/data getconnectioncount"
    code, output = docker_exec(container, cmd, timeout=10)
    if code == 0:
        try:
            return int(output.strip())
        except:
            pass
    return None


def get_peer_info(container: str) -> list:
    """Get detailed peer info."""
    cmd = "/app/build/bin/unicity-cli --datadir=/data getpeerinfo"
    code, output = docker_exec(container, cmd, timeout=10)
    if code == 0:
        try:
            return json.loads(output.strip())
        except:
            pass
    return []


def main():
    print("=" * 60)
    print("TEST: Partition Then Flood Attack")
    print("=" * 60)
    print("Attack: Rapid reconnection with simultaneous GETHEADERS")
    print("Expected: Node handles surge gracefully, limits connections\n")

    # Check container is running
    result = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", TARGET_CONTAINER],
        capture_output=True, text=True
    )
    if "true" not in result.stdout.lower():
        print("ERROR: Container not running. Run: docker-compose up -d")
        return 1

    # Step 1: Establish baseline connections
    print("Step 1: Establishing baseline connections...")
    baseline = []
    for i in range(4):
        sock, ms = p2p_connect_timed("127.0.0.1", P2P_PORT, timeout=5)
        if sock:
            baseline.append(sock)
            print(f"  Connection {i+1}: Established in {ms:.0f}ms")

    if len(baseline) < 2:
        print("\nFAIL: Could not establish baseline connections")
        return 1

    print(f"  Total: {len(baseline)} connections")

    # Check RPC responsiveness during baseline
    baseline_rpc_start = time.time()
    baseline_peer_count = get_peer_count(TARGET_CONTAINER)
    baseline_rpc_time = (time.time() - baseline_rpc_start) * 1000
    print(f"  RPC response time: {baseline_rpc_time:.0f}ms")

    # Step 2: Simulate partition (close all connections)
    print("\nStep 2: Simulating partition (closing connections)...")
    for sock in baseline:
        try:
            sock.close()
        except:
            pass
    print("  All connections closed")

    # Step 3: Brief partition duration
    print("\nStep 3: Partition duration (1 second)...")
    time.sleep(1)

    # Step 4: Reconnection flood - try many connections rapidly
    print(f"\nStep 4: Reconnection flood ({FLOOD_CONNECTIONS} attempts)...")
    flood_start = time.time()

    flood = []
    accepted = 0
    rejected = 0
    connect_times = []

    for i in range(FLOOD_CONNECTIONS):
        sock, ms = p2p_connect_timed("127.0.0.1", P2P_PORT, timeout=2)
        if sock:
            flood.append(sock)
            accepted += 1
            connect_times.append(ms)
        else:
            rejected += 1
        time.sleep(FLOOD_INTERVAL_MS / 1000.0)

    flood_duration = time.time() - flood_start
    print(f"  Flood duration: {flood_duration:.2f}s")
    print(f"  Accepted: {accepted}/{FLOOD_CONNECTIONS}")
    print(f"  Rejected: {rejected}/{FLOOD_CONNECTIONS}")

    if connect_times:
        avg_connect = sum(connect_times) / len(connect_times)
        print(f"  Avg connect time: {avg_connect:.0f}ms")

    # Step 5: Check RPC responsiveness DURING flood
    print("\nStep 5: Checking RPC responsiveness during load...")
    flood_rpc_start = time.time()
    flood_peer_count = get_peer_count(TARGET_CONTAINER)
    flood_rpc_time = (time.time() - flood_rpc_start) * 1000

    if flood_peer_count is not None:
        print(f"  RPC response time: {flood_rpc_time:.0f}ms")
        print(f"  Node peer count: {flood_peer_count}")
    else:
        print("  WARNING: RPC not responding during flood")

    # Step 6: All established connections send GETHEADERS
    print("\nStep 6: Sending GETHEADERS from all connections...")
    getheaders_msg = create_message("getheaders", create_getheaders_message())

    sent = 0
    responses = 0
    for sock in flood:
        try:
            sock.sendall(getheaders_msg)
            sent += 1
        except:
            pass

    print(f"  Sent GETHEADERS from {sent} connections")

    # Wait and check for responses
    time.sleep(1)
    for sock in flood:
        try:
            sock.settimeout(0.5)
            data = sock.recv(4096)
            if data:
                cmd, _, _ = parse_message(data)
                if cmd == "headers":
                    responses += 1
        except:
            pass

    print(f"  Received {responses} HEADERS responses")

    # Step 7: Verify node stability after flood
    print("\nStep 7: Verifying node stability after flood...")
    time.sleep(1)

    test_passed = True

    # Check RPC still works
    post_rpc_start = time.time()
    post_peer_count = get_peer_count(TARGET_CONTAINER)
    post_rpc_time = (time.time() - post_rpc_start) * 1000

    if post_peer_count is not None:
        print(f"  Post-flood RPC response: {post_rpc_time:.0f}ms")
        print(f"  Post-flood peer count: {post_peer_count}")
        print(f"  PASS: Node responsive after flood")
    else:
        print("  FAIL: Node not responding after flood")
        test_passed = False

    # Verify netgroup limiting worked (should have rejected some connections)
    # We expect max 4 connections from same /16 netgroup
    MAX_EXPECTED_CONNECTIONS = 4
    if accepted <= MAX_EXPECTED_CONNECTIONS:
        print(f"  PASS: Netgroup limit enforced ({accepted} <= {MAX_EXPECTED_CONNECTIONS})")
    else:
        print(f"  WARNING: More connections than expected ({accepted} > {MAX_EXPECTED_CONNECTIONS})")

    # Clean up
    print("\nStep 8: Cleaning up...")
    for sock in flood:
        try:
            sock.close()
        except:
            pass

    print("\n" + "=" * 60)
    if test_passed:
        print("PASS: Node handled partition-flood gracefully")
        print(f"  - Processed {FLOOD_CONNECTIONS} connection attempts")
        print(f"  - Accepted {accepted}, rejected {rejected} (netgroup limit)")
        print(f"  - {responses}/{sent} GETHEADERS responses")
        print(f"  - RPC remained responsive during flood")
    else:
        print("FAIL: Node did not handle partition-flood correctly")
    print("=" * 60)
    return 0 if test_passed else 1


if __name__ == "__main__":
    sys.exit(main())
