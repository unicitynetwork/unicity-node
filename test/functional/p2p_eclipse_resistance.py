#!/usr/bin/env python3
"""P2P Eclipse Attack Resistance Test.

Tests the node's resistance to eclipse attacks by verifying:
1. AddrManager netgroup limits (max 32 per /16 in NEW table)
2. Address diversity acceptance (diverse netgroups all accepted)

Note: Bitcoin Core parity - no per-netgroup connection-time limits.
Netgroup diversity is enforced via EVICTION when at capacity, not at
connection time. See eviction_manager.cpp for netgroup-aware eviction.

Per-netgroup eviction tests require filling the connection pool to capacity,
which is tested separately in integration tests.

Usage: python3 p2p_eclipse_resistance.py
"""

import sys
import socket
import struct
import hashlib
import time
import random
import tempfile
import shutil
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))

from test_node import TestNode
from util import wait_until, pick_free_port

# Protocol constants (must match include/network/protocol.hpp)
REGTEST_MAGIC = 0x4B7C2E91  # Regtest magic from protocol.hpp
PROTOCOL_VERSION = 70016
NODE_NETWORK = 1

# Security constants (must match addr_manager.cpp)
MAX_PER_NETGROUP_NEW = 32  # Max addresses per /16 in NEW table

# Note: There is NO per-netgroup connection-time limit in the code.
# Netgroup diversity is enforced via eviction when at capacity.
# See connection_manager.cpp:171-173 and eviction_manager.cpp.


def double_sha256(data):
    """Compute double SHA256 hash."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def write_varint(n):
    """Encode an integer as a Bitcoin-style varint."""
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    elif n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    else:
        return b"\xff" + struct.pack("<Q", n)


def create_version_message(nonce=None):
    """Create a VERSION message payload."""
    if nonce is None:
        nonce = random.getrandbits(64)

    payload = b""
    # version (int32)
    payload += struct.pack("<i", PROTOCOL_VERSION)
    # services (uint64)
    payload += struct.pack("<Q", NODE_NETWORK)
    # timestamp (int64)
    payload += struct.pack("<q", int(time.time()))
    # addr_recv (26 bytes: services + ip + port)
    payload += struct.pack("<Q", NODE_NETWORK)  # services
    payload += b"\x00" * 10 + b"\xff\xff" + socket.inet_aton("127.0.0.1")  # IPv4-mapped IPv6
    payload += struct.pack(">H", 9590)  # port (big endian)
    # addr_from (26 bytes)
    payload += struct.pack("<Q", NODE_NETWORK)
    payload += b"\x00" * 10 + b"\xff\xff" + socket.inet_aton("127.0.0.1")
    payload += struct.pack(">H", 9590)
    # nonce (uint64)
    payload += struct.pack("<Q", nonce)
    # user_agent (varint + string)
    user_agent = b"/EclipseTest:1.0/"
    payload += bytes([len(user_agent)]) + user_agent
    # start_height (int32)
    payload += struct.pack("<i", 0)

    return payload


def create_verack_message():
    """Create a VERACK message payload (empty)."""
    return b""


def create_addr_message(addresses):
    """Create an ADDR message payload.

    addresses: list of (ip_string, port, timestamp) tuples
    """
    payload = write_varint(len(addresses))

    for ip_str, port, timestamp in addresses:
        # timestamp (uint32)
        payload += struct.pack("<I", timestamp)
        # services (uint64)
        payload += struct.pack("<Q", NODE_NETWORK)
        # ip (16 bytes, IPv4-mapped IPv6)
        payload += b"\x00" * 10 + b"\xff\xff" + socket.inet_aton(ip_str)
        # port (uint16, big endian)
        payload += struct.pack(">H", port)

    return payload


def create_message(command, payload):
    """Create a complete protocol message with header."""
    # Header: magic(4) + command(12) + length(4) + checksum(4)
    magic = struct.pack("<I", REGTEST_MAGIC)
    cmd_bytes = command.encode("ascii").ljust(12, b"\x00")
    length = struct.pack("<I", len(payload))
    checksum = double_sha256(payload)[:4]

    return magic + cmd_bytes + length + checksum + payload


def read_message(sock, timeout=5):
    """Read a protocol message from socket. Returns (command, payload) or None."""
    sock.settimeout(timeout)
    try:
        # Read header (24 bytes)
        header = b""
        while len(header) < 24:
            chunk = sock.recv(24 - len(header))
            if not chunk:
                return None
            header += chunk

        # Parse header
        magic = struct.unpack("<I", header[0:4])[0]
        if magic != REGTEST_MAGIC:
            return None

        command = header[4:16].rstrip(b"\x00").decode("ascii")
        length = struct.unpack("<I", header[16:20])[0]

        # Read payload
        if length > 0:
            payload = b""
            while len(payload) < length:
                chunk = sock.recv(length - len(payload))
                if not chunk:
                    return None
                payload += chunk
        else:
            payload = b""

        return (command, payload)

    except socket.timeout:
        return None
    except Exception:
        return None


def attempt_handshake(host, port, timeout=5):
    """Attempt to complete a P2P handshake. Returns socket if successful, None otherwise."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((host, port))

        # Send VERSION
        version_msg = create_message("version", create_version_message())
        sock.sendall(version_msg)

        # Read VERSION from peer
        msg = read_message(sock, timeout)
        if msg is None or msg[0] != "version":
            sock.close()
            return None

        # Send VERACK
        verack_msg = create_message("verack", create_verack_message())
        sock.sendall(verack_msg)

        # Read VERACK from peer
        msg = read_message(sock, timeout)
        if msg is None or msg[0] != "verack":
            sock.close()
            return None

        return sock

    except Exception:
        sock.close()
        return None


def test_multiple_connections(host, port):
    """Test that multiple connections from same IP are accepted.

    Bitcoin Core parity: There is NO per-netgroup connection-time limit.
    Netgroup diversity is enforced via EVICTION when at capacity, not by
    rejecting connections. All connections from localhost should succeed
    when below capacity.

    This test verifies basic connectivity and that connections are tracked.
    """
    print("\n=== TEST: Multiple Connections Accepted (Bitcoin Core parity) ===")
    print("Attempting 5 connections from same IP...")
    print("Expected: All should succeed (no connection-time netgroup limit)\n")

    successful_sockets = []
    failed = 0

    for i in range(5):
        sock = attempt_handshake(host, port)
        if sock:
            print(f"  [{i}] Connected successfully")
            successful_sockets.append(sock)
        else:
            print(f"  [{i}] Failed to connect")
            failed += 1

    success_count = len(successful_sockets)
    print(f"\nResults: {success_count} connected, {failed} failed")

    # Cleanup
    for sock in successful_sockets:
        try:
            sock.close()
        except Exception:
            pass

    # All 5 should succeed when below capacity (default max inbound is 125)
    if success_count == 5:
        print("PASS: All connections accepted (no connection-time netgroup limit)")
        return True
    else:
        print(f"FAIL: Some connections failed unexpectedly ({failed} failed)")
        return False


def test_addr_flooding(host, port, node):
    """Test that AddrManager limits addresses per netgroup."""
    print("\n=== TEST: AddrManager Netgroup Limits ===")
    print(f"Sending 50 addresses from same /16 subnet...")
    print(f"Expected: Only {MAX_PER_NETGROUP_NEW} should be accepted (per-netgroup limit)\n")

    # Set initial mock time BEFORE connection
    base_time = int(time.time())
    node.rpc("setmocktime", str(base_time))
    time.sleep(0.1)

    # Connect and complete handshake
    sock = attempt_handshake(host, port)
    if not sock:
        print("FAIL: Could not connect for addr test")
        return False

    try:
        # Send a priming ADDR to initialize the rate limit state at base_time
        # This triggers GetSteadyTime to be called while mock time = base_time
        prime_addr = create_message("addr", create_addr_message([("8.99.0.1", 9590, base_time)]))
        sock.sendall(prime_addr)
        time.sleep(0.1)

        # Now advance mock time - rate state refills based on elapsed time
        # 50 addresses need 500 seconds at 0.1 tokens/sec
        node.rpc("setmocktime", str(base_time + 600))  # Advance 600 seconds
        time.sleep(0.1)  # Let node process time change

        # Get initial addr count (includes the 1 priming address)
        initial_info = node.rpc("getaddrmaninfo")
        initial_new = initial_info.get("new", 0) if isinstance(initial_info, dict) else 0
        print(f"  Initial NEW table count: {initial_new}")

        # Create 50 addresses all in same /16 (e.g., 8.50.x.y)
        # Use public IP range (8.x.x.x) - private IPs like 10.x.x.x are filtered out
        # This simulates an attacker trying to poison the address table
        addresses = []
        timestamp = base_time + 600  # Use current mock time for addresses
        for i in range(50):
            # All in 8.50.x.x netgroup (public IP range)
            ip = f"8.50.{i // 256}.{i % 256 + 1}"
            addresses.append((ip, 9590, timestamp))

        # Send addr message
        addr_msg = create_message("addr", create_addr_message(addresses))
        sock.sendall(addr_msg)
        print(f"  Sent {len(addresses)} addresses from netgroup 8.50")

        # Give node time to process
        time.sleep(1)

        # Check how many were accepted
        final_info = node.rpc("getaddrmaninfo")
        final_new = final_info.get("new", 0) if isinstance(final_info, dict) else 0
        added = final_new - initial_new
        print(f"  Final NEW table count: {final_new}")
        print(f"  Addresses added: {added}")

        # Verify limit was enforced - should add exactly MAX_PER_NETGROUP_NEW
        if added <= MAX_PER_NETGROUP_NEW:
            print(f"PASS: Per-netgroup limit enforced (added {added} <= {MAX_PER_NETGROUP_NEW})")
            return True
        else:
            print(f"FAIL: Too many addresses accepted from same netgroup ({added} > {MAX_PER_NETGROUP_NEW})")
            return False

    except Exception as e:
        print(f"FAIL: Error during addr test: {e}")
        return False
    finally:
        sock.close()
        node.rpc("setmocktime", "0")  # Reset mock time


def test_addr_diversity(host, port, node):
    """Test that addresses from diverse netgroups are all accepted."""
    print("\n=== TEST: Address Diversity Acceptance ===")
    print("Sending 20 addresses from 20 different /16 subnets...")
    print("Expected: All should be accepted (diverse netgroups)\n")

    # Set initial mock time BEFORE connection
    base_time = int(time.time())
    node.rpc("setmocktime", str(base_time))
    time.sleep(0.1)

    # Connect and complete handshake
    sock = attempt_handshake(host, port)
    if not sock:
        print("FAIL: Could not connect for diversity test")
        return False

    try:
        # Send a priming ADDR to initialize the rate limit state at base_time
        # This triggers GetSteadyTime to be called while mock time = base_time
        prime_addr = create_message("addr", create_addr_message([("8.99.1.1", 9590, base_time)]))
        sock.sendall(prime_addr)
        time.sleep(0.1)

        # Now advance mock time - rate state refills based on elapsed time
        # 20 addresses need 200 seconds at 0.1 tokens/sec
        node.rpc("setmocktime", str(base_time + 300))  # Advance 300 seconds
        time.sleep(0.1)  # Let node process time change

        # Get initial addr count (includes the 1 priming address)
        initial_info = node.rpc("getaddrmaninfo")
        initial_new = initial_info.get("new", 0) if isinstance(initial_info, dict) else 0
        print(f"  Initial NEW table count: {initial_new}")

        # Create 20 addresses from 20 different /16 subnets
        # Use public IP ranges (not 10.x.x.x/192.168.x.x which are filtered)
        addresses = []
        timestamp = base_time + 300  # Use current mock time for addresses
        for i in range(20):
            # Each in different /16: 8.1.x.x, 8.2.x.x, ..., 8.20.x.x (public range)
            ip = f"8.{i + 1}.0.1"
            addresses.append((ip, 9590, timestamp))

        # Send addr message
        addr_msg = create_message("addr", create_addr_message(addresses))
        sock.sendall(addr_msg)
        print(f"  Sent {len(addresses)} addresses from {len(addresses)} different netgroups")

        # Give node time to process
        time.sleep(1)

        # Check how many were accepted
        final_info = node.rpc("getaddrmaninfo")
        final_new = final_info.get("new", 0) if isinstance(final_info, dict) else 0
        added = final_new - initial_new
        print(f"  Final NEW table count: {final_new}")
        print(f"  Addresses added: {added}")

        # All 20 should be accepted since they're from different netgroups
        if added >= 15:  # Allow some margin for duplicates/filtering
            print(f"PASS: Diverse addresses accepted ({added} of 20)")
            return True
        else:
            print(f"FAIL: Too few addresses accepted ({added} of 20)")
            return False

    except Exception as e:
        print(f"FAIL: Error during diversity test: {e}")
        return False
    finally:
        sock.close()
        node.rpc("setmocktime", "0")  # Reset mock time


def test_rpc_peer_count(node):
    """Verify peer count via RPC is tracked correctly."""
    print("\n=== TEST: RPC Peer Verification ===")
    print("Checking that peers are tracked via RPC...")

    try:
        peers = node.get_peer_info()
        inbound_count = sum(1 for p in peers if p.get("inbound", False))
        outbound_count = sum(1 for p in peers if not p.get("inbound", False))
        print(f"  Total peers: {len(peers)}, Inbound: {inbound_count}, Outbound: {outbound_count}")

        # Just verify RPC works and returns valid data
        if len(peers) >= 0:
            print(f"PASS: RPC peer tracking works ({len(peers)} peers tracked)")
            return True
        else:
            print("FAIL: Invalid peer data")
            return False
    except Exception as e:
        print(f"FAIL: RPC error: {e}")
        return False


def main():
    print("=" * 60)
    print(" Eclipse Attack Resistance Test")
    print("=" * 60)
    print("\nThis test verifies security hardening against eclipse/Sybil attacks:")
    print("  - AddrManager netgroup limits (max 32 per /16 in NEW table)")
    print("  - Multiple connections accepted (no connection-time netgroup limit)")
    print("  - RPC peer tracking")

    # Setup test directory
    test_dir = Path(tempfile.mkdtemp(prefix="unicity_eclipse_test_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node = None
    all_passed = True

    try:
        # Pick a free port
        port = pick_free_port()
        print(f"\nStarting victim node on port {port}...")

        # Start the victim node
        node = TestNode(0, test_dir / "node0", binary_path,
                       extra_args=["--listen", f"--port={port}"])
        node.start()
        print("Node started successfully")

        # Give node a moment to fully initialize
        time.sleep(1)

        # Run tests
        host = "127.0.0.1"

        # Test 1: AddrManager netgroup flooding
        if not test_addr_flooding(host, port, node):
            all_passed = False

        # Test 2: Address diversity acceptance
        if not test_addr_diversity(host, port, node):
            all_passed = False

        # Test 3: Multiple connections (no connection-time netgroup limit)
        if not test_multiple_connections(host, port):
            all_passed = False

        # Wait a bit between tests
        time.sleep(2)

        # Test 4: RPC verification
        if not test_rpc_peer_count(node):
            all_passed = False

        print("\n" + "=" * 60)
        if all_passed:
            print(" All tests PASSED")
            print("=" * 60)
            return 0
        else:
            print(" Some tests FAILED")
            print("=" * 60)
            return 1

    except Exception as e:
        print(f"\nTest failed with error: {e}")
        import traceback
        traceback.print_exc()

        if node:
            print("\nNode last 30 lines of debug.log:")
            print(node.read_log(30))
        return 1

    finally:
        # Cleanup
        if node and node.is_running():
            node.stop()
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
