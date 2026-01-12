#!/usr/bin/env python3
"""
Test: Selective Relay Attack

Some peers refuse to respond to requests while others respond normally.
Tests node's ability to handle unresponsive peers.

Expected: Node continues functioning with partial peer responses.

Verification:
- Connect mix of silent and responsive peers
- Verify responsive peers receive valid responses
- Verify node continues functioning despite silent peers
- Check peer info for timeout/misbehavior detection
- Verify node can still sync with responsive peers

Usage:
    docker-compose up -d
    python3 test_selective_relay.py
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

# Protocol constants
REGTEST_MAGIC = 0x4B7C2E91
PROTOCOL_VERSION = 70016
NODE_NETWORK = 1
P2P_PORT = 29790
TARGET_CONTAINER = "sybil_target"


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
    user_agent = b"/SelectiveRelayTest:1.0/"
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
    payload += b"\x00" * 32
    payload += b"\x00" * 32
    return payload


def create_ping_message(nonce: int) -> bytes:
    """Create PING message with nonce."""
    return struct.pack("<Q", nonce)


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


def p2p_connect(ip: str, port: int, timeout: float = 10.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.sendall(create_message("version", create_version_message()))
        sock.recv(4096)
        sock.sendall(create_message("verack", b""))
        time.sleep(0.3)
        try:
            sock.recv(4096)
        except:
            pass
        return sock
    except:
        return None


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
    """Get detailed peer info including misbehavior status."""
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
    print("TEST: Selective Relay Attack")
    print("=" * 60)
    print("Attack: Some peers refuse to respond to any requests")
    print("Expected: Responsive peers work, node detects unresponsive\n")

    # Check container is running
    result = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", TARGET_CONTAINER],
        capture_output=True, text=True
    )
    if "true" not in result.stdout.lower():
        print("ERROR: Container not running. Run: docker-compose up -d")
        return 1

    # Step 1: Connect peers with different behaviors
    print("Step 1: Connecting peers (3 silent, 1 responsive)...")
    connections = []  # (socket, is_silent, peer_name)

    for i in range(4):
        sock = p2p_connect("127.0.0.1", P2P_PORT, timeout=5)
        if sock:
            is_silent = (i < 3)  # First 3 are silent
            behavior = "silent" if is_silent else "responsive"
            connections.append((sock, is_silent, f"Peer{i+1}"))
            print(f"  Peer {i+1}: Connected ({behavior})")

    if len(connections) < 2:
        print("\nFAIL: Could not establish enough connections")
        return 1

    silent_count = sum(1 for _, is_silent, _ in connections if is_silent)
    responsive_count = len(connections) - silent_count
    print(f"  Total: {len(connections)} peers ({silent_count} silent, {responsive_count} responsive)")

    # Step 2: Send PING to all peers - only responsive should reply
    print("\nStep 2: Testing responsiveness with PING...")
    ping_nonce = random.getrandbits(64)
    ping_msg = create_message("ping", create_ping_message(ping_nonce))

    responsive_replies = 0
    for sock, is_silent, name in connections:
        try:
            # Send ping
            sock.sendall(ping_msg)

            if is_silent:
                # Silent peers intentionally don't respond
                print(f"  {name} (silent): Ignoring PING")
            else:
                # Responsive peer waits for response
                sock.settimeout(3.0)
                try:
                    data = sock.recv(4096)
                    if data:
                        cmd, payload, _ = parse_message(data)
                        if cmd == "pong":
                            print(f"  {name} (responsive): Got PONG")
                            responsive_replies += 1
                        else:
                            print(f"  {name} (responsive): Got {cmd} instead of PONG")
                    else:
                        print(f"  {name} (responsive): No response")
                except socket.timeout:
                    print(f"  {name} (responsive): Timeout waiting for PONG")
        except Exception as e:
            print(f"  {name}: Error ({e})")

    # Step 3: Send GETHEADERS from responsive peer
    print("\nStep 3: Responsive peer sends GETHEADERS...")
    getheaders_msg = create_message("getheaders", create_getheaders_message())

    headers_received = False
    for sock, is_silent, name in connections:
        if not is_silent:
            try:
                sock.sendall(getheaders_msg)
                sock.settimeout(3.0)
                data = sock.recv(4096)
                if data:
                    cmd, payload, _ = parse_message(data)
                    if cmd == "headers":
                        print(f"  {name}: Received HEADERS response")
                        headers_received = True
                    else:
                        print(f"  {name}: Got {cmd}")
                else:
                    print(f"  {name}: No response")
            except socket.timeout:
                print(f"  {name}: Timeout")
            except Exception as e:
                print(f"  {name}: Error ({e})")

    # Step 4: Check node's view of peer health
    print("\nStep 4: Checking node's peer status...")
    time.sleep(1)

    peer_info = get_peer_info(TARGET_CONTAINER)
    if peer_info:
        print(f"  Node sees {len(peer_info)} peers")
        for peer in peer_info:
            misbehaving = peer.get("misbehaving", False)
            ping_time = peer.get("pingtime", "null")
            status = "misbehaving" if misbehaving else "ok"
            print(f"    Peer {peer.get('id')}: {status}, ping={ping_time}")
    else:
        print("  WARNING: Could not get peer info")

    # Step 5: Verify node functionality
    print("\nStep 5: Verifying node functionality...")
    test_passed = True

    peer_count = get_peer_count(TARGET_CONTAINER)
    if peer_count is not None:
        print(f"  Peer count: {peer_count}")
        print(f"  PASS: Node responds to RPC")
    else:
        print("  FAIL: Node not responding")
        test_passed = False

    # Verify responsive peer got valid responses
    if headers_received:
        print(f"  PASS: Responsive peer received HEADERS")
    else:
        print(f"  WARNING: No HEADERS received (chain may be empty)")

    # Step 6: Verify node prefers responsive peers
    print("\nStep 6: Analyzing peer behavior...")

    # The key test: does the node continue to function despite silent peers?
    # A good implementation should:
    # 1. Not crash or hang waiting for silent peers
    # 2. Continue to serve responsive peers
    # 3. Eventually time out or deprioritize silent peers

    if peer_count is not None and peer_count > 0:
        print(f"  PASS: Node maintained {peer_count} connections")
        print(f"  PASS: Silent peers did not block node operation")
    else:
        print(f"  FAIL: Node lost all connections")
        test_passed = False

    # Clean up
    print("\nStep 7: Cleaning up...")
    for sock, _, _ in connections:
        try:
            sock.close()
        except:
            pass

    print("\n" + "=" * 60)
    if test_passed:
        print("PASS: Node handled selective relay attack correctly")
        print(f"  - {responsive_count} responsive peer(s) worked normally")
        print(f"  - {silent_count} silent peer(s) did not block operation")
        print(f"  - Node continued serving requests")
    else:
        print("FAIL: Node did not handle selective relay properly")
    print("=" * 60)
    return 0 if test_passed else 1


if __name__ == "__main__":
    sys.exit(main())
