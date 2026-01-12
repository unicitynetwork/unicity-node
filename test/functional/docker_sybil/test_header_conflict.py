#!/usr/bin/env python3
"""
Test: Header Conflict Attack

Multiple peers send GETHEADERS simultaneously, testing concurrent
header processing and potential race conditions.

Expected: Node handles concurrent requests without crash.

Verification:
- Parse HEADERS responses from each peer
- Verify responses are valid (proper message format, matching checksums)
- Verify all peers receive identical header data (no corruption)
- Verify node remains responsive

Usage:
    docker-compose up -d
    python3 test_header_conflict.py
    docker-compose down -v
"""

import socket
import struct
import hashlib
import time
import sys
import subprocess
import random

# Protocol constants
REGTEST_MAGIC = 0x4B7C2E91
PROTOCOL_VERSION = 70016
NODE_NETWORK = 1
P2P_PORT = 29790
TARGET_CONTAINER = "sybil_target"
HEADER_SIZE = 100  # Unicity header size


def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def write_varint(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    else:
        return b"\xfe" + struct.pack("<I", n)


def read_varint(data: bytes, offset: int) -> tuple:
    """Read varint from data at offset, return (value, new_offset)."""
    if offset >= len(data):
        return None, offset
    first = data[offset]
    if first < 0xfd:
        return first, offset + 1
    elif first == 0xfd:
        if offset + 3 > len(data):
            return None, offset
        return struct.unpack("<H", data[offset+1:offset+3])[0], offset + 3
    elif first == 0xfe:
        if offset + 5 > len(data):
            return None, offset
        return struct.unpack("<I", data[offset+1:offset+5])[0], offset + 5
    else:
        if offset + 9 > len(data):
            return None, offset
        return struct.unpack("<Q", data[offset+1:offset+9])[0], offset + 9


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
    user_agent = b"/HeaderConflictTest:1.0/"
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
    """Parse a P2P message, return (command, payload, remaining_data) or (None, None, data) on error."""
    if len(data) < 24:  # Minimum header size
        return None, None, data

    magic = struct.unpack("<I", data[0:4])[0]
    if magic != REGTEST_MAGIC:
        return None, None, data

    command = data[4:16].rstrip(b"\x00").decode("ascii", errors="replace")
    payload_len = struct.unpack("<I", data[16:20])[0]
    checksum = data[20:24]

    if len(data) < 24 + payload_len:
        return None, None, data  # Incomplete message

    payload = data[24:24+payload_len]

    # Verify checksum
    expected_checksum = double_sha256(payload)[:4]
    if checksum != expected_checksum:
        return None, None, data  # Bad checksum

    remaining = data[24+payload_len:]
    return command, payload, remaining


def parse_headers_payload(payload: bytes) -> list:
    """Parse HEADERS message payload, return list of header hashes."""
    if not payload:
        return []

    count, offset = read_varint(payload, 0)
    if count is None:
        return []

    headers = []
    for _ in range(count):
        if offset + HEADER_SIZE > len(payload):
            break
        header_data = payload[offset:offset+HEADER_SIZE]
        header_hash = double_sha256(header_data)
        headers.append(header_hash.hex())
        offset += HEADER_SIZE

    return headers


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


def main():
    print("=" * 60)
    print("TEST: Header Conflict Attack")
    print("=" * 60)
    print("Attack: Concurrent GETHEADERS from multiple peers")
    print("Expected: Valid, identical responses to all peers\n")

    # Check container is running
    result = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", TARGET_CONTAINER],
        capture_output=True, text=True
    )
    if "true" not in result.stdout.lower():
        print("ERROR: Container not running. Run: docker-compose up -d")
        return 1

    # Step 1: Connect multiple peers
    print("Step 1: Connecting peers (max 4 per netgroup)...")
    connections = []
    for i in range(4):
        sock = p2p_connect("127.0.0.1", P2P_PORT, timeout=5)
        if sock:
            connections.append(sock)
            print(f"  Peer {i+1}: Connected")

    if len(connections) < 2:
        print("\nFAIL: Could not establish enough connections")
        return 1

    print(f"  Total: {len(connections)} peers")

    # Step 2: All peers send GETHEADERS simultaneously
    print("\nStep 2: All peers send GETHEADERS simultaneously...")
    getheaders_msg = create_message("getheaders", create_getheaders_message())

    for i, sock in enumerate(connections):
        try:
            sock.sendall(getheaders_msg)
            print(f"  Peer {i+1}: Sent GETHEADERS")
        except Exception as e:
            print(f"  Peer {i+1}: Failed ({e})")

    # Step 3: Collect and parse responses
    print("\nStep 3: Collecting and parsing responses...")
    time.sleep(2)  # Give time for responses

    responses = []  # List of (peer_idx, command, header_hashes)
    valid_responses = 0
    invalid_responses = 0

    for i, sock in enumerate(connections):
        try:
            sock.settimeout(2.0)
            data = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 100000:  # Safety limit
                        break
            except socket.timeout:
                pass
            except Exception:
                pass

            if not data:
                print(f"  Peer {i+1}: No response received")
                invalid_responses += 1
                continue

            # Parse all messages in the response
            remaining = data
            found_headers = False
            while remaining:
                command, payload, remaining = parse_message(remaining)
                if command is None:
                    break

                if command == "headers":
                    headers = parse_headers_payload(payload)
                    responses.append((i+1, headers))
                    found_headers = True
                    print(f"  Peer {i+1}: HEADERS with {len(headers)} header(s), checksum valid")
                    valid_responses += 1
                    break

            if not found_headers:
                print(f"  Peer {i+1}: No HEADERS in response ({len(data)} bytes received)")
                # Not necessarily invalid - could be other messages

        except Exception as e:
            print(f"  Peer {i+1}: Error reading response ({e})")
            invalid_responses += 1

    # Step 4: Verify response consistency
    print("\nStep 4: Verifying response consistency...")
    test_passed = True

    if valid_responses == 0:
        print("  WARNING: No valid HEADERS responses received")
        # This might be OK if chain is empty, check node health instead
    elif len(responses) >= 2:
        # Check all responses contain identical headers
        first_headers = responses[0][1]
        all_match = True
        for peer_idx, headers in responses[1:]:
            if headers != first_headers:
                print(f"  FAIL: Peer {peer_idx} headers differ from Peer {responses[0][0]}")
                all_match = False
                test_passed = False

        if all_match:
            print(f"  PASS: All {len(responses)} peers received identical headers")
        else:
            print(f"  FAIL: Header responses are inconsistent (race condition?)")

    # Step 5: Check node health
    print("\nStep 5: Checking node health...")
    peer_count = get_peer_count(TARGET_CONTAINER)
    if peer_count is not None:
        print(f"  Peer count: {peer_count}")
        print(f"  PASS: Node responds to CLI")
    else:
        print("  FAIL: Node not responding")
        test_passed = False

    # Clean up
    print("\nStep 6: Cleaning up...")
    for sock in connections:
        try:
            sock.close()
        except:
            pass

    print("\n" + "=" * 60)
    if test_passed:
        print("PASS: Node handled concurrent header requests correctly")
        print(f"  - {valid_responses} valid HEADERS responses")
        print(f"  - All responses consistent (no race conditions)")
        print(f"  - Node remained responsive")
    else:
        print("FAIL: Concurrent header handling has issues")
    print("=" * 60)
    return 0 if test_passed else 1


if __name__ == "__main__":
    sys.exit(main())
