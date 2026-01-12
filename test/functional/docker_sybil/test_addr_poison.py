#!/usr/bin/env python3
"""
Test: ADDR Poisoning Attack

Multiple peers flood ADDR messages trying to fill the target's address manager
with attacker-controlled addresses.

Expected: Address manager limits per-netgroup addresses, node remains healthy.

Verification:
- Query getaddrmaninfo before/after attack
- Verify address count increase is bounded (not all poison addresses accepted)
- Verify node remains responsive

Usage:
    docker-compose up -d
    python3 test_addr_poison.py
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

# Attack parameters
POISON_ADDRS_PER_MSG = 100  # Addresses per ADDR message
FLOOD_ROUNDS = 5           # Number of flood rounds
TOTAL_POISON_SENT = POISON_ADDRS_PER_MSG * FLOOD_ROUNDS * 4  # ~2000 addresses


def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def write_varint(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    elif n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    else:
        return b"\xff" + struct.pack("<Q", n)


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
    user_agent = b"/AddrPoisonTest:1.0/"
    payload += bytes([len(user_agent)]) + user_agent
    payload += struct.pack("<i", 0)
    return payload


def create_message(command: str, payload: bytes) -> bytes:
    magic = struct.pack("<I", REGTEST_MAGIC)
    cmd_bytes = command.encode("ascii").ljust(12, b"\x00")
    length = struct.pack("<I", len(payload))
    checksum = double_sha256(payload)[:4]
    return magic + cmd_bytes + length + checksum + payload


def create_addr_message(addresses: list) -> bytes:
    """Create ADDR message with list of (ip, port) tuples."""
    payload = write_varint(len(addresses))
    for ip, port in addresses:
        payload += struct.pack("<I", int(time.time()) - random.randint(0, 3600))
        payload += struct.pack("<Q", NODE_NETWORK)
        payload += b"\x00" * 10 + b"\xff\xff" + socket.inet_aton(ip)
        payload += struct.pack(">H", port)
    return payload


def p2p_connect(ip: str, port: int, timeout: float = 10.0):
    """Connect to node and complete handshake."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.sendall(create_message("version", create_version_message()))
        sock.recv(4096)
        sock.sendall(create_message("verack", b""))
        time.sleep(0.5)
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


def get_addrman_info(container: str) -> dict:
    """Get address manager stats: total, tried, new counts."""
    cmd = "/app/build/bin/unicity-cli --datadir=/data getaddrmaninfo"
    code, output = docker_exec(container, cmd, timeout=10)
    if code == 0:
        try:
            return json.loads(output.strip())
        except:
            pass
    return None


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
    print("TEST: ADDR Poisoning Attack")
    print("=" * 60)
    print("Attack: Flood ADDR messages with fake addresses")
    print("Expected: Address manager limits entries, rejects most poison\n")

    # Check container is running
    result = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", TARGET_CONTAINER],
        capture_output=True, text=True
    )
    if "true" not in result.stdout.lower():
        print("ERROR: Container not running. Run: docker-compose up -d")
        return 1

    # Step 1: Get baseline address manager stats
    print("Step 1: Getting baseline address manager stats...")
    baseline = get_addrman_info(TARGET_CONTAINER)
    if baseline is None:
        print("  ERROR: Could not get addrman info")
        return 1
    print(f"  Before attack: total={baseline['total']}, new={baseline['new']}, tried={baseline['tried']}")

    # Step 2: Connect peers
    print("\nStep 2: Connecting peers (max 4 per netgroup)...")
    connections = []
    for i in range(4):
        sock = p2p_connect("127.0.0.1", P2P_PORT)
        if sock:
            connections.append(sock)
            print(f"  Peer {i+1}: Connected")
        else:
            print(f"  Peer {i+1}: Failed")

    if len(connections) < 2:
        print("\nFAIL: Could not establish enough connections")
        return 1

    # Step 3: Generate and send ADDR flood
    # All addresses in same /16 netgroup (172.50.x.x) to test netgroup limits
    print(f"\nStep 3: Sending ADDR flood...")
    print(f"  Addresses per message: {POISON_ADDRS_PER_MSG}")
    print(f"  Rounds: {FLOOD_ROUNDS}")
    print(f"  Total poison addresses: ~{TOTAL_POISON_SENT}")

    total_sent = 0
    for round_num in range(FLOOD_ROUNDS):
        # Generate fresh addresses each round (same /16 netgroup)
        poison_addrs = [
            (f"172.50.{random.randint(1, 254)}.{random.randint(1, 254)}", P2P_PORT)
            for _ in range(POISON_ADDRS_PER_MSG)
        ]
        addr_msg = create_message("addr", create_addr_message(poison_addrs))

        for sock in connections:
            try:
                sock.sendall(addr_msg)
                total_sent += POISON_ADDRS_PER_MSG
            except:
                pass

        print(f"  Round {round_num + 1}/{FLOOD_ROUNDS}: Sent {POISON_ADDRS_PER_MSG * len(connections)} addresses")
        time.sleep(0.5)

    print(f"  Total sent: {total_sent} addresses")

    # Step 4: Wait for processing
    print("\nStep 4: Waiting for address manager to process...")
    time.sleep(3)

    # Step 5: Get post-attack stats
    print("\nStep 5: Checking address manager after attack...")
    after = get_addrman_info(TARGET_CONTAINER)
    if after is None:
        print("  ERROR: Node not responding")
        for sock in connections:
            try:
                sock.close()
            except:
                pass
        return 1

    print(f"  After attack:  total={after['total']}, new={after['new']}, tried={after['tried']}")

    # Calculate how many addresses were accepted
    addresses_added = after['total'] - baseline['total']
    acceptance_rate = (addresses_added / total_sent * 100) if total_sent > 0 else 0

    print(f"\n  Addresses accepted: {addresses_added}")
    print(f"  Acceptance rate: {acceptance_rate:.1f}%")

    # Step 6: Verify defensive behavior
    print("\nStep 6: Verifying defensive behavior...")

    # The node should NOT accept all addresses - netgroup/rate limits should apply
    # If >50% accepted, something is wrong with the defenses
    MAX_ACCEPTABLE_RATE = 50  # Should accept far less than 50% from same netgroup

    test_passed = True
    if acceptance_rate > MAX_ACCEPTABLE_RATE:
        print(f"  FAIL: Acceptance rate {acceptance_rate:.1f}% exceeds {MAX_ACCEPTABLE_RATE}%")
        print(f"        Address manager did not properly limit poison addresses")
        test_passed = False
    else:
        print(f"  PASS: Acceptance rate {acceptance_rate:.1f}% is within limits")
        print(f"        Address manager properly limited poison addresses")

    # Verify node still responsive
    peer_count = get_peer_count(TARGET_CONTAINER)
    if peer_count is None:
        print("  FAIL: Node stopped responding to RPC")
        test_passed = False
    else:
        print(f"  PASS: Node responsive (peer count: {peer_count})")

    # Step 7: Clean up
    print("\nStep 7: Cleaning up connections...")
    for sock in connections:
        try:
            sock.close()
        except:
            pass

    print("\n" + "=" * 60)
    if test_passed:
        print("PASS: Address manager defended against ADDR poisoning")
        print(f"  - Sent {total_sent} poison addresses")
        print(f"  - Only {addresses_added} accepted ({acceptance_rate:.1f}%)")
        print(f"  - Netgroup limits working correctly")
    else:
        print("FAIL: Address manager did not properly defend against attack")
    print("=" * 60)
    return 0 if test_passed else 1


if __name__ == "__main__":
    sys.exit(main())
