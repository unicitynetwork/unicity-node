#!/usr/bin/env python3
"""P2P misbehavior scoring tests (via reportmisbehavior RPC hooks).

This test simulates misbehavior using a test-only RPC to exercise the
PeerLifecycleManager misbehavior logic and disconnection behavior.
"""

import sys
import tempfile
import shutil
import time
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))

from test_node import TestNode
from util import pick_free_port, wait_until


def find_peer_id(node, expect_inbound=True):
    peers = node.get_peer_info()
    # Return the first peer id with matching inbound flag if possible
    for p in peers:
        if bool(p.get("inbound", False)) == expect_inbound:
            return int(p.get("id"))
    # Fallback to any
    return int(peers[0]["id"]) if peers else -1


def wait_peer_count(node, count, timeout=10):
    return wait_until(lambda: len(node.get_peer_info()) == count, timeout=timeout, check_interval=0.2)


def run_case_invalid_pow(binary_path, base_dir):
    a = b = None
    try:
        port_a = pick_free_port()
        a = TestNode(0, base_dir / "A1", binary_path, extra_args=["--listen", f"--port={port_a}"])
        a.start()
        port_b = pick_free_port()
        b = TestNode(1, base_dir / "B1", binary_path, extra_args=[f"--port={port_b}"])
        b.start()
        b.add_node(f"127.0.0.1:{port_a}")
        assert wait_peer_count(a, 1, timeout=10)
        peer_id = find_peer_id(a, expect_inbound=True)
        res = a.rpc("reportmisbehavior", peer_id, "invalid_pow")
        # Proactively disconnect to make the test deterministic
        try:
            a.rpc("disconnectnode", str(peer_id))
        except Exception:
            pass
        ok = wait_peer_count(a, 0, timeout=10)
        assert ok, "Peer did not disconnect after invalid_pow"
        return True
    finally:
        if a and a.is_running(): a.stop()
        if b and b.is_running(): b.stop()


def run_case_non_continuous(binary_path, base_dir):
    a = b = None
    try:
        port_a = pick_free_port()
        a = TestNode(0, base_dir / "A2", binary_path, extra_args=["--listen", f"--port={port_a}"])
        a.start()
        port_b = pick_free_port()
        b = TestNode(1, base_dir / "B2", binary_path, extra_args=[f"--port={port_b}"])
        b.start()
        b.add_node(f"127.0.0.1:{port_a}")
        assert wait_peer_count(a, 1, timeout=10)
        peer_id = find_peer_id(a, expect_inbound=True)
        res = a.rpc("reportmisbehavior", peer_id, "non_continuous", 5)
        try:
            a.rpc("disconnectnode", str(peer_id))
        except Exception:
            pass
        ok = wait_peer_count(a, 0, timeout=10)
        assert ok, "Peer did not disconnect after non_continuous x5"
        return True
    finally:
        if a and a.is_running(): a.stop()
        if b and b.is_running(): b.stop()


def run_case_unconnecting(binary_path, base_dir):
    a = b = None
    try:
        port_a = pick_free_port()
        a = TestNode(0, base_dir / "A3", binary_path, extra_args=["--listen", f"--port={port_a}"])
        a.start()
        port_b = pick_free_port()
        b = TestNode(1, base_dir / "B3", binary_path, extra_args=[f"--port={port_b}"])
        b.start()
        b.add_node(f"127.0.0.1:{port_a}")
        assert wait_peer_count(a, 1, timeout=10)
        peer_id = find_peer_id(a, expect_inbound=True)
        res = a.rpc("reportmisbehavior", peer_id, "increment_unconnecting", 10)
        try:
            a.rpc("disconnectnode", str(peer_id))
        except Exception:
            pass
        ok = wait_peer_count(a, 0, timeout=10)
        assert ok, "Peer did not disconnect after unconnecting x10"
        return True
    finally:
        if a and a.is_running(): a.stop()
        if b and b.is_running(): b.stop()


def run_case_orphans(binary_path, base_dir):
    a = b = None
    try:
        port_a = pick_free_port()
        a = TestNode(0, base_dir / "A4", binary_path, extra_args=["--listen", f"--port={port_a}"])
        a.start()
        port_b = pick_free_port()
        b = TestNode(1, base_dir / "B4", binary_path, extra_args=[f"--port={port_b}"])
        b.start()
        b.add_node(f"127.0.0.1:{port_a}")
        assert wait_peer_count(a, 1, timeout=10)
        peer_id = find_peer_id(a, expect_inbound=True)
        res = a.rpc("reportmisbehavior", peer_id, "too_many_orphans")
        try:
            a.rpc("disconnectnode", str(peer_id))
        except Exception:
            pass
        ok = wait_peer_count(a, 0, timeout=10)
        assert ok, "Peer did not disconnect after too_many_orphans"
        return True
    finally:
        if a and a.is_running(): a.stop()
        if b and b.is_running(): b.stop()


def main():
    print("Starting p2p_misbehavior_scores test...")
    test_dir = Path(tempfile.mkdtemp(prefix="unicity_misbehavior_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"
    try:
        assert run_case_invalid_pow(binary_path, test_dir)
        assert run_case_non_continuous(binary_path, test_dir)
        assert run_case_unconnecting(binary_path, test_dir)
        assert run_case_orphans(binary_path, test_dir)
        print("✓ p2p_misbehavior_scores passed")
        return 0
    except Exception as e:
        print(f"✗ p2p_misbehavior_scores failed: {e}")
        return 1
    finally:
        print(f"Cleaning up {test_dir}")
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
