#!/usr/bin/env python3
"""DoS protection via test-only RPC (strict).

Uses reportmisbehavior RPC to deterministically trigger disconnects and
verifies them via getpeerinfo.
"""

import sys
import tempfile
import shutil
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))

from test_node import TestNode
from util import pick_free_port, wait_until


def main():
    print("Starting p2p_dos_headers (strict) test...")

    # Setup test directory
    test_dir = Path(tempfile.mkdtemp(prefix="unicity_test_dos_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node0 = None
    node1 = None

    try:
        # Start nodes
        port0 = pick_free_port()
        node0 = TestNode(0, test_dir / "node0", binary_path,
                        extra_args=["--listen", f"--port={port0}"])
        node0.start()

        port1 = pick_free_port()
        node1 = TestNode(1, test_dir / "node1", binary_path,
                        extra_args=[f"--port={port1}"])
        node1.start()

        # Connect and wait for peer listing
        r = node1.add_node(f"127.0.0.1:{port0}", "add")
        assert isinstance(r, dict) and r.get("success") is True, f"addnode failed: {r}"

        def have_peer(n):
            peers = n.get_peer_info()
            return isinstance(peers, list) and len(peers) >= 1 and peers[0].get("connected") is True
        assert wait_until(lambda: have_peer(node0), timeout=15), "node0 did not report connected peer"
        assert wait_until(lambda: have_peer(node1), timeout=15), "node1 did not report connected peer"

        # Get node0's view of peer_id
        peers0 = node0.get_peer_info()
        assert len(peers0) >= 1, "node0 expected at least 1 peer"
        peer_id = peers0[0].get("id")
        assert isinstance(peer_id, int), f"invalid peer id: {peer_id}"

        # 1) invalid_pow should set should_disconnect=true; manual connections are not auto-dropped
        res1 = node0.rpc("reportmisbehavior", str(peer_id), "invalid_pow")
        assert isinstance(res1, dict) and res1.get("applied") == 1, f"reportmisbehavior invalid_pow failed: {res1}"
        assert res1.get("should_disconnect") in (True, "true"), f"should_disconnect not set after invalid_pow: {res1}"

        # Force disconnect via RPC and verify drop
        d1 = node0.rpc("disconnectnode", str(peer_id))
        assert isinstance(d1, dict) and d1.get("success") is True, f"disconnectnode failed: {d1}"
        assert wait_until(lambda: not any(p.get("id") == peer_id and p.get("connected") for p in node0.get_peer_info()), timeout=15), "Peer not disconnected after invalid_pow"
        # Ensure the outbound side also dropped before reconnecting
        peers1 = node1.get_peer_info()
        if isinstance(peers1, list) and len(peers1) > 0:
            pid1 = peers1[0].get("id")
            if isinstance(pid1, int):
                node1.rpc("disconnectnode", str(pid1))
        assert wait_until(lambda: len(node1.get_peer_info()) == 0, timeout=15), "node1 still thinks it's connected"

        # Clear discouraged addresses (invalid_pow discourages 127.0.0.1)
        node0.rpc("reportmisbehavior", "0", "clear_discouraged")

        # Reconnect for non_continuous test
        r = node1.add_node(f"127.0.0.1:{port0}", "add")
        assert isinstance(r, dict) and r.get("success") is True
        assert wait_until(lambda: have_peer(node0), timeout=15), "node0 did not reconnect"
        peers0b = node0.get_peer_info(); new_peer_id = peers0b[0].get("id")
        assert isinstance(new_peer_id, int)

        # 2) non_continuous 5x should reach threshold; then we disconnect via RPC
        res2 = node0.rpc("reportmisbehavior", str(new_peer_id), "non_continuous", "5")
        assert isinstance(res2, dict) and res2.get("applied") == 5, f"reportmisbehavior non_continuous failed: {res2}"
        assert res2.get("should_disconnect") in (True, "true"), f"should_disconnect not set after non_continuous: {res2}"
        d2 = node0.rpc("disconnectnode", str(new_peer_id))
        assert isinstance(d2, dict) and d2.get("success") is True, f"disconnectnode failed: {d2}"
        assert wait_until(lambda: not any(p.get("id") == new_peer_id and p.get("connected") for p in node0.get_peer_info()), timeout=15), "Peer not disconnected after non_continuous"

        print("✓ p2p_dos_headers (strict) passed")
        return 0

    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        if node0:
            print("\nNode0 last 50 lines of debug.log:")
            print(node0.read_log(50))
        if node1:
            print("\nNode1 last 50 lines of debug.log:")
            print(node1.read_log(50))
        return 1

    finally:
        if node0 and node0.is_running():
            node0.stop()
        if node1 and node1.is_running():
            node1.stop()
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
