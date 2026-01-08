#!/usr/bin/env python3
"""Mocktime RPC and propagation (strict).

Ensures mocktime can be set/advanced/reset via RPC and nodes stay functional.
"""

import sys
import tempfile
import shutil
import time
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))

from test_node import TestNode
from util import wait_until, pick_free_port


def main():
    print("Starting p2p_eviction (mocktime strict) test...")

    # Setup test directory
    test_dir = Path(tempfile.mkdtemp(prefix="unicity_test_eviction_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node0 = None
    node1 = None

    try:
        # Start nodes with dynamic ports
        port0 = pick_free_port()
        node0 = TestNode(0, test_dir / "node0", binary_path,
                        extra_args=["--listen", f"--port={port0}"])
        node0.start()

        port1 = pick_free_port()
        node1 = TestNode(1, test_dir / "node1", binary_path,
                        extra_args=[f"--port={port1}"])
        node1.start()

        # Connect node1 -> node0
        res = node1.add_node(f"127.0.0.1:{port0}", "add")
        assert isinstance(res, dict) and res.get("success") is True, f"addnode failed: {res}"

        # Mine 3 blocks and wait for propagation
        node0.generate(3)
        def propagated():
            i0 = node0.get_info(); i1 = node1.get_info()
            return i0['blocks'] >= 3 and i1['blocks'] >= 3 and i0['bestblockhash'] == i1['bestblockhash']
        assert wait_until(propagated, timeout=30), "Failed to propagate initial blocks"

        # Strict mocktime checks
        current_time = int(time.time())
        r1 = node0.rpc("setmocktime", str(current_time))
        assert isinstance(r1, dict) and r1.get("success") is True, f"setmocktime failed: {r1}"

        future_time = current_time + (21 * 60)
        r2 = node0.rpc("setmocktime", str(future_time))
        assert isinstance(r2, dict) and r2.get("success") is True and r2.get("mocktime") == future_time, f"advance mocktime failed: {r2}"

        # Reset mocktime
        r3 = node0.rpc("setmocktime", "0")
        assert isinstance(r3, dict) and r3.get("success") is True, f"reset mocktime failed: {r3}"

        # Verify node still works after mocktime operations
        node0.generate(2)
        def synced5():
            i0 = node0.get_info(); i1 = node1.get_info()
            return i0['blocks'] == 5 and i1['blocks'] == 5 and i0['bestblockhash'] == i1['bestblockhash']
        assert wait_until(synced5, timeout=30), "Failed to reach height 5 in sync"

        # getpeerinfo must be a list
        peers0 = node0.get_peer_info()
        assert isinstance(peers0, list), f"getpeerinfo must return a list, got {type(peers0)}"

        print("✓ p2p_eviction (mocktime strict) passed")
        return 0

    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        if node0:
            print("\nNode0 last 30 lines of debug.log:")
            print(node0.read_log(30))
        if node1:
            print("\nNode1 last 30 lines of debug.log:")
            print(node1.read_log(30))
        return 1

    finally:
        if node0 and node0.is_running():
            node0.stop()
        if node1 and node1.is_running():
            node1.stop()
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
