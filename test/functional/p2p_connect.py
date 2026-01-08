#!/usr/bin/env python3
"""P2P connection test (strict).

Ensures two nodes connect, report connected=true via RPC, and propagate blocks.
"""

import sys
import tempfile
import shutil
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))

from test_node import TestNode
from util import wait_until, pick_free_port


def main():
    print("Starting p2p_connect (strict) test...")

    # Setup test directory
    test_dir = Path(tempfile.mkdtemp(prefix="unicity_test_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node0 = None
    node1 = None

    try:
        # Pick dynamic ports to avoid conflicts in parallel runs
        port0 = pick_free_port()
        port1 = pick_free_port()

        # Start node0 with listening enabled
        node0 = TestNode(0, test_dir / "node0", binary_path,
                        extra_args=["--listen", f"--port={port0}"])
        node0.start()

        # Start node1
        node1 = TestNode(1, test_dir / "node1", binary_path,
                        extra_args=[f"--port={port1}"])
        node1.start()

        # Connect node1 to node0
        result = node1.add_node(f"127.0.0.1:{port0}", "add")
        assert isinstance(result, dict) and result.get("success") is True, f"addnode failed: {result}"

        # Wait for both nodes to report a connected peer via RPC
        def connected(n):
            peers = n.get_peer_info()
            return isinstance(peers, list) and any(p.get("connected") is True for p in peers)
        assert wait_until(lambda: connected(node0), timeout=15), "node0 did not report a connected peer"
        assert wait_until(lambda: connected(node1), timeout=15), "node1 did not report a connected peer"

        # Generate and verify propagation
        node0.generate(5)

        def synced():
            i0 = node0.get_info()
            i1 = node1.get_info()
            return i1['blocks'] == i0['blocks'] == 5 and i0['bestblockhash'] == i1['bestblockhash']
        assert wait_until(synced, timeout=30), "Blocks/tips did not synchronize"

        print("✓ p2p_connect (strict) passed")
        return 0

    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()

        # Print logs on failure
        if node0:
            print("\nNode0 last 30 lines of debug.log:")
            print(node0.read_log(30))
        if node1:
            print("\nNode1 last 30 lines of debug.log:")
            print(node1.read_log(30))
        return 1

    finally:
        # Cleanup
        if node0 and node0.is_running():
            node0.stop()
        if node1 and node1.is_running():
            node1.stop()
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
