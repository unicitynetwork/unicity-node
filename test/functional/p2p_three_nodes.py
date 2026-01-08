#!/usr/bin/env python3
"""Three-node P2P chain test.

Tests that blocks propagate through a chain of three nodes:
node0 -> node1 -> node2

This verifies that node1 can relay blocks it receives from node0 to node2.
"""

import sys
import tempfile
import shutil
import time
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))

from test_node import TestNode
from util import wait_until
from util import pick_free_port


def main():
    """Run the test."""
    print("Starting p2p_three_nodes test...")

    # Setup test directory
    test_dir = Path(tempfile.mkdtemp(prefix="unicity_test_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node0 = None
    node1 = None
    node2 = None

    try:
        # Start node0 (mining node) on dynamic port
        port0 = pick_free_port()
        print(f"Starting node0 (port {port0})...")
        node0 = TestNode(0, test_dir / "node0", binary_path,
                        extra_args=["--listen", f"--port={port0}"])
        node0.start()

        # Start node1 (relay node) on dynamic port
        port1 = pick_free_port()
        print(f"Starting node1 (port {port1})...")
        node1 = TestNode(1, test_dir / "node1", binary_path,
                        extra_args=["--listen", f"--port={port1}"])
        node1.start()

        # Start node2 (receiving node) on dynamic port - must listen to receive relayed blocks
        port2 = pick_free_port()
        print(f"Starting node2 (port {port2})...")
        node2 = TestNode(2, test_dir / "node2", binary_path,
                        extra_args=["--listen", f"--port={port2}"])
        node2.start()

        time.sleep(1)

        # Build network topology: node0 -> node1 -> node2
        print("\nBuilding network topology: node0 -> node1 -> node2")

        print("Connecting node1 to node0 (outbound)...")
        node1.add_node(f"127.0.0.1:{port0}", "add")

        print("Connecting node2 to node1 (outbound)...")
        node2.add_node(f"127.0.0.1:{port1}", "add")

        # Wait for connections to establish
        time.sleep(2)

        # Verify all nodes start at genesis
        info0 = node0.get_info()
        info1 = node1.get_info()
        info2 = node2.get_info()

        print(f"\nInitial state:")
        print(f"  Node0: {info0['blocks']} blocks")
        print(f"  Node1: {info1['blocks']} blocks")
        print(f"  Node2: {info2['blocks']} blocks")

        assert info0['blocks'] == 0, f"Node0 should start at genesis, got {info0['blocks']}"
        assert info1['blocks'] == 0, f"Node1 should start at genesis, got {info1['blocks']}"
        assert info2['blocks'] == 0, f"Node2 should start at genesis, got {info2['blocks']}"

        # Mine 10 blocks on node0
        print("\nMining 10 blocks on node0...")
        blocks = node0.generate(10)
        if isinstance(blocks, list) and len(blocks) > 0:
            print(f"Mined blocks: {[b[:16] + '...' for b in blocks[:3]]} ...")
        else:
            print(f"Mined {len(blocks) if isinstance(blocks, list) else 'unknown'} blocks")

        # Wait for propagation through the chain (up to 20s)
        print("Waiting for blocks to propagate through node0 -> node1 -> node2...")
        def synced():
            try:
                i0 = node0.get_info()
                i1 = node1.get_info()
                i2 = node2.get_info()
                return (
                    i0['blocks'] >= 10 and i1['blocks'] >= 10 and i2['blocks'] >= 10 and
                    i0['bestblockhash'] == i1['bestblockhash'] == i2['bestblockhash']
                )
            except Exception:
                return False
        ok = wait_until(synced, timeout=20, check_interval=0.5)

        # Verify all nodes synced to height >=10 and same tip
        info0 = node0.get_info()
        info1 = node1.get_info()
        info2 = node2.get_info()

        print(f"\nFinal state:")
        print(f"  Node0: height={info0['blocks']}, tip={info0['bestblockhash'][:16]}...")
        print(f"  Node1: height={info1['blocks']}, tip={info1['bestblockhash'][:16]}...")
        print(f"  Node2: height={info2['blocks']}, tip={info2['bestblockhash'][:16]}...")

        assert ok, "Nodes did not converge to same tip within timeout"

        print("\n✓ Test passed! Blocks successfully propagated through chain:")
        print("  node0 (mined) -> node1 (relayed) -> node2 (synced)")
        print(f"  All nodes at height 10 with tip: {info0['bestblockhash'][:16]}...")

    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()

        # Print logs on failure
        for i, node in enumerate([node0, node1, node2]):
            if node:
                print(f"\n--- Node{i} last 20 lines ---")
                print(node.read_log(20))
        return 1

    finally:
        # Cleanup
        for i, node in enumerate([node0, node1, node2]):
            if node and node.is_running():
                print(f"Stopping node{i}...")
                node.stop()

        print(f"Cleaning up test directory: {test_dir}")
        shutil.rmtree(test_dir, ignore_errors=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
