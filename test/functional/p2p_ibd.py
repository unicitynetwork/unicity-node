#!/usr/bin/env python3
"""Initial Block Download (IBD) test.

Tests that a new node can sync an existing chain from a peer.

Scenario:
1. Start node0 and mine a long chain (50 blocks)
2. Start node1 (fresh, at genesis)
3. Connect node1 to node0
4. Verify node1 syncs the entire chain via IBD
"""

import sys
import tempfile
import shutil
import time
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))

from test_node import TestNode
from util import pick_free_port


def main():
    """Run the test."""
    print("Starting p2p_ibd test...")

    # Setup test directory
    test_dir = Path(tempfile.mkdtemp(prefix="unicity_test_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node0 = None
    node1 = None

    try:
        # Choose dynamic ports to avoid conflicts
        port0 = pick_free_port()
        port1 = pick_free_port()

        # Start node0 (will mine the chain)
        print(f"Starting node0 (listening on port {port0})...")
        node0 = TestNode(0, test_dir / "node0", binary_path,
                        extra_args=["--listen", f"--port={port0}"])
        node0.start()

        time.sleep(1)

        # Mine a long chain on node0
        print("\n=== Phase 1: Building chain on node0 ===")
        print("Mining 50 blocks on node0...")
        blocks = node0.generate(50)

        info0 = node0.get_info()
        print(f"Node0 after mining: {info0['blocks']} blocks")
        print(f"  Tip: {info0['bestblockhash'][:16]}...")

        assert info0['blocks'] >= 50, f"Node0 should have at least 50 blocks, got {info0['blocks']}"

        # Start node1 (fresh node at genesis)
        print("\n=== Phase 2: Starting fresh node (at genesis) ===")
        print(f"Starting node1 (port {port1})...")
        node1 = TestNode(1, test_dir / "node1", binary_path,
                        extra_args=[f"--port={port1}"])
        node1.start()

        time.sleep(1)

        # Verify node1 is at genesis
        info1 = node1.get_info()
        print(f"Node1 initial state: {info1['blocks']} blocks")
        assert info1['blocks'] == 0, f"Node1 should start at genesis, got {info1['blocks']}"

        # Connect node1 to node0 to trigger IBD
        print("\n=== Phase 3: Connecting node1 to node0 (triggering IBD) ===")
        print("Connecting node1 to node0...")
        result = node1.add_node(f"127.0.0.1:{port0}", "add")
        print(f"Connection result: {result}")

        # Wait for IBD to complete
        print("\nWaiting for IBD to complete...")
        print("(Node1 should sync all 50 blocks from node0)")

        # Poll node1's height until it catches up (or timeout after 30 seconds)
        max_wait = 30
        start_time = time.time()
        last_height = 0

        while time.time() - start_time < max_wait:
            info1 = node1.get_info()
            current_height = info1['blocks']

            if current_height != last_height:
                print(f"  Node1 syncing: {current_height}/50 blocks ({current_height*100//50}%)")
                last_height = current_height

            if current_height >= 50:
                print(f"  Node1 reached height {current_height}!")
                break

            time.sleep(0.5)

        # Final verification
        print("\n=== Phase 4: Verifying sync ===")
        info0 = node0.get_info()
        info1 = node1.get_info()

        print(f"Node0: height={info0['blocks']}, tip={info0['bestblockhash'][:16]}...")
        print(f"Node1: height={info1['blocks']}, tip={info1['bestblockhash'][:16]}...")

        # Assert node1 has at least 50 blocks (allow extra due to regtest race)
        assert info1['blocks'] >= 50, f"Node1 should have at least 50 blocks, got {info1['blocks']}"

        # Assert both nodes have same tip (this is the real test - they must be synced)
        assert info0['bestblockhash'] == info1['bestblockhash'], \
            f"Nodes have different tips:\n  node0={info0['bestblockhash']}\n  node1={info1['bestblockhash']}"

        print("\n✓ Test passed! IBD successful:")
        print(f"  Node1 synced all 50 blocks from node0")
        print(f"  Both nodes at height 50 with tip: {info0['bestblockhash'][:16]}...")

    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()

        # Print logs on failure
        if node0:
            print("\n--- Node0 last 30 lines ---")
            print(node0.read_log(30))
        if node1:
            print("\n--- Node1 last 30 lines ---")
            print(node1.read_log(30))
        return 1

    finally:
        # Cleanup
        if node0 and node0.is_running():
            print("Stopping node0...")
            node0.stop()
        if node1 and node1.is_running():
            print("Stopping node1...")
            node1.stop()

        print(f"Cleaning up test directory: {test_dir}")
        shutil.rmtree(test_dir, ignore_errors=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
