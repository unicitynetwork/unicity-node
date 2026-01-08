#!/usr/bin/env python3
"""Test the --suspiciousreorgdepth feature.

Tests that nodes correctly halt when presented with deep reorgs that exceed
their configured suspicious reorg depth threshold.
"""

import sys
import tempfile
import shutil
import time
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))

from test_node import TestNode


def main():
    """Run the suspicious reorg test."""
    print("\n=== Suspicious Reorg Detection Test ===\n")

    # Setup test directory
    test_dir = Path(tempfile.mkdtemp(prefix="cbc_susp_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node0 = None
    node1 = None

    try:
        # Test 1: Reorg within threshold should be accepted
        print("=== Test 1: Reorg within threshold ===\n")

        node0 = TestNode(0, test_dir / "test1_node0", binary_path,
                        extra_args=["--listen", "--port=29590", "--suspiciousreorgdepth=20"])
        node1 = TestNode(1, test_dir / "test1_node1", binary_path,
                        extra_args=["--listen", "--port=29591", "--suspiciousreorgdepth=20"])

        node0.start()
        node1.start()
        time.sleep(1)

        # Both start at genesis
        assert node0.get_info()['blocks'] == 0
        assert node1.get_info()['blocks'] == 0
        print("✓ Both nodes at genesis")

        # Node0 mines 9 blocks (chain A) - ISOLATED
        print("Node0 mining 9 blocks...")
        node0.generate(9)
        time.sleep(0.5)  # Let miner finish
        info0 = node0.get_info()
        blocks0 = info0['blocks']
        print(f"✓ Node0 at height {blocks0}")

        # Node1 mines 20 blocks (chain B - longer) - ISOLATED
        print("Node1 mining 20 blocks...")
        node1.generate(20)
        time.sleep(0.5)  # Let miner finish
        info1 = node1.get_info()
        blocks1 = info1['blocks']
        print(f"✓ Node1 at height {blocks1}")

        assert blocks1 > blocks0, "Node1 must have more blocks"

        # Reorg depth = number of blocks node0 needs to disconnect
        reorg_depth = blocks0
        print(f"✓ Reorg depth will be {reorg_depth} blocks")

        # Connect - node0 should accept the reorg (within threshold)
        print(f"\nConnecting (node0 should accept {reorg_depth}-block reorg)...")
        node0.add_node("127.0.0.1:29591", "add")
        node1.add_node("127.0.0.1:29590", "add")

        # Wait for sync
        time.sleep(3)
        info0 = node0.get_info()

        assert info0['blocks'] >= blocks1, f"Expected node0 to sync to at least {blocks1}, got {info0['blocks']}"
        print(f"✓ Node0 accepted {reorg_depth}-block reorg (within threshold)\n")

        # Cleanup test 1
        node0.stop()
        node1.stop()
        time.sleep(1)

        # Test 2: Reorg exceeding threshold should trigger shutdown
        print("=== Test 2: Deep reorg triggers shutdown ===\n")

        node0 = TestNode(0, test_dir / "test2_node0", binary_path,
                        extra_args=["--listen", "--port=29590", "--suspiciousreorgdepth=10"])
        node1 = TestNode(1, test_dir / "test2_node1", binary_path,
                        extra_args=["--listen", "--port=29591", "--suspiciousreorgdepth=10"])

        node0.start()
        node1.start()
        time.sleep(1)

        # Both start at genesis
        assert node0.get_info()['blocks'] == 0
        assert node1.get_info()['blocks'] == 0
        print("✓ Both nodes at genesis")

        # Node0 mines 50 blocks - ISOLATED
        print("Node0 mining 50 blocks...")
        node0.generate(50)
        time.sleep(1)  # Let miner finish
        info0 = node0.get_info()
        blocks0 = info0['blocks']
        print(f"✓ Node0 at height {blocks0}")

        # Node1 mines 70 blocks - ISOLATED (more work)
        print("Node1 mining 70 blocks...")
        node1.generate(70)
        time.sleep(1)  # Let miner finish
        info1 = node1.get_info()
        blocks1 = info1['blocks']
        print(f"✓ Node1 at height {blocks1}")

        assert blocks1 > blocks0, "Node1 must have more blocks"

        reorg_depth = blocks0
        print(f"✓ Reorg would be {reorg_depth} blocks (exceeds threshold of 10)")

        # Connect - node0 should refuse and shut down
        print(f"\nConnecting (node0 should refuse {reorg_depth}-block reorg and shut down)...")
        node0.add_node("127.0.0.1:29591", "add")
        node1.add_node("127.0.0.1:29590", "add")

        # Wait for headers to be exchanged and reorg detected
        # (need enough time for RandomX PoW validation of all headers)
        time.sleep(5)

        # Check logs for shutdown message
        log = node0.read_log()
        assert "Suspicious reorg detected" in log or "suspicious reorg" in log.lower(), \
            "Expected suspicious reorg detection in logs"
        assert "Shutting down" in log, "Expected shutdown initiation in logs"
        print("✓ Node0 detected deep reorg and initiated shutdown")

        print("\n✓ All suspicious reorg tests passed!")
        return 0

    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()

        # Print logs on failure
        if node0:
            print("\n--- Node0 last 50 lines ---")
            print(node0.read_log(50))
        if node1:
            print("\n--- Node1 last 50 lines ---")
            print(node1.read_log(50))
        return 1

    finally:
        # Cleanup
        if node0 and node0.is_running():
            node0.stop()
        if node1 and node1.is_running():
            node1.stop()

        print(f"\nCleaning up test directory: {test_dir}")
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
