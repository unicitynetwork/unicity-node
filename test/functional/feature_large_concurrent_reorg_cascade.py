#!/usr/bin/env python3
"""Test large-scale concurrent reorg cascade during active reorganization.

This test verifies that a node can handle a second, longer reorg request
while already processing an initial reorg with much larger chains:

1. Node 0 starts on Chain A (3,000 blocks)
2. Node 0 connects to Node 1 with Chain B (4,000 blocks) → reorg begins
3. While reorg is in progress, Node 0 connects to Node 2 with Chain C (5,000 blocks)
4. Verify Node 0 properly abandons the intermediate reorg and switches to Chain C

This tests the node's ability to prioritize and switch to the longest chain
even when a reorg is already in progress, at a larger scale than the basic test.
The suspiciousreorgdepth is set very high to allow deep reorgs without
triggering protection mechanisms.
"""

import sys
import time
import tempfile
import shutil
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))

from test_node import TestNode
from util import pick_free_port, wait_until


def main():
    print("=" * 70)
    print("=== Large-Scale Concurrent Reorg Cascade Test (3000→4000→5000) ===")
    print("=" * 70)
    print()

    # Optional flag to keep data around for debugging
    no_cleanup = "--no-cleanup" in sys.argv

    # Create test directories
    test_base = Path(tempfile.mkdtemp(prefix="unicity_large_reorg_"))

    node0 = None
    node1 = None
    node2 = None

    try:
        # Pick ports for all nodes
        port0 = pick_free_port()
        port1 = pick_free_port()
        port2 = pick_free_port()

        # Step 1: Load pre-generated reorg chains BEFORE starting nodes
        print("Step 1: Loading pre-generated reorg chains...")
        chain_a = Path(__file__).parent / "test_chains" / "chain_3000_blocks"
        chain_b = Path(__file__).parent / "test_chains" / "chain_4000_blocks"
        chain_c = Path(__file__).parent / "test_chains" / "chain_5000_blocks"

        for chain in [chain_a, chain_b, chain_c]:
            if not chain.exists():
                print(f"✗ Error: Chain not found: {chain}")
                print("If you cloned with Git LFS enabled, run: git lfs pull && git lfs checkout")
                print("Otherwise, generate reorg chains with: python3 test/functional/generate_reorg_chains.py")
                return 1

        print("  Copying chain_3000_blocks to node0...")
        shutil.rmtree(test_base / "node0", ignore_errors=True)
        shutil.copytree(chain_a, test_base / "node0")

        print("  Copying chain_4000_blocks to node1...")
        shutil.rmtree(test_base / "node1", ignore_errors=True)
        shutil.copytree(chain_b, test_base / "node1")

        print("  Copying chain_5000_blocks to node2...")
        shutil.rmtree(test_base / "node2", ignore_errors=True)
        shutil.copytree(chain_c, test_base / "node2")

        print("  ✓ Chains loaded\n")

        # Step 2: Start 3 nodes with high suspiciousreorgdepth to disable protection
        print("Step 2: Starting 3 nodes with disabled suspicious reorg detection...")

        node0 = TestNode(0, test_base / "node0",
                        extra_args=["--listen", f"--port={port0}", "--connect=0",
                                   "--suspiciousreorgdepth=20000", "--loglevel=trace"])
        node1 = TestNode(1, test_base / "node1",
                        extra_args=["--listen", f"--port={port1}", "--connect=0",
                                   "--suspiciousreorgdepth=20000"])
        node2 = TestNode(2, test_base / "node2",
                        extra_args=["--listen", f"--port={port2}", "--connect=0",
                                   "--suspiciousreorgdepth=20000"])

        node0.start()
        node1.start()
        node2.start()

        time.sleep(2)

        print(f"  ✓ Node 0: port {port0}")
        print(f"  ✓ Node 1: port {port1}")
        print(f"  ✓ Node 2: port {port2}\n")

        # Step 3: Verify chains loaded correctly
        # Use longer timeout - large chains take time to load from disk
        print("Step 3: Verifying chains loaded correctly...")
        info0 = node0.get_info(timeout=60)
        info1 = node1.get_info(timeout=60)
        info2 = node2.get_info(timeout=60)

        height_a = info0["blocks"]
        tip_a = info0["bestblockhash"]
        print(f"  ✓ Chain A (node0): height={height_a}, tip={tip_a[:16]}...")

        height_b = info1["blocks"]
        tip_b = info1["bestblockhash"]
        print(f"  ✓ Chain B (node1): height={height_b}, tip={tip_b[:16]}...")

        height_c = info2["blocks"]
        tip_c = info2["bestblockhash"]
        print(f"  ✓ Chain C (node2): height={height_c}, tip={tip_c[:16]}...\n")

        assert height_a == 3000, f"Expected height 3000, got {height_a}"
        assert height_b == 4000, f"Expected height 4000, got {height_b}"
        assert height_c == 5000, f"Expected height 5000, got {height_c}"

        # Verify chains share base but have different tips
        assert tip_a != tip_b, "Chain A and B should have different tips"
        assert tip_a != tip_c, "Chain A and C should have different tips"
        assert tip_b != tip_c, "Chain B and C should have different tips"
        print("  ✓ All chains share base but have diverged\n")

        # Step 4: Connect Node 0 to Node 1 (trigger first reorg: 3k → 4k)
        print("Step 4: Connecting Node 0 to Node 1 (3000→4000 reorg)...")
        print("  (This may take time as node processes headers...)")
        node0.add_node(f"127.0.0.1:{port1}", "add", timeout=120)

        # Give it a short time to start syncing but not complete
        print("  Waiting 10 seconds for initial reorg to begin...")
        time.sleep(10)

        # Check Node 0 status during initial reorg (may timeout due to mutex)
        info0 = node0.get_info_safe(timeout=10)
        if info0:
            print(f"  Node 0 status after 10s: height={info0['blocks']}, " +
                  f"headers={info0.get('headers', info0['blocks'])}")
        else:
            print("  Node 0 busy processing headers...")

        # Step 5: Immediately connect Node 0 to Node 2 (trigger second reorg: ? → 5000)
        # This happens while the first reorg is still in progress
        print("\nStep 5: Connecting Node 0 to Node 2 (introducing 5000-block chain mid-reorg)...")
        node0.add_node(f"127.0.0.1:{port2}", "add", timeout=120)

        # Give brief moment for headers to propagate
        time.sleep(2)
        info0 = node0.get_info_safe(timeout=10)
        if info0:
            print(f"  Node 0 status after both connections: height={info0['blocks']}, " +
                  f"headers={info0.get('headers', info0['blocks'])}")
        else:
            print("  Node 0 busy processing headers...")

        # Step 6: Wait for Node 0 to stabilize on longest chain (Chain C - 5000 blocks)
        # NOTE: RPC may timeout during header processing (validation_mutex_ held).
        print("\nStep 6: Waiting for Node 0 to complete cascade reorg to 5,000 blocks...")
        print("  (This validates 5,000 headers - may take a few minutes)")
        max_wait = 600  # 10 minutes for full header sync
        start_time = time.time()

        last_height = -1
        stable_count = 0
        last_update = time.time()

        while time.time() - start_time < max_wait:
            info0 = node0.get_info_safe(timeout=10)
            if info0 is None:
                # RPC timed out - node is busy with header processing
                elapsed = time.time() - start_time
                if elapsed - last_update > 15:
                    print(f"  [{elapsed:6.1f}s] RPC busy (header processing)...")
                    last_update = elapsed
                if not node0.is_running():
                    raise Exception("Node 0 crashed during header sync")
                time.sleep(2)
                continue

            height = info0["blocks"]
            headers = info0.get("headers", height)

            # Show progress when height changes or every 15 seconds
            if height != last_height or (time.time() - last_update > 15):
                elapsed = time.time() - start_time
                print(f"  [{elapsed:6.1f}s] Node 0: height={height}, headers={headers}")
                last_height = height
                last_update = time.time()
                stable_count = 0

            # Node 0 should eventually reach height 5000 (Chain C)
            if height == 5000:
                stable_count += 1
                # Wait for stability (multiple checks at height 5000)
                if stable_count >= 3:
                    elapsed = time.time() - start_time
                    print(f"  ✓ Node 0 reached and stabilized at height 5,000 (took {elapsed:.1f}s)")
                    break

            time.sleep(1)
        else:
            print(f"  ✗ TIMEOUT: Node 0 did not reach height 5,000 in {max_wait}s")
            final_info = node0.get_info_safe(timeout=30)
            if final_info:
                print(f"  Final state: height={final_info['blocks']}, " +
                      f"headers={final_info.get('headers', final_info['blocks'])}")
            print("\n--- Node 0 last 100 lines of log ---")
            print(node0.read_log(100))
            raise Exception("Node 0 failed to complete large concurrent cascade reorg")

        # Step 7: Verify final state matches Chain C
        print("\nStep 7: Verifying final chain state...")

        final_info = node0.get_info()
        final_height = final_info["blocks"]
        final_tip = final_info["bestblockhash"]

        print(f"  Node 0 final state:")
        print(f"    Height: {final_height}")
        print(f"    Tip:    {final_tip[:16]}...")
        print(f"  Expected (Chain C):")
        print(f"    Height: 5000")
        print(f"    Tip:    {tip_c[:16]}...")

        # Verify Node 0 is on Chain C (5000 blocks)
        assert final_height == 5000, \
            f"Expected height 5000, got {final_height}"

        assert final_tip == tip_c, \
            f"Node 0 tip mismatch\n  Got:      {final_tip}\n  Expected: {tip_c}"

        print("\n  ✓ Node 0 successfully switched to longest chain (Chain C)")
        print("  ✓ Large-scale concurrent reorg cascade handled correctly")
        print("  ✓ Node properly abandoned intermediate reorg for 5000-block chain")

        print("\n" + "=" * 70)
        print("✓ Large-Scale Concurrent Reorg Cascade Test PASSED")
        print("=" * 70)

        return 0

    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()

        # Print logs on failure
        if node0 and node0.is_running():
            print("\n--- Node 0 last 100 lines ---")
            print(node0.read_log(100))
        if node1 and node1.is_running():
            print("\n--- Node 1 last 50 lines ---")
            print(node1.read_log(50))
        if node2 and node2.is_running():
            print("\n--- Node 2 last 50 lines ---")
            print(node2.read_log(50))

        return 1

    finally:
        # Clean shutdown
        print("\nStopping nodes...")
        if node0 and node0.is_running():
            node0.stop()
        if node1 and node1.is_running():
            node1.stop()
        if node2 and node2.is_running():
            node2.stop()

        # Cleanup (or preserve for debugging)
        if no_cleanup:
            print(f"\nTest directory preserved (--no-cleanup): {test_base}")
            print(f"  Node 0 data: {test_base / 'node0'}")
            print(f"  Node 1 data: {test_base / 'node1'}")
            print(f"  Node 2 data: {test_base / 'node2'}")
        else:
            print(f"Cleaning up test directory: {test_base}")
            shutil.rmtree(test_base, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
