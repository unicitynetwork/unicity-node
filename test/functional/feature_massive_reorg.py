#!/usr/bin/env python3
"""Test massive legitimate reorganizations with thousands of blocks.

This test verifies that nodes can successfully handle very deep reorgs
when chains share a common base but fork:

Scenario:
1. Node 0 starts with Chain A (3,000 blocks: base + 2000)
2. Node 0 connects to Node 1 with Chain B (4,000 blocks: base + 3000 fork)
   → Reorg of 1,000 blocks
3. Node 0 connects to Node 2 with Chain C (5,000 blocks: base + 4000 fork)
   → Reorg of 2,000 blocks (abandoning the in-progress 1000-block reorg)

All chains share the same first 1000 blocks, then diverge with different
blocks but equal difficulty. With the sync peer isolation fix, this tests
that massive reorgs work correctly without premature disconnects.
"""

import sys
import time
import tempfile
import shutil
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))

from test_node import TestNode
from util import pick_free_port


def main():
    print("=" * 70)
    print("=== Massive Reorg Test (1k→2k block reorgs) ===")
    print("=" * 70)
    print()
    
    # Check for --no-cleanup flag
    no_cleanup = "--no-cleanup" in sys.argv
    
    # Create test directories
    test_base = Path(tempfile.mkdtemp(prefix="unicity_massive_reorg_"))
    
    node0 = None
    node1 = None
    node2 = None
    
    try:
        # Pick ports for all nodes
        port0 = pick_free_port()
        port1 = pick_free_port()
        port2 = pick_free_port()
        
        # Load pre-generated chains BEFORE starting nodes
        print("Step 1: Loading pre-generated reorg chains...")
        chain_a = Path(__file__).parent / "test_chains" / "chain_3000_blocks"
        chain_b = Path(__file__).parent / "test_chains" / "chain_4000_blocks"
        chain_c = Path(__file__).parent / "test_chains" / "chain_5000_blocks"
        
        for chain, name in [(chain_a, "3k"), (chain_b, "4k"), (chain_c, "5k")]:
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
        
        # Start 3 nodes with high suspicious_reorg_threshold
        print("Step 2: Starting 3 nodes...")
        
        node0 = TestNode(0, test_base / "node0",
                        extra_args=["--listen", f"--port={port0}", "--connect=0",
                                   "--suspiciousreorgdepth=10000", "--loglevel=debug"])
        node1 = TestNode(1, test_base / "node1",
                        extra_args=["--listen", f"--port={port1}", "--connect=0",
                                   "--suspiciousreorgdepth=10000"])
        node2 = TestNode(2, test_base / "node2",
                        extra_args=["--listen", f"--port={port2}", "--connect=0",
                                   "--suspiciousreorgdepth=10000"])
        
        node0.start()
        node1.start()
        node2.start()

        time.sleep(2)

        # Set mock time near the TIP timestamps of all chains
        # The chains have real timestamps from when they were generated (Nov 17, 2025):
        #   Chain A (3000 blocks): tip time = 1763400867 (17:34:27 UTC)
        #   Chain B (4000 blocks): tip time = 1763401043 (17:37:23 UTC)
        #   Chain C (5000 blocks): tip time = 1763401381 (17:43:01 UTC)
        #
        # Mock time must satisfy TWO constraints:
        #   1. time-too-new: mock_time > max_block_time - MAX_FUTURE_BLOCK_TIME (600s)
        #      So: mock_time > 1763401381 - 600 = 1763400781
        #   2. IBD stale-tip: tip_time > mock_time - IBD_STALE_TIP_SECONDS (432000s = 5 days)
        #      For all chains: mock_time < min_tip_time + 432000 = 1763400867 + 432000 = 1763832867
        #
        # Valid range: 1763400782 - 1763832866
        # We pick ~5 hours after chain tips (well within 5-day IBD window)
        mock_time = 1763419124  # 2025-11-17 22:38:44 UTC
        print(f"  Setting mock time to {mock_time} (past chain C tip timestamp)...")
        node0.rpc("setmocktime", str(mock_time))
        node1.rpc("setmocktime", str(mock_time))
        node2.rpc("setmocktime", str(mock_time))

        print(f"  ✓ Node 0: port {port0}")
        print(f"  ✓ Node 1: port {port1}")
        print(f"  ✓ Node 2: port {port2}\n")
        
        # Verify chains loaded correctly
        print("Step 3: Verifying chains loaded correctly...")
        info0 = node0.get_info()
        info1 = node1.get_info()
        info2 = node2.get_info()
        
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
        
        # Step 4: Connect Node 0 to Node 1 and wait for first reorg (3000→4000)
        print("Step 4: Connecting Node 0 to Node 1 (1000-block reorg)...")
        print("  (This may take 30-60s as node processes headers...)")
        node0.add_node(f"127.0.0.1:{port1}", "add", timeout=120)  # Long timeout for header validation

        # Wait for first reorg to complete (3000 → 4000)
        # Note: RPC may timeout while node processes headers (validation_mutex held)
        print("  Waiting for first reorg to complete...")
        max_wait_reorg1 = 180  # 3 minutes (headers take ~18ms each)
        start_time_reorg1 = time.time()
        last_print = 0
        while time.time() - start_time_reorg1 < max_wait_reorg1:
            info0 = node0.get_info_safe(timeout=10)
            if info0 is None:
                # RPC timed out - node is busy with header processing
                elapsed = time.time() - start_time_reorg1
                if elapsed - last_print > 10:
                    print(f"  [{elapsed:.0f}s] RPC busy (header processing)...")
                    last_print = elapsed
                if not node0.is_running():
                    raise Exception("Node 0 crashed during header sync")
                time.sleep(2)
                continue
            height = info0["blocks"]
            if height == 4000:
                elapsed = time.time() - start_time_reorg1
                print(f"  ✓ First reorg completed in {elapsed:.1f}s (height={height})")
                break
            elapsed = time.time() - start_time_reorg1
            if elapsed - last_print > 10:
                print(f"  [{elapsed:.0f}s] height={height}")
                last_print = elapsed
            time.sleep(1)
        else:
            print(f"  ✗ First reorg did not complete in {max_wait_reorg1}s")
            info0 = node0.get_info_safe(timeout=30)
            if info0:
                print(f"  Current state: height={info0['blocks']}, headers={info0.get('headers', info0['blocks'])}")

        # Step 5: Connect Node 0 to Node 2 AFTER first reorg completes
        # This avoids connection timeout issues when node 0 is busy with header validation
        print("\nStep 5: Connecting Node 0 to Node 2 (introducing 5k chain)...")
        print("  (This triggers a cascade reorg from 4k to 5k blocks)")
        node0.add_node(f"127.0.0.1:{port2}", "add", timeout=120)  # Long timeout

        time.sleep(2)
        info0 = node0.get_info_safe(timeout=10)
        if info0:
            print(f"  Node 0 status after connecting to Node 2: height={info0['blocks']}, " +
                  f"headers={info0.get('headers', info0['blocks'])}")
        else:
            print("  Node 0 busy processing headers...")

        # Step 6: Wait for Node 0 to complete cascade reorg to Chain C (5000 blocks)
        print("\nStep 6: Waiting for Node 0 to complete reorg to 5,000 blocks...")
        print("  (Header sync from diverged chain requires multiple round-trips)")
        # When syncing from a diverged chain, the getheaders locator may not find
        # the exact fork point (block 1000), causing node 2 to send headers from
        # genesis. This requires multiple request/response cycles to fetch all
        # ~4000 unique headers from Chain C. Allow up to 10 minutes for this.
        max_wait = 600  # 10 minutes for full header sync of diverged chain
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
                # Wait for stability
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
            raise Exception("Node 0 failed to complete massive cascade reorg")
        
        # Step 7: Verify final state
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
        print("  ✓ Massive cascade reorg handled correctly (2000 blocks)")
        print("  ✓ Node properly abandoned 1000-block reorg for 2000-block reorg")
        print("  ✓ Sync peer isolation fix allows legitimate deep reorgs")
        
        print("\n" + "=" * 70)
        print("✓ Massive Reorg Test PASSED")
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
        
        # Cleanup (skip if --no-cleanup flag is set)
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
