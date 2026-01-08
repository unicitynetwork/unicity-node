#!/usr/bin/env python3
"""Test concurrent reorg cascade during active reorganization.

This test verifies that a node can handle a second, longer reorg request
while already processing an initial reorg:

1. Node 0 starts on Chain A (100 blocks)
2. Node 0 connects to Node 1 with Chain B (110 blocks) → reorg begins
3. While reorg is in progress, Node 0 connects to Node 2 with Chain C (120 blocks)
4. Verify Node 0 properly abandons the 110-block reorg and switches to Chain C

This tests the node's ability to prioritize and switch to the longest chain
even when a reorg is already in progress. The suspicious_reorg_threshold is
disabled to allow deep reorgs without triggering protection mechanisms.
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


def generate_chain(node, num_blocks, miner_address="0000000000000000000000000000000000000000"):
    """Generate a chain of blocks on a node."""
    print(f"  Generating {num_blocks} blocks...")
    result = node.generate(num_blocks, miner_address, timeout=300)
    return result


def main():
    print("=== Concurrent Reorg Cascade Test (100→110→120) ===\n")
    
    # Create test directories
    test_base = Path(tempfile.mkdtemp(prefix="unicity_concurrent_reorg_"))
    
    node0 = None
    node1 = None
    node2 = None
    
    try:
        # Pick ports for all nodes
        port0 = pick_free_port()
        port1 = pick_free_port()
        port2 = pick_free_port()
        
        # Start 3 nodes with high suspicious_reorg_threshold to disable protection
        print("Step 1: Starting 3 nodes with disabled suspicious reorg detection...")
        
        node0 = TestNode(0, test_base / "node0",
                        extra_args=["--listen", f"--port={port0}", "--connect=0",
                                   "--suspiciousreorgdepth=1000"])
        node1 = TestNode(1, test_base / "node1",
                        extra_args=["--listen", f"--port={port1}", "--connect=0",
                                   "--suspiciousreorgdepth=1000"])
        node2 = TestNode(2, test_base / "node2",
                        extra_args=["--listen", f"--port={port2}", "--connect=0",
                                   "--suspiciousreorgdepth=1000"])
        
        node0.start()
        node1.start()
        node2.start()
        
        time.sleep(2)
        
        print(f"  ✓ Node 0: port {port0}")
        print(f"  ✓ Node 1: port {port1}")
        print(f"  ✓ Node 2: port {port2}\n")
        
        # Verify all nodes start at genesis
        info0 = node0.get_info()
        info1 = node1.get_info()
        info2 = node2.get_info()
        assert info0['blocks'] == 0, f"Node 0 should start at genesis, got {info0['blocks']}"
        assert info1['blocks'] == 0, f"Node 1 should start at genesis, got {info1['blocks']}"
        assert info2['blocks'] == 0, f"Node 2 should start at genesis, got {info2['blocks']}"
        print("  ✓ All nodes at genesis (height 0)\n")
        
        # Step 2: Generate Chain A on Node 0 (100 blocks)
        print("Step 2: Node 0 generates Chain A (100 blocks)...")
        generate_chain(node0, 100)
        info0 = node0.get_info()
        height_a = info0["blocks"]
        tip_a = info0["bestblockhash"]
        print(f"  ✓ Chain A: height={height_a}, tip={tip_a[:16]}...\n")
        
        assert height_a == 100, f"Expected height 100, got {height_a}"
        
        # Step 3: Generate Chain B on Node 1 (110 blocks)
        print("Step 3: Node 1 generates Chain B (110 blocks)...")
        generate_chain(node1, 110)
        info1 = node1.get_info()
        height_b = info1["blocks"]
        tip_b = info1["bestblockhash"]
        print(f"  ✓ Chain B: height={height_b}, tip={tip_b[:16]}...\n")
        
        assert height_b == 110, f"Expected height 110, got {height_b}"
        
        # Step 4: Generate Chain C on Node 2 (120 blocks)
        print("Step 4: Node 2 generates Chain C (120 blocks)...")
        generate_chain(node2, 120)
        info2 = node2.get_info()
        height_c = info2["blocks"]
        tip_c = info2["bestblockhash"]
        print(f"  ✓ Chain C: height={height_c}, tip={tip_c[:16]}...\n")
        
        assert height_c == 120, f"Expected height 120, got {height_c}"
        
        # Verify all chains are different
        assert tip_a != tip_b, "Chain A and B should have different tips"
        assert tip_a != tip_c, "Chain A and C should have different tips"
        assert tip_b != tip_c, "Chain B and C should have different tips"
        print("  ✓ All chains are distinct\n")
        
        # Step 5: Connect Node 0 to Node 1 (trigger first reorg: 100 → 110)
        print("Step 5: Connecting Node 0 to Node 1 (initiating 100→110 reorg)...")
        node0.add_node(f"127.0.0.1:{port1}", "onetry")
        
        # Give it a short time to start syncing but not complete
        # We want to catch it mid-reorg
        time.sleep(1)
        
        # Check Node 0 status during initial reorg
        info0 = node0.get_info()
        print(f"  Node 0 status after 1s: height={info0['blocks']}, " +
              f"headers={info0.get('headers', info0['blocks'])}")
        
        # Step 6: Immediately connect Node 0 to Node 2 (trigger second reorg: ? → 120)
        # This happens while the first reorg is still in progress
        print("\nStep 6: Connecting Node 0 to Node 2 (introducing 120-block chain mid-reorg)...")
        node0.add_node(f"127.0.0.1:{port2}", "onetry")
        
        # Give brief moment for headers to propagate
        time.sleep(1)
        info0 = node0.get_info()
        print(f"  Node 0 status after connecting to both: height={info0['blocks']}, " +
              f"headers={info0.get('headers', info0['blocks'])}")
        
        # Step 7: Wait for Node 0 to stabilize on longest chain (Chain C - 120 blocks)
        print("\nStep 7: Waiting for Node 0 to complete cascade reorg to 120 blocks...")
        max_wait = 90
        start_time = time.time()
        
        last_height = -1
        stable_count = 0
        
        while time.time() - start_time < max_wait:
            info0 = node0.get_info()
            height = info0["blocks"]
            headers = info0.get("headers", height)
            
            # Show progress when height changes
            if height != last_height:
                print(f"  Node 0: height={height}, headers={headers}")
                last_height = height
                stable_count = 0
            
            # Node 0 should eventually reach height 120 (Chain C)
            if height == 120:
                stable_count += 1
                # Wait for stability (multiple checks at height 120)
                if stable_count >= 3:
                    print(f"  ✓ Node 0 reached and stabilized at height 120")
                    break
            
            time.sleep(1)
        else:
            print(f"  ✗ TIMEOUT: Node 0 did not reach height 120 in {max_wait}s")
            final_info = node0.get_info()
            print(f"  Final state: height={final_info['blocks']}, " +
                  f"headers={final_info.get('headers', final_info['blocks'])}")
            print("\n--- Node 0 last 100 lines of log ---")
            print(node0.read_log(100))
            raise Exception("Node 0 failed to complete cascade reorg")
        
        # Step 8: Verify final state matches Chain C
        print("\nStep 8: Verifying final chain state...")
        
        final_info = node0.get_info()
        final_height = final_info["blocks"]
        final_tip = final_info["bestblockhash"]
        
        print(f"  Node 0 final state:")
        print(f"    Height: {final_height}")
        print(f"    Tip:    {final_tip[:16]}...")
        print(f"  Expected (Chain C):")
        print(f"    Height: 120")
        print(f"    Tip:    {tip_c[:16]}...")
        
        # Verify Node 0 is on Chain C (120 blocks)
        assert final_height == 120, \
            f"Expected height 120, got {final_height}"
        
        assert final_tip == tip_c, \
            f"Node 0 tip mismatch\n  Got:      {final_tip}\n  Expected: {tip_c}"
        
        print("\n  ✓ Node 0 successfully switched to longest chain (Chain C)")
        print("  ✓ Concurrent reorg cascade handled correctly")
        print("  ✓ Node properly abandoned 110-block reorg for 120-block chain")
        
        print("\n" + "=" * 60)
        print("✓ Concurrent Reorg Cascade Test PASSED")
        print("=" * 60)
        
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
        
        # Cleanup
        print(f"Cleaning up test directory: {test_base}")
        shutil.rmtree(test_base, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
