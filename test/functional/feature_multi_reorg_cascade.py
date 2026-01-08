#!/usr/bin/env python3
"""Test cascading reorgs with multiple competing chains.

This test verifies behavior when a node encounters progressively longer chains
while already processing a reorg:

1. Node 0 starts on Chain A (100 blocks)
2. Node 0 connects to Node 1 with Chain B (110 blocks) → reorg begins
3. While processing reorg, Node 0 connects to Node 2 with Chain C (120 blocks)
4. Verify Node 0 properly switches to Chain C (longest chain)

This tests that the node can handle overlapping reorg requests and properly
prioritize the longest chain even during an active reorganization.
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


def generate_chain(node, num_blocks, miner_address="0000000000000000000000000000000000000000"):
    """Generate a chain of blocks on a node."""
    print(f"  Generating {num_blocks} blocks...")
    result = node.generate(num_blocks, miner_address, timeout=300)
    return result


def main():
    print("=== Multi-Reorg Cascade Test ===\n")
    
    # Create test directories
    test_base = Path(tempfile.mkdtemp(prefix="unicity_multi_reorg_"))
    
    try:
        # Pick ports for all nodes
        port0 = pick_free_port()
        port1 = pick_free_port()
        port2 = pick_free_port()
        
        # Start 3 nodes with high suspiciousreorgdepth to disable protection
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
        
        print(f"  Node 0: port {port0}")
        print(f"  Node 1: port {port1}")
        print(f"  Node 2: port {port2}\n")
        
        # Step 2: Generate Chain A on Node 0 (100 blocks)
        print("Step 2: Node 0 generates Chain A (100 blocks)...")
        generate_chain(node0, 100)
        info0 = node0.get_info()
        height_a = info0["blocks"]
        tip_a = info0["bestblockhash"]
        print(f"  Chain A: height={height_a}, tip={tip_a[:16]}...\n")
        
        assert height_a == 100, f"Expected height 100, got {height_a}"
        
        # Step 3: Generate Chain B on Node 1 (110 blocks)
        print("Step 3: Node 1 generates Chain B (110 blocks)...")
        generate_chain(node1, 110)
        info1 = node1.get_info()
        height_b = info1["blocks"]
        tip_b = info1["bestblockhash"]
        print(f"  Chain B: height={height_b}, tip={tip_b[:16]}...\n")
        
        assert height_b == 110, f"Expected height 110, got {height_b}"
        
        # Step 4: Generate Chain C on Node 2 (120 blocks)
        print("Step 4: Node 2 generates Chain C (120 blocks)...")
        generate_chain(node2, 120)
        info2 = node2.get_info()
        height_c = info2["blocks"]
        tip_c = info2["bestblockhash"]
        print(f"  Chain C: height={height_c}, tip={tip_c[:16]}...\n")
        
        assert height_c == 120, f"Expected height 120, got {height_c}"
        
        # Verify all chains are different
        assert tip_a != tip_b, "Chain A and B should be different"
        assert tip_a != tip_c, "Chain A and C should be different"
        assert tip_b != tip_c, "Chain B and C should be different"
        
        # Step 5: Connect Node 0 to Node 1 (trigger first reorg: 100 → 110)
        print("Step 5: Connecting Node 0 to Node 1 (Chain A → Chain B reorg)...")
        node0.add_node(f"127.0.0.1:{port1}", "onetry")
        
        # Give it a moment to start syncing
        time.sleep(2)
        
        # Check Node 0 status during reorg
        info = node0.get_info()
        print(f"  Node 0 during first reorg: height={info['blocks']}, " +
              f"headers={info.get('headers', info['blocks'])}")
        
        # Step 6: Immediately connect Node 0 to Node 2 (trigger second reorg: ? → 120)
        print("\nStep 6: Connecting Node 0 to Node 2 (introducing Chain C mid-reorg)...")
        node0.add_node(f"127.0.0.1:{port2}", "onetry")
        
        # Wait for sync to complete (both reorgs)
        print("\nStep 7: Waiting for Node 0 to stabilize on longest chain...")
        max_wait = 60
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            info = node0.get_info()
            height = info["blocks"]
            headers = info.get("headers", height)
            
            print(f"  Node 0: height={height}, headers={headers}")
            
            # Node 0 should eventually reach height 120 (Chain C)
            if height == 120:
                time.sleep(2)  # Extra wait to ensure stability
                final_info = node0.get_info()
                if final_info["blocks"] == 120:
                    print(f"  ✓ Node 0 reached height 120")
                    break
            
            time.sleep(2)
        else:
            print(f"  ✗ TIMEOUT: Node 0 did not reach height 120 in {max_wait}s")
            final_info = node0.get_info()
            print(f"  Final state: height={final_info['blocks']}, " +
                  f"headers={final_info.get('headers', final_info['blocks'])}")
            node0.stop()
            node1.stop()
            node2.stop()
            return False
        
        # Step 8: Verify final state
        print("\nStep 8: Verifying final chain state...")
        
        final_info = node0.get_info()
        final_height = final_info["blocks"]
        final_tip = final_info["bestblockhash"]
        
        print(f"  Node 0 final state:")
        print(f"    Height: {final_height}")
        print(f"    Tip:    {final_tip[:16]}...")
        print(f"  Expected:")
        print(f"    Height: 120")
        print(f"    Tip:    {tip_c[:16]}... (Chain C)")
        
        # Verify Node 0 is on Chain C (120 blocks)
        if final_height != 120:
            print(f"\n  ✗ FAILED: Expected height 120, got {final_height}")
            node0.stop()
            node1.stop()
            node2.stop()
            return False
        
        if final_tip != tip_c:
            print(f"\n  ✗ FAILED: Node 0 tip mismatch")
            print(f"    Got:      {final_tip}")
            print(f"    Expected: {tip_c}")
            node0.stop()
            node1.stop()
            node2.stop()
            return False
        
        print("\n  ✓ Node 0 successfully switched to longest chain (Chain C)")
        print("  ✓ Multi-reorg cascade handled correctly")
        
        # Clean shutdown
        print("\nStopping nodes...")
        node0.stop()
        node1.stop()
        node2.stop()
        
        print("\n" + "=" * 50)
        print("✓ Multi-Reorg Cascade Test PASSED")
        print("=" * 50)
        
        return True
        
    except Exception as e:
        print(f"\n✗ Test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # Cleanup
        print(f"\nCleaning up {test_base}")
        shutil.rmtree(test_base, ignore_errors=True)


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
