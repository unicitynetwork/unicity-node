#!/usr/bin/env python3
"""Setup script to create 3 nodes with 10k, 11k, and 12k blocks for manual testing.

This script creates the test environment but doesn't connect the nodes or trigger
the reorg - that's left for manual testing.

Usage:
    ./setup_10k_reorg_test.py

The script will:
1. Create a test directory in /tmp/unicity_10k_reorg_manual/
2. Start 3 nodes on ports 60001, 60002, 60003
3. Generate 10k, 11k, and 12k blocks respectively
4. Print instructions for manual testing
5. Leave nodes running for you to experiment with
"""

import sys
import time
import tempfile
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))

from test_node import TestNode


def generate_chain(node, num_blocks, miner_address="0000000000000000000000000000000000000000"):
    """Generate a chain of blocks on a node, in batches if needed."""
    print(f"  Generating {num_blocks} blocks...")
    
    # RPC generate has a limit of 1000 blocks per call
    batch_size = 1000
    remaining = num_blocks
    generated = 0
    
    while remaining > 0:
        to_generate = min(remaining, batch_size)
        node.generate(to_generate, miner_address, timeout=300)
        remaining -= to_generate
        generated += to_generate
        if remaining > 0:
            print(f"    Progress: {generated}/{num_blocks} blocks")
    
    # Return final height for verification
    return node.get_info()


def main():
    print("=== Setting up 10k/11k/12k Reorg Test Environment ===\n")
    
    # Create persistent test directory
    test_base = Path("/tmp/unicity_10k_reorg_manual")
    if test_base.exists():
        print(f"ERROR: Test directory already exists: {test_base}")
        print("Please remove it first or use a different location.")
        return 1
    
    test_base.mkdir(parents=True)
    print(f"Created test directory: {test_base}\n")
    
    # Fixed ports for easy manual testing
    port0 = 60001
    port1 = 60002
    port2 = 60003
    
    try:
        # Start 3 nodes
        print("Step 1: Starting 3 nodes...")
        
        node0 = TestNode(0, test_base / "node0",
                        extra_args=["--listen", f"--port={port0}", "--connect=0",
                                   "--suspiciousreorgdepth=20000"])
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
        
        print(f"  ✓ Node 0: port {port0}, datadir: {test_base / 'node0'}")
        print(f"  ✓ Node 1: port {port1}, datadir: {test_base / 'node1'}")
        print(f"  ✓ Node 2: port {port2}, datadir: {test_base / 'node2'}\n")
        
        # Step 2: Generate chains
        print("Step 2: Generating 10,000 blocks on Node 0...")
        generate_chain(node0, 10000)
        info0 = node0.get_info()
        print(f"  ✓ Node 0: height={info0['blocks']}, tip={info0['bestblockhash'][:16]}...\n")
        
        print("Step 3: Generating 11,000 blocks on Node 1...")
        generate_chain(node1, 11000)
        info1 = node1.get_info()
        print(f"  ✓ Node 1: height={info1['blocks']}, tip={info1['bestblockhash'][:16]}...\n")
        
        print("Step 4: Generating 12,000 blocks on Node 2...")
        generate_chain(node2, 12000)
        info2 = node2.get_info()
        print(f"  ✓ Node 2: height={info2['blocks']}, tip={info2['bestblockhash'][:16]}...\n")
        
        # Print summary and instructions
        print("=" * 70)
        print("✓ Setup Complete!")
        print("=" * 70)
        print(f"\nTest environment: {test_base}")
        print(f"\nNodes are RUNNING:")
        print(f"  Node 0: 127.0.0.1:{port0} (10,000 blocks)")
        print(f"  Node 1: 127.0.0.1:{port1} (11,000 blocks)")
        print(f"  Node 2: 127.0.0.1:{port2} (12,000 blocks)")
        
        print(f"\nRPC access (from {test_base}):")
        print(f"  ../../../build/bin/unicity-cli --datadir=node0 getinfo")
        print(f"  ../../../build/bin/unicity-cli --datadir=node1 getinfo")
        print(f"  ../../../build/bin/unicity-cli --datadir=node2 getinfo")
        
        print(f"\nTo trigger the reorg test:")
        print(f"  # Connect Node 0 to Node 1 (should start 10k→11k reorg)")
        print(f"  ../../../build/bin/unicity-cli --datadir=node0 addnode 127.0.0.1:{port1} onetry")
        print(f"  ")
        print(f"  # Wait a few seconds, then connect to Node 2 (introduce 12k chain)")
        print(f"  ../../../build/bin/unicity-cli --datadir=node0 addnode 127.0.0.1:{port2} onetry")
        print(f"  ")
        print(f"  # Monitor Node 0's progress:")
        print(f"  watch -n1 '../../../build/bin/unicity-cli --datadir=node0 getinfo'")
        
        print(f"\nLogs:")
        print(f"  tail -f {test_base / 'node0' / 'debug.log'}")
        print(f"  tail -f {test_base / 'node1' / 'debug.log'}")
        print(f"  tail -f {test_base / 'node2' / 'debug.log'}")
        
        print(f"\nTo stop nodes:")
        print(f"  pkill -f 'unicityd.*{test_base}'")
        print(f"  # Or individually:")
        print(f"  ../../../build/bin/unicity-cli --datadir=node0 stop")
        print(f"  ../../../build/bin/unicity-cli --datadir=node1 stop")
        print(f"  ../../../build/bin/unicity-cli --datadir=node2 stop")
        
        print(f"\nTo cleanup:")
        print(f"  rm -rf {test_base}")
        
        print("\n" + "=" * 70)
        print("Nodes will continue running. Press Ctrl+C to exit this script.")
        print("(The nodes will keep running in the background)")
        print("=" * 70)
        
        # Keep script alive to show it's complete
        input("\nPress Enter to exit (nodes will keep running)...")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        return 0
        
    except Exception as e:
        print(f"\n✗ Setup failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
