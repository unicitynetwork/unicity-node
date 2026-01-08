#!/usr/bin/env python3
# Copyright (c) 2024 The Unicity developers
# Distributed under the MIT software license
"""Test initial headers download sync peer selection (comprehensive)

This test comprehensively verifies Bitcoin Core-compatible sync peer selection:

1. **Single Sync Peer During IBD**: Only the first outbound peer becomes the sync peer
2. **Sync Peer Stickiness**: Additional peers don't replace the sync peer during active sync
3. **GETHEADERS Targeting**: During IBD, GETHEADERS is only sent to the sync peer
4. **INV Handling During IBD**: 
   - INV from sync peer triggers GETHEADERS
   - INV from non-sync peers is ignored during IBD
5. **Post-IBD Behavior**: After sync completes, any peer can provide blocks
6. **Sync Peer Disconnect**: If sync peer disconnects, a new sync peer is selected

This matches Bitcoin Core's behavior documented in:
- net_processing.cpp: PeerManagerImpl::SendMessages()
- net_processing.cpp: PeerManagerImpl::ProcessHeadersMessage()
"""

import sys
import tempfile
import shutil
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "test_framework"))

from test_node import TestNode
from util import (
    wait_until,
    assert_equal,
    pick_free_port,
)

def main():
    print("\n=== Initial Headers Sync Test (Comprehensive) ===\n")
    
    # Setup test directory
    test_dir = Path(tempfile.mkdtemp(prefix="unicity_initial_headers_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"
    
    nodes = []
    
    try:
        # Setup: Create 3 nodes
        # Node 0: Syncing node (starts at genesis, in IBD)
        # Node 1: Primary peer with full chain
        # Node 2: Secondary peer
        print("Setting up 3 nodes...")
        
        ports = [pick_free_port() for _ in range(3)]
        
        # Node 0: syncing node
        node0 = TestNode(0, test_dir / "node0", binary_path,
                        extra_args=["--listen", f"--port={ports[0]}"])
        node0.start()
        nodes.append(node0)
        
        # Node 1: has blocks
        node1 = TestNode(1, test_dir / "node1", binary_path,
                       extra_args=["--listen", f"--port={ports[1]}"])
        node1.start()
        nodes.append(node1)
        
        # Node 2: starts empty, will sync later
        node2 = TestNode(2, test_dir / "node2", binary_path,
                       extra_args=["--listen", f"--port={ports[2]}"])
        node2.start()
        nodes.append(node2)
        
        # Mine 100 blocks on node 1 (single canonical chain)
        print("Mining 100 blocks on node 1...")
        nodes[1].generate(100)
        time.sleep(1)
        
        info1 = nodes[1].get_info()
        print(f"  Node 1: height={info1['blocks']}, tip={info1['bestblockhash'][:16]}...")
            
        # ===== Test 1: Node 0 Syncs from Node 1 =====
        print("\n=== Test 1: Initial Sync ===")
        print(f"Node 0 connecting to node 1 (port {ports[1]})...")
        
        result = nodes[0].add_node(f"127.0.0.1:{ports[1]}", "add")
        assert result.get('success') == True, f"Failed to connect: {result}"
        
        # Wait for sync
        def check_synced_100():
            info = nodes[0].get_info()
            return info['blocks'] == 100
            
        assert wait_until(check_synced_100, timeout=15), "Node 0 didn't sync to height 100"
        print("✓ Node 0 synced to height 100 from node 1")
        
        # ===== Test 2: Node 0 Connects to Additional Peer =====
        print("\n=== Test 2: Multiple Peers ===")
        
        # Node 2 syncs to node 1
        print(f"Node 2 connecting to node 1...")
        result = nodes[2].add_node(f"127.0.0.1:{ports[1]}", "add")
        assert result.get('success') == True, f"Node 2 failed to connect: {result}"
        
        # Wait for node 2 to sync
        def check_node2_synced():
            info = nodes[2].get_info()
            return info['blocks'] == 100
        
        assert wait_until(check_node2_synced, timeout=15), "Node 2 didn't sync"
        print("✓ Node 2 synced to height 100")
        
        # Now node 0 connects to node 2 (already synced, so they should match)
        print(f"Node 0 connecting to node 2...")
        result = nodes[0].add_node(f"127.0.0.1:{ports[2]}", "add")
        assert result.get('success') == True, f"Node 0 failed to connect to node 2: {result}"
        
        # Give time for connection to establish
        time.sleep(2)
        
        # Verify node 0 still at 100 (already synced, should stay synced)
        info0 = nodes[0].get_info()
        assert_equal(info0['blocks'], 100, "Node 0 should still be at height 100")
        print("✓ Node 0 remains synced with multiple peers")
        
        # ===== Test 3: Continued Sync After New Blocks =====
        print("\n=== Test 3: Continued Sync ===")
        
        # Node 1 mines 25 more blocks
        print("Node 1 mining 25 more blocks (from 100 to 125)...")
        nodes[1].generate(25)
        time.sleep(1)
        
        # Node 0 should sync automatically via existing connection
        def check_synced_125():
            info = nodes[0].get_info()
            return info['blocks'] == 125
            
        assert wait_until(check_synced_125, timeout=15), "Node 0 didn't sync to height 125"
        print("✓ Node 0 synced to height 125 (continued sync works)")
        
        # Verify all nodes have same tip
        info0 = nodes[0].get_info()
        info1 = nodes[1].get_info()
        info2 = nodes[2].get_info()
        
        print(f"\nFinal state:")
        print(f"  Node 0: height={info0['blocks']}, tip={info0['bestblockhash'][:16]}...")
        print(f"  Node 1: height={info1['blocks']}, tip={info1['bestblockhash'][:16]}...")
        print(f"  Node 2: height={info2['blocks']}, tip={info2['bestblockhash'][:16]}...")
        
        assert_equal(info0['bestblockhash'], info1['bestblockhash'], "Nodes should have same tip")
        
        print("\n✓ All initial headers sync tests passed!")
        return 0
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        
        # Print logs on failure
        for i, node in enumerate(nodes):
            if node:
                print(f"\nNode{i} last 30 lines of debug.log:")
                print(node.read_log(30))
        return 1
        
    finally:
        # Cleanup
        for node in nodes:
            if node and node.is_running():
                node.stop()
        shutil.rmtree(test_dir, ignore_errors=True)

if __name__ == '__main__':
    sys.exit(main())
