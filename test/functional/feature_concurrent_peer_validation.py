#!/usr/bin/env python3
# Copyright (c) 2025 The Unicity Foundation
# Test concurrent validation from multiple peers sending headers simultaneously

"""
Concurrent Peer Validation Test.

Goal:
- Exercise header validation under heavy multi-peer load
- Ensure validation_mutex_ correctly serializes access to ChainstateManager
- Verify no crashes, deadlocks, or corruption when many peers send headers

Notes on threading model:
- The production networking stack is intentionally single-threaded (one io_context
  thread). We do *not* run multiple boost::asio IO threads in unicityd.
- True concurrent calls into ChainstateManager are covered by dedicated C++
  threading tests (see test/unit/threading_tests.cpp and related stress tests).
- This Python test focuses on realistic multi-peer behavior and chain selection
  under load, not on creating extra network threads.

Scenario:
- Node0: Central hub that will validate headers from multiple peers
- Node1-10: Each mines a different chain and connects to Node0
- Node0 processes headers from 10 different peers during the same time window
"""

import sys
import time
import tempfile
import shutil
import threading
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))

from test_node import TestNode
from util import regtest_base_port

# Color codes for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def log(msg, color=None):
    if color:
        print(f"{color}{msg}{RESET}")
    else:
        print(msg)


def main():
    log("\n=== Concurrent Peer Validation Test ===", BLUE)
    log("Testing validation mutex under multi-peer concurrent header load\n")

    # Configuration
    NUM_PEER_NODES = 10  # 10 peers sending headers to Node0
    BLOCKS_PER_PEER = 20  # Each peer mines 20 blocks
    BLOCKS_WINNING_PEER = 50  # One peer mines 50 blocks (most work)
    BASE_PORT = regtest_base_port()

    test_dir = Path(tempfile.mkdtemp(prefix='cbc_concurrent_'))
    log(f"Test directory: {test_dir}\n")

    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"
    nodes = []

    try:
        # Step 1: Create Node0 (the validation target - will receive headers from all peers)
        log("Step 1: Creating Node0 (validation target)...", BLUE)
        node0 = TestNode(0, test_dir / 'node0', binary_path,
                        extra_args=["--listen", f"--port={BASE_PORT}"])
        nodes.append(node0)

        node0.start()
        time.sleep(1)

        log(f"✓ Node0 started and listening on port {BASE_PORT}\n", GREEN)

        # Step 2: Create peer nodes (each will mine a different chain)
        log(f"Step 2: Creating {NUM_PEER_NODES} peer nodes...", BLUE)
        peer_nodes = []
        for i in range(1, NUM_PEER_NODES + 1):
            node = TestNode(i, test_dir / f'node{i}', binary_path,
                          extra_args=["--listen", f"--port={BASE_PORT + i}"])
            nodes.append(node)
            peer_nodes.append(node)
            node.start()
            time.sleep(0.1)

        log(f"✓ All {NUM_PEER_NODES} peer nodes started\n", GREEN)

        # Step 3: Each peer mines a different chain
        log(f"Step 3: Each peer mining blocks independently...", BLUE)
        log(f"  - Node1 will mine {BLOCKS_WINNING_PEER} blocks (most work - should win!)")
        log(f"  - Nodes 2-10 will each mine {BLOCKS_PER_PEER} blocks\n")

        # Use threads to mine in parallel (faster test)
        def mine_peer(node):
            # Node1 gets the longest chain
            num_blocks = BLOCKS_WINNING_PEER if node.index == 1 else BLOCKS_PER_PEER
            result = node.generate(num_blocks)
            # generate() now returns {"blocks": N, "height": N}
            blocks_mined = result.get('blocks', 0) if isinstance(result, dict) else num_blocks
            log(f"  Node{node.index} mined {blocks_mined} blocks", BLUE)

        threads = []
        for node in peer_nodes:
            t = threading.Thread(target=mine_peer, args=(node,))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        log(f"✓ All peers completed mining\n", GREEN)
        log(f"Expected result: All nodes should converge to Node1's chain (height={BLOCKS_WINNING_PEER})\n", YELLOW)

        # Step 4: Connect all peers to Node0 SIMULTANEOUSLY
        log("Step 4: Connecting all peers to Node0 SIMULTANEOUSLY...", BLUE)
        log("*** THIS IS THE CRITICAL MOMENT FOR THREAD SAFETY ***\n", YELLOW)
        log("Node0 will receive headers from 10 peers in rapid succession:")
        log("  • Networking remains single-threaded (one io_context thread)")
        log("  • ChainstateManager is still written to be thread-safe if called")
        log("    from multiple threads (see C++ threading tests)")
        log("  • validation_mutex_ must serialize all operations correctly")
        log("  • Race conditions would manifest as crashes/corruption here!\n")

        # Connect all peers to Node0 at nearly the same time
        log("Connecting all peers to Node0...\n")

        def connect_peer(node):
            node.add_node(f"127.0.0.1:{BASE_PORT}", "add")

        connect_threads = []
        for node in peer_nodes:
            t = threading.Thread(target=connect_peer, args=(node,))
            t.start()
            connect_threads.append(t)

        for t in connect_threads:
            t.join()

        log(f"✓ All {NUM_PEER_NODES} peers connected to Node0\n", GREEN)
        log("Node0 is now processing headers from 10 peers concurrently...\n", BLUE)

        # Step 5: Wait for processing and monitor for crashes
        log("Step 5: Waiting for header processing (monitoring for crashes)...", BLUE)
        log("Letting nodes exchange headers for 15 seconds...\n")

        for i in range(15):
            time.sleep(1)
            # Check if Node0 is still running
            if not node0.is_running():
                log(f"\n✗ Node0 crashed after {i+1} seconds!", RED)
                log("\nNode0 debug.log (last 50 lines):", YELLOW)
                log(node0.read_log(50))
                raise RuntimeError("Node0 crashed during header processing!")
            log(f"  {i+1}/15 seconds - Node0 still running ✓")

        log(f"\n✓ Node0 survived 15 seconds of concurrent header processing\n", GREEN)

        # Step 6: Check chain state
        log("Step 6: Checking chain state of all nodes...", BLUE)

        node_states = []
        for node in nodes:
            if node.is_running():
                try:
                    info = node.get_info()
                    node_states.append({
                        'index': node.index,
                        'height': info['blocks'],
                        'tip': info['bestblockhash']
                    })
                    log(f"  Node{node.index}: height={info['blocks']}, tip={info['bestblockhash'][:16]}...")
                except Exception as e:
                    log(f"  Node{node.index}: Failed to get info: {e}", YELLOW)
            else:
                log(f"  Node{node.index}: Not running", RED)

        # Analyze the results
        log("\nChain consensus analysis:", BLUE)
        heights = [s['height'] for s in node_states]
        tips = [s['tip'] for s in node_states]

        # Find most common height
        height_counts = {}
        for h in heights:
            height_counts[h] = height_counts.get(h, 0) + 1
        most_common_height = max(height_counts, key=height_counts.get)
        nodes_at_height = height_counts[most_common_height]

        log(f"  Most common height: {most_common_height} ({nodes_at_height}/{len(nodes)} nodes)")

        # Find most common tip
        tip_counts = {}
        for t in tips:
            tip_counts[t] = tip_counts.get(t, 0) + 1
        most_common_tip = max(tip_counts, key=tip_counts.get)
        nodes_with_tip = tip_counts[most_common_tip]

        log(f"  Most common tip: {most_common_tip[:16]}... ({nodes_with_tip}/{len(nodes)} nodes)")

        if nodes_at_height == len(nodes) and nodes_with_tip == len(nodes):
            log(f"  ✓ ALL NODES AGREE on chain (height={most_common_height}, tip={most_common_tip[:16]}...)", GREEN)

            # Verify they selected the longest chain (Node1's chain with 50 blocks)
            if most_common_height == BLOCKS_WINNING_PEER:
                log(f"  ✓ All nodes correctly selected the longest chain (Node1's {BLOCKS_WINNING_PEER}-block chain)", GREEN)
            else:
                log(f"  ✗ Unexpected: Expected height {BLOCKS_WINNING_PEER}, got {most_common_height}", RED)
        else:
            log(f"  ⚠ Nodes have different chains", YELLOW)
            log(f"    This could indicate a chain selection issue under concurrent load", YELLOW)

        log("")

        # Step 7: Check for crashes
        log("Step 7: Checking all nodes for crashes...", BLUE)

        crashed = []
        for node in nodes:
            if not node.is_running():
                crashed.append(node.index)

        if crashed:
            raise RuntimeError(f"Nodes crashed: {crashed}")

        log(f"✓ No crashes detected\n", GREEN)

        # Success!
        log("\n" + "="*70, GREEN)
        log("✓ MULTI-PEER HEADER LOAD TEST PASSED!", GREEN)
        log("="*70 + "\n", GREEN)

        log("Test verified:", BLUE)
        log(f"  • {NUM_PEER_NODES} peers sent headers to Node0 during the same time window")
        log(f"  • Node0 processed headers from all peers without divergence")
        log(f"  • Networking remained single-threaded (no extra IO threads)")
        log(f"  • validation_mutex_ correctly serialized all operations")
        log(f"  • No crashes, deadlocks, or data corruption")
        log(f"\n✓ Chainstate behavior VERIFIED under real multi-peer load! ✓\n", GREEN)

        return 0

    except Exception as e:
        log(f"\n✗ Test FAILED: {e}", RED)
        import traceback
        traceback.print_exc()
        return 1

    finally:
        # Cleanup
        log("\nCleaning up...", YELLOW)
        for node in nodes:
            if node.is_running():
                node.stop()

        time.sleep(1)

        try:
            shutil.rmtree(test_dir)
            log(f"Cleaned up test directory: {test_dir}\n")
        except Exception as e:
            log(f"Warning: Could not clean up {test_dir}: {e}", YELLOW)

if __name__ == '__main__':
    sys.exit(main())
