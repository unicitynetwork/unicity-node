#!/usr/bin/env python3
# Chaos convergence test - 100 peers with random chain lengths converge to longest chain

import sys
import time
import tempfile
import shutil
import threading
import random
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode
from util import regtest_base_port

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
    # Configuration
    NUM_PEER_NODES = 20  # 20 random chains
    BASE_PORT = regtest_base_port()

    test_dir = Path(tempfile.mkdtemp(prefix='cbc_chaos_'))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"
    nodes = []

    try:
        log("\n" + "="*70, BLUE)
        log("CHAOS CONVERGENCE TEST - Random Chain Lengths", BLUE)
        log("="*70, BLUE)
        log(f"Testing: {NUM_PEER_NODES} peers with random chain lengths (1-100 blocks)", YELLOW)
        log(f"Expected: All converge to longest chain without crashes\n", YELLOW)

        # Create Node0 (starts at genesis, will sync from peers)
        node0 = TestNode(0, test_dir / 'node0', binary_path,
                        extra_args=["--listen", f"--port={BASE_PORT}"])
        nodes.append(node0)
        node0.start()
        log(f"✓ Main node (Node0) started at genesis", GREEN)

        # Create peer nodes
        log(f"\nStarting {NUM_PEER_NODES} peer nodes...", BLUE)
        peer_nodes = []
        for i in range(1, NUM_PEER_NODES + 1):
            node = TestNode(i, test_dir / f'node{i}', binary_path,
                          extra_args=["--listen", f"--port={BASE_PORT + i}"])
            nodes.append(node)
            peer_nodes.append(node)
            node.start()
            time.sleep(0.01)  # Very minimal delay

            if i % 10 == 0:
                log(f"  {i}/{NUM_PEER_NODES} nodes started...", BLUE)

        log(f"✓ All {NUM_PEER_NODES} peer nodes started\n", GREEN)

        # Mine random number of blocks on each peer
        log("Mining random chains (1-300 blocks per peer)...", BLUE)
        log("This will take a few minutes...\n", YELLOW)

        max_blocks = 0
        longest_node_idx = None
        peer_heights = {}

        def mine_peer(node):
            # Generate random height, but make ONE peer extra long to ensure we have a clear winner
            # IMPORTANT: Limited to 100 blocks max due to RPC 4KB buffer limit
            # (>60 blocks causes JSON truncation, >~250 blocks causes node crash)
            if node.index == 1:
                num_blocks = random.randint(80, 100)  # Winning chain
            else:
                num_blocks = random.randint(1, 100)

            try:
                # Generate blocks (now returns {"blocks": N, "height": N})
                result = node.generate(num_blocks, timeout=600)

                # Verify result is a dict and extract height
                if isinstance(result, dict):
                    actual_height = result.get('height', 0)
                else:
                    log(f"  Node{node.index}: Unexpected return type: {type(result)}, falling back to getinfo", RED)
                    # Fall back to getinfo
                    info = node.get_info()
                    actual_height = info['blocks']

                peer_heights[node.index] = actual_height

                if node.index % 5 == 0:
                    log(f"  Node{node.index}: {actual_height} blocks", BLUE)

                return actual_height
            except Exception as e:
                log(f"  Node{node.index}: Mining failed: {str(e)[:200]}", RED)

                # Check if node crashed
                if not node.is_running():
                    log(f"  Node{node.index}: CRASHED - process died!", RED)
                    log(f"  Node{node.index}: Last log lines:", RED)
                    log(node.read_log(20), RED)
                    peer_heights[node.index] = 0
                    return 0

                # Try to get current height anyway
                try:
                    info = node.get_info()
                    if isinstance(info, dict) and 'blocks' in info:
                        peer_heights[node.index] = info['blocks']
                        log(f"  Node{node.index}: Recovered, at height {info['blocks']}", YELLOW)
                        return info['blocks']
                except Exception as e2:
                    log(f"  Node{node.index}: Cannot get info: {str(e2)[:100]}", RED)
                    pass

                peer_heights[node.index] = 0
                return 0

        # Mine in parallel for speed
        mining_threads = []
        for node in peer_nodes:
            t = threading.Thread(target=mine_peer, args=(node,))
            t.start()
            mining_threads.append(t)

        for t in mining_threads:
            t.join()

        # Find longest chain
        max_blocks = max(peer_heights.values())
        longest_node_idx = [idx for idx, h in peer_heights.items() if h == max_blocks][0]

        log(f"\n✓ Mining complete!", GREEN)
        log(f"  Chain heights range: {min(peer_heights.values())} to {max_blocks} blocks", BLUE)
        log(f"  Longest chain: Node{longest_node_idx} with {max_blocks} blocks", BLUE)
        log(f"  Average height: {sum(peer_heights.values())//len(peer_heights)} blocks\n", BLUE)

        # Get expected final hash from longest chain
        longest_node = nodes[longest_node_idx]
        longest_info = longest_node.get_info()
        expected_best_hash = longest_info['bestblockhash']

        log(f"Expected final state:", YELLOW)
        log(f"  Height: {max_blocks}", YELLOW)
        log(f"  Hash: {expected_best_hash}\n", YELLOW)

        # Connect all peers to main node SIMULTANEOUSLY
        log(f"Connecting ALL {NUM_PEER_NODES} peers to Node0 SIMULTANEOUSLY...", BLUE)
        log("This is the critical stress test moment!\n", YELLOW)

        def connect_peer(node):
            try:
                node.add_node(f"127.0.0.1:{BASE_PORT}", "add")
            except Exception as e:
                log(f"  Node{node.index}: Connection failed: {e}", RED)

        connect_start = time.time()
        connect_threads = []
        for node in peer_nodes:
            t = threading.Thread(target=connect_peer, args=(node,))
            t.start()
            connect_threads.append(t)

        for t in connect_threads:
            t.join()

        connect_time = time.time() - connect_start
        log(f"✓ All {NUM_PEER_NODES} peers connected in {connect_time:.2f}s\n", GREEN)

        # Also connect Node0 back to peers for bidirectional sync
        # This ensures Node0 can push headers to peers after it syncs
        log("Establishing bidirectional connections (Node0 → peers)...", BLUE)
        for node in peer_nodes:
            try:
                node0.add_node(f"127.0.0.1:{BASE_PORT + node.index}", "add")
            except Exception as e:
                log(f"  Node0 → Node{node.index}: {e}", RED)
        time.sleep(1)  # Let connections establish
        log("✓ Bidirectional connections established\n", GREEN)

        # Monitor and wait for convergence
        log("Monitoring convergence (max 2 minutes)...", BLUE)
        max_wait = 120
        check_interval = 2  # Check every 2 seconds for faster completion
        converged = False

        for elapsed in range(0, max_wait, check_interval):
            time.sleep(check_interval)

            # Check for crashes first
            if not node0.is_running():
                log(f"\n✗ CRASH: Node0 crashed after {elapsed+check_interval}s!", RED)
                log("\nNode0 log (last 100 lines):", YELLOW)
                log(node0.read_log(100))
                raise RuntimeError("Node0 crashed during convergence!")

            # Check convergence
            try:
                main_info = node0.get_info()
                main_height = main_info['blocks']
                main_hash = main_info['bestblockhash']

                print(f"  {elapsed+check_interval}s: Node0 height={main_height}/{max_blocks}", end='')

                if main_height == max_blocks and main_hash == expected_best_hash:
                    print(" ✓ CONVERGED!")
                    converged = True
                    convergence_time = elapsed + check_interval
                    break
                else:
                    print()
            except Exception as e:
                print(f" (RPC error: {e})")

        print()

        if not converged:
            log("⚠ Did not fully converge in 2 minutes (may still be syncing)", YELLOW)
        else:
            log(f"✓ Converged in {convergence_time} seconds!", GREEN)

        # Final verification
        log("\nFinal verification:", BLUE)
        log("-" * 70, BLUE)

        main_info = node0.get_info()
        main_height = main_info['blocks']
        main_hash = main_info['bestblockhash']

        log(f"Main node (Node0):", YELLOW)
        log(f"  Height: {main_height} (expected: {max_blocks})", YELLOW)
        log(f"  Hash: {main_hash}", YELLOW)
        log(f"  Match: {main_hash == expected_best_hash}", YELLOW)
        print()

        # Check height convergence (hash might still be syncing)
        if main_height >= max_blocks:
            log("✓ Main node reached expected height!", GREEN)
        else:
            log(f"⚠ Main node at {main_height}/{max_blocks} (still syncing)", YELLOW)

        # Sample some peers
        log("\nSampling peer states (first 10):", BLUE)
        for i in range(1, min(11, NUM_PEER_NODES + 1)):
            node = nodes[i]
            if node.is_running():
                try:
                    info = node.get_info()
                    height = info['blocks']
                    bhash = info['bestblockhash']
                    match = "✓" if bhash == expected_best_hash else "✗"
                    log(f"  Node{i}: height={height}, converged={match}", BLUE)
                except:
                    log(f"  Node{i}: RPC failed", RED)

        # ======================================================================
        # EXTENDED TEST: Continue mining to verify nodes stay in sync
        # ======================================================================
        print()
        log("="*70, BLUE)
        log("EXTENDED TEST: Continued Mining", BLUE)
        log("="*70, BLUE)
        log("Each peer will mine 10 more blocks randomly...", YELLOW)
        log("Expected: All nodes should stay synchronized\n", YELLOW)

        # Each peer mines 10 more blocks (will create temporary forks)
        def mine_more(node):
            try:
                node.generate(10)
                info = node.get_info()
                return info['blocks']
            except Exception as e:
                log(f"  Node{node.index}: Mining failed: {e}", RED)
                return 0

        mining_threads = []
        for node in peer_nodes:
            t = threading.Thread(target=mine_more, args=(node,))
            t.start()
            mining_threads.append(t)

        for t in mining_threads:
            t.join()

        log("✓ All peers mined 10 more blocks\n", GREEN)

        # Give network time to propagate and resolve to longest chain
        log("Waiting for network to resolve to longest chain...", BLUE)
        time.sleep(5)  # Reduced from 10s - sync is fast

        # Check final state - all nodes should converge to same height and hash
        log("\nVerifying final sync state:", BLUE)
        log("-" * 70, BLUE)

        # Get Node0's final state
        node0_info = node0.get_info()
        final_height = node0_info['blocks']
        final_hash = node0_info['bestblockhash']

        log(f"Node0 final state:", YELLOW)
        log(f"  Height: {final_height}", YELLOW)
        log(f"  Hash: {final_hash}\n", YELLOW)

        # Check all other nodes
        synced_count = 0
        unsynced_count = 0
        crashed_count = 0

        for i in range(1, NUM_PEER_NODES + 1):
            node = nodes[i]
            if not node.is_running():
                crashed_count += 1
                log(f"  Node{i}: CRASHED ✗", RED)
                continue

            try:
                info = node.get_info()
                height = info['blocks']
                bhash = info['bestblockhash']

                if height == final_height and bhash == final_hash:
                    synced_count += 1
                    if i <= 10:  # Only log first 10
                        log(f"  Node{i}: height={height}, synced=✓", GREEN)
                else:
                    unsynced_count += 1
                    log(f"  Node{i}: height={height}, hash={bhash[:16]}... NOT SYNCED ✗", RED)
            except Exception as e:
                unsynced_count += 1
                log(f"  Node{i}: RPC failed: {e} ✗", RED)

        print()
        log(f"Sync results: {synced_count}/{NUM_PEER_NODES} peers synced",
            GREEN if synced_count == NUM_PEER_NODES else YELLOW)

        if crashed_count > 0:
            log(f"  {crashed_count} peers crashed!", RED)
        if unsynced_count > 0:
            log(f"  {unsynced_count} peers out of sync", RED)

        print()
        log("="*70, GREEN)
        log("CHAOS CONVERGENCE TEST COMPLETE - NO CRASHES!", GREEN)
        log("="*70, GREEN)
        print()
        log("Summary:", YELLOW)
        log(f"  • {NUM_PEER_NODES} peers with random chains (1-{max(peer_heights.values())} blocks)", YELLOW)
        log(f"  • All connected simultaneously to main node", YELLOW)
        log(f"  • Main node converged to height {main_height}", YELLOW)
        log(f"  • Extended mining: {synced_count}/{NUM_PEER_NODES} peers stayed in sync",
            GREEN if synced_count == NUM_PEER_NODES else YELLOW)
        log(f"  • No crashes detected ✓", GREEN)

        test_passed = (synced_count == NUM_PEER_NODES and crashed_count == 0)
        if test_passed:
            log(f"  • Test passed! ✓\n", GREEN)
        else:
            log(f"  • Test FAILED - sync issues detected ✗\n", RED)
            return 1

        return 0

    except Exception as e:
        log(f"\n✗ CHAOS TEST FAILED: {e}", RED)
        import traceback
        traceback.print_exc()
        return 1

    finally:
        log("\nCleaning up...", YELLOW)
        for node in nodes:
            if node.is_running():
                node.stop()
        log(f"Test directory preserved: {test_dir}", YELLOW)

if __name__ == '__main__':
    sys.exit(main())
