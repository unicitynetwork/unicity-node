#!/usr/bin/env python3
# Fork resolution test - Multiple nodes with different chain lengths should converge to longest

import sys
import time
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode
from util import pick_free_port

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
    test_dir = Path(tempfile.mkdtemp(prefix='cbc_fork_'))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"
    nodes = []

    try:
        log("\n" + "="*70, BLUE)
        log("FORK RESOLUTION TEST", BLUE)
        log("="*70, BLUE)
        log("Scenario:", YELLOW)
        log("  - Node0: 5 blocks (shortest)", YELLOW)
        log("  - Node1: 10 blocks (medium)", YELLOW)
        log("  - Node2: 15 blocks (longest)", YELLOW)
        log("Expected: All nodes converge to 15 blocks\n", YELLOW)

        # Dynamic ports
        port0 = pick_free_port()
        port1 = pick_free_port()
        port2 = pick_free_port()

        # Create Node0 and mine 5 blocks
        log("Setting up Node0 with 5-block chain...", BLUE)
        node0_dir = test_dir / 'node0'
        node0 = TestNode(0, node0_dir, binary_path,
                        extra_args=["--listen", f"--port={port0}"])
        nodes.append(node0)
        node0.start()
        node0.generate(5)
        info = node0.get_info()
        log(f"✓ Node0 started: height={info['blocks']}, hash={info['bestblockhash'][:16]}...", GREEN)

        # Create Node1 and mine 10 blocks
        log("Setting up Node1 with 10-block chain...", BLUE)
        node1_dir = test_dir / 'node1'
        node1 = TestNode(1, node1_dir, binary_path,
                        extra_args=["--listen", f"--port={port1}"])
        nodes.append(node1)
        node1.start()
        node1.generate(10)
        info = node1.get_info()
        log(f"✓ Node1 started: height={info['blocks']}, hash={info['bestblockhash'][:16]}...", GREEN)

        # Create Node2 (longest) and mine 15 blocks
        log("Setting up Node2 with 15-block chain (longest)...", BLUE)
        node2_dir = test_dir / 'node2'
        node2 = TestNode(2, node2_dir, binary_path,
                        extra_args=["--listen", f"--port={port2}"])
        nodes.append(node2)
        node2.start()
        node2.generate(15)
        info = node2.get_info()
        expected_hash = info['bestblockhash']
        log(f"✓ Node2 started: height={info['blocks']}, hash={expected_hash[:16]}...", GREEN)
        log(f"\nExpected final hash: {expected_hash}\n", YELLOW)

        # Prefer outbound connections from shorter chains to longer chain
        # Node0 (5) → Node2 (15), Node1 (10) → Node2 (15)
        log("Connecting Node0 → Node2 (outbound)...", BLUE)
        r0 = node0.add_node(f"127.0.0.1:{port2}", "add")
        assert isinstance(r0, dict) and r0.get("success") is True, f"Node0→Node2 addnode failed: {r0}"
        time.sleep(1)

        log("Connecting Node1 → Node2 (outbound)...", BLUE)
        r1 = node1.add_node(f"127.0.0.1:{port2}", "add")
        assert isinstance(r1, dict) and r1.get("success") is True, f"Node1→Node2 addnode failed: {r1}"
        time.sleep(1)

        log("✓ All nodes connected\n", GREEN)

        # Monitor convergence
        log("Monitoring convergence (max 180 seconds)...", BLUE)
        max_wait = 180
        check_interval = 2
        converged = [False, False, False]

        for elapsed in range(0, max_wait, check_interval):
            time.sleep(check_interval)

            # Check each node
            for i, node in enumerate(nodes):
                if converged[i]:
                    continue

                if not node.is_running():
                    log(f"\n✗ CRASH: Node{i} crashed!", RED)
                    raise RuntimeError(f"Node{i} crashed!")

                try:
                    info = node.get_info()
                    height = info['blocks']
                    bhash = info['bestblockhash']

                    if height == 15 and bhash == expected_hash:
                        converged[i] = True
                        log(f"  {elapsed+check_interval}s: Node{i} converged to height 15 ✓", GREEN)
                    else:
                        log(f"  {elapsed+check_interval}s: Node{i} height={height}/15", BLUE)

                except Exception as e:
                    log(f"  Node{i}: RPC error: {e}", RED)

            # Check if all converged
            if all(converged):
                log(f"\n✓ All nodes converged in {elapsed+check_interval} seconds!", GREEN)
                break

        print()

        # Final verification
        log("Final verification:", BLUE)
        log("-" * 70, BLUE)

        all_synced = True
        for i, node in enumerate(nodes):
            info = node.get_info()
            height = info['blocks']
            bhash = info['bestblockhash']
            match = "✓" if (height == 15 and bhash == expected_hash) else "✗"

            log(f"Node{i}: height={height}, hash={bhash[:16]}... {match}",
                GREEN if match == "✓" else RED)

            if height != 15 or bhash != expected_hash:
                all_synced = False

        print()

        if all_synced:
            log("="*70, GREEN)
            log("FORK RESOLUTION TEST PASSED ✓", GREEN)
            log("="*70, GREEN)
            log("All nodes successfully converged to the longest chain (15 blocks)", GREEN)
            return 0
        else:
            log("="*70, RED)
            log("FORK RESOLUTION TEST FAILED ✗", RED)
            log("="*70, RED)
            log("Not all nodes converged to the longest chain", RED)
            return 1

    except Exception as e:
        log(f"\n✗ TEST FAILED: {e}", RED)
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
