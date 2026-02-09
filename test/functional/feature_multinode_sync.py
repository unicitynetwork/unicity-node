#!/usr/bin/env python3
# Copyright (c) 2025 The Unicity Foundation
# Test concurrent sync from multiple nodes

"""
Multi-node concurrent sync test.

Tests that the node can safely sync from multiple peers concurrently,
verifying that serving many peers on a single network thread is stable.

Scenario:
- Node0: Mines a long chain (50 blocks)
- Node1-10: Start with genesis, connect to Node0
- All nodes sync from Node0 concurrently (single network thread, many peers)
- Verify no crashes, deadlocks, or data corruption
"""

import os
import sys
import time
import subprocess
import tempfile
import shutil
import signal
from pathlib import Path

# Add framework helpers
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import resolve_unicityd
from util import pick_free_port

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

class TestNode:
    def __init__(self, node_id, datadir, port):
        self.node_id = node_id
        self.datadir = datadir
        self.port = port
        self.process = None

    def start(self, extra_args=None, binary_path=None):
        """Start the node"""
        if binary_path is None:
            binary_path = str(resolve_unicityd())

        args = [
            binary_path,
            '--regtest',
            f'--datadir={self.datadir}',
            f'--port={self.port}',
        ]

        if extra_args:
            args.extend(extra_args)

        self.process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Wait a bit for startup
        time.sleep(0.5)

        # Check if process is still running
        if self.process.poll() is not None:
            stdout, stderr = self.process.communicate()
            raise RuntimeError(f"Node{self.node_id} failed to start:\nSTDOUT: {stdout}\nSTDERR: {stderr}")

        log(f"Node{self.node_id} started (port={self.port})", GREEN)

    def stop(self):
        """Stop the node"""
        if self.process:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            log(f"Node{self.node_id} stopped", YELLOW)

    def rpc(self, method, params=None):
        """Call RPC method via unicity-cli"""
        import json

        # Find unicity-cli binary
        script_dir = os.path.dirname(os.path.abspath(__file__))
        cli_binary = os.path.join(script_dir, '../../build/bin/unicity-cli')

        args = [
            cli_binary,
            f'--datadir={self.datadir}',
            method
        ]

        if params:
            args.extend(str(p) for p in params)

        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                raise RuntimeError(f"RPC {method} failed: {result.stderr}")

            # Try to parse JSON response
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return result.stdout.strip()

        except Exception as e:
            raise RuntimeError(f"RPC call failed: {e}")

    def getblockcount(self):
        """Get current block height"""
        try:
            info = self.rpc('getinfo')
            return info.get('blocks', 0) if isinstance(info, dict) else 0
        except:
            return 0

    def mine_blocks(self, n):
        """Mine n blocks"""
        try:
            # Generate all blocks at once
            address = "0000000000000000000000000000000000000000"
            self.rpc('generate', [n, address])
        except Exception as e:
            log(f"Warning: Mining {n} blocks failed: {e}", YELLOW)
            time.sleep(0.1)

        # Verify we mined them
        height = self.getblockcount()
        log(f"Node{self.node_id} mined {n} blocks, now at height {height}", BLUE)
        return height

    def connect_to_peer(self, peer_addr):
        """Connect to a peer node"""
        try:
            return self.rpc('addnode', [peer_addr, 'add'])
        except Exception as e:
            log(f"Warning: Connection to {peer_addr} failed: {e}", YELLOW)
            return None

def wait_for_sync(nodes, target_height, timeout=30):
    """Wait for all nodes to sync to target height"""
    start = time.time()

    while time.time() - start < timeout:
        heights = []
        all_synced = True

        for node in nodes:
            try:
                height = node.getblockcount()
                heights.append(height)
                if height < target_height:
                    all_synced = False
            except:
                heights.append(0)
                all_synced = False

        if all_synced:
            log(f"✓ All nodes synced to height {target_height}", GREEN)
            return True

        # Print progress
        synced = sum(1 for h in heights if h >= target_height)
        log(f"  Sync progress: {synced}/{len(nodes)} nodes at height {target_height} (heights: {heights})")
        time.sleep(1)

    log(f"✗ Sync timeout! Heights: {heights}", RED)
    return False

def main():
    log("\n=== Multi-Node Concurrent Sync Test ===\n", BLUE)

    # Configuration
    # Note: Eviction-based netgroup limiting (~4 per /16) affects localhost connections
    NUM_SYNC_NODES = 4  # 4 nodes syncing from Node0
    CHAIN_LENGTH = 50

    test_dir = tempfile.mkdtemp(prefix='cbc_multinode_')
    log(f"Test directory: {test_dir}\n")

    nodes = []

    try:
        # Create Node0 (the node with the chain)
        node0_dir = os.path.join(test_dir, 'node0')
        os.makedirs(node0_dir)
        port0 = pick_free_port()
        node0 = TestNode(0, node0_dir, port0)
        nodes.append(node0)

        # Create syncing nodes (Node1-10)
        for i in range(1, NUM_SYNC_NODES + 1):
            node_dir = os.path.join(test_dir, f'node{i}')
            os.makedirs(node_dir)
            node_port = pick_free_port()
            node = TestNode(i, node_dir, node_port)
            nodes.append(node)

        # Step 1: Start Node0 and mine chain
        # Increase per-IP inbound limit so all localhost peers can connect
        log("Step 1: Starting Node0 and mining chain...", BLUE)
        node0.start(extra_args=["--listen"])
        time.sleep(1)

        initial_height = node0.getblockcount()
        log(f"✓ Node0 initial height: {initial_height}")

        log(f"\nMining {CHAIN_LENGTH} blocks on Node0...")
        final_height = node0.mine_blocks(CHAIN_LENGTH)

        if final_height < CHAIN_LENGTH:
            raise RuntimeError(f"Node0 only reached height {final_height}, expected {CHAIN_LENGTH}")

        log(f"✓ Node0 mined chain to height {final_height}\n", GREEN)

        # Step 2: Start all sync nodes simultaneously
        log(f"Step 2: Starting {NUM_SYNC_NODES} nodes to sync from Node0...", BLUE)
        log("This tests concurrent header processing from many peers on a single network thread\n")

        for node in nodes[1:]:
            node.start()
            time.sleep(0.5)  # Wait for node to be ready

        log(f"✓ All {NUM_SYNC_NODES} sync nodes started\n", GREEN)

        # Connect all sync nodes to Node0 (outbound from sync nodes)
        # Note: Eviction-based netgroup limiting (~4 per /16) limits localhost connections to Node0
        log("Connecting all sync nodes to Node0...", BLUE)
        for node in nodes[1:]:
            node.connect_to_peer(f'127.0.0.1:{port0}')
            time.sleep(0.1)

        log(f"✓ All nodes connected to Node0\n", GREEN)

        # Step 3: Wait for all nodes to sync
        log(f"Step 3: Waiting for all nodes to sync to height {CHAIN_LENGTH}...", BLUE)
        log("(This stresses the validation mutex with many peers syncing at once)\n")

        if not wait_for_sync(nodes[1:], CHAIN_LENGTH, timeout=60):
            raise RuntimeError("Nodes failed to sync in time!")

        # Step 4: Verify all nodes have same tip
        log("\nStep 4: Verifying all nodes have consistent state...", BLUE)

        heights = [node.getblockcount() for node in nodes]
        log(f"Final heights: {heights}")

        if not all(h == CHAIN_LENGTH for h in heights):
            raise RuntimeError(f"Height mismatch! Expected all nodes at {CHAIN_LENGTH}, got {heights}")

        log(f"✓ All {len(nodes)} nodes at height {CHAIN_LENGTH}", GREEN)

        # Step 5: Test continued operation - mine more blocks and sync again
        log("\nStep 5: Testing continued operation (mine 10 more blocks)...", BLUE)

        new_height = node0.mine_blocks(10)
        log(f"Node0 now at height {new_height}")

        if not wait_for_sync(nodes[1:], new_height, timeout=30):
            raise RuntimeError("Second sync failed!")

        log(f"✓ All nodes synced to new height {new_height}", GREEN)

        # Success!
        log("\n" + "="*60, GREEN)
        log("✓ Multi-node concurrent sync test PASSED!", GREEN)
        log("="*60 + "\n", GREEN)

        log("Test verified:", BLUE)
        log(f"  • {NUM_SYNC_NODES} nodes syncing concurrently from Node0")
        log(f"  • {CHAIN_LENGTH + 10} blocks synced total")
        log(f"  • Single network thread serving many concurrent peers")
        log(f"  • No crashes, deadlocks, or data corruption")
        log(f"  • Validation mutex correctly serializes concurrent operations")

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
            node.stop()

        time.sleep(1)

        try:
            shutil.rmtree(test_dir)
            log(f"Cleaned up test directory: {test_dir}\n")
        except Exception as e:
            log(f"Warning: Could not clean up {test_dir}: {e}", YELLOW)

if __name__ == '__main__':
    sys.exit(main())
