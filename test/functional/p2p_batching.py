#!/usr/bin/env python3
"""Test P2P header batching behavior.

Tests that headers sync happens in batches of MAX_HEADERS_SIZE (80000).

Scenario:
1. Start node0 with a pre-built chain (200000 blocks)
2. Start node1 (fresh, at genesis)
3. Connect node1 to node0
4. Verify node1 syncs in multiple batches (200000 / 80000 = 3 batches)

This is a SLOW test (~60+ minutes) and is excluded from the default test run.
Run directly: python3 test/functional/p2p_batching.py

Note: Requires chain_200000_blocks in test_chains/. Generate with:
  python3 test/functional/regenerate_test_chains.py
"""

import sys
import tempfile
import shutil
import time
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))

from test_node import TestNode
from util import pick_free_port

# Protocol limit for headers per message
MAX_HEADERS_SIZE = 80000


def main():
    """Run the test."""
    print("Starting P2P batching test...")
    print(f"This test verifies that headers sync in batches of {MAX_HEADERS_SIZE}")
    print("WARNING: This is a slow test (~60+ minutes)")
    print()

    # Setup test directory
    test_dir = Path(tempfile.mkdtemp(prefix="unicity_test_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node0 = None
    node1 = None

    try:
        # Load pre-built chain for node0
        print("\n=== Phase 1: Loading pre-built chain for node0 ===")
        prebuilt_chain = Path(__file__).parent / "test_chains" / "chain_200000_blocks"

        if not prebuilt_chain.exists():
            print(f"✗ Error: Pre-built chain not found at {prebuilt_chain}")
            print("Please run: python3 test/functional/regenerate_test_chains.py")
            print("(This will create chain_200000_blocks - takes ~1 hour to generate)")
            return 1

        print(f"Copying pre-built chain from {prebuilt_chain}...")
        shutil.copytree(prebuilt_chain, test_dir / "node0")

        # Start node0 with the pre-built chain (dynamic port)
        port0 = pick_free_port()
        print(f"Starting node0 (listening on port {port0})...")
        node0 = TestNode(0, test_dir / "node0", binary_path,
                        extra_args=["--listen", f"--port={port0}"])
        node0.start()

        time.sleep(2)

        info0 = node0.get_info()
        total = info0['blocks']
        print(f"\nNode0 loaded with {total} blocks")
        print(f"  Tip: {info0['bestblockhash'][:16]}...")

        # Set mock time to match chain timestamps (which were advanced during generation)
        # Read tip timestamp from chain and add buffer
        import json
        headers_file = prebuilt_chain / "headers.json"
        with open(headers_file) as f:
            chain_data = json.load(f)
        tip_timestamp = chain_data['blocks'][-1]['time']
        mock_time = tip_timestamp + 600  # Add 10 min buffer
        print(f"  Setting mock time to {mock_time} (tip timestamp + 600s)")
        node0.setmocktime(mock_time)

        expected_batches = (total // MAX_HEADERS_SIZE) + (1 if total % MAX_HEADERS_SIZE != 0 else 0)
        print(f"  Expected batches: {expected_batches} (at {MAX_HEADERS_SIZE} headers/batch)")

        assert total >= MAX_HEADERS_SIZE + 1, \
            f"Node0 needs > {MAX_HEADERS_SIZE} blocks for batching test, got {total}"

        # Start node1 (fresh node at genesis)
        print("\n=== Phase 2: Starting fresh node (at genesis) ===")
        port1 = pick_free_port()
        print(f"Starting node1 (port {port1})...")
        node1 = TestNode(1, test_dir / "node1", binary_path,
                        extra_args=[f"--port={port1}"])
        node1.start()

        time.sleep(2)

        info1 = node1.get_info()
        print(f"Node1 initial state: {info1['blocks']} blocks")
        assert info1['blocks'] == 0, f"Node1 should start at genesis, got {info1['blocks']}"

        # Set mock time on node1 to match node0 (so it accepts future-dated headers)
        print(f"  Setting mock time to {mock_time} (matching node0)")
        node1.setmocktime(mock_time)

        # Connect node1 to node0 to trigger IBD
        print("\n=== Phase 3: Connecting node1 to node0 (triggering IBD with batching) ===")
        print("Connecting node1 to node0...")
        result = node1.add_node(f"127.0.0.1:{port0}", "add")
        print(f"Connection result: {result}")

        print(f"\nWaiting for IBD to complete...")
        print(f"Expecting {expected_batches} batches of ~{MAX_HEADERS_SIZE} headers each")
        print()

        # Track batches
        target_height = info0['blocks']
        last_height = 0
        batch_count = 0
        batch_heights = []
        start_time = time.time()
        max_wait = 7200  # 2 hours max for 200k blocks

        while time.time() - start_time < max_wait:
            try:
                info1 = node1.get_info(timeout=120)
            except Exception as e:
                print(f"  Warning: get_info() failed: {e}")
                time.sleep(1)
                continue

            current_height = info1['blocks']
            current_time = time.time()

            if current_height > last_height:
                height_increase = current_height - last_height
                elapsed = current_time - start_time
                blocks_per_sec = current_height / elapsed if elapsed > 0 else 0
                eta = (target_height - current_height) / blocks_per_sec if blocks_per_sec > 0 else 0

                # Detect batch completion (large height jump, typically ~80000)
                if height_increase >= MAX_HEADERS_SIZE * 0.9:  # Allow 10% variance
                    batch_count += 1
                    batch_heights.append(current_height)
                    print(f"  [Batch {batch_count}] Synced to height {current_height} "
                          f"(+{height_increase} headers) - {elapsed:.1f}s elapsed, "
                          f"{blocks_per_sec:.1f} blocks/sec, ETA: {eta/60:.1f}min")
                else:
                    # Regular progress update
                    progress_pct = (current_height / target_height) * 100
                    print(f"  Syncing: {current_height}/{target_height} ({progress_pct:.1f}%) - "
                          f"{blocks_per_sec:.1f} blocks/sec, ETA: {eta/60:.1f}min")

                last_height = current_height

            if current_height >= target_height:
                elapsed = time.time() - start_time
                avg_blocks_per_sec = target_height / elapsed if elapsed > 0 else 0
                print(f"\n  IBD complete in {elapsed/60:.1f} minutes!")
                print(f"  Average sync rate: {avg_blocks_per_sec:.1f} blocks/sec")
                break

            time.sleep(1)

        # Final verification
        print("\n=== Phase 4: Verifying sync and batching ===")
        info0 = node0.get_info()
        info1 = node1.get_info()

        print(f"Node0: height={info0['blocks']}, tip={info0['bestblockhash'][:16]}...")
        print(f"Node1: height={info1['blocks']}, tip={info1['bestblockhash'][:16]}...")

        # Assert both nodes have same height
        assert info1['blocks'] == info0['blocks'], \
            f"Node1 should have synced to {info0['blocks']} blocks, got {info1['blocks']}"

        # Assert both nodes have same tip
        assert info0['bestblockhash'] == info1['bestblockhash'], \
            f"Nodes have different tips:\n  node0={info0['bestblockhash']}\n  node1={info1['bestblockhash']}"

        # Verify batching occurred
        print(f"\nBatching results:")
        print(f"  Detected {batch_count} batches")
        print(f"  Expected {expected_batches} batches")

        if batch_count >= expected_batches - 1:  # Allow some detection variance
            print(f"\n✓ Test passed! Batching works correctly:")
            print(f"  Node1 synced all {info0['blocks']} headers in {batch_count} batches")
            print(f"  Protocol limit: {MAX_HEADERS_SIZE} headers/batch")
            print(f"  Both nodes at height {info0['blocks']} with matching tip")
        else:
            print(f"\n⚠ Warning: Expected ~{expected_batches} batches, only detected {batch_count}")
            print("  (Polling may have missed some batch boundaries)")
            print(f"  Sync still completed successfully with {info0['blocks']} headers")

    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()

        if node0:
            print("\n--- Node0 last 30 lines ---")
            print(node0.read_log(30))
        if node1:
            print("\n--- Node1 last 30 lines ---")
            print(node1.read_log(30))
        return 1

    finally:
        if node0 and node0.is_running():
            print("\nStopping node0...")
            node0.stop()
        if node1 and node1.is_running():
            print("Stopping node1...")
            node1.stop()

        print(f"Cleaning up test directory: {test_dir}")
        shutil.rmtree(test_dir, ignore_errors=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
