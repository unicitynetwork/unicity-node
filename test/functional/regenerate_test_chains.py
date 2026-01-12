#!/usr/bin/env python3
"""Regenerate large test chains for batching/persistence tests.

Usage:
    # Generate all chains (sequential)
    python3 regenerate_test_chains.py

    # Generate specific chain by name
    python3 regenerate_test_chains.py chain_12000_blocks

    # Generate specific chain by height
    python3 regenerate_test_chains.py 12000

    # Generate multiple specific chains
    python3 regenerate_test_chains.py 200 2500 12000

    # List available chains
    python3 regenerate_test_chains.py --list

    # Run multiple in parallel (in separate terminals):
    python3 regenerate_test_chains.py 200 &
    python3 regenerate_test_chains.py 2500 &
    python3 regenerate_test_chains.py 12000 &
    python3 regenerate_test_chains.py 200000 &
"""

import sys
import time
import tempfile
import shutil
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode

# Available chains - add new ones here
CHAINS = [
    (200, "chain_200_blocks"),
    (2500, "chain_2500_blocks"),
    (12000, "chain_12000_blocks"),
    # Large chain for batching test (MAX_HEADERS_SIZE=80000, so 200k requires 3 batches)
    (200000, "chain_200000_blocks"),
]


def generate_chain(height, output_name):
    """Generate a test chain and save it."""
    print(f"\n{'='*70}")
    print(f"Generating {height}-block chain: {output_name}")
    print(f"{'='*70}")

    test_dir = Path(tempfile.mkdtemp(prefix=f"gen_{height}_"))

    # Use --nolisten to avoid port conflicts
    node = TestNode(0, test_dir / "node0", extra_args=["--nolisten"])
    try:
        print("Starting node...")
        node.start()
        time.sleep(1)

        print(f"Mining {height} blocks...")
        print(f"Debug log: {test_dir / 'node0' / 'debug.log'}")
        start = time.time()

        # Initialize mock time to allow block timestamps to advance ahead of real time
        # This prevents "time-too-new" validation errors during rapid block generation
        mock_time = int(time.time())
        node.setmocktime(mock_time)

        # Mine in batches for progress updates
        # Use longer timeout - RandomX mining is slow (~50 blocks/sec after warmup)
        batch_size = 100
        for i in range(0, height, batch_size):
            remaining = min(batch_size, height - i)
            node.generate(remaining, address=None, timeout=600)  # 10 min timeout per batch

            # Advance mock time by batch_size seconds to keep up with block timestamps
            # Each block can increment timestamp by 1 second, so we need mock time
            # to advance at least as fast as the number of blocks mined
            mock_time += remaining
            node.setmocktime(mock_time)

            elapsed = time.time() - start
            rate = (i + remaining) / elapsed if elapsed > 0 else 0
            eta = (height - i - remaining) / rate if rate > 0 else 0
            print(f"  Progress: {i + remaining}/{height} blocks ({int((i + remaining) / height * 100)}%) "
                  f"- {rate:.1f} blocks/sec, ETA: {eta:.0f}s")

        elapsed = time.time() - start
        print(f"Mining complete in {elapsed:.1f}s ({height/elapsed:.1f} blocks/sec)")

        info = node.get_info()
        print(f"Final height: {info['blocks']}")
        print(f"Tip: {info['bestblockhash'][:16]}...")

        node.stop()
        time.sleep(1)

        # Save to test_chains
        output_dir = Path(__file__).parent / "test_chains" / output_name
        if output_dir.exists():
            shutil.rmtree(output_dir)
        output_dir.parent.mkdir(parents=True, exist_ok=True)

        print(f"Saving chain to {output_dir}...")
        shutil.copytree(test_dir / "node0", output_dir)

        # Verify
        print("Verifying saved chain...")
        with open(output_dir / "headers.json") as f:
            data = json.load(f)
            saved_height = data['block_count'] - 1
            print(f"Saved {saved_height} blocks (+ genesis = {saved_height + 1} total)")
            assert saved_height == height, f"Height mismatch: expected {height}, got {saved_height}"

        print(f"✓ Successfully generated {output_name}")
        return 0

    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        if node:
            node.stop()
        # Clean up temp dir
        shutil.rmtree(test_dir, ignore_errors=True)


def list_chains():
    """List available chains."""
    print("\nAvailable chains:")
    print("-" * 50)
    for height, name in CHAINS:
        est_time = height / 50  # ~50 blocks/sec estimate
        if est_time < 60:
            time_str = f"~{est_time:.0f}s"
        elif est_time < 3600:
            time_str = f"~{est_time/60:.0f}min"
        else:
            time_str = f"~{est_time/3600:.1f}hr"
        print(f"  {height:>6} blocks  {name:<25} {time_str}")
    print()


def find_chain(spec):
    """Find a chain by height or name."""
    # Try as height first
    try:
        height = int(spec)
        for h, name in CHAINS:
            if h == height:
                return (h, name)
    except ValueError:
        pass

    # Try as name
    for h, name in CHAINS:
        if name == spec or spec in name:
            return (h, name)

    return None


def main():
    parser = argparse.ArgumentParser(
        description="Generate test chains for functional tests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      Generate all chains sequentially
  %(prog)s 12000                Generate chain_12000_blocks only
  %(prog)s chain_200_blocks     Generate by name
  %(prog)s 200 2500             Generate multiple specific chains
  %(prog)s --list               Show available chains

To run in parallel, use separate terminals or background jobs:
  %(prog)s 200 &
  %(prog)s 2500 &
  %(prog)s 12000 &
""")
    parser.add_argument("chains", nargs="*", help="Chain heights or names to generate")
    parser.add_argument("--list", action="store_true", help="List available chains")
    args = parser.parse_args()

    if args.list:
        list_chains()
        return 0

    # Determine which chains to generate
    if args.chains:
        chains_to_generate = []
        for spec in args.chains:
            chain = find_chain(spec)
            if chain is None:
                print(f"Error: Unknown chain '{spec}'")
                list_chains()
                return 1
            chains_to_generate.append(chain)
    else:
        chains_to_generate = CHAINS

    print("\n" + "="*70)
    print("REGENERATING TEST CHAINS")
    print("="*70)
    print(f"Chains to generate: {[name for _, name in chains_to_generate]}")

    for height, name in chains_to_generate:
        result = generate_chain(height, name)
        if result != 0:
            print(f"\n✗ Failed to generate {name}")
            return result

    print("\n" + "="*70)
    print("✓ ALL REQUESTED CHAINS GENERATED SUCCESSFULLY")
    print("="*70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
