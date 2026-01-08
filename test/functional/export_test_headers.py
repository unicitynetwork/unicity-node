#!/usr/bin/env python3
"""Export headers for RandomX verification testing.

Mines a simple regtest chain and exports header data with RandomX hashes.
"""

import sys
import tempfile
import shutil
import json
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))

from test_node import TestNode


def main():
    """Run the test."""
    print("Mining test chain for RandomX verification...")

    # Setup test directory
    test_dir = Path(tempfile.mkdtemp(prefix="unicity_rxtest_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node = None
    try:
        # Start a single regtest node
        node = TestNode(0, test_dir / "node0", binary_path)
        print(f"Starting regtest node at {node.datadir}...")
        node.start()

        # Check initial state
        info = node.rpc("getblockchaininfo")
        print(f"Initial blocks: {info['blocks']}")

        # Generate 5 blocks
        print("\nGenerating 5 blocks...")
        hashes = node.rpc("generate", 5)
        print(f"Generated block hashes: {hashes}")

        # Export headers
        headers_data = {
            "chain": "regtest",
            "epoch_duration": 365 * 24 * 60 * 60 * 100,  # 100 years for regtest
            "seed_prefix": "Alpha/RandomX/Epoch/",
            "blocks": []
        }

        for height in range(6):  # 0 (genesis) through 5
            block_hash = node.rpc("getblockhash", height)
            header = node.rpc("getblockheader", block_hash)

            # Debug: print all fields for first block
            if height == 0:
                print("\nAvailable header fields:", list(header.keys()))

            block_data = {
                "height": header["height"],
                "hash": header["hash"],
                "version": header["version"],
                "prev_hash": header.get("previousblockhash", "0" * 64),
                "miner_address": "0" * 40,  # Not exposed by RPC, use zeros
                "time": header["time"],
                "bits": int(header["bits"], 16) if isinstance(header["bits"], str) else header["bits"],
                "nonce": header["nonce"],
                "hash_randomx": header.get("rx_hash", ""),
                "chainwork": header.get("chainwork", ""),
            }

            headers_data["blocks"].append(block_data)

            print(f"\nBlock {height}:")
            print(f"  Hash:      {block_data['hash']}")
            print(f"  RandomX:   {block_data['hash_randomx']}")
            print(f"  Time:      {block_data['time']}")
            print(f"  Nonce:     {block_data['nonce']}")

        # Save to file - use OUTPUT_PATH env var or current directory
        output_file = Path(os.environ.get("OUTPUT_PATH", "test_headers.json"))
        with open(output_file, 'w') as f:
            json.dump(headers_data, f, indent=2)

        print(f"\n✓ Headers exported to: {output_file.absolute()}")
        return 0

    except Exception as e:
        print(f"✗ Failed: {e}")
        import traceback
        traceback.print_exc()
        if node:
            print("\nLast 20 lines of debug.log:")
            print(node.read_log(20))
        return 1

    finally:
        # Cleanup
        if node and node.is_running():
            print("\nStopping node...")
            node.stop()

        print(f"Cleaning up test directory: {test_dir}")
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
