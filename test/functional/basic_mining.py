#!/usr/bin/env python3
"""Basic mining test.

Tests that a single node can start, generate blocks, and report correct state.
"""

import sys
import tempfile
import shutil
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))

from test_node import TestNode


def main():
    """Run the test."""
    print("Starting basic_mining test...")

    # Setup test directory
    test_dir = Path(tempfile.mkdtemp(prefix="unicity_test_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    try:
        # Start a single node
        node = TestNode(0, test_dir / "node0", binary_path)
        print(f"Starting node at {node.datadir}...")
        node.start()

        # Check initial state
        info = node.get_info()
        print(f"Initial state: {info}")
        assert info["blocks"] == 0, f"Expected blocks 0, got {info['blocks']}"

        # Generate 10 blocks
        print("Generating 10 blocks...")
        result = node.generate(10)
        print(f"Generated blocks: {result}")

        # Check new state
        info = node.get_info()
        print(f"New state: {info}")
        assert info["blocks"] >= 10, f"Expected at least 10 blocks, got {info['blocks']}"

        # Generate 5 more blocks
        print("Generating 5 more blocks...")
        node.generate(5)

        # Final state
        info = node.get_info()
        print(f"Final state: {info}")
        assert info["blocks"] >= 15, f"Expected at least 15 blocks, got {info['blocks']}"

        print("✓ Test passed!")

    except Exception as e:
        print(f"✗ Test failed: {e}")
        # Print last 20 lines of log on failure
        if node:
            print("\nLast 20 lines of debug.log:")
            print(node.read_log(20))
        return 1

    finally:
        # Cleanup
        if node and node.is_running():
            print("Stopping node...")
            node.stop()

        print(f"Cleaning up test directory: {test_dir}")
        shutil.rmtree(test_dir, ignore_errors=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
