#!/usr/bin/env python3
"""Test starting two nodes with different suspiciousreorgdepth settings."""

import sys
import tempfile
import shutil
import time
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))

from test_node import TestNode
from util import pick_free_port


def main():
    """Run two-node test."""
    print("\n=== Two Node Test ===\n")

    # Setup test directory
    test_dir = Path(tempfile.mkdtemp(prefix="unicity_two_nodes_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node0 = None
    node1 = None

    try:
        # Dynamic ports
        port0 = pick_free_port()
        port1 = pick_free_port()

        # Start node0 with default limit (100)
        print("Starting node0 (default suspiciousreorgdepth=100)...")
        node0 = TestNode(0, test_dir / "node0", binary_path,
                        extra_args=["--listen", f"--port={port0}", "--verbose"])

        print("Calling node0.start()...")
        node0.start()
        print("✓ node0.start() returned successfully!")

        # Start node1 with custom limit (5)
        print("\nStarting node1 (suspiciousreorgdepth=5)...")
        node1 = TestNode(1, test_dir / "node1", binary_path,
                        extra_args=["--listen", f"--port={port1}", "--suspiciousreorgdepth=5"])

        print("Calling node1.start()...")
        node1.start()
        print("✓ node1.start() returned successfully!")

        # Test both nodes
        print("\nGetting info from both nodes...")
        info0 = node0.get_info()
        info1 = node1.get_info()

        print(f"✓ Node0: blocks={info0['blocks']}")
        print(f"✓ Node1: blocks={info1['blocks']}")

        print("\n✓ Two-node test passed!")
        return 0

    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()

        # Print logs on failure
        if node0:
            print("\n--- Node0 last 50 lines ---")
            print(node0.read_log(50))
        if node1:
            print("\n--- Node1 last 50 lines ---")
            print(node1.read_log(50))
        return 1

    finally:
        # Cleanup
        if node0 and node0.is_running():
            node0.stop()
        if node1 and node1.is_running():
            node1.stop()

        print(f"\nKeeping test directory for debugging: {test_dir}")
        # TEMPORARILY DISABLED FOR DEBUGGING
        # shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
