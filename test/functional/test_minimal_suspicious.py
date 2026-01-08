#!/usr/bin/env python3
"""Minimal test to isolate the RPC connection issue."""

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
    """Run minimal test."""
    print("\n=== Minimal Suspicious Reorg Test ===\n")

    # Setup test directory
    test_dir = Path(tempfile.mkdtemp(prefix="unicity_minimal_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node0 = None

    try:
        # Start ONE node with suspiciousreorgdepth flag
        port = pick_free_port()
        print(f"Starting node0 with --suspiciousreorgdepth=5 on port {port}...")
        node0 = TestNode(0, test_dir / "node0", binary_path,
                        extra_args=["--listen", f"--port={port}", "--suspiciousreorgdepth=5"])

        print("Calling node0.start()...")
        node0.start()
        print("node0.start() returned successfully!")

        # Simple test - just get info
        print("\nGetting info from node0...")
        info = node0.get_info()
        print(f"Success! Node0 info: blocks={info['blocks']}")

        print("\n✓ Minimal test passed!")
        return 0

    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()

        # Print logs on failure
        if node0:
            print("\n--- Node0 last 50 lines ---")
            print(node0.read_log(50))
        return 1

    finally:
        # Cleanup
        if node0 and node0.is_running():
            node0.stop()

        print(f"\nCleaning up test directory: {test_dir}")
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
