#!/usr/bin/env python3
"""Test external miner integration with the node.

Tests:
1. Miner can connect to node via Unix socket
2. Miner can retrieve block template
3. Miner can submit valid blocks
"""

import os
import sys
import time
import tempfile
import shutil
import subprocess
import signal
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))

from test_node import TestNode


def test_miner_integration(node, miner_path, test_dir):
    """Test that external miner can mine blocks."""
    print("  Testing miner integration...")

    # Get initial block count
    info = node.rpc("getblockchaininfo")
    initial_height = info["blocks"]
    print(f"    Initial height: {initial_height}")

    # Create address file with a test address (40 hex chars)
    address_file = test_dir / "addresses.txt"
    test_address = "1234567890abcdef1234567890abcdef12345678"
    with open(address_file, 'w') as f:
        f.write(test_address + "\n")

    # Socket path
    socket_path = node.datadir / "node.sock"

    # Start miner
    miner_cmd = [
        str(miner_path),
        "--algo=randomx",
        f"--socket={socket_path}",
        f"--afile={address_file}",
        "--url=http://localhost/",  # URL is required but socket will be used
        "-t", "1",  # Single thread for testing
        "--no-stratum",
        "-D",  # Debug output
    ]

    print(f"    Starting miner: {' '.join(miner_cmd)}")

    miner_proc = subprocess.Popen(
        miner_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    try:
        # Let miner run for a bit and mine some blocks
        # RandomX takes time to initialize (dataset creation ~30s)
        print("    Waiting for miner to initialize and mine blocks...")
        print("    (RandomX dataset creation takes ~30 seconds)")

        target_blocks = initial_height + 1
        timeout = 180  # 3 minutes (includes dataset creation time)
        start_time = time.time()
        last_output_check = 0

        while time.time() - start_time < timeout:
            time.sleep(5)

            # Check miner output periodically
            if miner_proc.poll() is not None:
                print(f"    Miner process exited with code {miner_proc.returncode}")
                break

            try:
                info = node.rpc("getblockchaininfo")
                current_height = info["blocks"]
                elapsed = int(time.time() - start_time)
                print(f"    [{elapsed}s] Height: {current_height}")

                if current_height >= target_blocks:
                    print(f"    Mined {current_height - initial_height} blocks!")
                    return True
            except Exception as e:
                print(f"    RPC error: {e}")

        print(f"    Timeout waiting for blocks")
        return False

    finally:
        # Stop miner
        print("    Stopping miner...")
        miner_proc.send_signal(signal.SIGINT)
        try:
            stdout, _ = miner_proc.communicate(timeout=5)
            print("    Miner output (last 50 lines):")
            for line in stdout.split('\n')[-50:]:
                if line.strip():
                    print(f"      {line}")
        except subprocess.TimeoutExpired:
            miner_proc.kill()


def main():
    """Run miner integration tests."""
    print("Starting miner integration tests...\n")

    # Find miner binary - check MINER_PATH env var or search common locations
    miner_path = None
    if os.environ.get("MINER_PATH"):
        miner_path = Path(os.environ["MINER_PATH"])
    else:
        # Search common locations relative to this repo
        search_paths = [
            Path(__file__).parent.parent.parent.parent / "unicity-miner" / "minerd",
            Path.home() / "Code" / "unicity-miner" / "minerd",
            Path("/usr/local/bin/minerd"),
        ]
        for p in search_paths:
            if p.exists():
                miner_path = p
                break

    if not miner_path or not miner_path.exists():
        print("Error: Miner not found. Set MINER_PATH environment variable.")
        print("  Example: MINER_PATH=/path/to/minerd python3 miner_integration.py")
        return 1

    # Setup
    test_dir = Path(tempfile.mkdtemp(prefix="unicity_miner_test_"))
    node = None

    try:
        # Start node
        node = TestNode(0, test_dir / "node0")
        print(f"Starting node at {node.datadir}...")
        node.start()

        # Generate some initial blocks with internal miner
        print("Generating initial blocks...")
        node.generate(5)

        # Run tests
        print("\nRunning tests:")

        success = test_miner_integration(node, miner_path, test_dir)

        if success:
            print("\n" + "=" * 50)
            print("All tests passed!")
            print("=" * 50)
            return 0
        else:
            print("\n" + "=" * 50)
            print("TEST FAILED: Miner did not produce blocks")
            print("=" * 50)
            return 1

    except Exception as e:
        print(f"\n{'=' * 50}")
        print(f"TEST FAILED: {e}")
        print("=" * 50)

        if node:
            print("\nLast 30 lines of debug.log:")
            print(node.read_log(30))

        import traceback
        traceback.print_exc()
        return 1

    finally:
        if node and node.is_running():
            print("\nStopping node...")
            node.stop()

        print(f"Cleaning up: {test_dir}")
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
