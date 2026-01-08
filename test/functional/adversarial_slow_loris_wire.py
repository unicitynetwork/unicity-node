#!/usr/bin/env python3
"""Wire-level adversarial test: slow-loris (chunked drip + early close).

Sends a large HEADERS payload slowly and closes before completion.
Asserts: node remains responsive and no peers connected afterward.
"""

import sys
import tempfile
import shutil
import time
import subprocess
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))
from test_node import TestNode
from util import pick_free_port, wait_until


def run_node_simulator(port: int, test: str, host: str = "127.0.0.1", timeout: int = 40):
    exe = Path(__file__).parent.parent.parent / "build" / "bin" / "node_simulator"
    if not exe.exists():
        raise FileNotFoundError(f"node_simulator not found at {exe}; run cmake --build build")
    cmd = [str(exe), "--host", host, "--port", str(port), "--test", test]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def main():
    print("Starting adversarial_slow_loris_wire test (opt-in)")

    test_dir = Path(tempfile.mkdtemp(prefix="unicity_wire_loris_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node = None
    try:
        port = pick_free_port()
        node = TestNode(0, test_dir / "node0", binary_path, extra_args=["--listen", f"--port={port}"])
        node.start()

        time.sleep(1)

        print("Running node_simulator --test slow-loris ...")
        proc = run_node_simulator(port, "slow-loris", timeout=40)
        print(proc.stdout)
        # slow-loris may end via client close; expect return code 0
        if proc.returncode != 0:
            print(proc.stderr)
            raise RuntimeError("node_simulator slow-loris failed")

        # Basic responsiveness AND peer dropped deterministically
        info = node.get_info()
        assert isinstance(info, dict) and "blocks" in info

        def no_peers():
            peers = node.get_peer_info()
            if not isinstance(peers, list):
                return False
            connected = [p for p in peers if isinstance(p, dict) and p.get("connected")]
            return len(connected) == 0
        ok = wait_until(no_peers, timeout=15, check_interval=0.5)
        assert ok, "Expected peer to be dropped after slow-loris close"

        print("✓ adversarial_slow_loris_wire passed")
        return 0

    except Exception as e:
        print(f"✗ adversarial_slow_loris_wire failed: {e}")
        if node:
            print("\nNode last 80 lines of debug.log:")
            print(node.read_log(80))
        return 1
    finally:
        if node and node.is_running():
            node.stop()
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
