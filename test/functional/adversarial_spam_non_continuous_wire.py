#!/usr/bin/env python3
"""Wire-level adversarial test: spam non-continuous headers until disconnect.

Invokes node_simulator --test spam-continuous (5x), expecting disconnect at 100 points.
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


def run_node_simulator(port: int, test: str, host: str = "127.0.0.1", timeout: int = 30):
    exe = Path(__file__).parent.parent.parent / "build" / "bin" / "node_simulator"
    if not exe.exists():
        raise FileNotFoundError(f"node_simulator not found at {exe}; run cmake --build build")
    cmd = [str(exe), "--host", host, "--port", str(port), "--test", test]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def main():
    print("Starting adversarial_spam_non_continuous_wire test (opt-in)")

    test_dir = Path(tempfile.mkdtemp(prefix="unicity_wire_spam_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node = None
    try:
        port = pick_free_port()
        node = TestNode(0, test_dir / "node0", binary_path, extra_args=["--listen", f"--port={port}"])
        node.start()

        # Give node time to fully start and bind to port
        time.sleep(2)

        print("Running node_simulator --test spam-continuous ...")
        proc = run_node_simulator(port, "spam-continuous", timeout=40)
        print(proc.stdout)
        if proc.returncode != 0 and ("Broken pipe" not in proc.stderr and "connection closed" not in proc.stderr.lower()):
            print(proc.stderr)
            raise RuntimeError("node_simulator spam-continuous failed")

        # Allow node to process disconnect (may take a moment after last batch)
        def no_peers():
            try:
                peers = node.get_peer_info()
                if not isinstance(peers, list):
                    return False
                connected = [p for p in peers if isinstance(p, dict) and p.get("connected")]
                return len(connected) == 0
            except Exception:
                return False
        ok = wait_until(no_peers, timeout=15, check_interval=0.5)
        assert ok, "Expected disconnect after 5x non-continuous headers"

        print("✓ adversarial_spam_non_continuous_wire passed")
        return 0

    except Exception as e:
        print(f"✗ adversarial_spam_non_continuous_wire failed: {e}")
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
