#!/usr/bin/env python3
"""Wire-level adversarial tests using the Node Simulator (real TCP).

This test starts a listening node and drives the node_simulator CLI to send
malicious HEADERS over a real socket, then asserts disconnects via RPC/logs.

Scenarios (opt-in; slow/advanced):
- invalid-pow: send HEADERS with impossible difficulty -> expect disconnect

Note: The node_simulator binary is built under build/bin/ as part of tests.
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


def run_node_simulator(port: int, test: str, host: str = "127.0.0.1", timeout: int = 20):
    exe = Path(__file__).parent.parent.parent / "build" / "bin" / "node_simulator"
    if not exe.exists():
        raise FileNotFoundError(f"node_simulator not found at {exe}; run cmake --build build")

    cmd = [str(exe), "--host", host, "--port", str(port), "--test", test]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def main():
    print("Starting adversarial_headers_wire test (opt-in)")

    test_dir = Path(tempfile.mkdtemp(prefix="unicity_wire_adv_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node = None
    try:
        port = pick_free_port()
        node = TestNode(0, test_dir / "node0", binary_path, extra_args=["--listen", f"--port={port}"])
        node.start()

        # Give node time to fully start and bind to port
        time.sleep(2)

        # Run invalid-pow scenario – expect peer disconnect
        print("Running node_simulator --test invalid-pow ...")
        proc = run_node_simulator(port, "invalid-pow", timeout=25)
        print(proc.stdout)
        if proc.returncode != 0:
            print(proc.stderr)
            raise RuntimeError("node_simulator invalid-pow failed")

        # Allow node to process disconnect
        time.sleep(1)

        # Assert no peers connected
        peers = node.get_peer_info()
        if isinstance(peers, list) and len(peers) == 0:
            print("✓ Peer disconnected as expected")
        else:
            # Some implementations may drop before getpeerinfo sees the peer; poll briefly
            def no_peers():
                try:
                    p = node.get_peer_info()
                    return isinstance(p, list) and len(p) == 0
                except Exception:
                    return False
            ok = wait_until(no_peers, timeout=5, check_interval=0.5)
            assert ok, f"Expected no peers, got: {peers}"

        print("✓ adversarial_headers_wire passed")
        return 0

    except Exception as e:
        print(f"✗ adversarial_headers_wire failed: {e}")
        # Print logs for debugging
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
