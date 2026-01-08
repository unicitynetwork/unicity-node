#!/usr/bin/env python3
"""Wire-level adversarial framing tests via node_simulator.

Covers: bad-magic, bad-checksum, bad-length, truncation.
Each scenario connects, sends one malformed message, and exits.
Assertions: peer disconnects (no peers after the run) and node remains responsive.
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


def assert_no_peers(node: TestNode, timeout: int = 5):
    def no_peers():
        try:
            peers = node.get_peer_info()
            if not isinstance(peers, list):
                return False
            connected = [p for p in peers if isinstance(p, dict) and p.get("connected")]
            return len(connected) == 0
        except Exception:
            return False
    ok = wait_until(no_peers, timeout=timeout, check_interval=0.5)
    assert ok, "Expected no peers"


def main():
    print("Starting adversarial_framing_wire test (opt-in)")

    test_dir = Path(tempfile.mkdtemp(prefix="unicity_wire_frame_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node = None
    try:
        port = pick_free_port()
        node = TestNode(0, test_dir / "node0", binary_path, extra_args=["--listen", f"--port={port}"])
        node.start()

        time.sleep(1)

        # bad-magic
        print("Running node_simulator --test bad-magic ...")
        r = run_node_simulator(port, "bad-magic", timeout=15)
        print(r.stdout)
        if r.returncode != 0 and ("broken pipe" not in r.stderr.lower() and "end of file" not in r.stdout.lower() and "connection reset" not in r.stderr.lower()):
            raise AssertionError(r.stderr)
        # Require disconnect observable via RPC within 15s
        assert_no_peers(node, timeout=15)

        # bad-checksum
        print("Running node_simulator --test bad-checksum ...")
        r = run_node_simulator(port, "bad-checksum", timeout=15)
        print(r.stdout)
        if r.returncode != 0 and ("broken pipe" not in r.stderr.lower() and "end of file" not in r.stdout.lower() and "connection reset" not in r.stderr.lower()):
            raise AssertionError(r.stderr)
        assert_no_peers(node, timeout=15)

        # bad-length
        print("Running node_simulator --test bad-length ...")
        r = run_node_simulator(port, "bad-length", timeout=15)
        print(r.stdout)
        if r.returncode != 0 and ("broken pipe" not in r.stderr.lower() and "end of file" not in r.stdout.lower() and "connection reset" not in r.stderr.lower()):
            raise AssertionError(r.stderr)
        assert_no_peers(node, timeout=15)

        # truncation
        print("Running node_simulator --test truncation ...")
        r = run_node_simulator(port, "truncation", timeout=15)
        print(r.stdout)
        if r.returncode != 0 and ("broken pipe" not in r.stderr.lower() and "end of file" not in r.stdout.lower() and "connection reset" not in r.stderr.lower()):
            raise AssertionError(r.stderr)
        assert_no_peers(node, timeout=15)

        # basic responsiveness
        info = node.get_info()
        assert isinstance(info, dict) and "blocks" in info

        print("✓ adversarial_framing_wire passed")
        return 0

    except Exception as e:
        print(f"✗ adversarial_framing_wire failed: {e}")
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
