#!/usr/bin/env python3
"""Wire-level adversarial framing tests via node_simulator.

Covers: bad-magic, bad-checksum, bad-length, truncation.
Each scenario connects, sends one malformed message, and exits.

Verification:
- Peer is disconnected after sending malformed framing
- Node remains responsive to RPC
- Node detects the protocol violation (checked via disconnect)

Note: These are fundamental protocol violations that should always cause disconnect.
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


def wait_for_disconnect(node: TestNode, timeout: int = 15) -> bool:
    """Wait for peer to be disconnected."""
    def no_peers():
        try:
            peers = node.get_peer_info()
            if not isinstance(peers, list):
                return False
            connected = [p for p in peers if isinstance(p, dict) and p.get("connected")]
            return len(connected) == 0
        except Exception:
            return False
    return wait_until(no_peers, timeout=timeout, check_interval=0.5)


def run_framing_test(node: TestNode, port: int, test_name: str, description: str) -> tuple:
    """
    Run a framing test and verify proper handling.

    Returns: (passed: bool, details: str)
    """
    print(f"\n  Testing {test_name}: {description}")

    # Run the attack
    r = run_node_simulator(port, test_name, timeout=15)

    # Check if simulator reported connection was closed (expected for framing violations)
    connection_closed = any(x in (r.stdout + r.stderr).lower() for x in [
        "connection closed", "end of file", "broken pipe", "connection reset"
    ])

    if r.returncode != 0 and not connection_closed:
        return False, f"node_simulator failed unexpectedly: {r.stderr}"

    # Verify peer was disconnected
    if not wait_for_disconnect(node, timeout=10):
        return False, "Peer was NOT disconnected after framing violation"

    # Verify node is still responsive
    try:
        info = node.get_info()
        if not isinstance(info, dict) or "blocks" not in info:
            return False, "Node not responding to RPC after attack"
    except Exception as e:
        return False, f"Node RPC failed: {e}"

    return True, "Peer disconnected, node responsive"


def main():
    print("=" * 60)
    print("TEST: Adversarial Framing Wire")
    print("=" * 60)
    print("Tests protocol framing violations that should cause disconnect")

    test_dir = Path(tempfile.mkdtemp(prefix="unicity_wire_frame_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node = None
    results = []

    try:
        port = pick_free_port()
        node = TestNode(0, test_dir / "node0", binary_path, extra_args=["--listen", f"--port={port}"])
        node.start()
        time.sleep(2)

        # Test cases - all should cause disconnect
        test_cases = [
            ("bad-magic", "Message with wrong magic bytes"),
            ("bad-checksum", "Message with invalid checksum"),
            ("bad-length", "Message with mismatched length field"),
            ("truncation", "Truncated message (incomplete)"),
        ]

        for test_name, description in test_cases:
            passed, details = run_framing_test(node, port, test_name, description)
            results.append((test_name, passed, details))
            print(f"    {'PASS' if passed else 'FAIL'}: {details}")
            time.sleep(0.5)  # Brief pause between tests

        # Summary
        print("\n" + "=" * 60)
        passed_count = sum(1 for _, p, _ in results if p)
        total = len(results)

        print(f"Results: {passed_count}/{total} passed")
        for name, passed, details in results:
            status = "PASS" if passed else "FAIL"
            print(f"  {name}: {status}")

        if passed_count == total:
            print("\nadversarial_framing_wire PASSED")
            print("  - All framing violations caused peer disconnect")
            print("  - Node remained responsive throughout")
            return 0
        else:
            print(f"\nadversarial_framing_wire FAILED ({total - passed_count} failures)")
            return 1

    except Exception as e:
        print(f"\nadversarial_framing_wire FAILED: {e}")
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
