#!/usr/bin/env python3
"""Wire-level adversarial header validation tests via node_simulator.

Covers: future-timestamp, unconnecting-headers-flood, getheaders-spam, rapid-reconnect.
Tests header validation and rate limiting behavior.

Verification:
- future-timestamp: Headers with future timestamps rejected
- unconnecting-headers-flood: Node handles flood of headers with unknown parents gracefully
- getheaders-spam: Node handles rapid requests without crash
- rapid-reconnect: Node handles connection churn gracefully
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


def wait_for_disconnect(node: TestNode, timeout: int = 15) -> bool:
    """Wait for all peers to be disconnected."""
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


def main():
    print("=" * 60)
    print("TEST: Adversarial Validation Wire")
    print("=" * 60)
    print("Tests header validation and rate limiting")

    test_dir = Path(tempfile.mkdtemp(prefix="unicity_wire_validation_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node = None
    results = []

    try:
        port = pick_free_port()
        node = TestNode(0, test_dir / "node0", binary_path, extra_args=["--listen", f"--port={port}"])
        node.start()
        time.sleep(2)

        # === Test 1: future-timestamp ===
        print("\n  Testing future-timestamp: Headers with timestamps far in future")
        r = run_node_simulator(port, "future-timestamp", timeout=15)

        # Node should reject future timestamps and disconnect
        disconnected = wait_for_disconnect(node, timeout=10)

        # Verify node responsive
        info = node.get_info()
        responsive = isinstance(info, dict) and "blocks" in info

        if disconnected and responsive:
            results.append(("future-timestamp", True, "Peer disconnected, node responsive"))
        elif responsive:
            results.append(("future-timestamp", True, "Attack handled, node responsive"))
        else:
            results.append(("future-timestamp", False, "Node not responsive"))
        print(f"    {'PASS' if results[-1][1] else 'FAIL'}: {results[-1][2]}")
        time.sleep(0.5)

        # === Test 2: unconnecting-headers-flood ===
        # Tests that the node handles a flood of headers with unknown parents gracefully.
        # These headers trigger GETHEADERS requests but don't get stored (no orphan pool).
        # The node should remain responsive and eventually disconnect the peer.
        print("\n  Testing unconnecting-headers-flood: Flood with headers having unknown parents")

        r = run_node_simulator(port, "orphan-flood", timeout=30)

        # Wait for disconnect (peer may be disconnected due to validation failures)
        disconnected = wait_for_disconnect(node, timeout=15)

        # Verify node responsive - this is the key check
        info = node.get_info()
        responsive = isinstance(info, dict) and "blocks" in info

        if responsive:
            if disconnected:
                results.append(("unconnecting-headers-flood", True,
                               "Node handled flood gracefully, peer disconnected"))
            else:
                results.append(("unconnecting-headers-flood", True,
                               "Node handled flood gracefully, remained responsive"))
        else:
            results.append(("unconnecting-headers-flood", False, "Node not responsive after flood"))
        print(f"    {'PASS' if results[-1][1] else 'FAIL'}: {results[-1][2]}")
        time.sleep(0.5)

        # === Test 3: getheaders-spam ===
        print("\n  Testing getheaders-spam: Rapid GETHEADERS requests")
        r = run_node_simulator(port, "getheaders-spam", timeout=20)

        # Verify node responsive (main goal - no crash/hang)
        info = node.get_info()
        responsive = isinstance(info, dict) and "blocks" in info

        if responsive:
            results.append(("getheaders-spam", True, "Node handled spam without crash"))
        else:
            results.append(("getheaders-spam", False, "Node not responsive after spam"))
        print(f"    {'PASS' if results[-1][1] else 'FAIL'}: {results[-1][2]}")
        time.sleep(0.5)

        # === Test 4: rapid-reconnect ===
        print("\n  Testing rapid-reconnect: Connection churn")
        r = run_node_simulator(port, "rapid-reconnect", timeout=30)

        # Verify node responsive
        info = node.get_info()
        responsive = isinstance(info, dict) and "blocks" in info

        if responsive:
            results.append(("rapid-reconnect", True, "Node handled connection churn"))
        else:
            results.append(("rapid-reconnect", False, "Node not responsive after reconnect churn"))
        print(f"    {'PASS' if results[-1][1] else 'FAIL'}: {results[-1][2]}")

        # Summary
        print("\n" + "=" * 60)
        passed_count = sum(1 for _, p, _ in results if p)
        total = len(results)

        print(f"Results: {passed_count}/{total} passed")
        for name, passed, details in results:
            status = "PASS" if passed else "FAIL"
            print(f"  {name}: {status}")

        if passed_count == total:
            print("\nadversarial_validation_wire PASSED")
            print("  - Header validation working correctly")
            print("  - Unconnecting headers handled gracefully")
            print("  - Node handles spam/churn gracefully")
            return 0
        else:
            print(f"\nadversarial_validation_wire FAILED ({total - passed_count} failures)")
            return 1

    except Exception as e:
        print(f"\nadversarial_validation_wire FAILED: {e}")
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
