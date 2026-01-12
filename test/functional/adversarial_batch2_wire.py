#!/usr/bin/env python3
"""Wire-level adversarial tests - Batch 2 via node_simulator.

Covers additional adversarial scenarios:
- VERSION variants: bad-height, long-ua, old-proto, future-time
- PING/PONG: pong-no-ping, pong-wrong-nonce, ping-zero-nonce, ping-oversized
- Payload boundaries: getheaders-empty, locator-overflow
- Header chain: headers-bad-merkle, headers-deep-fork, headers-max-batch
- Other messages: inv-bad-type, inv-repeat, getaddr-spam, sendheaders-pre, sendheaders-dbl

Verification:
- Protocol violations cause appropriate response (disconnect or ignore)
- Node remains responsive after each attack
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


def wait_for_disconnect(node: TestNode, timeout: int = 10) -> bool:
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


def run_attack_test(node: TestNode, port: int, test_name: str, description: str,
                    expect_disconnect: bool) -> tuple:
    """
    Run a single attack test with proper verification.

    Returns: (passed: bool, details: str)
    """
    # Run the attack
    r = run_node_simulator(port, test_name, timeout=30)

    # Check if simulator reported disconnect
    sim_disconnected = any(x in (r.stdout + r.stderr).lower() for x in [
        "connection closed", "end of file", "broken pipe", "connection reset"
    ])

    # If simulator had unexpected error
    if r.returncode != 0 and not sim_disconnected:
        return False, f"simulator error: {r.stderr[:100]}"

    # Verify peer state
    node_disconnected = wait_for_disconnect(node, timeout=5)

    # Verify node still responsive
    try:
        info = node.get_info()
        responsive = isinstance(info, dict) and "blocks" in info
    except Exception:
        responsive = False

    if not responsive:
        return False, "Node not responsive after attack"

    if expect_disconnect:
        if node_disconnected:
            return True, "Peer disconnected (violation detected)"
        else:
            return False, "Peer NOT disconnected (violation not detected)"
    else:
        return True, "Attack handled, node responsive"


def main():
    print("=" * 60)
    print("TEST: Adversarial Batch 2 Wire")
    print("=" * 60)

    test_dir = Path(tempfile.mkdtemp(prefix="unicity_wire_batch2_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node = None
    results = []

    try:
        port = pick_free_port()
        node = TestNode(0, test_dir / "node0", binary_path, extra_args=["--listen", f"--port={port}"])
        node.start()
        time.sleep(2)

        # === VERSION Variants ===
        print("\n=== VERSION Variants ===")
        version_tests = [
            ("ver-bad-height", "VERSION with start_height=-1", True),
            ("ver-long-ua", "VERSION with 300-char user agent", False),  # Truncated, not error
            ("ver-old-proto", "VERSION with protocol 209", True),  # Too old
            ("ver-future-time", "VERSION timestamp 1 year future", False),  # Tolerated
            ("sendheaders-pre", "SENDHEADERS before VERSION", True),
        ]

        for test_name, desc, expect_disconnect in version_tests:
            print(f"  {test_name}: {desc}...", end=" ", flush=True)
            passed, details = run_attack_test(node, port, test_name, desc, expect_disconnect)
            results.append((test_name, passed, details))
            print(f"{'PASS' if passed else 'FAIL'} - {details}")
            time.sleep(0.3)

        # === PING/PONG Attacks (all should be tolerated) ===
        print("\n=== PING/PONG Attacks ===")
        ping_tests = [
            ("pong-no-ping", "PONG without PING", False),
            ("pong-wrong-nonce", "PONG with wrong nonce", False),
            ("ping-zero-nonce", "PING with nonce=0", False),
            ("ping-oversized", "PING with 100-byte payload", False),
        ]

        for test_name, desc, expect_disconnect in ping_tests:
            print(f"  {test_name}: {desc}...", end=" ", flush=True)
            passed, details = run_attack_test(node, port, test_name, desc, expect_disconnect)
            results.append((test_name, passed, details))
            print(f"{'PASS' if passed else 'FAIL'} - {details}")
            time.sleep(0.3)

        # === Payload Boundary Tests ===
        print("\n=== Payload Boundary Tests ===")
        payload_tests = [
            ("getheaders-empty", "GETHEADERS empty locator", False),
            ("locator-overflow", "GETHEADERS 150 hashes", True),  # Exceeds limit
        ]

        for test_name, desc, expect_disconnect in payload_tests:
            print(f"  {test_name}: {desc}...", end=" ", flush=True)
            passed, details = run_attack_test(node, port, test_name, desc, expect_disconnect)
            results.append((test_name, passed, details))
            print(f"{'PASS' if passed else 'FAIL'} - {details}")
            time.sleep(0.3)

        # === Header Chain Attacks ===
        print("\n=== Header Chain Attacks ===")
        header_tests = [
            ("headers-bad-merkle", "Header with 0xFF merkle", True),
            ("headers-deep-fork", "Header from random block", True),
            ("headers-max-batch", "2000 headers at once", False),  # Large but valid
        ]

        for test_name, desc, expect_disconnect in header_tests:
            print(f"  {test_name}: {desc}...", end=" ", flush=True)
            passed, details = run_attack_test(node, port, test_name, desc, expect_disconnect)
            results.append((test_name, passed, details))
            print(f"{'PASS' if passed else 'FAIL'} - {details}")
            time.sleep(0.5)

        # === Other Message Tests (all should be tolerated) ===
        print("\n=== Other Message Tests ===")
        other_tests = [
            ("inv-bad-type", "INV with type=99", False),
            ("inv-repeat", "Same INV hash 100x", False),
            ("getaddr-spam", "50 GETADDR requests", False),
            ("sendheaders-dbl", "SENDHEADERS twice", False),
        ]

        for test_name, desc, expect_disconnect in other_tests:
            print(f"  {test_name}: {desc}...", end=" ", flush=True)
            passed, details = run_attack_test(node, port, test_name, desc, expect_disconnect)
            results.append((test_name, passed, details))
            print(f"{'PASS' if passed else 'FAIL'} - {details}")
            time.sleep(0.3)

        # Final responsiveness check
        print("\n=== Final Responsiveness Check ===")
        info = node.get_info()
        if isinstance(info, dict) and "blocks" in info:
            print("  Node responsive: PASS")
        else:
            print("  Node responsive: FAIL")
            results.append(("final-responsive", False, "Node not responsive"))

        # Summary
        print("\n" + "=" * 60)
        passed_count = sum(1 for _, p, _ in results if p)
        total = len(results)

        print(f"Results: {passed_count}/{total} passed")
        for name, passed, _ in results:
            status = "PASS" if passed else "FAIL"
            print(f"  {name}: {status}")

        if passed_count == total:
            print("\nadversarial_batch2_wire PASSED")
            return 0
        else:
            print(f"\nadversarial_batch2_wire FAILED ({total - passed_count} failures)")
            return 1

    except Exception as e:
        print(f"\nadversarial_batch2_wire FAILED: {e}")
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
