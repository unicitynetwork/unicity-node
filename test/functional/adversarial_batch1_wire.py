#!/usr/bin/env python3
"""Wire-level adversarial tests - Batch 1 via node_simulator.

Covers:
- Handshake variants: pre-handshake-gh, pre-handshake-inv, pre-handshake-gd,
                      verack-first, multi-verack, partial-version, silent
- Header validation: timestamp-zero, nbits-zero, nbits-max, self-ref,
                     circular-chain, version-zero-hdr, neg-version-hdr
- Framing: empty-command, length-short, length-max, command-null, command-non-ascii
- Message types: addr-flood, inv-spam
- Resource exhaustion: rapid-fire

Verification:
- Protocol violations cause disconnect (handshake, invalid headers)
- Framing violations handled appropriately
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


def run_node_simulator(port: int, test: str, host: str = "127.0.0.1", timeout: int = 20):
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
    r = run_node_simulator(port, test_name, timeout=20)

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
        # For non-disconnect tests, just verify node is responsive
        return True, "Attack handled, node responsive"


def main():
    print("=" * 60)
    print("TEST: Adversarial Batch 1 Wire")
    print("=" * 60)

    test_dir = Path(tempfile.mkdtemp(prefix="unicity_wire_batch1_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node = None
    results = []

    try:
        port = pick_free_port()
        node = TestNode(0, test_dir / "node0", binary_path, extra_args=["--listen", f"--port={port}"])
        node.start()
        time.sleep(2)

        # === Handshake Violations (all should cause disconnect) ===
        print("\n=== Handshake Violations ===")
        handshake_tests = [
            ("pre-handshake-gh", "GETHEADERS before handshake", True),
            ("pre-handshake-inv", "INV before handshake", True),
            ("verack-first", "VERACK without VERSION", True),
            ("multi-verack", "Send VERACK twice", True),
            ("pre-handshake-gd", "GETDATA before handshake", True),
            ("partial-version", "Truncated VERSION message", True),
            ("silent", "Connect but send nothing", False),  # Tolerated initially
        ]

        for test_name, desc, expect_disconnect in handshake_tests:
            print(f"  {test_name}: {desc}...", end=" ", flush=True)
            passed, details = run_attack_test(node, port, test_name, desc, expect_disconnect)
            results.append((test_name, passed, details))
            print(f"{'PASS' if passed else 'FAIL'} - {details}")
            time.sleep(0.3)

        # === Header Validation (invalid headers should cause disconnect) ===
        print("\n=== Header Validation ===")
        header_tests = [
            ("timestamp-zero", "Headers with timestamp=0", True),
            ("nbits-zero", "Headers with nBits=0", True),
            ("nbits-max", "Headers with nBits=0xFFFFFFFF", True),
            ("self-ref", "Self-referential prevblock", True),
            ("circular-chain", "Circular chain A->B->A", True),
            ("version-zero-hdr", "Header with nVersion=0", True),
            ("neg-version-hdr", "Header with nVersion=-1", True),
        ]

        for test_name, desc, expect_disconnect in header_tests:
            print(f"  {test_name}: {desc}...", end=" ", flush=True)
            passed, details = run_attack_test(node, port, test_name, desc, expect_disconnect)
            results.append((test_name, passed, details))
            print(f"{'PASS' if passed else 'FAIL'} - {details}")
            time.sleep(0.3)

        # === Framing Attacks (behavior varies) ===
        print("\n=== Framing Attacks ===")
        framing_tests = [
            ("empty-command", "Empty command field", False),  # May be ignored
            ("length-short", "Declared length < actual", False),  # Parsed weirdly
            ("length-max", "Declared length > MAX", True),  # Should disconnect
            ("command-null", "Command with null bytes", False),  # May be ignored
            ("command-non-ascii", "Command with non-ASCII", False),  # May be ignored
        ]

        for test_name, desc, expect_disconnect in framing_tests:
            print(f"  {test_name}: {desc}...", end=" ", flush=True)
            passed, details = run_attack_test(node, port, test_name, desc, expect_disconnect)
            results.append((test_name, passed, details))
            print(f"{'PASS' if passed else 'FAIL'} - {details}")
            time.sleep(0.3)

        # === Message Spam (should be handled gracefully) ===
        print("\n=== Message Spam ===")
        spam_tests = [
            ("addr-flood", "ADDR with 1000 addresses", False),
            ("inv-spam", "100 INV messages", False),
            ("rapid-fire", "500 PINGs rapid-fire", False),
        ]

        for test_name, desc, expect_disconnect in spam_tests:
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
            print("\nadversarial_batch1_wire PASSED")
            return 0
        else:
            print(f"\nadversarial_batch1_wire FAILED ({total - passed_count} failures)")
            return 1

    except Exception as e:
        print(f"\nadversarial_batch1_wire FAILED: {e}")
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
