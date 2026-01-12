#!/usr/bin/env python3
"""Wire-level adversarial rate limit tests via node_simulator.

Covers: unknown-cmd, unknown-cmd-flood.
Tests that the node properly rate-limits unknown commands.

Verification:
- Single unknown command: Should be tolerated (no disconnect)
- Unknown command flood (25x): Should trigger disconnect after limit (20)
- Verifies rate limiting mechanism is working
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

# Rate limit constant from the node implementation
MAX_UNKNOWN_COMMANDS_PER_MINUTE = 20


def run_node_simulator(port: int, test: str, host: str = "127.0.0.1", timeout: int = 20):
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


def has_connected_peer(node: TestNode) -> bool:
    """Check if node has any connected peers."""
    try:
        peers = node.get_peer_info()
        if not isinstance(peers, list):
            return False
        connected = [p for p in peers if isinstance(p, dict) and p.get("connected")]
        return len(connected) > 0
    except Exception:
        return False


def main():
    print("=" * 60)
    print("TEST: Adversarial Rate Limit Wire")
    print("=" * 60)
    print(f"Tests unknown command rate limiting (limit: {MAX_UNKNOWN_COMMANDS_PER_MINUTE}/min)")

    test_dir = Path(tempfile.mkdtemp(prefix="unicity_wire_ratelimit_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"

    node = None
    results = []

    try:
        port = pick_free_port()
        node = TestNode(0, test_dir / "node0", binary_path, extra_args=["--listen", f"--port={port}"])
        node.start()
        time.sleep(2)

        # === Test 1: Single unknown command (should be tolerated) ===
        print("\n  Testing unknown-cmd: Single unknown command")
        r = run_node_simulator(port, "unknown-cmd", timeout=15)

        # Check if connection was closed
        connection_closed = any(x in (r.stdout + r.stderr).lower() for x in [
            "connection closed", "end of file", "broken pipe", "connection reset"
        ])

        # Give node time to process
        time.sleep(1)

        # Verify node responsive
        info = node.get_info()
        responsive = isinstance(info, dict) and "blocks" in info

        # Single unknown command should NOT cause disconnect (tolerance)
        if connection_closed:
            # If disconnected, check if it was too aggressive
            results.append(("unknown-cmd", False,
                           "Disconnected after single unknown cmd (too aggressive)"))
        elif responsive:
            results.append(("unknown-cmd", True,
                           "Single unknown command tolerated (correct)"))
        else:
            results.append(("unknown-cmd", False, "Node not responsive"))
        print(f"    {'PASS' if results[-1][1] else 'FAIL'}: {results[-1][2]}")
        time.sleep(0.5)

        # === Test 2: Unknown command flood (25x - exceeds limit of 20) ===
        print(f"\n  Testing unknown-cmd-flood: 25 unknown commands (limit={MAX_UNKNOWN_COMMANDS_PER_MINUTE})")
        r = run_node_simulator(port, "unknown-cmd-flood", timeout=20)

        # Check if connection was closed (expected after exceeding limit)
        connection_closed = any(x in (r.stdout + r.stderr).lower() for x in [
            "connection closed", "end of file", "broken pipe", "connection reset"
        ])

        # Verify peer was disconnected
        disconnected = wait_for_disconnect(node, timeout=15)

        # Verify node responsive
        info = node.get_info()
        responsive = isinstance(info, dict) and "blocks" in info

        if disconnected and responsive:
            results.append(("unknown-cmd-flood", True,
                           f"Peer disconnected after exceeding {MAX_UNKNOWN_COMMANDS_PER_MINUTE} limit"))
        elif responsive and not disconnected:
            results.append(("unknown-cmd-flood", False,
                           "Peer NOT disconnected after flood (rate limit not working)"))
        else:
            results.append(("unknown-cmd-flood", False, "Node not responsive"))
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
            print("\nadversarial_rate_limit_wire PASSED")
            print(f"  - Single unknown command tolerated")
            print(f"  - Flood triggers disconnect at {MAX_UNKNOWN_COMMANDS_PER_MINUTE} limit")
            return 0
        else:
            print(f"\nadversarial_rate_limit_wire FAILED ({total - passed_count} failures)")
            return 1

    except Exception as e:
        print(f"\nadversarial_rate_limit_wire FAILED: {e}")
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
