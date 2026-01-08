#!/usr/bin/env python3
"""RPC setban tests: default bantime, modes, canonicalization, validation."""

import sys
import tempfile
import shutil
import time
from pathlib import Path

# Add test framework to path
sys.path.insert(0, str(Path(__file__).parent / "test_framework"))

from test_node import TestNode


def listbanned_map(node):
    arr = node.rpc("listbanned")
    # RPC returns a list of {address, banned_until, ban_created, ban_reason}
    return {e["address"]: e for e in arr}


def main():
    print("Starting rpc_setban test...")

    test_dir = Path(tempfile.mkdtemp(prefix="unicity_rpc_setban_"))
    binary_path = Path(__file__).parent.parent.parent / "build" / "bin" / "unicityd"
    node = None

    try:
        node = TestNode(0, test_dir / "node0", binary_path, extra_args=["--regtest"])  # default regtest
        node.start()

        # 1) Default bantime (24h) on valid IPv4
        res = node.rpc("setban", "127.0.0.2", "add")
        assert res.get("success") is True
        banned = listbanned_map(node)
        assert "127.0.0.2" in banned
        be = banned["127.0.0.2"]
        assert be["banned_until"] > be["ban_created"], "banned_until should be in future"
        # Roughly 24h (allow some slack)
        delta = be["banned_until"] - be["ban_created"]
        assert 86000 <= delta <= 87000, f"unexpected default bantime delta: {delta}"

        # 2) Permanent mode
        res = node.rpc("setban", "127.0.0.3", "add", 0, "permanent")
        assert res.get("success") is True
        banned = listbanned_map(node)
        assert "127.0.0.3" in banned
        assert banned["127.0.0.3"]["banned_until"] == 0

        # 3) Absolute mode (ban until now + 1h)
        now = int(time.time())
        abs_until = now + 3600
        res = node.rpc("setban", "127.0.0.4", "add", abs_until, "absolute")
        assert res.get("success") is True
        banned = listbanned_map(node)
        assert "127.0.0.4" in banned
        got_until = banned["127.0.0.4"]["banned_until"]
        assert abs(abs_until - got_until) <= 2, f"absolute until mismatch: {abs_until} vs {got_until}"

        # 4) Canonicalization: ban IPv4-mapped IPv6, unban IPv4
        res = node.rpc("setban", "::ffff:127.0.0.5", "add")
        assert res.get("success") is True
        banned = listbanned_map(node)
        assert "127.0.0.5" in banned, "should be canonicalized to dotted-quad"
        # Unban using canonical address
        res = node.rpc("setban", "127.0.0.5", "remove")
        assert res.get("success") is True
        banned = listbanned_map(node)
        assert "127.0.0.5" not in banned

        # 5) Invalid IP rejected
        res = node.rpc("setban", "not_an_ip", "add")
        assert "error" in res, "Expected error for invalid IP"

        # 6) Negative bantime rejected
        res = node.rpc("setban", "127.0.0.6", "add", -1)
        assert "error" in res and "Invalid bantime" in res["error"]

        print("✓ rpc_setban passed")
        return 0

    except Exception as e:
        print(f"✗ rpc_setban failed: {e}")
        import traceback
        traceback.print_exc()
        if node:
            print("\nNode last 50 lines of debug.log:")
            print(node.read_log(50))
        return 1
    finally:
        if node and node.is_running():
            print("Stopping node...")
            node.stop()
        print(f"Cleaning up {test_dir}")
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
